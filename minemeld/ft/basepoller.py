import logging
import copy
import gevent
import gevent.event
import random

from . import base
from . import ft_states
from . import table
from .utils import utc_millisec
from .utils import age_out_in_millisec
from .utils import RWLock

LOG = logging.getLogger(__name__)

_AGE_OUT_BASES = ['last_seen', 'first_seen']
_MAX_AGE_OUT = ((1 << 32)-1)*1000  # 2106-02-07 6:28:15


def _parse_age_out(s):
    if s is None:
        return None

    result = {}

    toks = s.split('+', 1)
    if len(toks) == 1:
        t = toks[0].strip()
        if t in _AGE_OUT_BASES:
            result['base'] = t
            result['offset'] = 0
        else:
            result['base'] = 'last_seen'
            result['offset'] = age_out_in_millisec(t)
            if result['offset'] is None:
                raise ValueError('Invalid age out offset %s' % t)
    else:
        base = toks[0].strip()
        if base not in _AGE_OUT_BASES:
            raise ValueError('Invalid age out base %s' % base)
        result['base'] = base
        result['offset'] = age_out_in_millisec(toks[1].strip())
        if result['offset'] is None:
            raise ValueError('Invalid age out offset %s' % t)

    return result


class IndicatorStatus(object):
    D_MASK = 1
    F_MASK = 2
    A_MASK = 4
    W_MASK = 8

    NX = 0
    NFNANW = D_MASK
    XFNANW = D_MASK | F_MASK
    NFXANW = D_MASK | A_MASK
    XFXANW = D_MASK | F_MASK | A_MASK
    NFNAXW = D_MASK | W_MASK
    XFNAXW = D_MASK | F_MASK | W_MASK
    NFXAXW = D_MASK | A_MASK | W_MASK
    XFXAXW = D_MASK | F_MASK | A_MASK | W_MASK

    def __init__(self, indicator, attributes, table, now, in_feed_threshold):
        self.state = 0

        self.cv = table.get(indicator)
        if self.cv is None:
            return
        self.state = self.state | IndicatorStatus.D_MASK

        if self.cv['_age_out'] < now:
            self.state = self.state | IndicatorStatus.A_MASK

        if self.cv['_last_run'] >= in_feed_threshold:
            self.state = self.state | IndicatorStatus.F_MASK

        if self.cv.get('_withdrawn', None) is not None:
            self.state = self.state | IndicatorStatus.W_MASK

        LOG.debug('status %s %d', self.cv, self.state)


class BasePollerFT(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None
        self.ageout_glet = None

        self.active_requests = []
        self.rebuild_flag = False
        self.last_run = None
        self.last_ageout_run = None

        self.state_lock = RWLock()

        super(BasePollerFT, self).__init__(name, chassis, config)

    def configure(self):
        super(BasePollerFT, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.attributes = self.config.get('attributes', {})
        self.interval = self.config.get('interval', 3600)
        self.num_retries = self.config.get('num_retries', 2)

        _age_out = self.config.get('age_out', {})

        self.age_out = {
            'interval': _age_out.get('interval', 3600),
            'sudden_death': _age_out.get('sudden_death', True),
            'default': _parse_age_out(_age_out.get('default', '30d'))
        }
        for k, v in _age_out.iteritems():
            if k in self.age_out:
                continue
            self.age_out[k] = _parse_age_out(v)

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('_age_out')
        self.table.create_index('_withdrawn')
        self.table.create_index('_last_run')

    def initialize(self):
        self._initialize_table()

    def rebuild(self):
        self.rebuild_flag = True
        self._initialize_table(truncate=(self.last_checkpoint is None))

    def reset(self):
        self._initialize_table(truncate=True)

    @base.BaseFT.state.setter
    def state(self, value):
        LOG.debug("%s - acquiring state write lock", self.name)
        self.state_lock.lock()
        #  this is weird ! from stackoverflow 10810369
        super(BasePollerFT, self.__class__).state.fset(self, value)
        self.state_lock.unlock()
        LOG.debug("%s - releasing state write lock", self.name)

    def _age_out_run(self):
        while True:
            self.state_lock.rlock()
            if self.state != ft_states.STARTED:
                self.state_lock.runlock()
                return

            try:
                now = utc_millisec()

                LOG.debug('now: %s', now)

                for i, v in self.table.query(index='_age_out',
                                             to_key=now-1,
                                             include_value=True):
                    LOG.debug('%s - %s %s aged out', self.name, i, v)

                    if v.get('_withdrawn', None) is not None:
                        continue

                    self.emit_withdraw(indicator=i)
                    v['_withdrawn'] = now
                    self.table.put(i, v)

                    self.statistics['aged_out'] += 1

                self.last_ageout_run = now

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('Exception in _age_out_loop')

            finally:
                self.state_lock.runlock()

            try:
                gevent.sleep(self.age_out['interval'])
            except gevent.GreenletExit:
                break

    def _calc_age_out(self, indicator, attributes):
        t = attributes.get('type', None)
        if t is None or t not in self.age_out:
            sel = self.age_out['default']
        else:
            sel = self.age_out[t]

        if sel is None:
            return _MAX_AGE_OUT

        b = attributes[sel['base']]

        return b + sel['offset']

    def _sudden_death(self):
        if self.last_run is None:
            return

        LOG.debug('checking sudden death')

        for i, v in self.table.query(index='_last_run',
                                     to_key=self.last_run,
                                     include_value=True):
            LOG.debug('%s - %s %s sudden death', self.name, i, v)

            v['_age_out'] = self.last_run-1
            self.table.put(i, v)
            self.statistics['removed'] += 1

    def _collect_garbage(self, t0):
        for i in self.table.query(index='_withdrawn',
                                  to_key=t0-1,
                                  include_value=False):
            self.table.delete(i)
            self.statistics['garbage_collected'] += 1

    def _compare_attributes(self, oa, na):
        for k in na:
            if oa.get(k, None) != na[k]:
                return False
        return True

    def _polling_loop(self):
        LOG.info("Polling %s", self.name)

        now = utc_millisec()

        iterator = self._build_iterator(now)

        for item in iterator:
            try:
                ipairs = self._process_item(item)

            except:
                LOG.exception('%s - Exception parsing %s', self.name, item)
                continue

            for indicator, attributes in ipairs:
                if indicator is None:
                    LOG.debug('%s - indicator is None for item %s',
                              self.name, item)
                    continue

                in_feed_threshold = self.last_run
                if in_feed_threshold is None:
                    in_feed_threshold = now - self.interval*1000

                istatus = IndicatorStatus(
                    indicator=indicator,
                    attributes=attributes,
                    table=self.table,
                    now=now,
                    in_feed_threshold=in_feed_threshold
                )

                if istatus.state in [IndicatorStatus.NX,
                                     IndicatorStatus.NFNANW,
                                     IndicatorStatus.NFXANW,
                                     IndicatorStatus.NFXAXW,
                                     IndicatorStatus.NFNAXW]:
                    v = copy.copy(self.attributes)
                    v['sources'] = [self.source_name]
                    v['last_seen'] = now
                    v['first_seen'] = now
                    v['_last_run'] = now
                    v.update(attributes)
                    v['_age_out'] = self._calc_age_out(indicator, v)

                    self.statistics['added'] += 1
                    self.table.put(indicator, v)
                    self.emit_update(indicator, v)

                    LOG.debug('%s - added %s %s', self.name, indicator, v)

                elif istatus.state == IndicatorStatus.XFNANW:
                    v = istatus.cv

                    eq = self._compare_attributes(v, attributes)

                    v['_last_run'] = now
                    v.update(attributes)
                    v['_age_out'] = self._calc_age_out(indicator, v)

                    self.table.put(indicator, v)

                    if not eq:
                        self.emit_update(indicator, v)

                elif istatus.state == IndicatorStatus.XFXANW:
                    v = istatus.cv
                    v['_last_run'] = now
                    self.table.put(indicator, v)

                elif istatus.state in [IndicatorStatus.XFXAXW,
                                       IndicatorStatus.XFNAXW]:
                    v = istatus.cv
                    v['_last_run'] = now
                    v['_withdrawn'] = now
                    self.table.put(indicator, v)

                else:
                    LOG.error('%s - indicator state unhandled: %s',
                              self.name, istatus.state)
                    continue

    def _run(self):
        while self.last_ageout_run is None:
            gevent.sleep(1)

        self.state_lock.rlock()
        if self.state != ft_states.STARTED:
            self.state_lock.runlock()
            return

        try:
            if self.rebuild_flag:
                LOG.debug("rebuild flag set, resending current indicators")
                # reinit flag is set, emit update for all the known indicators
                for i, v in self.table.query(include_value=True):
                    self.emit_update(i, v)
        finally:
            self.state_lock.unlock()

        tryn = 0

        while True:
            lastrun = utc_millisec()

            self.state_lock.rlock()
            if self.state != ft_states.STARTED:
                self.state_lock.runlock()
                break

            try:
                self._polling_loop()

                if self.age_out['sudden_death']:
                    self._sudden_death()

                self._collect_garbage(lastrun)

            except gevent.GreenletExit:
                break

            except:
                LOG.exception("Exception in polling loop for %s", self.name)
                tryn += 1
                if tryn < self.num_retries:
                    gevent.sleep(random.randint(1, 5))
                    continue

            finally:
                self.state_lock.runlock()

            LOG.debug("%s - End of polling - #indicators: %d",
                      self.name, self.table.num_indicators)

            self.last_run = lastrun

            tryn = 0

            now = utc_millisec()
            deltat = (lastrun+self.interval*1000)-now

            while deltat < 0:
                LOG.warning("Time for processing exceeded interval for %s",
                            self.name)
                deltat += self.interval*1000

            try:
                gevent.sleep(deltat/1000.0)

            except gevent.GreenletExit:
                break

    def mgmtbus_status(self):
        result = super(BasePollerFT, self).mgmtbus_status()
        result['last_run'] = self.last_run

        return result

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(BasePollerFT, self).start()

        if self.glet is not None:
            return

        self.glet = gevent.spawn_later(random.randint(0, 2), self._run)
        self.ageout_glet = gevent.spawn(self._age_out_run)

    def stop(self):
        super(BasePollerFT, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()
        self.ageout_glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
