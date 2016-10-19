#  Copyright 2015-2016 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
This module implements minemeld.ft.basepoller.BasePollerFT, a base class for
miners retrieving indicators by periodically polling an external source.
"""

import logging
import copy
import gevent
import gevent.event
import gevent.queue
import random
import collections

from . import base
from . import ft_states
from . import table
from .utils import utc_millisec
from .utils import RWLock
from .utils import parse_age_out

LOG = logging.getLogger(__name__)

_MAX_AGE_OUT = ((1 << 32)-1)*1000  # 2106-02-07 6:28:15


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

    def __init__(self, indicator, attributes, itable, now, in_feed_threshold):
        self.state = 0

        self.cv = itable.get(indicator)
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
    """Implements base class for polling miners.

    **Config parameters**
        :source_name: name of the source. This is placed in the
            *sources* attribute of the generated indicators. Default: name
            of the node.
        :attributes: dictionary of attributes for the generated indicators.
            This dictionary is used as template for the value of the generated
            indicators. Default: empty
        :interval: polling interval in seconds. Default: 3600.
        :num_retries: in case of failure, how many times the miner should
            try to reach the source. If this number is exceeded, the miner
            waits until the next polling time to try again. Default: 2
        :age_out: age out policies to apply to the indicators.
            Default: age out check interval 3600 seconds, sudden death enabled,
            default age out interval 30 days.

    **Age out policy**
        Age out policy is described by a dictionary with at least 3 keys:

        :interval: number of seconds between successive age out checks.
        :sudden_death: boolean, if *true* indicators are immediately aged out
            when they disappear from the feed.
        :default: age out interval. After this interval an indicator is aged
            out even if it is still present in the feed. If *null*, no age out
            interval is applied.

        Additional keys can be used to specify age out interval per indicator
        *type*.

    **Age out interval**
        Age out intervals have the following format::

            <base attribute>+<interval>

        *base attribute* can be *last_seen*, if the age out interval should be
        calculated based on the last time the indicator was found in the feed,
        or *first_seen*, if instead the age out interval should be based on the
        time the indicator was first seen in the feed. If not specified
        *first_seen* is used.

        *interval* is the length of the interval expressed in seconds. Suffixes
        *d*, *h* and *m* can be used to specify days, hours or minutes.

    Example:
        Example config in YAML for a feed where indicators should be aged out
        only when they are removed from the feed::

            source_name: example.persistent_feed
            interval: 600
            age_out:
                default: null
                sudden_death: true
                interval: 300
            attributes:
                type: IPv4
                confidence: 100
                share_level: green
                direction: inbound

        Example config in YAML for a feed where indicators are aged out when
        they disappear from the feed and 30 days after they have seen for the
        first time in the feed::

            source_name: example.long_running_feed
            interval: 3600
            age_out:
                default: first_seen+30d
                sudden_death: true
                interval: 1800
            attributes:
                type: URL
                confidence: 50
                share_level: green

        Example config in YAML for a feed where indicators are aged 30 days
        after they have seen for the last time in the feed::

            source_name: example.delta_feed
            interval: 3600
            age_out:
                default: last_seen+30d
                sudden_death: false
                interval: 1800
            attributes:
                type: URL
                confidence: 50
                share_level: green

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """

    _AGE_OUT_BASES = None
    _DEFAULT_AGE_OUT_BASE = None

    def __init__(self, name, chassis, config):
        self.table = None

        self._actor_queue = gevent.queue.Queue(maxsize=128)
        self._actor_glet = None
        self._actor_commands_ts = collections.defaultdict(int)
        self._poll_glet = None
        self._age_out_glet = None

        self.last_run = None
        self.last_successful_run = None
        self.last_ageout_run = None
        self._sub_state = None
        self._sub_state_message = None

        self.poll_event = gevent.event.Event()

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
            'default': parse_age_out(
                _age_out.get('default', '30d'),
                age_out_bases=self._AGE_OUT_BASES,
                default_base=self._DEFAULT_AGE_OUT_BASE
            )
        }
        for k, v in _age_out.iteritems():
            if k in self.age_out:
                continue
            self.age_out[k] = parse_age_out(v)

    def _saved_state_restore(self, saved_state):
        self.last_run = saved_state.get('last_run', None)
        self.last_successful_run = saved_state.get(
            'last_successful_run',
            None
        )

    def _saved_state_create(self):
        return {
            'last_run': self.last_run,
            'last_successful_run': self.last_successful_run
        }

    def _saved_state_reset(self):
        self.last_successful_run = None
        self.last_run = None

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('_age_out')
        self.table.create_index('_withdrawn')
        self.table.create_index('_last_run')

    def initialize(self):
        self._initialize_table()

    def rebuild(self):
        self._actor_queue.put(
            (utc_millisec(), 'rebuild')
        )
        self._initialize_table(truncate=(self.last_checkpoint is None))

    def reset(self):
        self._saved_state_reset()
        self._initialize_table(truncate=True)

    @base.BaseFT.state.setter
    def state(self, value):
        LOG.debug("%s - acquiring state write lock", self.name)
        self.state_lock.lock()
        #  this is weird ! from stackoverflow 10810369
        super(BasePollerFT, self.__class__).state.fset(self, value)
        self.state_lock.unlock()
        LOG.debug("%s - releasing state write lock", self.name)

    def _age_out(self):
        with self.state_lock:
            if self.state != ft_states.STARTED:
                return

            try:
                now = utc_millisec()

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
                raise

            except:
                LOG.exception('Exception in _age_out')

    def _sudden_death(self):
        if self.last_successful_run is None:
            return

        with self.state_lock:
            if self.state != ft_states.STARTED:
                return

            LOG.debug('checking sudden death for %d', self.last_successful_run)

            for i, v in self.table.query(index='_last_run',
                                         to_key=self.last_successful_run-1,
                                         include_value=True):
                LOG.debug('%s - %s %s sudden death', self.name, i, v)

                v['_age_out'] = self.last_successful_run-1
                self.table.put(i, v)
                self.statistics['removed'] += 1

    def _collect_garbage(self):
        now = utc_millisec()

        with self.state_lock:
            if self.state != ft_states.STARTED:
                return

            for i in self.table.query(index='_withdrawn',
                                      to_key=now,
                                      include_value=False):
                LOG.debug('%s - %s collected', self.name, i)
                self.table.delete(i)
                self.statistics['garbage_collected'] += 1

    def _compare_attributes(self, oa, na):
        for k in na:
            if oa.get(k, None) != na[k]:
                return False
        return True

    def _update_attributes(self, current, _new):
        current.update(_new)

        return current

    def _polling_loop(self):
        LOG.info("Polling %s", self.name)

        now = utc_millisec()

        with self.state_lock:
            if self.state != ft_states.STARTED:
                LOG.info(
                    '%s - state not STARTED, polling not performed',
                    self.name
                )
                return

            iterator = self._build_iterator(now)

            if iterator is None:
                return False

        for item in iterator:
            with self.state_lock:
                if self.state != ft_states.STARTED:
                    break

                try:
                    ipairs = self._process_item(item)

                except gevent.GreenletExit:
                    raise

                except:
                    LOG.exception('%s - Exception parsing %s', self.name, item)
                    continue

                for indicator, attributes in ipairs:
                    if indicator is None:
                        LOG.debug('%s - indicator is None for item %s',
                                  self.name, item)
                        continue

                    in_feed_threshold = self.last_successful_run
                    if in_feed_threshold is None:
                        in_feed_threshold = now - self.interval*1000

                    istatus = IndicatorStatus(
                        indicator=indicator,
                        attributes=attributes,
                        itable=self.table,
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

                        v = self._update_attributes(v, attributes)

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

        return True

    def _rebuild(self):
        with self.state_lock:
            if self.state != ft_states.STARTED:
                return

            self.sub_state = 'REBUILDING'

            for i, v in self.table.query(include_value=True):
                self.emit_update(i, v)

    def _poll(self):
        tryn = 0

        while tryn < self.num_retries:
            lastrun = utc_millisec()

            try:
                self.sub_state = 'POLLING'

                performed = self._polling_loop()
                if performed:
                    self.last_successful_run = lastrun

                _result = 'SUCCESS'
                break

            except gevent.GreenletExit:
                raise

            except Exception as e:
                try:
                    _error_msg = str(e)
                except UnicodeDecodeError:
                    _error_msg = repr(e)

                _result = ('ERROR', _error_msg)

                self.statistics['error.polling'] += 1

                LOG.exception("Exception in polling loop for %s: %s",
                              self.name, str(e))

            tryn += 1
            gevent.sleep(random.randint(1, 5))

        LOG.debug("%s - End of polling - #indicators: %d",
                  self.name, self.table.num_indicators)

        self.last_run = lastrun
        self.sub_state = _result

    def _actor_loop(self):
        while True:
            timestamp, command = self._actor_queue.get()
            LOG.info('%s - command: %d %s', self.name, timestamp, command)

            try:
                last_ts = self._actor_commands_ts[command]
                if timestamp < last_ts:
                    LOG.info(
                        '%s - command %s, old timestamp - ignored',
                        self.name,
                        command
                    )
                    continue

                if command == 'poll':
                    self._poll()

                elif command == 'age_out':
                    self._age_out()

                elif command == 'sudden_death':
                    self._sudden_death()

                elif command == 'gc':
                    self._collect_garbage()

                elif command == 'rebuild':
                    self._rebuild()

                else:
                    LOG.error('%s - unknown command: %s', self.name, command)

            except gevent.GreenletExit:
                raise

            except:
                LOG.exception(
                    '%s - exception executing command %s', self.name, command
                )

            self._actor_commands_ts[command] = utc_millisec()

    def _poll_loop(self):
        # wait to poll until after the first ageout run
        while self.last_ageout_run is None:
            gevent.sleep(1)

        # if last_run is not None it means we have restored
        # a previous state, wait until poll time
        if self.last_run is not None:
            self.sub_state = 'WAITING'

            LOG.info(
                '%s - restored last run, waiting until the next poll time',
                self.name
            )

            try:
                self._huppable_wait(
                    (self.last_run+self.interval*1000)-utc_millisec()
                )
            except gevent.GreenletExit:
                return

        while True:
            with self.state_lock:
                if self.state != ft_states.STARTED:
                    break

            self._actor_queue.put(
                (utc_millisec(), 'poll')
            )

            if self.age_out['sudden_death']:
                self._actor_queue.put(
                    (utc_millisec(), 'sudden_death')
                )

            self._actor_queue.put(
                (utc_millisec(), 'age_out')
            )
            self._actor_queue.put(
                (utc_millisec(), 'gc')
            )

            try:
                self._huppable_wait(self.interval*1000)
            except gevent.GreenletExit:
                break

    def _age_out_loop(self):
        while True:
            with self.state_lock:
                if self.state != ft_states.STARTED:
                    break

            self._actor_queue.put(
                (utc_millisec(), 'age_out')
            )

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

    def _huppable_wait(self, deltat):
        while deltat < 0:
            LOG.warning(
                'Time for processing exceeded interval for %s',
                self.name
            )
            deltat += self.interval*1000

        LOG.info('hup is clear: %r', self.poll_event.is_set())
        hup_called = self.poll_event.wait(timeout=deltat/1000.0)
        if hup_called:
            LOG.debug('%s - clearing poll event', self.name)
            self.poll_event.clear()

    def mgmtbus_status(self):
        result = super(BasePollerFT, self).mgmtbus_status()
        result['last_run'] = self.last_run
        result['last_successful_run'] = self.last_successful_run
        result['sub_state'] = self.sub_state[0]

        if self.sub_state[1] is not None:
            result['sub_state_message'] = self.sub_state[1]

        return result

    @property
    def sub_state(self):
        return (self._sub_state, self._sub_state_message)

    @sub_state.setter
    def sub_state(self, value):
        if (type(value) == tuple):
            self._sub_state = value[0]
            self._sub_state_message = value[1]
        else:
            self._sub_state = value
            self._sub_state_message = None

        self.publish_status(force=True)

    def hup(self, source=None):
        LOG.info('%s - hup received, force polling', self.name)
        self.poll_event.set()

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(BasePollerFT, self).start()

        if self._actor_glet is not None:
            return

        self._actor_glet = gevent.spawn(
            self._actor_loop
        )
        self._poll_glet = gevent.spawn_later(
            random.randint(0, 2),
            self._poll_loop
        )
        self._age_out_glet = gevent.spawn(
            self._age_out_loop
        )

    def stop(self):
        super(BasePollerFT, self).stop()

        if self._actor_glet is None:
            return

        self._actor_glet.kill()
        self._poll_glet.kill()
        self._age_out_glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
