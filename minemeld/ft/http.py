import requests
import logging
import copy
import gevent
import gevent.event
import random

from . import base
from . import table
from . import ft_states
from .utils import utc_millisec

LOG = logging.getLogger(__name__)


class HttpFT(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None

        self.table = table.Table(name)
        self.table.create_index('_updated')
        self.active_requests = []
        self.rebuild_flag = False
        self.last_run = None
        self.idle_waitobject = gevent.event.AsyncResult()

        super(HttpFT, self).__init__(name, chassis, config)

    def configure(self):
        super(HttpFT, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.url = self.config.get('url', None)
        self.cchar = self.config.get('cchar', None)
        self.split_char = self.config.get('split_char', None)
        self.split_pos = self.config.get('split_pos', 0)
        self.attributes = self.config.get('attributes', {})
        self.interval = self.config.get('interval', 900)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.num_retries = self.config.get('num_retries', 2)

    def rebuild(self):
        self.rebuild_flag = True

    def reset(self):
        self.table.close()

        self.table = table.Table(self.name, truncate=True)
        self.table.create_index('_updated')

    def emit_checkpoint(self, value):
        LOG.debug("%s - checkpoint set to %s", self.name, value)
        self.idle_waitobject.set(value)

    def _process_line(self, line):
        attributes = copy.deepcopy(self.attributes)
        return line.split()[0], attributes

    def _polling_loop(self):
        LOG.info("Polling %s", self.name)

        now = utc_millisec()

        r = requests.get(
            self.url,
            stream=True,
            verify=True,
            timeout=self.polling_timeout
        )
        r.raise_for_status()

        for line in r.iter_lines():
            line = line.strip()
            if not line:
                continue

            if self.cchar is not None and \
               line.startswith(self.cchar):
                continue

            if self.split_char is not None:
                toks = line.split(self.split_char)
                if len(toks) < self.split_pos+1:
                    continue
                line = toks[self.split_pos].strip()

            indicator, attributes = self._process_line(line)
            if indicator is None:
                continue

            attributes['sources'] = [self.source_name]
            attributes['_updated'] = utc_millisec()

            ev = self.table.get(indicator)
            if ev is not None:
                attributes['first_seen'] = ev['first_seen']
            else:
                self.statistics['added'] += 1
                attributes['first_seen'] = utc_millisec()
            attributes['last_seen'] = utc_millisec()

            LOG.debug("%s - Updating %s %s", self.name, indicator, attributes)
            self.table.put(indicator, attributes)

            LOG.debug("%s - Emitting update for %s", self.name, indicator)
            self.emit_update(indicator, attributes)

        for i, v in self.table.query('_updated', from_key=0, to_key=now-1,
                                     include_value=True):
            LOG.debug("%s - Removing old %s - %s", self.name, i, v)
            self.statistics['removed'] += 1
            self.table.delete(i)
            self.emit_withdraw(i, value={'sources': [self.source_name]})

        LOG.debug("%s - End of polling #indicators: %d",
                  self.name, self.table.num_indicators)

    def _run(self):
        tryn = 0

        if self.rebuild_flag:
            LOG.debug("rebuild flag set, resending current indicators")
            # reinit flag is set, emit update for all the known indicators
            for i, v in self.table.query('_updated', include_value=True):
                self.emit_update(i, v)

        while True:
            if self.state != ft_states.STARTED:
                break

            lastrun = utc_millisec()

            try:
                self._polling_loop()
            except gevent.GreenletExit:
                return
            except:
                LOG.exception("Exception in polling loop for %s", self.name)
                tryn += 1
                if tryn < self.num_retries:
                    gevent.sleep(random.randint(1, 5))
                    continue

            self.last_run = lastrun

            tryn = 0

            now = utc_millisec()
            deltat = (lastrun+self.interval*1000)-now

            while deltat < 0:
                LOG.warning("Time for processing exceeded interval for %s",
                            self.name)
                deltat += self.interval*1000

            checkpoint = None
            try:
                LOG.debug("%s - start waiting", self.name)
                checkpoint = self.idle_waitobject.get(timeout=deltat/1000.0)
            except gevent.Timeout:
                pass
            LOG.debug('%s - waiting result: %s', self.name, checkpoint)

            if checkpoint is not None:
                super(HttpFT, self).emit_checkpoint(checkpoint)
                return

    def mgmtbus_status(self):
        result = super(HttpFT, self).mgmtbus_status()
        result['last_run'] = self.last_run

        return result

    def _send_indicators(self, source=None, from_key=None, to_key=None):
        q = self.table.query(
            '_updated',
            from_key=from_key,
            to_key=to_key,
            include_value=True
        )
        for i, v in q:
            self.do_rpc(source, "update", indicator=i, value=v)

    def get(self, source=None, indicator=None):
        if not type(indicator) in [str, unicode]:
            raise ValueError("Invalid indicator type")

        value = self.table.get(indicator)

        return value

    def get_all(self, source=None):
        self._send_indicators(source=source)
        return 'OK'

    def get_range(self, source=None, index=None, from_key=None, to_key=None):
        if index is not None and index != '_updated':
            raise ValueError('Index not found')

        self._send_indicators(
            source=source,
            from_key=from_key,
            to_key=to_key
        )

        return 'OK'

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(HttpFT, self).start()

        if self.glet is not None:
            return

        self.glet = gevent.spawn_later(random.randint(0, 2), self._run)

    def stop(self):
        super(HttpFT, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
