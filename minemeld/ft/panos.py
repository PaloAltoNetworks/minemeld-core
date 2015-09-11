import logging
import gevent
import gevent.event
import minemeld.packages.panforest.forest
import random
import copy

import pan.xapi

from . import base
from . import table
from .utils import utc_millisec

LOG = logging.getLogger(__name__)

def _sleeper(slot, maxretries):
    c = 0
    while c < maxretries:
        yield slot*random.uniform(0, (2**c-1))
        c = c+1

    yield maxretries*slot

class PanOSLogsAPIFT(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None

        self.tables = []
        self.active_requests = []
        self.rebuild_flag = False
        self.last_log = None
        self.idle_waitobject = gevent.event.AsyncResult()

        super(PanOSLogsAPIFT, self).__init__(name, chassis, config)

    def configure(self):
        super(PanOSLogsAPIFT, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.tag = self.config.get('tag', None)
        self.hostname = self.config.get('hostname', None)
        self.api_key = self.config.get('api_key', None)
        self.api_username = self.config.get('api_username', None)
        self.api_password = self.config.get('api_password', None)
        self.log_type = self.config.get('log_type', None)
        self.filter = self.config.get('filter', None)
        self.sleeper_slot = int(self.config.get('sleeper_slot', '10'))
        self.maxretries = int(self.config.get('maxretries', '16'))
        self.fields = self.config.get('fields', [])

    def _initialize_tables(self, truncate=False):
        for idx, field in enumerate(self.fields):
            t = table.Table(
                self.name+'_%d' % idx,
                truncate=truncate
            )
            t.create_index('last_seen')
            self.tables.append(t)

    def initialize(self):
        self._initialize_tables()

    def rebuild(self):
        self._initialize_tables()
        self.rebuild_flag = True

    def reset(self):
        self._initialize_tables(truncate=True)

    def emit_checkpoint(self, value):
        LOG.debug("%s - checkpoint set to %s", self.name, value)
        self.idle_waitobject.set(value)

    def _run(self):
        if self.rebuild_flag:
            LOG.debug("rebuild flag set, resending current indicators")
            # reinit flag is set, emit update for all the known indicators
            for t in self.tables:
                for i, v in t.query('last_seen', include_value=True):
                    self.emit_update(i, v)

        sleeper = _sleeper(self.sleeper_slot, self.maxretries)
        checkpoint = None
        while True:
            try:
                xapi = pan.xapi.PanXapi(
                    api_username=self.api_username,
                    api_password=self.api_password,
                    api_key=self.api_key,
                    hostname=self.hostname,
                    tag=self.tag,
                    timeout=60
                )
                pf = minemeld.packages.panforest.forest.PanForest(
                    xapi=xapi,
                    log_type=self.log_type,
                    filter=self.filter,
                    format='python'
                )

                for log in pf.follow():
                    sleeper = _sleeper(self.sleeper_slot, self.maxretries)

                    now = utc_millisec()

                    for idx, field in enumerate(self.fields):
                        if field['name'] in log:
                            v = copy.copy(field['attributes'])
                            v['last_seen'] = now
                            self.tables[idx].put(log[field['name']], v)
                            self.emit_update(indicator=log[field['name']], value=v)
                        else:
                            LOG.debug('%s - field %s not found', self.name, field['name'])

                    try:
                        checkpoint = self.idle_waitobject.get(block=False)
                    except gevent.Timeout:
                        pass
    
                    if checkpoint is not None:
                        break

            except gevent.GreenletExit:
                pass

            except:
                LOG.exception("%s - exception in log loop", self.name)

            try:
                checkpoint = self.idle_waitobject.get(timeout=next(sleeper))
            except gevent.Timeout:
                pass
    
            if checkpoint is not None:
                super(PanOSLogsAPIFT, self).emit_checkpoint(checkpoint)
                break

    def length(self, source=None):
        return sum([t.num_indicators for t in self.tables])

    def start(self):
        super(PanOSLogsAPIFT, self).start()

        if self.glet is not None:
            return

        self.glet = gevent.spawn_later(random.randint(0, 2), self._run)

    def stop(self):
        super(PanOSLogsAPIFT, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
