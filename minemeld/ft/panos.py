#  Copyright 2015 Palo Alto Networks, Inc
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

import logging
import gevent
import gevent.event
import minemeld.packages.panforest
import random
import copy
import re

import pan.xapi

from . import base
from . import table
from .utils import utc_millisec

LOG = logging.getLogger(__name__)

class CheckpointSet(Exception):
    pass

class InterruptablePanForest(minemeld.packages.panforest.PanForest):
    def __init__(self, wobject, xapi=None, log_type=None, filter=None,
                 nlogs=None, format=None):
        super(InterruptablePanForest, self).__init__(
            xapi=xapi,
            log_type=log_type,
            filter=filter,
            nlogs=nlogs,
            format=format
        )
        self.wobject = wobject

    def sleep(self, t):
        value = self.wobject.wait(timeout=t)
        LOG.debug('value %s', value)
        if value is not None:
            raise CheckpointSet()

def _age_out_in_usecs(val):
    multipliers = {
        '': 1000,
        'm': 60000,
        'h': 3600000,
        'd': 86400000
    }

    mo = re.match("([0-9]+)([dmh]?)", val)
    if mo is None:
        return None

    return int(mo.group(1))*multipliers[mo.group(2)]

def _sleeper(slot, maxretries):
    c = 0
    while c < maxretries:
        yield slot*random.uniform(0, (2**c-1))
        c = c+1

    yield maxretries*slot

class PanOSLogsAPIFT(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None

        self.age_out_glets = []

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
        self.age_out_interval = int(self.config.get('age_out_interval', '3600'))

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

    def _age_out_loop(self, fieldidx):
        interval = self.fields[fieldidx].get('age_out', '30d')
        interval = _age_out_in_usecs(interval)
        t = self.tables[fieldidx]

        while True:
            try:
                now = utc_millisec()
                for i, v in t.query(index='last_seen', to_key=now-interval,
                                    include_value=True):
                    LOG.debug('%s - %s %s aged out', self.name, i, v)
                    self.emit_withdraw(indicator=i)
                    t.delete(i)

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('Exception in _age_out_loop')

            gevent.sleep(self.age_out_interval)

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
                pf = InterruptablePanForest(
                    self.idle_waitobject,
                    xapi=xapi,
                    log_type=self.log_type,
                    filter=self.filter,
                    format='python'
                )

                for log in pf.follow():
                    sleeper = _sleeper(self.sleeper_slot, self.maxretries)

                    self.statistics['log.processed'] += 1

                    now = utc_millisec()

                    for idx, field in enumerate(self.fields):
                        if field['name'] in log:
                            v = copy.copy(field['attributes'])
                            v['last_seen'] = now
                            self.tables[idx].put(log[field['name']], v)
                            self.emit_update(indicator=log[field['name']], value=v)
                        else:
                            LOG.debug('%s - field %s not found', self.name, field['name'])

                    if self.idle_waitobject.ready():
                        break

            except gevent.GreenletExit:
                pass

            except CheckpointSet:
                LOG.debug('%s - CheckpointSet catched')
                pass

            except:
                LOG.exception("%s - exception in log loop", self.name)

            try:
                checkpoint = self.idle_waitobject.get(timeout=next(sleeper))
            except gevent.Timeout:
                pass

            LOG.debug('%s - checkpoint: %s', self.name, checkpoint)
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

        for idx in range(len(self.fields)):
            self.age_out_glets.append(
                gevent.spawn(self._age_out_loop, idx)
            )

    def stop(self):
        super(PanOSLogsAPIFT, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()
        for g in self.age_out_glets:
            g.kill()
        self.age_out_glets = None

        for t in self.tables:
            LOG.info("%s - # indicators: %d", self.name, t.num_indicators)
