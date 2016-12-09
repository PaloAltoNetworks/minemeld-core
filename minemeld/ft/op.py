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

import logging

from . import base
from . import table
from .utils import utc_millisec
from .utils import RESERVED_ATTRIBUTES

LOG = logging.getLogger(__name__)


class AggregateFT(base.BaseFT):
    _ftclass = 'AggregateFT'

    def __init__(self, name, chassis, config):
        self.active_requests = []
        self.table = None

        super(AggregateFT, self).__init__(name, chassis, config)

    def configure(self):
        super(AggregateFT, self).configure()

        self.whitelist_prefixes = self.config.get('whitelist_prefixes', [])

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)

    def initialize(self):
        self._initialize_table()

    def rebuild(self):
        self._initialize_table(truncate=True)

    def reset(self):
        self._initialize_table(truncate=True)

    def _indicator_key(self, indicator, source):
        return indicator+'\x00'+source

    def _is_whitelist(self, s):
        for p in self.whitelist_prefixes:
            if s.startswith(p):
                return True
        return False

    def _emit_update_indicator(self, indicator):
        LOG.debug("%s - emitting update: %s", self.name, indicator)

        mv = {'sources': []}
        for s in self.inputs:
            if self._is_whitelist(s):
                continue

            v = self.table.get(self._indicator_key(indicator, s))
            if v is None:
                continue

            for k in v.keys():
                if k in mv and k in RESERVED_ATTRIBUTES:
                    mv[k] = RESERVED_ATTRIBUTES[k](mv[k], v[k])
                else:
                    mv[k] = v[k]

        if len(mv) > 1:
            self.emit_update(indicator, mv)

    def _merge_values(self, source, ov, nv):
        result = {'sources': []}

        result['_added'] = ov['_added']

        for k in nv.keys():
            result[k] = nv[k]

        return result

    def _add_indicator(self, source, indicator, value):
        now = utc_millisec()

        v = self.table.get(self._indicator_key(indicator, source))
        if v is None:
            v = {
                '_added': now,
            }

        v = self._merge_values(source, v, value)
        v['_updated'] = now

        self.table.put(self._indicator_key(indicator, source), v)

        return v

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        ebl = False
        ewl = False
        for i in self.inputs:
            v = self.table.exists(self._indicator_key(indicator, i))
            if self._is_whitelist(i):
                ewl |= v
            else:
                ebl |= v

        v = self._add_indicator(source, indicator, value)

        if self._is_whitelist(source):
            # update from whitelist
            if ewl:
                # already whitelisted, no updates
                return

            if ebl:
                self.emit_withdraw(indicator)

        else:
            if ewl:
                return
            self._emit_update_indicator(indicator)

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        ebl = 0
        ewl = 0
        for i in self.inputs:
            v = int(self.table.exists(self._indicator_key(indicator, i)))
            if self._is_whitelist(i):
                ewl += v
            else:
                ebl += v

        e = self.table.exists(self._indicator_key(indicator, source))
        self.table.delete(self._indicator_key(indicator, source))

        if self._is_whitelist(source):
            # withdraw from whitelist
            if e and ewl > 1:
                return

            if ebl != 0:
                self._emit_update_indicator(indicator)

        else:
            if ewl > 0:
                return

            if e:
                if ebl > 1:
                    self._emit_update_indicator(indicator)
                else:
                    self.emit_withdraw(indicator)

    def get(self, source=None, indicator=None):
        mv = {}
        for s in self.inputs:
            v = self.table.get(self._indicator_key(indicator, s))
            if v is None:
                continue

            for k in v.keys():
                if k in mv and k in RESERVED_ATTRIBUTES:
                    mv[k] = RESERVED_ATTRIBUTES[k](mv[k], v[k])
                else:
                    mv[k] = v[k]

        return mv

    def get_all(self, source=None):
        return self.get_range(source=source)

    def get_range(self, source=None, index=None, from_key=None, to_key=None):
        if index is not None:
            raise ValueError("Index not found")

        if to_key is not None:
            to_key = self._indicator_key(to_key, '\x7F')

        cindicator = None
        cvalue = {}
        for k, v in self.table.query(index=index, from_key=from_key,
                                     to_key=to_key, include_value=True):
            indicator, _ = k.split('\x00')
            if indicator == cindicator:
                for vk in v.keys():
                    if vk in cvalue and vk in RESERVED_ATTRIBUTES:
                        cvalue[vk] = RESERVED_ATTRIBUTES[vk](cvalue[vk], v[vk])
                    else:
                        cvalue[vk] = v[vk]

            else:
                if cindicator is not None:
                    self.do_rpc(source, "update", indicator=cindicator,
                                value=cvalue)
                cindicator = indicator
                cvalue = v

        if cindicator is not None:
            self.do_rpc(source, "update", indicator=cindicator,
                        value=cvalue)

        return 'OK'

    def length(self, source=None):
        return self.table.num_indicators

    def stop(self):
        super(AggregateFT, self).stop()

        for g in self.active_requests:
            g.kill()
        self.active_requests = []

        self.table.close()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
