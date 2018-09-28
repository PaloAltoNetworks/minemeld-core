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
import netaddr
import uuid
import shutil

from . import base
from . import actorbase
from . import table
from . import st
from .utils import utc_millisec
from .utils import RESERVED_ATTRIBUTES

LOG = logging.getLogger(__name__)

WL_LEVEL = st.MAX_LEVEL


class MWUpdate(object):
    def __init__(self, start, end, uuids):
        self.start = start
        self.end = end
        self.uuids = set(uuids)

        s = netaddr.IPAddress(start)
        e = netaddr.IPAddress(end)
        self._indicator = '%s-%s' % (s, e)

    def indicator(self):
        return self._indicator

    def __repr__(self):
        return 'MWUpdate('+self._indicator+', %r)' % self.uuids

    def __hash__(self):
        return hash(self._indicator)

    def __eq__(self, other):
        return self.start == other.start and \
            self.end == other.end


class AggregateIPv4FT(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.active_requests = []

        super(AggregateIPv4FT, self).__init__(name, chassis, config)

    def configure(self):
        super(AggregateIPv4FT, self).configure()

        self.whitelist_prefixes = self.config.get('whitelist_prefixes', [])

    def _initialize_tables(self, truncate=False):
        self.table = table.Table(
            self.name,
            bloom_filter_bits=10,
            truncate=truncate
        )
        self.table.create_index('_id')
        self.st = st.ST(self.name+'_st', 32, truncate=truncate)

    def initialize(self):
        self._initialize_tables()

    def rebuild(self):
        self._initialize_tables(truncate=True)

    def reset(self):
        self._initialize_tables(truncate=True)

    def _indicator_key(self, indicator, source):
        return indicator+'\x00'+source

    def _calc_indicator_value(self, uuids, additional_uuid=None, additional_value=None):
        mv = {'sources': []}
        for uuid_ in uuids:
            if uuid_ == additional_uuid:
                v = additional_value
            else:
                # uuid_ = str(uuid.UUID(bytes=uuid_))
                k, v = next(
                    self.table.query('_id', from_key=uuid_, to_key=uuid_,
                                     include_value=True),
                    (None, None)
                )
                if k is None:
                    LOG.error("Unable to find key associated with uuid: %s", uuid_)

            for vk in v:
                if vk in mv and vk in RESERVED_ATTRIBUTES:
                    mv[vk] = RESERVED_ATTRIBUTES[vk](mv[vk], v[vk])
                else:
                    mv[vk] = v[vk]

        return mv

    def _merge_values(self, origin, ov, nv):
        result = {'sources': []}

        result['_added'] = ov['_added']
        result['_id'] = ov['_id']

        for k in nv.keys():
            result[k] = nv[k]

        return result

    def _add_indicator(self, origin, indicator, value):
        added = False

        now = utc_millisec()
        ik = self._indicator_key(indicator, origin)

        v = self.table.get(ik)
        if v is None:
            v = {
                '_id': str(uuid.uuid4()),
                '_added': now
            }
            added = True
            self.statistics['added'] += 1

        v = self._merge_values(origin, v, value)
        v['_updated'] = now

        self.table.put(ik, v)

        return v, added

    def _calc_ipranges(self, start, end):
        """Calc IP Ranges overlapping the range between start and end
        
        Args:
            start (int): start of the range
            end (int): end of the range
        
        Returns:
            set: set of ranges
        """

        result = set()

        # collect the endpoint between start and end
        eps = set()
        for epaddr, _, _, _ in self.st.query_endpoints(start=start, stop=end):
            eps.add(epaddr)
        eps = sorted(eps)

        if len(eps) == 0:
            return result

        # walk thru the endpoints, tracking last endpoint
        # current level, active segments and segments levels
        oep = None
        oeplevel = -1
        live_ids = set()
        slevels = {}

        for epaddr in eps:
            # for each endpoint we track which segments are starting
            # and which ones are ending with that specific endpoint
            end_ids = set()
            start_ids = set()
            eplevel = 0
            for cuuid, clevel, cstart, cend in self.st.cover(epaddr):
                slevels[cuuid] = clevel

                if clevel > eplevel:
                    eplevel = clevel
                if cstart == epaddr:
                    start_ids.add(cuuid)
                if cend == epaddr:
                    end_ids.add(cuuid)

                if cend != epaddr and cstart != epaddr:
                    if cuuid not in live_ids:
                        assert epaddr == eps[0]
                        live_ids.add(cuuid)

            assert len(end_ids) + len(start_ids) > 0

            if len(start_ids) != 0:
                if oep is not None and oep != epaddr and len(live_ids) != 0:
                    if oeplevel != WL_LEVEL:
                        result.add(MWUpdate(oep, epaddr-1,
                                            live_ids))

                oep = epaddr
                oeplevel = eplevel
                live_ids = live_ids | start_ids

            if len(end_ids) != 0:
                if oep is not None and len(live_ids) != 0:
                    if eplevel < WL_LEVEL:
                        result.add(MWUpdate(oep, epaddr, live_ids))

                oep = epaddr+1
                live_ids = live_ids - end_ids

                oeplevel = eplevel
                if len(live_ids) != 0:
                    oeplevel = max([slevels[id_] for id_ in live_ids])

        return result

    def _range_from_indicator(self, indicator):
        if '-' in indicator:
            start, end = map(
                lambda x: int(netaddr.IPAddress(x)),
                indicator.split('-', 1)
            )
        elif '/' in indicator:
            ipnet = netaddr.IPNetwork(indicator)
            start = int(ipnet.ip)
            end = start+ipnet.size-1
        else:
            start = int(netaddr.IPAddress(indicator))
            end = start

        if (not (start >= 0 and start <= 0xFFFFFFFF)) or \
           (not (end >= 0 and end <= 0xFFFFFFFF)):
            LOG.error('%s - {%s} invalid IPv4 indicator',
                      self.name, indicator)
            return None, None

        return start, end

    def _endpoints_from_range(self, start, end):
        """Return last endpoint before range and first endpoint after range
        
        Args:
            start (int): range start
            end (int): range stop
        
        Returns:
            tuple: (last endpoint before, first endpoint after)
        """

        rangestart = next(
            self.st.query_endpoints(start=0, stop=max(start-1, 0),
                                    reverse=True),
            None
        )
        if rangestart is not None:
            rangestart = rangestart[0]
        LOG.debug('%s - range start: %s', self.name, rangestart)

        rangestop = next(
            self.st.query_endpoints(reverse=False,
                                    start=min(end+1, self.st.max_endpoint),
                                    stop=self.st.max_endpoint,
                                    include_start=False),
            None
        )
        if rangestop is not None:
            rangestop = rangestop[0]
        LOG.debug('%s - range stop: %s', self.name, rangestop)

        return rangestart, rangestop

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        vtype = value.get('type', None)
        if vtype != 'IPv4':
            self.statistics['update.ignored'] += 1
            return

        v, newindicator = self._add_indicator(source, indicator, value)

        start, end = self._range_from_indicator(indicator)
        if start is None or end is None:
            return

        level = 1
        for p in self.whitelist_prefixes:
            if source.startswith(p):
                level = WL_LEVEL
                break

        LOG.debug("%s - update: indicator: (%s) %s %s level: %s",
                  self.name, indicator, start, end, level)

        rangestart, rangestop = self._endpoints_from_range(start, end)

        rangesb = set(self._calc_ipranges(rangestart, rangestop))
        LOG.debug('%s - ranges before update: %s', self.name, rangesb)

        if not newindicator and level != WL_LEVEL:
            for u in rangesb:
                self.emit_update(
                    u.indicator(),
                    self._calc_indicator_value(u.uuids)
                )
            return

        uuidbytes = v['_id']
        self.st.put(uuidbytes, start, end, level=level)

        rangesa = set(self._calc_ipranges(rangestart, rangestop))
        LOG.debug('%s - ranges after update: %s', self.name, rangesa)

        added = rangesa-rangesb
        LOG.debug("%s - IP ranges added: %s", self.name, added)

        removed = rangesb-rangesa
        LOG.debug("%s - IP ranges removed: %s", self.name, removed)

        for u in added:
            self.emit_update(
                u.indicator(),
                self._calc_indicator_value(u.uuids)
            )

        for u in rangesa - added:
            for ou in rangesb:
                if u == ou and len(u.uuids ^ ou.uuids) != 0:
                    LOG.debug("IP range updated: %s", repr(u))
                    self.emit_update(
                        u.indicator(),
                        self._calc_indicator_value(u.uuids)
                    )

        for u in removed:
            self.emit_withdraw(
                u.indicator(),
                value=self._calc_indicator_value(u.uuids)
            )

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        LOG.debug("%s - withdraw from %s - %s", self.name, source, indicator)

        if value is not None and value.get('type', None) != 'IPv4':
            self.statistics['withdraw.ignored'] += 1
            return

        ik = self._indicator_key(indicator, source)

        v = self.table.get(ik)
        LOG.debug("%s - v: %s", self.name, v)
        if v is None:
            return

        self.table.delete(ik)
        self.statistics['removed'] += 1

        start, end = self._range_from_indicator(indicator)
        if start is None or end is None:
            return

        level = 1
        for p in self.whitelist_prefixes:
            if source.startswith(p):
                level = WL_LEVEL
                break

        rangestart, rangestop = self._endpoints_from_range(start, end)

        rangesb = set(self._calc_ipranges(rangestart, rangestop))
        LOG.debug("ranges before: %s", rangesb)

        uuidbytes = v['_id']
        self.st.delete(uuidbytes, start, end, level=level)

        rangesa = set(self._calc_ipranges(rangestart, rangestop))
        LOG.debug("ranges after: %s", rangesa)

        added = rangesa-rangesb
        LOG.debug("IP ranges added: %s", added)

        removed = rangesb-rangesa
        LOG.debug("IP ranges removed: %s", removed)

        for u in added:
            self.emit_update(
                u.indicator(),
                self._calc_indicator_value(u.uuids)
            )

        for u in rangesa - added:
            for ou in rangesb:
                if u == ou and len(u.uuids ^ ou.uuids) != 0:
                    LOG.debug("IP range updated: %s", repr(u))
                    self.emit_update(
                        u.indicator(),
                        self._calc_indicator_value(u.uuids)
                    )

        for u in removed:
            self.emit_withdraw(
                u.indicator(),
                value=self._calc_indicator_value(
                    u.uuids,
                    additional_uuid=v['_id'],
                    additional_value=v
                )
            )

    def _send_indicators(self, source=None, from_key=None, to_key=None):
        if from_key is None:
            from_key = 0
        if to_key is None:
            to_key = 0xFFFFFFFF

        result = self._calc_ipranges(from_key, to_key)
        for u in result:
            self.do_rpc(
                source,
                "update",
                indicator=u.indicator(),
                value=self._calc_indicator_value(u.uuids)
            )

    def get(self, source=None, indicator=None):
        if not type(indicator) in [str, unicode]:
            raise ValueError("Invalid indicator type")

        indicator = int(netaddr.IPAddress(indicator))

        result = self._calc_ipranges(indicator, indicator)
        if len(result) == 0:
            return None

        u = result.pop()
        return self._calc_indicator_value(u.uuids)

    def get_all(self, source=None):
        self._send_indicators(source=source)
        return 'OK'

    def get_range(self, source=None, index=None, from_key=None, to_key=None):
        if index is not None:
            raise ValueError('Index not found')
        if from_key is not None:
            from_key = int(netaddr.IPAddress(from_key))
        if to_key is not None:
            to_key = int(netaddr.IPAddress(to_key))

        self._send_indicators(
            source=source,
            from_key=from_key,
            to_key=to_key
        )

        return 'OK'

    def length(self, source=None):
        return self.table.num_indicators

    def stop(self):
        super(AggregateIPv4FT, self).stop()

        for g in self.active_requests:
            g.kill()
        self.active_requests = []

        self.table.close()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)

    @staticmethod
    def gc(name, config=None):
        actorbase.ActorBaseFT.gc(name, config=config)

        shutil.rmtree(name, ignore_errors=True)
        shutil.rmtree('{}_st'.format(name), ignore_errors=True)
