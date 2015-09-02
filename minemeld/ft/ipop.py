import logging
import netaddr
import uuid

from . import base
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


class AggregateIPv4FT(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.table = table.Table(name)
        self.table.create_index('_id')
        self.st = st.ST(name+'_st', 32)
        self.active_requests = []

        super(AggregateIPv4FT, self).__init__(name, chassis, config)

    def configure(self):
        super(AggregateIPv4FT, self).configure()

        self.whitelists = self.config.get('whitelists', [])

    def rebuild(self):
        self.table.close()
        self.st.close()

        self.table = table.Table(self.name, truncate=True)
        self.table.create_index('_id')
        self.st = st.ST(self.name+'_st', 32, truncate=True)

    def reset(self):
        self.table.close()
        self.st.close()

        self.table = table.Table(self.name, truncate=True)
        self.table.create_index('_id')
        self.st = st.ST(self.name+'_st', 32, truncate=True)

    def _calc_indicator_value(self, uuids):
        mv = {'sources': []}
        for uuid_ in uuids:
            uuid_ = str(uuid.UUID(bytes=uuid_))
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

    def _merge_values(self, source, ov, nv):
        result = {'sources': []}

        result['_added'] = ov['_added']
        result['_id'] = ov['_id']

        for k in nv.keys():
            result[k] = nv[k]

        return result

    def _add_indicator(self, source, indicator, value):
        now = utc_millisec()

        v = self.table.get(indicator+source)
        if v is None:
            v = {
                '_id': str(uuid.uuid4()),
                '_added': now
            }

        v = self._merge_values(source, v, value)
        v['_updated'] = now

        self.table.put(indicator+source, v)

        return v

    def _calc_ipranges(self, start, end):
        LOG.debug('_calc_ipranges: %s %s', start, end)

        result = set()

        # collect the endpoint between start and end
        eps = set()
        for epaddr, _, _, _ in self.st.query_endpoints(start=start, stop=end):
            eps.add(epaddr)
        eps = sorted(eps)
        LOG.debug('eps: %s', eps)

        if len(eps) == 0:
            return result

        oep = None
        live_ids = set()
        for epaddr in eps:
            LOG.debug('status: epaddr: %s oep: %s live_ids: %s result: %s',
                      epaddr, oep, live_ids, result)
            end_ids = set()
            start_ids = set()
            eplevel = 0
            for cuuid, clevel, cstart, cend in self.st.cover(epaddr):
                if clevel > eplevel:
                    eplevel = clevel
                if cstart == epaddr:
                    start_ids.add(cuuid)
                if cend == epaddr:
                    end_ids.add(cuuid)

                if cend != epaddr and cstart != epaddr:
                    if cuuid not in live_ids:
                        LOG.debug("adding %r to live_ids", cuuid)
                        assert epaddr == eps[0]
                        live_ids.add(cuuid)

            LOG.debug('middle: %s %s %s', epaddr, start_ids, end_ids)
            assert len(end_ids) + len(start_ids) > 0

            if len(start_ids) != 0:
                if oep is not None and oep != epaddr and len(live_ids) != 0:
                    if eplevel < WL_LEVEL:
                        LOG.debug('start: %s %s %s',
                                  oep, epaddr-1, live_ids)
                        result.add(MWUpdate(oep, epaddr-1,
                                            live_ids))

                oep = epaddr
                live_ids = live_ids | start_ids

            if len(end_ids) != 0:
                if oep is not None and len(live_ids) != 0:
                    if eplevel < WL_LEVEL:
                        LOG.debug('end: %s %s %s', oep, epaddr, live_ids)
                        result.add(MWUpdate(oep, epaddr, live_ids))

                oep = epaddr+1
                live_ids = live_ids - end_ids

        return result

    def filtered_update(self, source=None, indicator=None, value=None):
        vtype = value.get('type', None)
        if vtype != 'IPv4':
            return

        v = self._add_indicator(source, indicator, value)

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

        level = 1
        if source in self.whitelists:
            level = WL_LEVEL

        LOG.debug("update: indicator: %s %s level: %s", start, end, level)

        rangestart = next(
            self.st.query_endpoints(start=0, stop=max(start-1, 0),
                                    reverse=True),
            None
        )
        if rangestart is not None:
            rangestart = rangestart[0]
        LOG.debug('rangestart: %s', rangestart)

        rangestop = next(
            self.st.query_endpoints(reverse=False,
                                    start=min(end+1, self.st.max_endpoint),
                                    stop=self.st.max_endpoint,
                                    include_start=False),
            None
        )
        if rangestop is not None:
            rangestop = rangestop[0]

        rangesb = set(self._calc_ipranges(rangestart, rangestop))
        LOG.debug('rangesb: %s', rangesb)

        uuidbytes = uuid.UUID(v['_id']).bytes
        self.st.put(uuidbytes, start, end, level=level)

        rangesa = set(self._calc_ipranges(rangestart, rangestop))
        LOG.debug('rangesa: %s', rangesa)

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
            self.emit_withdraw(u.indicator())

    def filtered_withdraw(self, source=None, indicator=None, value=None):
        LOG.debug("%s - withdraw from %s - %s", self.name, source, indicator)

        v = self.table.get(indicator+source)
        if v is None:
            return

        self.table.delete(indicator+source)

        if '-' in indicator:
            start, end = map(
                lambda x: int(netaddr.IPAddress(x)),
                indicator.split('-', 1)
            )
            end += 1
        elif '/' in indicator:
            ipnet = netaddr.IPNetwork(indicator)
            start = int(ipnet.ip)
            end = start+ipnet.size
        else:
            start = int(netaddr.IPAddress(indicator))
            end = start+1

        level = 1
        if source in self.whitelists:
            level = WL_LEVEL

        rangestart = next(
            self.st.query_endpoints(start=0, stop=start, reverse=True),
            None
        )
        if rangestart is not None:
            rangestart = rangestart[0]

        rangestop = next(
            self.st.query_endpoints(reverse=False, start=end,
                                    stop=self.st.max_endpoint),
            None
        )
        if rangestop is not None:
            rangestop = rangestop[0]

        rangesb = set(self._calc_ipranges(rangestart, rangestop))

        uuidbytes = uuid.UUID(v['id']).bytes
        self.st.delete(uuidbytes, start, end, level=level)

        rangesa = set(self._calc_ipranges(rangestart, rangestop))

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
            self.emit_withdraw(u.indicator())

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

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
