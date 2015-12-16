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
import copy
import gevent
import gevent.event
import random
import urlparse
import datetime
import pytz
import lxml.etree

import libtaxii
import libtaxii.clients
import libtaxii.messages_11

import stix.core.stix_package

from . import base
from . import table
from . import ft_states
from .utils import utc_millisec
from .utils import dt_to_millisec
from .utils import age_out_in_millisec
from .utils import RWLock

LOG = logging.getLogger(__name__)


class FtStateChanged(Exception):
    pass


class TaxiiClient(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None
        self.ageout_glet = None

        self.active_requests = []
        self.rebuild_flag = False
        self.last_run = None
        self.last_ageout_run = None

        self.poll_service = None
        self.collection_mgmt_service = None

        self.state_lock = RWLock()

        super(TaxiiClient, self).__init__(name, chassis, config)

    def configure(self):
        super(TaxiiClient, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.discovery_service = self.config.get('discovery_service', None)
        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)
        self.collection = self.config.get('collection', None)
        self.attributes = self.config.get('attributes', {})
        self.interval = self.config.get('interval', 900)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.num_retries = self.config.get('num_retries', 2)
        self.prefix = self.config.get('prefix', self.name+'_')
        self.age_out_interval = int(self.config.get(
            'age_out_interval',
            '3600'
        ))
        self.age_out = self.config.get('age_out', '30d')
        self.ca_file = self.config.get('ca_file', None)

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('last_seen')

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
        super(TaxiiClient, self.__class__).state.fset(self, value)
        self.state_lock.unlock()
        LOG.debug("%s - releasing state write lock", self.name)

    def _build_taxii_client(self):
        result = libtaxii.clients.HttpClient()

        up = urlparse.urlparse(self.discovery_service)

        if up.scheme == 'https':
            result.set_use_https(True)

        if self.username and self.password:
            result.set_auth_type(libtaxii.clients.HttpClient.AUTH_BASIC)
            result.set_auth_credentials({
                'username': self.username,
                'password': self.password
            })

        if self.ca_file is not None:
            result.set_verify_server(
                verify_server=True,
                ca_file=self.ca_file
            )

        return result

    def _discover_services(self, tc):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.DiscoveryRequest(msg_id)
        request = request.to_xml()

        up = urlparse.urlparse(self.discovery_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('Discovery_Response {%s} %s',
                  type(tm), tm.to_xml(pretty_print=True))

        self.collection_mgmt_service = None
        for si in tm.service_instances:
            if si.service_type != libtaxii.constants.SVC_COLLECTION_MANAGEMENT:
                continue

            self.collection_mgmt_service = si.service_address
            break

        if self.collection_mgmt_service is None:
            raise RuntimeError('%s - collection management service not found')

        LOG.debug('%s - collection_mgmt_service: %s',
                  self.name, self.collection_mgmt_service)

    def _check_collections(self, tc):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.CollectionInformationRequest(msg_id)
        request = request.to_xml()

        up = urlparse.urlparse(self.collection_mgmt_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('Collection_Information_Response {%s} %s',
                  type(tm), tm.to_xml(pretty_print=True))

        tci = None
        for ci in tm.collection_informations:
            if ci.collection_name != self.collection:
                continue

            tci = ci
            break

        if tci is None:
            raise RuntimeError('%s - collection %s not found',
                               self.name, self.collection)

        if tci.polling_service_instances is None or \
           len(tci.polling_service_instances) == 0:
            raise RuntimeError('%s - collection %s doesn\'t support polling',
                               self.name, self.collection)

        if tci.collection_type != libtaxii.constants.CT_DATA_FEED:
            raise RuntimeError('%s - collection %s is not a data feed (%s)',
                               self.name, self.collection, tci.collection_type)

        self.poll_service = tci.polling_service_instances[0].poll_address

        LOG.debug('%s - poll service: %s',
                  self.name, self.poll_service)

    def _poll_fulfillment_request(self, tc, result_id, result_part_number):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.PollFulfillmentRequest(
            message_id=msg_id,
            result_id=result_id,
            result_part_number=result_part_number,
            collection_name=self.collection
        )
        request = request.to_xml()

        up = urlparse.urlparse(self.poll_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        return libtaxii.get_message_from_http_response(resp, msg_id)

    def _poll_collection(self, tc, begin=None, end=None):
        msg_id = libtaxii.messages_11.generate_message_id()
        pps = libtaxii.messages_11.PollParameters(
            response_type='FULL',
            allow_asynch=False
        )
        request = libtaxii.messages_11.PollRequest(
            message_id=msg_id,
            collection_name=self.collection,
            exclusive_begin_timestamp_label=begin,
            inclusive_end_timestamp_label=end,
            poll_parameters=pps
        )

        LOG.debug('%s - first poll request %s',
                  self.name, request.to_xml(pretty_print=True))

        request = request.to_xml()

        up = urlparse.urlparse(self.poll_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('%s - Poll_Response {%s} %s',
                  self.name, type(tm), tm.to_xml(pretty_print=True))

        stix_objects = {
            'observables': {},
            'indicators': {},
            'ttps': {}
        }

        self._handle_content_blocks(
            tm.content_blocks,
            stix_objects
        )

        while tm.more:
            tm = self._poll_fulfillment_request(
                tc,
                result_id=tm.result_id,
                result_part_number=tm.result_part_number+1
            )
            self._handle_content_blocks(
                tm.content_blocks,
                stix_objects
            )

        LOG.debug('%s - stix_objects: %s', self.name, stix_objects)

        self._handle_indicators(stix_objects)

    def _handle_content_blocks(self, content_blocks, objects):
        try:
            for cb in content_blocks:
                if cb.content_binding.binding_id != \
                   libtaxii.constants.CB_STIX_XML_111:
                    LOG.error('%s - Unsupported content binding: %s',
                              self.name, cb.content_binding.binding_id)
                    continue

                stixpackage = stix.core.stix_package.STIXPackage.from_xml(
                    lxml.etree.fromstring(cb.content)
                )

                if stixpackage.indicators:
                    for i in stixpackage.indicators:
                        ci = {
                            'timestamp': dt_to_millisec(i.timestamp),
                        }

                        os = []
                        ttps = []

                        if i.observable:
                            os.append(self._decode_observable(i.observable))
                        if i.observables:
                            for o in i.observables:
                                os.append(self._decode_observable(o))
                        if i.indicated_ttps:
                            for t in i.indicated_ttps:
                                ttps.append(self._decode_ttp(t))

                        ci['observables'] = os
                        ci['ttps'] = ttps

                        objects['indicators'][i.id_] = ci

                if stixpackage.observables:
                    for o in stixpackage.observables:
                        co = self._decode_observable(o)
                        objects['observables'][o.id_] = co

                if stixpackage.ttps:
                    for t in stixpackage.ttps:
                        ct = self._decode_ttp(t)
                        objects['ttps'][t.id_] = ct

        except:
            LOG.exception("%s - exception in _handle_content_blocks" %
                          self.name)
            raise

    def _decode_observable(self, o):
        LOG.debug('observable: %s', o.to_dict())

        if o.idref:
            return {'idref': o.idref}

        odict = o.to_dict()

        oc = odict.get('observable_composition', None)
        if oc:
            LOG.error('%s - Observable composition not supported yet: %s',
                      self.name, odict)
            return None

        oo = odict.get('object', None)
        if oo is None:
            LOG.error('%s - no object in observable', self.name)
            return None

        op = oo.get('properties', None)
        if op is None:
            LOG.error('%s - no properties in observable object', self.name)
            return None

        ot = op.get('xsi:type', None)
        if ot is None:
            LOG.error('%s - no type in observable props', self.name)
            return None

        result = {}

        if ot == 'DomainNameObjectType':
            result['type'] = 'domain'

            ov = op.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable props', self.name)
                return None
            ov = ov.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable value', self.name)
                return None

        elif ot == 'AddressObjectType':
            addrcat = op.get('category', None)
            if addrcat == 'ipv6-addr':
                result['type'] = 'IPv6'
            result['type'] = 'IPv4'

            source = op.get('is_source', None)
            if source is True:
                result['direction'] = 'inbound'
            elif source is False:
                result['direction'] = 'outbound'

            ov = op.get('address_value', None)
            if ov is None:
                LOG.error('%s - no value in observable props', self.name)
                return None
            ov = ov.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable value', self.name)
                return None

        elif ot == 'URIObjectType':
            result['type'] = 'URL'

            ov = op.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable props', self.name)
                return None
            ov = ov.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable value', self.name)
                return None
        else:
            LOG.error('%s - unknown type %s', self.name, ot)
            return None

        result['indicator'] = ov

        return result

    def _decode_ttp(self, t):
        tdict = t.to_dict()

        LOG.debug('ttp: %s', tdict)

        if 'ttp' in tdict:
            tdict = tdict['ttp']

        if 'idref' in tdict:
            return {'idref': tdict['idref']}

        if 'description' in tdict:
            return {'description': tdict['description']}

        if 'title' in tdict:
            return {'description': tdict['title']}

        return {'description': ''}

    def _add_indicator(self, indicator, value):
        result = True

        v = self.table.get(indicator)
        if v is not None:
            if len(v) == len(value):

                ceq = 0
                for k in v:
                    if v[k] != value.get(k, None):
                        break
                    ceq += 1

                result = ceq == len(v)

        self.table.put(indicator, value)

        return result

    def _handle_indicators(self, stix_objects):
        self.state_lock.rlock()
        if self.state != ft_states.STARTED:
            self.state_lock.runlock()
            raise FtStateChanged('no more STARTED')

        try:
            for i in stix_objects['indicators'].values():
                value = copy.copy(self.attributes)

                value['last_seen'] = i.get('timestamp', utc_millisec())

                if len(i['ttps']) != 0:
                    ttp = i['ttps'][0]
                    if 'idref' in ttp:
                        ttp = stix_objects['ttps'][ttp['idref']]

                    value['%s_ttp' % self.prefix] = ttp['description']

                for o in i['observables']:
                    ob = o
                    if 'idref' in o:
                        ob = stix_objects['observables'][o['idref']]

                    if ob is None:
                        continue

                    indicator = ob['indicator']
                    value['type'] = ob['type']

                    if self._add_indicator(indicator, value):
                        self.emit_update(indicator, value)

        finally:
            self.state_lock.runlock()

    def _age_out_run(self):
        interval = age_out_in_millisec(self.age_out)

        while True:
            self.state_lock.rlock()
            if self.state != ft_states.STARTED:
                self.state_lock.runlock()
                return

            try:
                now = utc_millisec()

                for i, v in self.table.query(index='last_seen',
                                             to_key=now-interval,
                                             include_value=True):
                    LOG.debug('%s - %s %s aged out', self.name, i, v)
                    self.emit_withdraw(indicator=i)
                    self.table.delete(i)

                self.last_ageout_run = now

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('Exception in _age_out_loop')

            finally:
                self.state_lock.runlock()

            gevent.sleep(self.age_out_interval)

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
                for i, v in self.table.query('last_seen', include_value=True):
                    self.emit_update(i, v)
        finally:
            self.state_lock.unlock()

        tc = self._build_taxii_client()

        while True:
            try:
                self._discover_services(tc)
                self._check_collections(tc)

                while True:
                    now = utc_millisec()

                    last_run = self.last_run
                    if last_run is None:
                        last_run = now-86400000

                    begin = datetime.datetime.fromtimestamp(last_run/1000)
                    begin = begin.replace(tzinfo=pytz.UTC)

                    end = datetime.datetime.fromtimestamp(now/1000)
                    end = end.replace(tzinfo=pytz.UTC)

                    self._poll_collection(
                        tc,
                        begin=begin,
                        end=end
                    )

                    self.last_run = now

                    gevent.sleep(self.interval)

            except gevent.GreenletExit:
                break

            except FtStateChanged:
                break

            except:
                LOG.exception('%s - exception in main loop', self.name)
                gevent.sleep(300)

    def mgmtbus_status(self):
        result = super(TaxiiClient, self).mgmtbus_status()
        result['last_run'] = self.last_run

        return result

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(TaxiiClient, self).start()

        if self.glet is not None:
            return

        self.glet = gevent.spawn_later(random.randint(0, 2), self._run)
        self.ageout_glet = gevent.spawn(self._age_out_run)

    def stop(self):
        super(TaxiiClient, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()
        self.ageout_glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
