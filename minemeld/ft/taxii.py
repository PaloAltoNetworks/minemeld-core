#  Copyright 2015-present Palo Alto Networks, Inc
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

from __future__ import absolute_import

import logging
import copy
import urlparse
import uuid
import os.path
from datetime import datetime, timedelta

import pytz
import lz4
import lxml.etree
import yaml
import redis
import gevent
import gevent.event
import netaddr
import werkzeug.urls
from six import string_types

import libtaxii
import libtaxii.clients
import libtaxii.messages_11
from libtaxii.constants import MSG_STATUS_MESSAGE, ST_SUCCESS

import stix.core.stix_package
import stix.core.stix_header
import stix.indicator
import stix.common.vocabs
import stix.common.information_source
import stix.common.identity
import stix.extensions.marking.ais
import stix.data_marking
import stix.extensions.marking.tlp

import stix_edh

import cybox.core
import cybox.objects.address_object
import cybox.objects.domain_name_object
import cybox.objects.uri_object
import cybox.objects.file_object

import mixbox.idgen
import mixbox.namespaces

from . import basepoller
from . import base
from . import actorbase
from .utils import dt_to_millisec, interval_in_sec, utc_millisec


# stix_edh is imported to register the EDH data marking extensions, but it is not directly used.
# Delete the symbol to silence the warning about the import being unnecessary and prevent the
# PyCharm 'Optimize Imports' operation from removing the import.
del stix_edh

LOG = logging.getLogger(__name__)


_STIX_MINEMELD_HASHES = [
    'ssdeep',
    'md5',
    'sha1',
    'sha256',
    'sha512'
]


def set_id_namespace(uri, name):
    # maec and cybox
    NS = mixbox.namespaces.Namespace(uri, name)
    mixbox.idgen.set_id_namespace(NS)


class TaxiiClient(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        self.poll_service = None
        self.collection_mgmt_service = None
        self.last_taxii_run = None
        self.last_stix_package_ts = None

        super(TaxiiClient, self).__init__(name, chassis, config)

    def configure(self):
        super(TaxiiClient, self).configure()

        self.initial_interval = self.config.get('initial_interval', '1d')
        self.initial_interval = interval_in_sec(self.initial_interval)
        if self.initial_interval is None:
            LOG.error(
                '%s - wrong initial_interval format: %s',
                self.name, self.initial_interval
            )
            self.initial_interval = 86400
        self.max_poll_dt = self.config.get(
            'max_poll_dt',
            86400
        )

        # options for processing
        self.ip_version_auto_detect = self.config.get('ip_version_auto_detect', True)
        self.ignore_composition_operator = self.config.get('ignore_composition_operator', False)
        self.create_fake_indicator = self.config.get('create_fake_indicator', False)
        self.hash_priority = self.config.get('hash_priority', _STIX_MINEMELD_HASHES)
        self.lower_timestamp_precision = self.config.get('lower_timestamp_precision', False)

        self.discovery_service = self.config.get('discovery_service', None)
        self.collection = self.config.get('collection', None)

        # option for enabling client authentication
        self.client_credentials_required = self.config.get(
            'client_credentials_required',
            True
        )
        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)
        if self.username is not None or self.password is not None:
            self.client_credentials_required = False

        # option for enabling client cert, default disabled
        self.client_cert_required = self.config.get('client_cert_required', False)
        self.key_file = self.config.get('key_file', None)
        if self.key_file is None and self.client_cert_required:
            self.key_file = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s.pem' % self.name
            )
        self.cert_file = self.config.get('cert_file', None)
        if self.cert_file is None and self.client_cert_required:
            self.cert_file = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s.crt' % self.name
            )

        self.subscription_id = None
        self.subscription_id_required = self.config.get('subscription_id_required', False)

        self.ca_file = self.config.get('ca_file', None)
        if self.ca_file is None:
            self.ca_file = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s-ca.crt' % self.name
            )

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self.prefix = self.config.get('prefix', self.name)

        self.confidence_map = self.config.get('confidence_map', {
            'low': 40,
            'medium': 60,
            'high': 80
        })

        self._load_side_config()

    def _load_side_config(self):
        if not self.client_credentials_required and not self.subscription_id_required:
            LOG.info('{} - side config not needed'.format(self.name))
            return

        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        if self.client_credentials_required:
            username = sconfig.get('username', None)
            password = sconfig.get('password', None)
            if username is not None and password is not None:
                self.username = username
                self.password = password
                LOG.info('{} - Loaded credentials from side config'.format(self.name))

        if self.subscription_id_required:
            subscription_id = sconfig.get('subscription_id', None)
            if subscription_id is not None:
                self.subscription_id = subscription_id
                LOG.info('{} - Loaded subscription id from side config'.format(self.name))

    def _saved_state_restore(self, saved_state):
        super(TaxiiClient, self)._saved_state_restore(saved_state)
        self.last_taxii_run = saved_state.get('last_taxii_run', None)
        LOG.info('last_taxii_run from sstate: %s', self.last_taxii_run)

    def _saved_state_create(self):
        sstate = super(TaxiiClient, self)._saved_state_create()
        sstate['last_taxii_run'] = self.last_taxii_run

        return sstate

    def _saved_state_reset(self):
        super(TaxiiClient, self)._saved_state_reset()
        self.last_taxii_run = None

    def _build_taxii_client(self):
        result = libtaxii.clients.HttpClient()

        up = urlparse.urlparse(self.discovery_service)

        if up.scheme == 'https':
            result.set_use_https(True)

        if self.username and self.password:
            if self.key_file and self.cert_file:
                result.set_auth_type(
                    libtaxii.clients.HttpClient.AUTH_CERT_BASIC
                )
                result.set_auth_credentials({
                    'username': self.username,
                    'password': self.password,
                    'key_file': self.key_file,
                    'cert_file': self.cert_file
                })

            else:
                result.set_auth_type(
                    libtaxii.clients.HttpClient.AUTH_BASIC
                )
                result.set_auth_credentials({
                    'username': self.username,
                    'password': self.password
                })

        else:
            if self.key_file and self.cert_file:
                result.set_auth_type(
                    libtaxii.clients.HttpClient.AUTH_CERT
                )
                result.set_auth_credentials({
                    'key_file': self.key_file,
                    'cert_file': self.cert_file
                })

            else:
                result.set_auth_type(
                    libtaxii.clients.HttpClient.AUTH_NONE
                )

        if self.ca_file is not None and os.path.isfile(self.ca_file):
            result.set_verify_server(
                verify_server=True,
                ca_file=self.ca_file
            )

        return result

    def _call_taxii_service(self, service_url, tc, request):
        up = urlparse.urlparse(service_url)
        hostname = up.hostname
        path = up.path
        port = up.port

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request,
            port=port
        )

        return resp

    def _discover_services(self, tc):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.DiscoveryRequest(msg_id)
        request = request.to_xml()

        resp = self._call_taxii_service(self.discovery_service, tc, request)

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('Discovery_Response {%s} %s',
                  type(tm), tm.to_xml(pretty_print=True))

        if tm.message_type == MSG_STATUS_MESSAGE:
            raise RuntimeError('{} - Error retrieving collections: {} - {}'.format(
                self.name, tm.status_type, tm.message
            ))

        self.collection_mgmt_service = None
        for si in tm.service_instances:
            if si.service_type != libtaxii.constants.SVC_COLLECTION_MANAGEMENT:
                continue

            self.collection_mgmt_service = si.service_address
            break

        if self.collection_mgmt_service is None:
            raise RuntimeError('%s - collection management service not found' %
                               self.name)

    def _check_collections(self, tc):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.CollectionInformationRequest(msg_id)
        request = request.to_xml()

        resp = self._call_taxii_service(self.collection_mgmt_service, tc, request)

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('Collection_Information_Response {%s} %s',
                  type(tm), tm.to_xml(pretty_print=True))

        if tm.message_type == MSG_STATUS_MESSAGE:
            raise RuntimeError('{} - Error retrieving collections: {} - {}'.format(
                self.name, tm.status_type, tm.message
            ))

        tci = None
        for ci in tm.collection_informations:
            if ci.collection_name != self.collection:
                continue

            tci = ci
            break

        if tci is None:
            raise RuntimeError('%s - collection %s not found' %
                               (self.name, self.collection))

        if tci.polling_service_instances is None or \
           len(tci.polling_service_instances) == 0:
            raise RuntimeError('%s - collection %s doesn\'t support polling' %
                               (self.name, self.collection))

        if tci.collection_type != libtaxii.constants.CT_DATA_FEED:
            raise RuntimeError(
                '%s - collection %s is not a data feed (%s)' %
                (self.name, self.collection, tci.collection_type)
            )

        for pi in tci.polling_service_instances:
            LOG.info('{} - message binding: {}'.format(
                self.name, pi.poll_message_bindings
            ))
            if pi.poll_message_bindings[0] == libtaxii.constants.VID_TAXII_XML_11:
                self.poll_service = pi.poll_address
                LOG.info('{} - poll service found'.format(self.name))
                break
        else:
            raise RuntimeError(
                '%s - collection %s does not support TAXII 1.1 message binding (%s)' %
                (self.name, self.collection, tci.collection_type)
            )

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

        resp = self._call_taxii_service(self.poll_service, tc, request)

        return libtaxii.get_message_from_http_response(resp, msg_id)

    def _poll_collection(self, tc, begin=None, end=None):
        msg_id = libtaxii.messages_11.generate_message_id()

        prargs = dict(
            message_id=msg_id,
            collection_name=self.collection,
            exclusive_begin_timestamp_label=begin,
            inclusive_end_timestamp_label=end,
        )
        if self.subscription_id_required:
            prargs['subscription_id'] = self.subscription_id
        else:
            pps = libtaxii.messages_11.PollParameters(
                response_type='FULL',
                allow_asynch=False
            )
            prargs['poll_parameters'] = pps

        request = libtaxii.messages_11.PollRequest(**prargs)

        LOG.debug('%s - first poll request %s',
                  self.name, request.to_xml(pretty_print=True))

        request = request.to_xml()

        resp = self._call_taxii_service(self.poll_service, tc, request)

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('%s - Poll_Response {%s} %s',
                  self.name, type(tm), tm.to_xml(pretty_print=True))

        if tm.message_type == MSG_STATUS_MESSAGE:
            if tm.status_type == ST_SUCCESS:
                LOG.info('{} - TAXII Server returned success with no STIX packages'.format(
                    self.name
                ))
                return []

            raise RuntimeError('{} - Error polling: {} - {}'.format(
                self.name, tm.status_type, tm.message
            ))

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

            LOG.debug('{} - Poll_Response {!r}'.format(
                self.name, tm.to_xml(pretty_print=True)
            ))

            if tm.message_type == MSG_STATUS_MESSAGE:
                if tm.status_type == ST_SUCCESS:
                    break

                raise RuntimeError('{} - Error polling: {} - {}'.format(
                    self.name, tm.status_type, tm.message
                ))

            self._handle_content_blocks(
                tm.content_blocks,
                stix_objects
            )

        LOG.debug('%s - stix_objects: %s', self.name, stix_objects)

        params = {
            'ttps': stix_objects['ttps'],
            'observables': stix_objects['observables']
        }

        if len(stix_objects['indicators']) == 0 and len(stix_objects['observables']) != 0:
            LOG.info('{} - TAXII Content contains observables but no indicators'.format(self.name))
            if self.create_fake_indicator:
                stix_objects['indicators']['minemeld:00000000-0000-0000-0000-000000000000'] = {
                    'observables': stix_objects['observables'].values(),
                    'ttps': []
                }

        return [[iid, iv, params]
                for iid, iv in stix_objects['indicators'].iteritems()]

    def _incremental_poll_collection(self, taxii_client, begin, end):
        cbegin = begin
        dt = timedelta(seconds=self.max_poll_dt)

        self.last_stix_package_ts = None

        while cbegin < end:
            cend = min(end, cbegin+dt)

            LOG.info('{} - polling {!r} to {!r}'.format(self.name, cbegin, cend))
            result = self._poll_collection(
                taxii_client,
                begin=cbegin,
                end=cend
            )

            for i in result:
                yield i

            if self.last_stix_package_ts is not None:
                self.last_taxii_run = self.last_stix_package_ts

            cbegin = cend

    def _handle_content_blocks(self, content_blocks, objects):
        try:
            for cb in content_blocks:
                if cb.content_binding.binding_id != \
                   libtaxii.constants.CB_STIX_XML_111:
                    LOG.error('%s - Unsupported content binding: %s',
                              self.name, cb.content_binding.binding_id)
                    continue

                try:
                    stixpackage = stix.core.stix_package.STIXPackage.from_xml(
                        lxml.etree.fromstring(cb.content)
                    )
                except Exception:
                    LOG.exception(
                        '%s - Exception parsing content block',
                        self.name
                    )
                    continue

                if stixpackage.indicators:
                    for i in stixpackage.indicators:
                        ci = {}

                        if i.timestamp is not None:
                            ci = {
                                'timestamp': dt_to_millisec(i.timestamp),
                            }

                        if i.description is not None and i.description.structuring_format is None:
                            # copy description only if there is no markup to avoid side-effects
                            ci['description'] = i.description.value

                        if i.confidence is not None:
                            confidence = str(i.confidence.value).lower()
                            if confidence in self.confidence_map:
                                ci['confidence'] = \
                                    self.confidence_map[confidence]

                        os = []
                        ttps = []

                        if i.observables:
                            for o in i.observables:
                                os.append(self._decode_observable(o))
                        if i.observable and len(os) == 0:
                            os.append(self._decode_observable(i.observable))

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

                timestamp = stixpackage.timestamp
                if isinstance(timestamp, datetime):
                    timestamp = dt_to_millisec(timestamp)
                    if self.last_stix_package_ts is None or timestamp > self.last_stix_package_ts:
                        LOG.debug('{} - last STIX package timestamp set to {!r}'.format(self.name, timestamp))
                        self.last_stix_package_ts = timestamp

        except:
            LOG.exception("%s - exception in _handle_content_blocks" %
                          self.name)
            raise

    def _decode_observable(self, o):
        LOG.debug('observable: %s', o.to_dict())

        if o.idref:
            return {'idref': o.idref}

        odict = o.to_dict()
        result = {}

        oc = odict.get('observable_composition', None)
        if oc:
            ocoperator = oc.get('operator', None)
            if ocoperator != 'OR' and not self.ignore_composition_operator:
                LOG.error(
                    '%s - Observable composition with %s not supported yet: %s',
                    self.name, ocoperator, odict
                )
                return None

            result['type'] = '_cyboxOR'

            result['observables'] = []
            for nestedo in oc.get('observables', []):
                if 'idref' not in nestedo:
                    LOG.error(
                        '%s - only Observable references are supported in Observable Composition: %s',
                        self.name, odict
                    )
                    return None
                result['observables'].append(nestedo['idref'])

            return result

        oo = odict.get('object', None)
        if oo is None:
            LOG.error('%s - no object in observable', self.name)
            return None

        op = oo.get('properties', None)
        if op is None:
            LOG.error('%s - no properties in observable object', self.name)
            return None

        return self._decode_object_properties(op, odict=odict)

    def _decode_object_properties(self, op, odict=None):
        result = {}

        ot = op.get('xsi:type', None)
        if ot is None:
            LOG.error('%s - no type in observable props', self.name)
            return None

        if ot == 'DomainNameObjectType':
            result['type'] = 'domain'

            ov = op.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable props', self.name)
                return None
            if not isinstance(ov, string_types):
                ov = ov.get('value', None)
                if ov is None:
                    LOG.error('%s - no value in observable value', self.name)
                    return None

        elif ot == 'FileObjectType':
            ov = ''

            if 'file_name' in op.keys():
                file_name = op.get('file_name')
                if isinstance(file_name, dict):
                    ov = op['file_name'].get('value', None)
                    result['type'] = 'file.name'
                else:
                    ov = op['file_name']
                    result['type'] = 'file.name'

            hashes = op.get('hashes', [])
            if not isinstance(hashes, list) or len(hashes) == 0:
                LOG.error('{} - FileObjectType with unhandled structure: {!r}'.format(
                    self.name, op
                ))
                return None

            indicator_type = None
            cprio = -1
            indicator_hashes = {}

            for h in hashes:
                hvalue = h.get('simple_hash_value', None)
                if hvalue is None:
                    continue

                if not isinstance(hvalue, string_types):
                    if not isinstance(hvalue, dict):
                        continue

                    hvalue = hvalue.get('value', None)
                    if hvalue is None:
                        continue

                htype = h.get('type', None)
                if htype is None:
                    continue

                elif isinstance(htype, string_types):
                    htype = htype.lower()

                elif isinstance(htype, dict):
                    htype = htype.get('value', None)
                    if htype is None or not isinstance(htype, string_types):
                        continue

                htype = htype.lower()
                if htype not in self.hash_priority:
                    continue

                prio = self.hash_priority.index(htype)

                if prio > cprio:
                    indicator_type = htype
                    cprio = prio

                indicator_hashes[htype] = hvalue

            if indicator_type is None:
                LOG.error('{} - No valid hash found in FileObjectType: {!r}'.format(
                    self.name, op
                ))
                return None

            if ov == '':
                ov = indicator_hashes[indicator_type]
                result['type'] = indicator_type

            for h, v in indicator_hashes.iteritems():
                if h == indicator_type:
                    continue
                result['{}_{}'.format(self.prefix, h)] = v

        elif ot == 'SocketAddressObjectType':
            ip_address = op.get('ip_address', None)
            if ip_address is None:
                return None

            return self._decode_object_properties(ip_address)

        elif ot == 'AddressObjectType':
            ov = op.get('address_value', None)
            if ov is None:
                LOG.error('%s - no value in observable props', self.name)
                return None
            if not isinstance(ov, string_types):
                ov = ov.get('value', None)
                if ov is None:
                    LOG.error('%s - no value in observable value', self.name)
                    return None

            # set the IP Address type
            if not self.ip_version_auto_detect:
                addrcat = op.get('category', None)
                if addrcat == 'ipv6-addr':
                    result['type'] = 'IPv6'
                elif addrcat == 'ipv4-addr':
                    result['type'] = 'IPv4'
                elif addrcat == 'e-mail':
                    result['type'] = 'email-addr'
                else:
                    LOG.error('{} - unknown address category: {}'.format(self.name, addrcat))
                    return None

            else:
                # some feeds do not set the IP Address type and it
                # defaults to ipv4-addr even if the IP is IPv6
                # this is to auto detect the type
                if type(ov) == list:
                    address = ov[0]
                else:
                    address = ov

                try:
                    parsed = netaddr.IPNetwork(address)
                except (netaddr.AddrFormatError, ValueError):
                    LOG.error('{} - Unknown IP version: {}'.format(self.name, address))
                    return None

                if parsed.version == 4:
                    result['type'] = 'IPv4'
                elif parsed.version == 6:
                    result['type'] = 'IPv6'

            if result['type'] in ['IPv4', 'IPv6']:
                source = op.get('is_source', None)
                if source is True:
                    result['direction'] = 'inbound'
                elif source is False:
                    result['direction'] = 'outbound'

            if 'type' not in result:
                LOG.error('%s - no IP category and unknown version')
                return None

        elif ot == 'URIObjectType':
            result['type'] = 'URL'

            ov = op.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable props', self.name)
                return None
            if not isinstance(ov, string_types):
                ov = ov.get('value', None)
                if ov is None:
                    LOG.error('%s - no value in observable value', self.name)
                    return None

        elif ot == 'LinkObjectType':
            if op.get('type', 'URL') != 'URL':
                LOG.error('{} - Unhandled LinkObjectType type: {!r}'.format(self.name, op))
                return None

            result['type'] = 'URL'

            ov = op.get('value', None)
            if ov is None:
                LOG.error('%s - no value in observable props', self.name)
                return None
            if not isinstance(ov, string_types):
                ov = ov.get('value', None)
                if ov is None:
                    LOG.error('%s - no value in observable value', self.name)
                    return None

        elif ot == 'EmailMessageObjectType':
            result['type'] = 'email-message'

            ov = ''
            LOG.debug('EmailMessageObjectType OP: {!r}'.format(op))

            body = op.get('raw_body', None)
            if body is not None:
                result['body'] = body
                LOG.debug('EmailMessage Body: {!r}'.format(body))

            header = op.get('header', None)
            if header is not None:
                result['header'] = header
                try:
                    ov = header.get('from').get('address_value').get('value')
                except Exception:
                    LOG.error('{} - no email address listed'.format(self.name))

            subject = op.get('subject', None)
            if subject is not None:
                result['subject'] = subject
                if ov == '':
                    ov = subject

        elif ot == 'ArtifactObjectType':
            ov = ''
            result['type'] = 'artifact'

            LOG.debug('ArtifactObjectType OV: {!r}'.format(ov))

            title = odict.get('title', None)
            if title is not None:
                ov = title
                result['title'] = title

            description = odict.get('description', None)
            if description is not None:
                result['description'] = description
                if ov == '':
                    ov = description

            artifact = op['raw_artifact']
            if artifact is not None:
                result['artifact'] = artifact

        elif ot == 'PDFFileObjectType':
            ov = ''
            result['type'] = 'pdf-file'

            if 'file_name' in op.keys():
                file_name = op.get('file_name')
                if type(file_name) == dict:
                    if file_name.get('value', None) is not None:
                        ov = op['file_name'].get('value', None)
                    else:
                        ov = op['file_name']
                else:
                    ov = file_name

            LOG.debug('PDFObjectType OV: {!r}'.format(ov))

            if 'file_path' in op.keys():
                result['file_path'] = op['file_path'].get('value', None)

            if 'file_size' in op.keys():
                result['file_size'] = op['file_size'].get('value', None)

            if 'metadata' in op.keys():
                result['metadata'] = op['metadata']

            if 'file_format' in op.keys():
                result['file_format'] = op['file_format']

            hashes = op.get('hashes', None)
            if hashes is not None:
                for i in hashes:
                    if 'type' in i.keys():
                        if isinstance(i['type'], string_types):
                            hash_type = i['type']
                        else:
                            hash_type = i['type'].get('value', None)
                    if 'simple_hash_value' in i.keys():
                        if isinstance(i['simple_hash_value'], string_types):
                            result[hash_type] = i['simple_hash_value']
                        else:
                            result[hash_type] = i['simple_hash_value'].get('value', None)

        elif ot == 'WhoisObjectType':
            ov = ''
            result['type'] = 'whois'
            LOG.debug('WhoisObjectType OV: {!r}'.format(ov))

            remarks = op.get('remarks', None)
            if remarks is not None:
                result['remarks'] = op['remarks']
                ov = remarks.split('\n')[0]

        elif ot == 'HTTPSessionObjectType':
            ov = ''
            result['type'] = 'http-session'

            if 'http_request_response' in op.keys():
                tmp = op['http_request_response']

                if len(tmp) == 1:
                    item = tmp[0]
                    LOG.debug('HTTPSessionObjectType item: {!r}'.format(item))
                    http_client_request = item.get('http_client_request', None)
                    if http_client_request is not None:
                        http_request_header = http_client_request.get('http_request_header', None)
                        if http_request_header is not None:
                            raw_header = http_request_header.get('raw_header', None)
                            if raw_header is not None:
                                result['header'] = raw_header
                                ov = raw_header.split('\n')[0]
                else:
                    LOG.error('{} - multiple HTTPSessionObjectTypes not supported'.format(self.name))

        elif ot == 'PortObjectType':
            result['type'] = 'port'
            LOG.debug('PortObjectType OP: {!r}'.format(op))
            protocol = op.get('layer4_protocol', None)
            port = op.get('port_value', None)
            ov = '{}:{}'.format(protocol, port)

        elif ot == 'WindowsExecutableFileObjectType':
            ov = ''
            result['type'] = 'windows-executable'
            LOG.debug('WindowsExecutableFileObjectType OP: {!r}'.format(op))

            if 'file_name' in op.keys():
                if isinstance(op['file_name'], string_types):
                    ov = op['file_name']
                else:
                    ov = op['file_name'].get('value', None)

            if 'size_in_bytes' in op.keys():
                result['file_size'] = op['size_in_bytes']

            if 'file_format' in op.keys():
                result['file_format'] = op['file_format']

            hashes = op.get('hashes', None)
            if hashes is not None:
                for i in hashes:
                    if 'type' in i.keys():
                        if isinstance(i['type'], string_types):
                            hash_type = i['type']
                        else:
                            hash_type = i['type'].get('value', None)
                    if 'simple_hash_value' in i.keys():
                        if isinstance(i['simple_hash_value'], string_types):
                            result[hash_type] = i['simple_hash_value']
                        else:
                            result[hash_type] = i['simple_hash_value'].get('value', None)

        elif ot == 'CISCP:IndicatorTypeVocab-0.0':
            result['type'] = op['xsi:type']
            LOG.debug('CISCP:IndicatorTypeVocab-0.0 OP: {!r}'.format(op))
            ov = None
            LOG.error('{} - CISCP:IndicatorTypeVocab-0.0 Type not currently supported'.format(self.name))
            return None

        elif ot == 'WindowsRegistryKeyObjectType':
            result['type'] = op['xsi:type']
            LOG.debug('WindowsRegistryKeyObjectType OP: {!r}'.format(op))
            ov = None
            LOG.error('{} - WindowsRegistryKeyObjectType Type not currently supported'.format(self.name))
            return None

        elif ot == 'stixVocabs:IndicatorTypeVocab-1.0':
            result['type'] = op['xsi:type']
            LOG.debug('stixVocabs:IndicatorTypeVocab-1.0 OP: {!r}'.format(op))
            ov = None
            LOG.error('{} - stixVocabs:IndicatorTypeVocab-1.0 Type not currently supported'.format(self.name))
            return None

        elif ot == 'NetworkConnectionObjectType':
            result['type'] = 'NetworkConnection'
            LOG.debug('NetworkConnectionObjectType OP: {!r}'.format(op))
            ov = None
            LOG.error('{} - NetworkConnectionObjectType Type not currently supported'.format(self.name))
            return None

        else:
            LOG.error('{} - unknown type {} {!r}'.format(self.name, ot, op))
            return None

        result['indicator'] = ov

        LOG.debug('{!r}'.format(result))

        return result

    def _decode_ttp(self, t):
        tdict = t.to_dict()

        if 'ttp' in tdict:
            tdict = tdict['ttp']

        if 'idref' in tdict:
            return {'idref': tdict['idref']}

        if 'description' in tdict:
            return {'description': tdict['description']}

        if 'title' in tdict:
            return {'description': tdict['title']}

        return {'description': ''}

    def _process_item(self, item):
        result = []
        value = {}

        iid, iv, stix_objects = item

        value['%s_indicator' % self.prefix] = iid

        if 'description' in iv:
            value['{}_indicator_description'.format(self.prefix)] = iv['description']

        if 'confidence' in iv:
            value['confidence'] = iv['confidence']

        if len(iv['ttps']) != 0:
            ttp = iv['ttps'][0]
            if 'idref' in ttp:
                ttp = stix_objects['ttps'].get(ttp['idref'])

            if ttp is not None and 'description' in ttp:
                value['%s_ttp' % self.prefix] = ttp['description']

        composed_observables = []
        for o in iv['observables']:
            if o is None:
                continue

            v = copy.copy(value)

            ob = o
            if 'idref' in o:
                ob = stix_objects['observables'].get(o['idref'], None)
                v['%s_observable' % self.prefix] = o['idref']

            if ob is None:
                continue

            if ob['type'] == '_cyboxOR':
                for o in ob['observables']:
                    composed_observables.append(o)
                continue

            v['type'] = ob['type']

            if type(ob['indicator']) == list:
                indicator = ob['indicator']
            else:
                indicator = [ob['indicator']]

            for i in indicator:
                result.append([i, v])

        for o in composed_observables:
            v = copy.copy(value)

            ob = stix_objects['observables'].get(o, None)
            v['%s_observable' % self.prefix] = o

            if ob is None:
                continue

            if ob['type'] == '_cyboxOR':
                LOG.error(
                    '%s - Nested Observable Composition not supported',
                    self.name
                )
                continue

            v['type'] = ob['type']

            if type(ob['indicator']) == list:
                indicator = ob['indicator']
            else:
                indicator = [ob['indicator']]

            for i in indicator:
                result.append([i, v])

        return result

    def _build_iterator(self, now):
        if self.client_credentials_required:
            if self.username is None or self.password is None:
                raise RuntimeError(
                    '%s - username or password required and not set, poll not performed' % self.name
                )
        if self.cert_file is not None and not os.path.isfile(self.cert_file):
            raise RuntimeError(
                '%s - client cert required and not set, poll not performed' % self.name
            )
        if self.key_file is not None and not os.path.isfile(self.key_file):
            raise RuntimeError(
                '%s - client cert key required and not set, poll not performed' % self.name
            )
        if self.subscription_id_required and self.subscription_id is None:
            raise RuntimeError(
                '%s - subscription id required and not set, poll not performed' % self.name
            )

        tc = self._build_taxii_client()
        self._discover_services(tc)
        self._check_collections(tc)

        last_run = self.last_taxii_run
        max_back = now-(self.initial_interval*1000)
        if last_run is None or last_run < max_back:
            last_run = max_back

        begin = datetime.utcfromtimestamp(last_run/1000)
        begin = begin.replace(tzinfo=pytz.UTC)

        end = datetime.utcfromtimestamp(now/1000)
        end = end.replace(tzinfo=pytz.UTC)

        if self.lower_timestamp_precision:
            end = end.replace(second=0, microsecond=0)
            begin = begin.replace(second=0, microsecond=0)

        return self._incremental_poll_collection(
            taxii_client=tc,
            begin=begin,
            end=end
        )

    def _flush(self):
        self.last_taxii_run = None
        super(TaxiiClient, self)._flush()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(TaxiiClient, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except:
            pass

        client_cert_required = False
        if config is not None:
            client_cert_required = config.get('client_cert_required', False)

        cert_path = None
        if config is not None:
            cert_path = config.get('cert_file', None)
            if cert_path is None and client_cert_required:
                cert_path = os.path.join(
                    os.environ['MM_CONFIG_DIR'],
                    '{}.crt'.format(name)
                )

            if cert_path is not None:
                try:
                    os.remove(cert_path)
                except:
                    pass

        key_path = None
        if config is not None:
            key_path = config.get('key_file', None)
            if key_path is None and client_cert_required:
                key_path = os.path.join(
                    os.environ['MM_CONFIG_DIR'],
                    '{}.pem'.format(name)
                )

            if key_path is not None:
                try:
                    os.remove(key_path)
                except:
                    pass


def _stix_ip_observable(namespace, indicator, value):
    category = cybox.objects.address_object.Address.CAT_IPV4
    if value['type'] == 'IPv6':
        category = cybox.objects.address_object.Address.CAT_IPV6

    indicators = [indicator]
    if '-' in indicator:
        # looks like an IP Range, let's try to make it a CIDR
        a1, a2 = indicator.split('-', 1)
        if a1 == a2:
            # same IP
            indicators = [a1]
        else:
            # use netaddr builtin algo to summarize range into CIDR
            iprange = netaddr.IPRange(a1, a2)
            cidrs = iprange.cidrs()
            indicators = map(str, cidrs)

    observables = []
    for i in indicators:
        id_ = '{}:observable-{}'.format(
            namespace,
            uuid.uuid4()
        )

        ao = cybox.objects.address_object.Address(
            address_value=i,
            category=category
        )

        o = cybox.core.Observable(
            title='{}: {}'.format(value['type'], i),
            id_=id_,
            item=ao
        )

        observables.append(o)

    return observables


def _stix_email_addr_observable(namespace, indicator, value):
    category = cybox.objects.address_object.Address.CAT_EMAIL

    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    ao = cybox.objects.address_object.Address(
        address_value=indicator,
        category=category
    )

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=ao
    )

    return [o]


def _stix_domain_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    do = cybox.objects.domain_name_object.DomainName()
    do.value = indicator
    do.type_ = 'FQDN'

    o = cybox.core.Observable(
        title='FQDN: ' + indicator,
        id_=id_,
        item=do
    )

    return [o]


def _stix_url_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    uo = cybox.objects.uri_object.URI(
        value=indicator,
        type_=cybox.objects.uri_object.URI.TYPE_URL
    )

    o = cybox.core.Observable(
        title='URL: ' + indicator,
        id_=id_,
        item=uo
    )

    return [o]


def _stix_hash_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    uo = cybox.objects.file_object.File()
    uo.add_hash(indicator)

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=uo
    )

    return [o]


_TYPE_MAPPING = {
    'IPv4': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': _stix_ip_observable
    },
    'IPv6': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': _stix_ip_observable
    },
    'URL': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_URL_WATCHLIST,
        'mapper': _stix_url_observable
    },
    'domain': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_DOMAIN_WATCHLIST,
        'mapper': _stix_domain_observable
    },
    'sha256': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': _stix_hash_observable
    },
    'sha1': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': _stix_hash_observable
    },
    'md5': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': _stix_hash_observable
    },
    'email-addr': {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALICIOUS_EMAIL,
        'mapper': _stix_email_addr_observable
    }
}


class DataFeed(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.redis_skey = name
        self.redis_skey_value = name+'.value'
        self.redis_skey_chkp = name+'.chkp'

        self.SR = None
        self.ageout_glet = None

        super(DataFeed, self).__init__(name, chassis, config)

    def configure(self):
        super(DataFeed, self).configure()

        self.redis_host = self.config.get('redis_host', '127.0.0.1')
        self.redis_port = self.config.get('redis_port', 6379)
        self.redis_password = self.config.get('redis_password', None)
        self.redis_db = self.config.get('redis_db', 0)

        self.namespace = self.config.get('namespace', 'minemeld')
        self.namespaceuri = self.config.get(
            'namespaceuri',
            'https://go.paloaltonetworks.com/minemeld'
        )

        self.age_out_interval = self.config.get('age_out_interval', '24h')
        self.age_out_interval = interval_in_sec(self.age_out_interval)
        if self.age_out_interval < 60:
            LOG.info('%s - age out interval too small, forced to 60 seconds')
            self.age_out_interval = 60

        self.max_entries = self.config.get('max_entries', 1000 * 1000)

        self.attributes_package_title = self.config.get('attributes_package_title', [])
        if not isinstance(self.attributes_package_title, list):
            LOG.error('{} - attributes_package_title should be a list - ignored')
            self.attributes_package_title = []

        self.attributes_package_description = self.config.get('attributes_package_description', [])
        if not isinstance(self.attributes_package_description, list):
            LOG.error('{} - attributes_package_description should be a list - ignored')
            self.attributes_package_description = []

        self.attributes_package_sdescription = self.config.get('attributes_package_short_description', [])
        if not isinstance(self.attributes_package_sdescription, list):
            LOG.error('{} - attributes_package_sdescription should be a list - ignored')
            self.attributes_package_sdescription = []

        self.attributes_package_information_source = self.config.get('attributes_package_information_source', [])
        if not isinstance(self.attributes_package_information_source, list):
            LOG.error('{} - attributes_package_information_source should be a list - ignored')
            self.attributes_package_information_source = []

    def connect(self, inputs, output):
        output = False
        super(DataFeed, self).connect(inputs, output)

    def read_checkpoint(self):
        self._connect_redis()
        self.last_checkpoint = self.SR.get(self.redis_skey_chkp)

    def create_checkpoint(self, value):
        self._connect_redis()
        self.SR.set(self.redis_skey_chkp, value)

    def remove_checkpoint(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey_chkp)

    def _connect_redis(self):
        if self.SR is not None:
            return

        self.SR = redis.StrictRedis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password,
            db=self.redis_db
        )

    def _read_oldest_indicator(self):
        olist = self.SR.zrange(
            self.redis_skey, 0, 0,
            withscores=True
        )
        LOG.debug('%s - oldest: %s', self.name, olist)
        if len(olist) == 0:
            return None, None

        return int(olist[0][1]), olist[0][0]

    def initialize(self):
        self._connect_redis()

    def rebuild(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey)
        self.SR.delete(self.redis_skey_value)

    def reset(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey)
        self.SR.delete(self.redis_skey_value)

    def _add_indicator(self, score, indicator, value):
        if self.length() >= self.max_entries:
            LOG.info('dropped overflow')
            self.statistics['drop.overflow'] += 1
            return

        type_ = value['type']
        type_mapper = _TYPE_MAPPING.get(type_, None)
        if type_mapper is None:
            self.statistics['drop.unknown_type'] += 1
            LOG.error('%s - Unsupported indicator type: %s', self.name, type_)
            return

        set_id_namespace(self.namespaceuri, self.namespace)

        title = None
        if len(self.attributes_package_title) != 0:
            for pt in self.attributes_package_title:
                if pt not in value:
                    continue

                title = '{}'.format(value[pt])
                break

        description = None
        if len(self.attributes_package_description) != 0:
            for pd in self.attributes_package_description:
                if pd not in value:
                    continue

                description = '{}'.format(value[pd])
                break

        sdescription = None
        if len(self.attributes_package_sdescription) != 0:
            for pd in self.attributes_package_sdescription:
                if pd not in value:
                    continue

                sdescription = '{}'.format(value[pd])
                break

        information_source = None
        if len(self.attributes_package_information_source) != 0:
            for isource in self.attributes_package_information_source:
                if isource not in value:
                    continue

                information_source = '{}'.format(value[isource])
                break

            if information_source is not None:
                identity = stix.common.identity.Identity(name=information_source)
                information_source = stix.common.information_source.InformationSource(identity=identity)

        handling = None
        share_level = value.get('share_level', None)
        if share_level in ['white', 'green', 'amber', 'red']:
            marking_specification = stix.data_marking.MarkingSpecification()
            marking_specification.controlled_structure = "//node() | //@*"

            tlp = stix.extensions.marking.tlp.TLPMarkingStructure()
            tlp.color = share_level.upper()
            marking_specification.marking_structures.append(tlp)

            handling = stix.data_marking.Marking()
            handling.add_marking(marking_specification)

        header = None
        if (title is not None or
            description is not None or
            handling is not None or
            sdescription is not None or
            information_source is not None):
            header = stix.core.STIXHeader(
                title=title,
                description=description,
                handling=handling,
                short_description=sdescription,
                information_source=information_source
            )

        spid = '{}:indicator-{}'.format(
            self.namespace,
            uuid.uuid4()
        )
        sp = stix.core.STIXPackage(id_=spid, stix_header=header)

        observables = type_mapper['mapper'](self.namespace, indicator, value)

        for o in observables:
            id_ = '{}:indicator-{}'.format(
                self.namespace,
                uuid.uuid4()
            )

            if value['type'] == 'URL':
                eindicator = werkzeug.urls.iri_to_uri(indicator, safe_conversion=True)
            else:
                eindicator = indicator

            sindicator = stix.indicator.indicator.Indicator(
                id_=id_,
                title='{}: {}'.format(
                    value['type'],
                    eindicator
                ),
                description='{} indicator from {}'.format(
                    value['type'],
                    ', '.join(value['sources'])
                ),
                timestamp=datetime.utcnow().replace(tzinfo=pytz.utc)
            )

            confidence = value.get('confidence', None)
            if confidence is None:
                LOG.error('%s - indicator without confidence', self.name)
                sindicator.confidence = "Unknown"  # We shouldn't be here
            elif confidence < 50:
                sindicator.confidence = "Low"
            elif confidence < 75:
                sindicator.confidence = "Medium"
            else:
                sindicator.confidence = "High"

            sindicator.add_indicator_type(type_mapper['indicator_type'])

            sindicator.add_observable(o)

            sp.add_indicator(sindicator)

        spackage = 'lz4'+lz4.compressHC(sp.to_json())
        with self.SR.pipeline() as p:
            p.multi()

            p.zadd(self.redis_skey, score, spid)
            p.hset(self.redis_skey_value, spid, spackage)

            result = p.execute()[0]

        self.statistics['added'] += result

    def _delete_indicator(self, indicator_id):
        with self.SR.pipeline() as p:
            p.multi()

            p.zrem(self.redis_skey, indicator_id)
            p.hdel(self.redis_skey_value, indicator_id)

            result = p.execute()[0]

        self.statistics['removed'] += result

    def _age_out_run(self):
        while True:
            now = utc_millisec()
            low_watermark = now - self.age_out_interval*1000

            otimestamp, oindicator = self._read_oldest_indicator()
            LOG.debug(
                '{} - low watermark: {} otimestamp: {}'.format(
                    self.name,
                    low_watermark,
                    otimestamp
                )
            )
            while otimestamp is not None and otimestamp < low_watermark:
                self._delete_indicator(oindicator)
                otimestamp, oindicator = self._read_oldest_indicator()

            wait_time = 30
            if otimestamp is not None:
                next_expiration = (
                    (otimestamp + self.age_out_interval*1000) - now
                )
                wait_time = max(wait_time, next_expiration/1000 + 1)
            LOG.debug('%s - sleeping for %d secs', self.name, wait_time)

            gevent.sleep(wait_time)

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        now = utc_millisec()

        self._add_indicator(now, indicator, value)

    @base._counting('withdraw.ignored')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        # this is a TAXII data feed, old indicators never expire
        pass

    def length(self, source=None):
        return self.SR.zcard(self.redis_skey)

    def start(self):
        super(DataFeed, self).start()

        self.ageout_glet = gevent.spawn(self._age_out_run)

    def stop(self):
        super(DataFeed, self).stop()

        self.ageout_glet.kill()

        LOG.info(
            "%s - # indicators: %d",
            self.name,
            self.SR.zcard(self.redis_skey)
        )

    @staticmethod
    def gc(name, config=None):
        actorbase.ActorBaseFT.gc(name, config=config)

        if config is None:
            config = {}

        redis_skey = name
        redis_skey_value = '{}.value'.format(name)
        redis_skey_chkp = '{}.chkp'.format(name)
        redis_host = config.get('redis_host', '127.0.0.1')
        redis_port = config.get('redis_port', 6379)
        redis_password = config.get('redis_password', None)
        redis_db = config.get('redis_db', 0)

        cp = None
        try:
            cp = redis.ConnectionPool(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                db=redis_db,
                socket_timeout=10
            )

            SR = redis.StrictRedis(connection_pool=cp)

            SR.delete(redis_skey)
            SR.delete(redis_skey_value)
            SR.delete(redis_skey_chkp)

        except Exception as e:
            raise RuntimeError(str(e))

        finally:
            if cp is not None:
                cp.disconnect()
