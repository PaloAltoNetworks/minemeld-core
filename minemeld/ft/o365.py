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

from __future__ import absolute_import

import logging
import itertools
import functools
import uuid
import os

import yaml
import netaddr
import requests
import lxml.etree

from . import basepoller

LOG = logging.getLogger(__name__)

O365_URL = \
    'https://support.content.office.net/en-us/static/O365IPAddresses.xml'
XPATH_FUNS_NS = 'http://minemeld.panw.io/o365functions'
XPATH_FUNS_PREFIX = 'o365f'
XPATH_PRODUCTS = "/products/product/@name"
BASE_XPATH = "/products/product[" + XPATH_FUNS_PREFIX + ":lower-case(@name)='%s']"

O365_API_BASE_URL = 'https://endpoints.office.com'

def _build_IPv4(source, address):
    item = {
        'indicator': address.text,
        'type': 'IPv4',
        'confidence': 100,
        'sources': [source]
    }
    return item


def _build_IPv6(source, address):
    item = {
        'indicator': address.text,
        'type': 'IPv6',
        'confidence': 100,
        'sources': [source]
    }
    return item


def _build_URL(source, url):
    item = {
        'indicator': url.text,
        'type': 'URL',
        'confidence': 100,
        'sources': [source]
    }
    return item


def _xpath_lower_case(context, a):
    return [e.lower() for e in a]


class O365XML(basepoller.BasePollerFT):
    def configure(self):
        super(O365XML, self).configure()

        # register lower-case
        ns = lxml.etree.FunctionNamespace(XPATH_FUNS_NS)
        ns['lower-case'] = _xpath_lower_case
        self.prefixmap = {XPATH_FUNS_PREFIX: XPATH_FUNS_NS}

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)
        self.products = self.config.get('products', [])

        self.url = self.config.get('url', O365_URL)

    def _process_item(self, item):
        indicator = item.pop('indicator', None)
        return [[indicator, item]]

    def _build_request(self, now):
        r = requests.Request(
            'GET',
            self.url
        )

        return r.prepare()

    def _o365_iterator(self, now):
        _iterators = []

        _session = requests.Session()
        _adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=3
        )
        _session.mount('https://', _adapter)

        prepreq = self._build_request(now)

        # this is to honour the proxy environment variables
        rkwargs = _session.merge_environment_settings(
            prepreq.url,
            {}, None, None, None  # defaults
        )
        rkwargs['stream'] = True
        rkwargs['verify'] = self.verify_cert
        rkwargs['timeout'] = self.polling_timeout
        r = _session.send(prepreq, **rkwargs)

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.text)
            raise

        parser = lxml.etree.XMLParser()
        for chunk in r.iter_content(chunk_size=10 * 1024):
            parser.feed(chunk)
        rtree = parser.close()

        products = self.products
        if len(products) == 0:
            products = self._extract_products(rtree)

        for p in products:
            xpath = BASE_XPATH % p.lower()
            pIPv4s = rtree.xpath(
                xpath + "/addresslist[@type='IPv4']/address",
                namespaces=self.prefixmap
            )
            _iterators.append(itertools.imap(
                functools.partial(_build_IPv4, 'office365.%s' % p.lower()),
                pIPv4s
            ))

            pIPv6s = rtree.xpath(
                xpath + "/addresslist[@type='IPv6']/address",
                namespaces=self.prefixmap
            )
            _iterators.append(itertools.imap(
                functools.partial(_build_IPv6, 'office365.%s' % p.lower()),
                pIPv6s
            ))

            pURLs = rtree.xpath(
                xpath + "/addresslist[@type='URL']/address",
                namespaces=self.prefixmap
            )
            _iterators.append(itertools.imap(
                functools.partial(_build_URL, 'office365.%s' % p.lower()),
                pURLs
            ))

        return itertools.chain(*_iterators)

    def _build_iterator(self, now):
        oiterator = self._o365_iterator(now)

        idict = {}
        for i in oiterator:
            indicator = i['indicator']
            cvalue = idict.get(indicator, None)
            if cvalue is not None:
                i['sources'] = list(set(i['sources']) | set(cvalue['sources']))
            idict[indicator] = i

        return itertools.imap(lambda i: i[1], idict.iteritems())

    def _extract_products(self, rtree):
        products = rtree.xpath(XPATH_PRODUCTS)
        LOG.info('%s - found products: %r', self.name, products)
        return products


class O365API(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        self.client_request_id = str(uuid.uuid4())
        self.latest_version = '0000000000'

        super(O365API, self).__init__(name, chassis, config)

    def configure(self):
        super(O365API, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.instance = self.config.get('instance', 'O365Worldwide')
        self.service_areas = self.config.get('service_areas', None)
        self.tenant_name = self.config.get('tenant_name', None)
        self.disable_integrations = self.config.get('disable_integrations', False)

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        disable_integrations = sconfig.get('disable_integrations', None)
        if disable_integrations is not None:
            self.disable_integrations = disable_integrations
            LOG.info('{} - Loaded side config'.format(self.name))

    def _saved_state_restore(self, saved_state):
        super(O365API, self)._saved_state_restore(saved_state)

        self.client_request_id = saved_state.get('client_request_id', None)
        self.latest_version = saved_state.get('latest_version', None)

        LOG.info('saved state: client_request_id: {} latest_version: {}'.format(
            self.client_request_id,
            self.latest_version
        ))

    def _saved_state_create(self):
        sstate = super(O365API, self)._saved_state_create()

        sstate['latest_version'] = self.latest_version
        sstate['client_request_id'] = self.client_request_id

        return sstate

    def _saved_state_reset(self):
        super(O365API, self)._saved_state_reset()

        self.client_request_id = str(uuid.uuid4())
        self.latest_version = '0000000000'

    def _check_version(self):
        rkwargs = dict(
            stream=False,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            params={
                'clientrequestid': self.client_request_id
            }
        )

        url = '{}/version/{}'.format(
            O365_API_BASE_URL,
            self.instance
        )

        r = requests.get(
            url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('{} - exception in request: {} {!r}'.format(
                self.name, r.status_code, r.content
            ))
            raise

        version = r.json()

        LOG.debug('{} - version: {}'.format(self.name, version))

        if version['latest'] > self.latest_version:
            return version['latest']

        return

    def _process_item(self, item):
        item.pop('id', None)

        result = []

        base_value = {}
        for wka in ['expressRoute', 'notes', 'serviceArea', 'tcpPorts', 'udpPorts', 'category', 'required']:
            if wka in item:
                base_value['o365_{}'.format(wka)] = item[wka]

        if self.disable_integrations and 'o365_notes' in base_value:
            if 'integration' in base_value['o365_notes'].lower():
                return result

        for url in item.get('urls', []):
            value = base_value.copy()
            value['type'] = 'URL'

            result.append([url, value])

        for ip in item.get('ips', []):
            try:
                parsed = netaddr.IPNetwork(ip)
            except (netaddr.AddrFormatError, ValueError):
                LOG.error('{} - Unknown IP version: {}'.format(self.name, ip))
                continue

            value = base_value.copy()
            if parsed.version == 4:
                value['type'] = 'IPv4'
            elif parsed.version == 6:
                value['type'] = 'IPv6'

            result.append([ip, value])

        return result

    def _iterator(self, array, latest_version):
        for i in array:
            yield i

        self.latest_version = latest_version

    def _build_iterator(self, now):
        latest_version = self._check_version()
        if latest_version is None:
            LOG.info('{} - Already latest version, polling not performed'.format(
                self.name
            ))
            return None

        rkwargs = dict(
            stream=False,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            params={
                'clientrequestid': self.client_request_id
            }
        )
        if self.tenant_name is not None:
            rkwargs['params']['tenantname'] = self.tenant_name
        if self.service_areas is not None:
            rkwargs['params']['serviceareas'] = ','.join(self.service_areas)

        url = '{}/endpoints/{}'.format(
            O365_API_BASE_URL,
            self.instance
        )

        r = requests.get(
            url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('{} - exception in request: {} {!r}'.format(
                self.name, r.status_code, r.content
            ))
            raise

        return self._iterator(r.json(), latest_version)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        self.latest_version = None
        super(O365API, self).hup(source=source)
