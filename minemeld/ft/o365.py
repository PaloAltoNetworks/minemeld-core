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
