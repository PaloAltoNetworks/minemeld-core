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

O365_URL = 'https://support.content.office.net/en-us/static/O365IPAddresses.xml'
BASE_XPATH = "/products/product[@name='%s']"


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


class O365XML(basepoller.BasePollerFT):
    def configure(self):
        super(O365XML, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)
        self.products = self.config.get('products', [])

    def _process_item(self, item):
        indicator = item.pop('indicator', None)
        return [[indicator, item]]

    def _build_request(self, now):
        r = requests.Request(
            'GET',
            O365_URL
        )

        return r.prepare()

    def _build_iterator(self, now):
        _iterators = []

        _session = requests.Session()
        _adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=3
        )
        _session.mount('https://', _adapter)

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )
        prepreq = self._build_request(now)
        r = _session.send(prepreq, **rkwargs)

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.text)
            raise

        rtree = lxml.etree.parse(r.raw)
        for p in self.products:
            xpath = BASE_XPATH % p
            pIPv4s = rtree.xpath(
                xpath + "/addresslist[@type='IPv4']/address"
            )
            _iterators.append(itertools.imap(
                functools.partial(_build_IPv4, 'office365.%s' % p),
                pIPv4s
            ))

            pIPv6s = rtree.xpath(
                xpath + "/addresslist[@type='IPv6']/address"
            )
            _iterators.append(itertools.imap(
                functools.partial(_build_IPv6, 'office365.%s' % p),
                pIPv6s
            ))

            pURLs = rtree.xpath(
                xpath + "/addresslist[@type='URL']/address"
            )
            _iterators.append(itertools.imap(
                functools.partial(_build_URL, 'office365.%s' % p),
                pURLs
            ))

        return itertools.chain(*_iterators)
