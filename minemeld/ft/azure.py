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

from __future__ import absolute_import

import logging
import itertools
import functools
import requests
import netaddr
import lxml.etree
import bs4

from . import basepoller

LOG = logging.getLogger(__name__)

AZUREXML_URL = \
    'https://www.microsoft.com/EN-US/DOWNLOAD/confirmation.aspx?id=41653'

AZUREJSON_URL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519'

REGIONS_XPATH = '/AzurePublicIpAddresses/Region'


def _build_IPv4(nodename, region, iprange):
    iprange = iprange.get('Subnet', None)
    if iprange is None:
        LOG.error('%s - No Subnet', nodename)
        return {}

    try:
        netaddr.IPNetwork(iprange)
    except:
        LOG.exception('%s - Invalid ip range: %s', nodename, iprange)
        return {}

    item = {
        'indicator': iprange,
        'type': 'IPv4',
        'confidence': 100,
        'azure_region': region,
        'sources': ['azure.xml']
    }
    return item


def _build_IP(nodename, address_prefix, **keywords):
    try:
        ap = netaddr.IPNetwork(address_prefix)
    except Exception:
        LOG.exception('%s - Invalid ip range: %s', nodename, address_prefix)
        return {}

    if ap.version == 4:
        type_ = 'IPv4'
    elif ap.version == 6:
        type_ = 'IPv6'
    else:
        LOG.error('{} - Unknown IP version: {}'.format(nodename, ap.version))
        return {}

    item = {
        'indicator': address_prefix,
        'type': type_,
        'confidence': 100,
        'sources': [nodename]
    }
    item.update(keywords)

    return item


class AzureXML(basepoller.BasePollerFT):
    def configure(self):
        super(AzureXML, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

    def _process_item(self, item):
        indicator = item.pop('indicator', None)
        return [[indicator, item]]

    def _build_request(self, now):
        r = requests.Request(
            'GET',
            AZUREXML_URL
        )

        return r.prepare()

    def _build_iterator(self, now):
        _iterators = []

        rkwargs = dict(
            stream=False,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            AZUREXML_URL,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.error('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        html_soup = bs4.BeautifulSoup(r.content, "lxml")
        a = html_soup.find('a', class_='failoverLink')
        if a is None:
            LOG.error('%s - failoverLink not found', self.name)
            raise RuntimeError('{} - failoverLink not found'.format(self.name))
        LOG.debug('%s - download link: %s', self.name, a['href'])

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            a['href'],
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.error('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        parser = lxml.etree.XMLParser()
        for chunk in r.iter_content(chunk_size=10 * 1024):
            parser.feed(chunk)
        rtree = parser.close()

        regions = rtree.xpath(REGIONS_XPATH)

        for r in regions:
            LOG.debug('%s - Extracting region: %s', self.name, r.get('Name'))

            ipranges = r.xpath('IpRange')
            _iterators.append(itertools.imap(
                functools.partial(_build_IPv4, self.name, r.get('Name')),
                ipranges
            ))

        return itertools.chain(*_iterators)


class AzureJSON(basepoller.BasePollerFT):
    def configure(self):
        super(AzureJSON, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

    def _process_item(self, item):
        indicator = item.pop('indicator', None)
        return [[indicator, item]]

    def _build_request(self, now):
        r = requests.Request(
            'GET',
            AZUREJSON_URL
        )

        return r.prepare()

    def _build_iterator(self, now):
        _iterators = []

        rkwargs = dict(
            stream=False,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            AZUREJSON_URL,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.error('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        html_soup = bs4.BeautifulSoup(r.content, "lxml")
        a = html_soup.find('a', class_='failoverLink')
        if a is None:
            LOG.error('%s - failoverLink not found', self.name)
            raise RuntimeError('{} - failoverLink not found'.format(self.name))
        LOG.debug('%s - download link: %s', self.name, a['href'])

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            a['href'],
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.error('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        rtree = r.json()

        values = rtree.get('values', None)
        if values is None:
            LOG.error('{} - no values in JSON response'.format(self.name))
            return []

        for v in values:
            LOG.debug('{} - Extracting value: {!r}'.format(self.name, v.get('id', None)))

            id_ = v.get('id', None)
            name = v.get('name', None)

            props = v.get('properties', None)
            if props is None:
                LOG.error('{} - no properties in value'.format(self.name))
                continue

            region = props.get('region', None)
            platform = props.get('platform', None)
            system_service = props.get('systemService', None)
            address_prefixes = props.get('addressPrefixes', [])
            _iterators.append(itertools.imap(
                functools.partial(
                    _build_IP,
                    self.name,
                    azure_name=name,
                    azure_id=id_,
                    azure_region=region,
                    azure_platform=platform,
                    azure_system_service=system_service
                ),
                address_prefixes
            ))

        return itertools.chain(*_iterators)
