#  Copyright 2016 Palo Alto Networks, Inc
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
import collections
import netaddr
import minemeld.packages.gdns.dig

from . import basepoller

LOG = logging.getLogger(__name__)

_GOOGLE_DNS_SERVER = '8.8.8.8'


class GoogleSPF(basepoller.BasePollerFT):
    def configure(self):
        super(GoogleSPF, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.tries = self.config.get('tries', 3)
        self.verify_cert = self.config.get('verify_cert', True)
        self.udp_port = self.config.get('udp_port', None)
        self.tcp_port = self.config.get('tcp_port', 53)
        self.source_name = self.config.get('source_name', self.SOURCE_NAME)

    def _process_item(self, item):
        indicator = item.pop('indicator', None)
        return [[indicator, item]]

    def _resolve_spf(self, dig, name):
        LOG.debug('%s - Resolving SPF for %s', self.name, name)
        reply = dig.query(name, dig.NS_C_IN, dig.NS_T_TXT)
        spf = dig.parse_txt_reply(reply)
        if len(spf) > 1:
            raise RuntimeError(
                '%s - TXT record for %s has more than 1 block' %
                (self.name, name)
            )

        spf = spf[0]
        result = collections.defaultdict(list)
        spftoks = spf.split()

        if spftoks[0] != 'v=spf1':
            raise RuntimeError(
                '%s - Wrong SPF signature in SPF for %s' %
                (self.name, name)
            )

        for t in spftoks[1:]:
            toks = t.split(':', 1)
            if toks[0] in ['include', 'ip4', 'ip6']:
                result[toks[0]].append(toks[1])

        return result

    def _build_IPv4(self, netblock, ipnetwork):
        try:
            n = netaddr.IPNetwork(ipnetwork)
            if n.version != 4:
                raise ValueError('invalid ip4 network: %d' % n.version)
        except:
            LOG.exception('%s - Invalid ip4 network: %s', self.name, ipnetwork)
            return {}

        item = {
            'indicator': ipnetwork,
            'type': 'IPv4',
            'confidence': 100,
            self.BLOCK_ATTRIBUTE: netblock,
            'sources': [self.SOURCE_NAME]
        }
        return item

    def _build_IPv6(self, netblock, ipnetwork):
        try:
            n = netaddr.IPNetwork(ipnetwork)
            if n.version != 6:
                raise ValueError('invalid ip6 network: %d' % n.version)
        except:
            LOG.exception('%s - Invalid ip6 network: %s', self.name, ipnetwork)
            return {}

        item = {
            'indicator': ipnetwork,
            'type': 'IPv6',
            'confidence': 100,
            self.BLOCK_ATTRIBUTE: netblock,
            'sources': [self.SOURCE_NAME]
        }
        return item

    def _build_iterator(self, now):
        _iterators = []

        dig = minemeld.packages.gdns.dig.Dig(
            servers=[_GOOGLE_DNS_SERVER],
            udp_port=self.udp_port,
            tcp_port=self.tcp_port,
            tries=self.tries,
            timeout=self.polling_timeout*1000
        )

        mainspf = self._resolve_spf(dig, self.ROOT_SPF)
        if 'include' not in mainspf:
            LOG.error(
                '%s - No includes in SPF' % self.name
            )
            return []

        for idomain in mainspf['include']:
            ispf = self._resolve_spf(dig, idomain)

            _iterators.append(itertools.imap(
                functools.partial(self._build_IPv4, idomain),
                ispf.get('ip4', [])
            ))
            _iterators.append(itertools.imap(
                functools.partial(self._build_IPv6, idomain),
                ispf.get('ip6', [])
            ))

        return itertools.chain(*_iterators)


class GoogleNetBlocks(GoogleSPF):
    ROOT_SPF = '_spf.google.com'
    SOURCE_NAME = 'google.netblocks'
    BLOCK_ATTRIBUTE = 'google_netblock'


class GoogleCloudNetBlocks(GoogleSPF):
    ROOT_SPF = '_cloud-netblocks.googleusercontent.com'
    SOURCE_NAME = 'google.cloudnetblocks'
    BLOCK_ATTRIBUTE = 'google_cloudnetblock'
