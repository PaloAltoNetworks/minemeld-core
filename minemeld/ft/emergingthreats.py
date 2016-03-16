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
import requests
import os
import yaml
import datetime
import pytz
import netaddr
import netaddr.core

from . import basepoller
from .utils import dt_to_millisec

LOG = logging.getLogger(__name__)

_IP_CAT_MAPPING = {
    1: {
        'emergingthreats_iqrisk_category': 'CnC',
        'direction': 'outbound'
    },
    2: {
        'emergingthreats_iqrisk_category': 'Bot'
    },
    3: {
        'emergingthreats_iqrisk_category': 'Spam',
        'direction': 'inbound'
    },
    4: {
        'emergingthreats_iqrisk_category': 'Drop',
        'direction': 'outbound'
    },
    5: {
        'emergingthreats_iqrisk_category': 'SpywareCnC',
        'direction': 'outbound'
    },
    6: {
        'emergingthreats_iqrisk_category': 'OnlineGaming',
        'direction': 'outbound'
    },
    7: {
        'emergingthreats_iqrisk_category': 'DriveBySrc',
        'direction': 'outbound'
    },
    9: {
        'emergingthreats_iqrisk_category': 'ChatServer',
        'direction': 'outbound'
    },
    10: {
        'emergingthreats_iqrisk_category': 'TorNode'
    },
    13: {
        'emergingthreats_iqrisk_category': 'Compromised'
    },
    15: {
        'emergingthreats_iqrisk_category': 'P2P'
    },
    16: {
        'emergingthreats_iqrisk_category': 'Proxy'
    },
    17: {
        'emergingthreats_iqrisk_category': 'IPCheck',
        'direction': 'outbound'
    },
    19: {
        'emergingthreats_iqrisk_category': 'Utility'
    },
    20: {
        'emergingthreats_iqrisk_category': 'DDoSTarget'
    },
    21: {
        'emergingthreats_iqrisk_category': 'Scanner',
        'direction': 'inbound'
    },
    23: {
        'emergingthreats_iqrisk_category': 'Brute_Forcer',
        'direction': 'inbound'
    },
    24: {
        'emergingthreats_iqrisk_category': 'FakeAV',
        'direction': 'outbound'
    },
    25: {
        'emergingthreats_iqrisk_category': 'DynDNS'
    },
    26: {
        'emergingthreats_iqrisk_category': 'Undesirable'
    },
    27: {
        'emergingthreats_iqrisk_category': 'AbusedTLD'
    },
    28: {
        'emergingthreats_iqrisk_category': 'SelfSignedSSL'
    },
    29: {
        'emergingthreats_iqrisk_category': 'Blackhole',
        'direction': 'outbound'
    },
    30: {
        'emergingthreats_iqrisk_category': 'RemoteAccessService'
    },
    31: {
        'emergingthreats_iqrisk_category': 'P2PCnC'
    },
    33: {
        'emergingthreats_iqrisk_category': 'Parking',
        'direction': 'outbound'
    },
    34: {
        'emergingthreats_iqrisk_category': 'VPN'
    },
    35: {
        'emergingthreats_iqrisk_category': 'EXE_Source',
        'direction': 'outbound'
    },
    37: {
        'emergingthreats_iqrisk_category': 'Mobile_CnC',
        'direction': 'outbound'
    },
    38: {
        'emergingthreats_iqrisk_category': 'Mobile_Spyware_CnC',
        'direction': 'outbound'
    },
    39: {
        'emergingthreats_iqrisk_category': 'Skype_SuperNode'
    },
    40: {
        'emergingthreats_iqrisk_category': 'Bitcoin_Related'
    },
    41: {
        'emergingthreats_iqrisk_category': 'DDoSAttacker',
        'direction': 'inbound'
    },
    '*': {
    }
}

_DOMAIN_CAT_MAPPING = {
    1: {
        'emergingthreats_iqrisk_category': 'CnC'
    },
    2: {
        'emergingthreats_iqrisk_category': 'Bot'
    },
    3: {
        'emergingthreats_iqrisk_category': 'Spam'
    },
    4: {
        'emergingthreats_iqrisk_category': 'Drop'
    },
    5: {
        'emergingthreats_iqrisk_category': 'SpywareCnC'
    },
    6: {
        'emergingthreats_iqrisk_category': 'OnlineGaming'
    },
    7: {
        'emergingthreats_iqrisk_category': 'DriveBySrc'
    },
    9: {
        'emergingthreats_iqrisk_category': 'ChatServer'
    },
    10: {
        'emergingthreats_iqrisk_category': 'TorNode'
    },
    13: {
        'emergingthreats_iqrisk_category': 'Compromised'
    },
    15: {
        'emergingthreats_iqrisk_category': 'P2P'
    },
    16: {
        'emergingthreats_iqrisk_category': 'Proxy'
    },
    17: {
        'emergingthreats_iqrisk_category': 'IPCheck'
    },
    19: {
        'emergingthreats_iqrisk_category': 'Utility'
    },
    20: {
        'emergingthreats_iqrisk_category': 'DDoSTarget'
    },
    21: {
        'emergingthreats_iqrisk_category': 'Scanner'
    },
    23: {
        'emergingthreats_iqrisk_category': 'Brute_Forcer'
    },
    24: {
        'emergingthreats_iqrisk_category': 'FakeAV'
    },
    25: {
        'emergingthreats_iqrisk_category': 'DynDNS'
    },
    26: {
        'emergingthreats_iqrisk_category': 'Undesirable'
    },
    27: {
        'emergingthreats_iqrisk_category': 'AbusedTLD'
    },
    28: {
        'emergingthreats_iqrisk_category': 'SelfSignedSSL'
    },
    29: {
        'emergingthreats_iqrisk_category': 'Blackhole'
    },
    30: {
        'emergingthreats_iqrisk_category': 'RemoteAccessService'
    },
    31: {
        'emergingthreats_iqrisk_category': 'P2PCnC'
    },
    33: {
        'emergingthreats_iqrisk_category': 'Parking'
    },
    34: {
        'emergingthreats_iqrisk_category': 'VPN'
    },
    35: {
        'emergingthreats_iqrisk_category': 'EXE_Source'
    },
    37: {
        'emergingthreats_iqrisk_category': 'Mobile_CnC'
    },
    38: {
        'emergingthreats_iqrisk_category': 'Mobile_Spyware_CnC'
    },
    39: {
        'emergingthreats_iqrisk_category': 'Skype_SuperNode'
    },
    40: {
        'emergingthreats_iqrisk_category': 'Bitcoin_Related'
    },
    41: {
        'emergingthreats_iqrisk_category': 'DDoSAttacker'
    },
    '*': {
    }
}


class IQRisk(basepoller.BasePollerFT):
    _FILE = None

    def configure(self):
        super(IQRisk, self).configure()

        self.source_name = 'emergingthreats.iqrisk'

        self.auth_code = None
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

        self.auth_code = sconfig.get('auth_code', None)
        if self.token is not None:
            LOG.info('%s - authorization code set', self.name)

        monitored_categories = sconfig.get('monitored_categories', [])
        if type(monitored_categories) != list:
            LOG.error('%s - wrong monitored_categories format, should '
                      'be a list of ints', self.name)
            self.monitored_categories = []
        else:
            self.monitored_categories = monitored_categories

    def _process_item(self, row):
        indicator, category, score, first_seen, last_seen, ports = \
            row.split(',')

        if indicator == 'ip' or indicator == 'domain':
            return []

        try:
            category = int(category)
        except ValueError:
            LOG.error('%s - wrong category format, ignored', self.name)
            return []

        if category not in self.monitored_categories:
            return []

        try:
            score = int(score)
            if score < 0 or score > 127:
                raise ValueError('wrong score format')
        except ValueError:
            LOG.error('%s - wrong score format, ignored', self.name)
            return []

        confidence = (score*100)/127

        try:
            fs = datetime.datetime.strptime(first_seen, '%Y-%M-%d')
            fs.replace(tzinfo=pytz.UTC)
            fs = dt_to_millisec(fs)
        except:
            LOG.error('%s - wrong first_seen format, ignored', self.name)
            return []

        try:
            ls = datetime.datetime.strptime(last_seen, '%Y-%M-%d')
            ls.replace(tzinfo=pytz.UTC)
            ls = dt_to_millisec(ls)
        except:
            LOG.error('%s - wrong first_seen format, ignored', self.name)
            return []

        ports = ports.split()

        value = {
            'confidence': confidence,
            'last_seen': ls,
            'first_seen': fs,
            'emergingthreats_iqrisk_ports': ports,
            'emergingthreats_iqrisk_category': category
        }

        return [[indicator, value]]

    def _build_iterator(self, now):
        if self.auth_code is None or len(self.monitored_categories) == 0:
            LOG.info('%s - authorization code not set, '
                     'poll not performed', self.name)
            return []

        url = ('https://rules.emergingthreats.net/' +
               self.auth_code +
               '/reputation/' +
               self._FILE)

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        result = r.iter_lines()

        return result

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(IQRisk, self).hup(source=source)


class IQRiskIP(basepoller.BasePollerFT):
    _FILE = 'detailed-iprepdata.txt'

    def _process_item(self, row):
        ipairs = super(IQRiskIP, self)._process_item(row)

        result = []

        for i, v in ipairs:
            try:
                parsed_ip = netaddr.IPAddress(i)
            except:
                LOG.error('%s - invalid IP %s, ignored', self.name, i)
                continue

            if parsed_ip.version == 4:
                v['type'] = 'IPv4'
            elif parsed_ip.version == 6:
                v['type'] = 'IPv6'
            else:
                LOG.error('%s - unknown IP version %s, ignored', self.name, i)
                continue

            if v['emergingthreats_iqrisk_category'] in _IP_CAT_MAPPING:
                v.update(
                    _IP_CAT_MAPPING[v['emergingthreats_iqrisk_category']]
                )
            else:
                v.update(_IP_CAT_MAPPING['*'])

            result.append([i, v])

        return result


class IQRiskDomain(basepoller.BasePollerFT):
    _FILE = 'detailed-domainrepdata.txt'

    def _process_item(self, row):
        ipairs = super(IQRiskIP, self)._process_item(row)

        result = []

        for i, v in ipairs:
            v['type'] = 'domain'

            if v['emergingthreats_iqrisk_category'] in _DOMAIN_CAT_MAPPING:
                v.update(
                    _DOMAIN_CAT_MAPPING[v['emergingthreats_iqrisk_category']]
                )
            else:
                v.update(_DOMAIN_CAT_MAPPING['*'])

            result.append([i, v])

        return result
