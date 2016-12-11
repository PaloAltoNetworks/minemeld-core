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
import shutil
import yaml
import datetime
import pytz
import netaddr
import netaddr.core

from minemeld import __version__ as MM_VERSION

from . import basepoller
from . import table
from .utils import dt_to_millisec

LOG = logging.getLogger(__name__)

_CATNAME = [
    "CnC",
    "Bot",
    "Spam",
    "Drop",
    "SpywareCnC",
    "OnlineGaming",
    "DriveBySrc",
    "ChatServer",
    "TorNode",
    "Compromised",
    "P2P",
    "Proxy",
    "IPCheck",
    "Utility",
    "DDoSTarget",
    "Scanner",
    "Brute_Forcer",
    "FakeAV",
    "DynDNS",
    "Undesirable",
    "AbusedTLD",
    "SelfSignedSSL",
    "Blackhole",
    "RemoteAccessService",
    "P2PCnC",
    "Parking",
    "VPN",
    "EXE_Source",
    "Mobile_CnC",
    "Mobile_Spyware_CnC",
    "Skype_SuperNode",
    "Bitcoin_Related",
    "DDoSAttacker"
]


class ETIntelligence(basepoller.BasePollerFT):
    _FILE = None

    def __init__(self, name, chassis, config):
        self.ttable = None

        super(ETIntelligence, self).__init__(name, chassis, config)

    def configure(self):
        super(ETIntelligence, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)
        self.score_threshold = self.config.get('score_threshold', 50)

        self.source_name = 'proofpoint.etintelligence'

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
        if self.auth_code is not None:
            LOG.info('%s - authorization code set', self.name)

        monitored_categories = sconfig.get('monitored_categories', [])
        if type(monitored_categories) != list:
            LOG.error('%s - wrong monitored_categories format, should '
                      'be a list of ints', self.name)
            self.monitored_categories = []
        else:
            self.monitored_categories = monitored_categories

    def _process_row(self, row):
        indicator, category, score, first_seen, last_seen, ports = \
            row.split(',')

        if indicator == 'ip' or indicator == 'domain':
            return None

        try:
            category = int(category)
        except ValueError:
            LOG.error('%s - wrong category format, ignored', self.name)
            return None

        if category not in self.monitored_categories:
            return None

        if category > 0 and category <= len(_CATNAME):
            category_name = _CATNAME[category-1]
        else:
            category_name = '%d' % category

        try:
            score = int(score)
            if score < 0 or score > 127:
                raise ValueError('wrong score format')
        except ValueError:
            LOG.error('%s - wrong score format, ignored', self.name)
            return None

        if score <= self.score_threshold:
            LOG.debug('%s - score below threshold, ignored', self.name)
            return None

        try:
            fs = datetime.datetime.strptime(first_seen, '%Y-%m-%d')
            fs = fs.replace(tzinfo=pytz.UTC)
            fs = dt_to_millisec(fs)
        except:
            LOG.exception('%s - wrong first_seen format, ignored', self.name)
            return None

        try:
            ls = datetime.datetime.strptime(last_seen, '%Y-%m-%d')
            ls = ls.replace(tzinfo=pytz.UTC)
            ls = dt_to_millisec(ls)
        except:
            LOG.exception('%s - wrong last_seen format, ignored', self.name)
            return None

        ports = ports.split()

        value = {
            'proofpoint_etintelligence_max_score': score,
            'proofpoint_etintelligence_last_seen': ls,
            'proofpoint_etintelligence_first_seen': fs,
            'proofpoint_etintelligence_ports': ports,
            'proofpoint_etintelligence_categories': [category_name]
        }

        return [indicator, value]

    def _process_item(self, item):
        return [item]

    def _build_iterator(self, now):
        if self.auth_code is None or len(self.monitored_categories) == 0:
            raise RuntimeError(
                '%s - authorization code or categories not set, poll not performed' % self.name
            )

        LOG.info('%s - categories: %s', self.name, self.monitored_categories)

        if self.ttable is not None:
            self.ttable.close()
            self.ttable = None

        self.ttable = table.Table(self.name+'_temp', truncate=True)

        url = ('https://rules.emergingthreats.net/' +
               self.auth_code +
               '/reputation/' +
               self._FILE)

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            headers={
                'User-Agent': 'MineMeld/%s' % MM_VERSION
            }
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

        for line in r.iter_lines():
            p = self._process_row(line)
            if p is None:
                continue

            i, nv = p

            ov = self.ttable.get(i)
            if ov is None:
                self.ttable.put(i, nv)
            else:
                if (ov['proofpoint_etintelligence_max_score'] <
                        nv['proofpoint_etintelligence_max_score']):
                    ov['proofpoint_etintelligence_max_score'] = \
                        nv['proofpoint_etintelligence_max_score']
                if (ov['proofpoint_etintelligence_first_seen'] >
                        nv['proofpoint_etintelligence_first_seen']):
                    ov['proofpoint_etintelligence_first_seen'] = \
                        nv['proofpoint_etintelligence_first_seen']
                if (ov['proofpoint_etintelligence_last_seen'] >
                        nv['proofpoint_etintelligence_last_seen']):
                    ov['proofpoint_etintelligence_last_seen'] = \
                        nv['proofpoint_etintelligence_last_seen']
                ov['proofpoint_etintelligence_ports'] += \
                    nv['proofpoint_etintelligence_ports']
                ov['proofpoint_etintelligence_categories'] += \
                    nv['proofpoint_etintelligence_categories']
                self.ttable.put(i, ov)

        return self.ttable.query(include_value=True)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(ETIntelligence, self).hup(source=source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

        shutil.rmtree('{}_temp'.format(name), ignore_errors=True)
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


class EmergingThreatsIP(ETIntelligence):
    _FILE = 'detailed-iprepdata.txt'

    def _process_item(self, row):
        ipairs = super(EmergingThreatsIP, self)._process_item(row)

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

            result.append([i, v])

        return result


class EmergingThreatsDomain(ETIntelligence):
    _FILE = 'detailed-domainrepdata.txt'

    def _process_item(self, row):
        ipairs = super(EmergingThreatsDomain, self)._process_item(row)

        result = []

        for i, v in ipairs:
            v['type'] = 'domain'

            result.append([i, v])

        return result
