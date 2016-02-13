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
import ujson
import yaml
import netaddr
import netaddr.core

from . import csv

LOG = logging.getLogger(__name__)


class ThreatFeed(csv.CSVFT):
    def configure(self):
        super(ThreatFeed, self).configure()

        self.source_name = 'recordedfuture.threatfeed'
        self.confidence = self.config.get('confidence', 80)

        self.token = None
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

        self.token = sconfig.get('token', None)
        if self.token is not None:
            LOG.info('%s - token set', self.name)

    def _process_item(self, row):
        row.pop(None, None)  # I love this

        result = {}

        indicator = row.get('Name', '')
        if indicator == '':
            return []

        try:
            if '/' in indicator:
                ip = netaddr.IPNetwork(indicator)
            else:
                ip = netaddr.IPAddress(indicator)
        except netaddr.core.AddrFormatError:
            LOG.exception("%s - failed parsing indicator", self.name)
            return []

        if ip.version == 4:
            result['type'] = 'IPv4'
        elif ip.version == 6:
            result['type'] = 'IPv6'
        else:
            LOG.debug("%s - unknown IP version %d", self.name, ip.version)
            return []

        risk = row.get('Risk', '')
        if risk != '':
            try:
                result['recordedfuture_risk'] = int(risk)
                result['confidence'] = (int(risk)*self.confidence)/100
            except:
                LOG.debug("%s - invalid risk string: %s",
                          self.name, risk)

        riskstring = row.get('RiskString', '')
        if riskstring != '':
            result['recordedfuture_riskstring'] = riskstring

        edetails = row.get('EvidenceDetails', '')
        if edetails != '':
            try:
                edetails = ujson.loads(edetails)
            except:
                LOG.debug("%s - invalid JSON string in EvidenceDetails: %s",
                          self.name, edetails)
            else:
                edetails = edetails.get('EvidenceDetails', [])
                result['recordedfuture_evidencedetails'] = \
                    [ed['Rule'] for ed in edetails]

        result['recordedfuture_entityurl'] = \
            'https://www.recordedfuture.com/live/sc/entity/ip:'+indicator

        return [[indicator, result]]

    def _build_iterator(self, now):
        if self.token is None:
            LOG.info('%s - token not set, poll not performed', self.name)
            return []

        return super(ThreatFeed, self)._build_iterator(now)

    def _build_request(self, now):
        params = {
            'version': '1.0',
            'output_format': 'csv/splunk',
            'token': self.token
        }

        r = requests.Request(
            'GET',
            'https://api.recordedfuture.com/query/list/HighRisk/IpAddress',
            params=params
        )

        return r.prepare()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(ThreatFeed, self).hup(source)
