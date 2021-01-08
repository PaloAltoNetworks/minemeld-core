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

from minemeld.ft import csv                      # changed from . to minemeld.ft

LOG = logging.getLogger(__name__)

class IPRiskList(csv.CSVFT):
    def configure(self):
        super(IPRiskList, self).configure()

        self.source_name = 'recordedfuture.iprisklist'
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
                result['confidence'] = (int(risk) * self.confidence) / 100
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
            'https://app.recordedfuture.com/live/sc/entity/ip:' + indicator

        return [[indicator, result]]

    def _build_iterator(self, now):
        if self.token is None:
            raise RuntimeError(
                '%s - token not set, poll not performed' % self.name
            )

        return super(IPRiskList, self)._build_iterator(now)

    def _build_request(self, now):
        params = {'output_format': 'csv/splunk'}
        headers = {'X-RFToken': self.token}
        r = requests.Request(
            'GET',
            'https://api.recordedfuture.com/v2/ip/risklist',
            headers=headers, params=params,

        )

        return r.prepare()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(IPRiskList, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        csv.CSVFT.gc(name, config=config)

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



class DomainRiskList(csv.CSVFT):
    def configure(self):
        super(DomainRiskList, self).configure()

        self.source_name = 'recordedfuture.domainriskList'
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

        risk = row.get('Risk', '')
        if risk != '':
            try:
                result['recordedfuture_risk'] = int(risk)
                result['confidence'] = (int(risk) * self.confidence) / 100
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
            'https://app.recordedfuture.com/live/sc/entity/idn:' + indicator

        return [[indicator, result]]

    def _build_iterator(self, now):
        if self.token is None:
            raise RuntimeError(
                '%s - token not set, poll not performed' % self.name
            )

        return super(DomainRiskList, self)._build_iterator(now)

    def _build_request(self, now):
        params = {'output_format': 'csv/splunk'}
        headers = {'X-RFToken': self.token}
        r = requests.Request(
            'GET',
            'https://api.recordedfuture.com/v2/domain/risklist',
            headers=headers, params=params,

        )

        return r.prepare()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(DomainRiskList, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        csv.CSVFT.gc(name, config=config)

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



class MasterRiskList(csv.CSVFT):
    def configure(self):
        super(MasterRiskList, self).configure()
        self.source_name = 'recordedfuture.masterrisklist'
        self.confidence = self.config.get('confidence', 80)

        self.entity = None                                                       ## entity added
        self.token = None
        self.path = None                                                         ## fusion/ risklist path added
        self.api = None                                                          ## api type added

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

        self.path = sconfig.get('path', None)
        if self.path is not None:
            LOG.info('%s - path set', self.name)

        self.entity = sconfig.get('entity', None)
        if self.entity is not None:
            LOG.info('%s - entity set', self.name)

        self.api = sconfig.get('api', None)
        if self.api is not None:
            LOG.info('%s - API set', self.name)

    def _process_item(self, row):

        row.pop(None, None)

        result = {}

        indicator = row.get('Name', '')
        if indicator == '':
            return []

        if self.entity == 'ip':                                                     ## Only for IP type entity
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
            result['recordedfuture_entityurl'] = \
                'https://app.recordedfuture.com/live/sc/entity/ip:' + indicator
        elif self.entity == 'domain':
            result['type'] = 'domain'
            result['recordedfuture_entityurl'] = \
                'https://app.recordedfuture.com/live/sc/entity/idn:' + indicator
        elif self.entity == 'url':
            result['type'] = 'URL'
            result['recordedfuture_entityurl'] = \
                'https://app.recordedfuture.com/live/sc/entity/url:' + indicator
        elif self.entity == 'hash':                                                   ## Only for hash type entity
            algo = row.get('Algorithm', '')
            if algo != '':
                result['recordedfuture_algorithm'] = algo
                result['type'] =
            result['recordedfuture_entityurl'] = \
                'https://app.recordedfuture.com/live/sc/entity/hash:' + indicator
        risk = row.get('Risk', '')
        if risk != '':
            try:
                result['recordedfuture_risk'] = int(risk)
                result['confidence'] = (int(risk) * self.confidence) / 100
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

        return [[indicator, result]]

    @staticmethod
    def _check_hash_type(entity):
        if len(entity) == 64:
            return 'sha256'
        elif len(entity) == 40:
            return 'sha1'
        elif len(entity) == 32:
            return 'md5'
        else:
            return ''

    def _build_iterator(self, now):
        if self.token is None:
            raise RuntimeError(
                '%s - token not set, poll not performed' % self.name
            )

        if self.entity is None:
            raise RuntimeError(
                '%s - entity not set, poll not performed' % self.name
            )

        if self.api is None:
            raise RuntimeError(
                '%s - api not set, poll not performed' % self.name
            )

        if self.api == 'fusion':
            if self.entity == 'ip':
                if self.path != None:
                    if self.path.find('ip') == -1:
                        raise RuntimeError(
                            '%s - wrong file path for the given miner' % self.name
                        )

            if self.entity == 'url':
                if self.path != None:
                    if self.path.find('url') == -1:
                        raise RuntimeError(
                            '%s - wrong file path for the given miner' % self.name
                        )

            if self.entity == 'hash':
                if self.path != None:
                    if self.path.find('hash') == -1:
                        raise RuntimeError(
                            '%s - wrong file path for the given miner' % self.name
                        )

            if self.entity == 'domain':
                if self.path != None:
                    if self.path.find('domain') == -1:
                        raise RuntimeError(
                            '%s - wrong file path for the given miner' % self.name
                        )

        return super(MasterRiskList, self)._build_iterator(now)

    def _build_request(self, now):
        if self.api == 'connectApi':
            if self.path is None:
                url = 'https://api.recordedfuture.com/v2/' + str(self.entity) + '/risklist'
            else:
                url = 'https://api.recordedfuture.com/v2/' + str(self.entity) + '/risklist?list=' + self.path

            params = {'output_format': 'csv/splunk'}
            headers = {'X-RFToken': self.token, 'X-RF-User-Agent': 'Minemeld v1.2',
                       'content-type': 'application/json'}

            r = requests.Request('GET', url, headers=headers, params=params)

            return r.prepare()

        if self.api == 'fusion':
            if self.path is None:
                url = '/public/risklists/default_' + str(self.entity) + '_risklist.csv'
            else:
                url = self.path

            url = url.replace('/', '%2F')
            params = {'output_format': 'csv/splunk'}
            headers = {'X-RFToken': self.token, 'X-RF-User-Agent': 'Minemeld v1.2', 'content-type': 'application/json'}
            re = requests.Request('GET', 'https://api.recordedfuture.com/v2/fusion/files/?path=' + url, headers=headers, params=params)

            return re.prepare()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(MasterRiskList, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        csvhelper.CSVFT.gc(name, config=config)

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
