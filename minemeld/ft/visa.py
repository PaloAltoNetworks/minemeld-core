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

"""
This module implements minemeld.ft.visa.VTI, the Miner node for
Visa Threat Intelligence API.
"""
import logging
import requests
import re

from . import json
from utils import utc_millisec, dt_to_millisec
from datetime import datetime
from netaddr import IPNetwork, AddrFormatError

LOG = logging.getLogger(__name__)
VTI_INDICATOR_TYPES = {'Hash': 'HASH',
                       'IP': 'IP',
                       'Email': 'email-addr',
                       'URL': 'URL',
                       'FQDN': 'domain'}
VTI_VICTIM_TYPES = ('Restaurant', 'Retail', 'Hospitality and Lodging', 'QSR',
                    'B2B', 'Supermarket', 'POS Integrator', 'Financial Institution',
                    'Cinema', 'Parking', 'Pharmacy', 'Telecommunications', 'Other Retail')
SHA256_PATTERN = "[A-Fa-f0-9]{64}"
SHA1_PATTERN = "[A-Fa-f0-9]{40}"
MD5_PATTERN = "[A-Fa-f0-9]{32}"


class VTI(json.SimpleJSON):
    initial_interval = None
    indicator_type = None
    victim_type = None
    hash_patterns = {"sha256": re.compile(SHA256_PATTERN), "sha1": re.compile(SHA1_PATTERN),
                     "md5": re.compile(MD5_PATTERN)}

    def configure(self):
        super(VTI, self).configure()
        self.initial_interval = self.config.get('initial_interval', '30')
        self.indicator_type = self.config.get('indicator_type', None)
        if self.indicator_type is not None and self.indicator_type not in VTI_INDICATOR_TYPES:
            self.indicator_type = None
        self.victim_type = self.config.get('victim_type', None)
        if self.victim_type is not None and self.victim_type not in VTI_VICTIM_TYPES:
            self.victim_type = None

    def _process_item(self, item):
        if self.indicator not in item:
            LOG.debug('%s not in %s', self.indicator, item)
            return [[None, None]]

        indicator = item[self.indicator]
        if not (isinstance(indicator, str) or
                isinstance(indicator, unicode)):
            LOG.error(
                'Wrong indicator type: %s - %s',
                indicator, type(indicator)
            )
            return [[None, None]]

        indicator_type = item.get('indicatorType', None)
        if indicator_type is not None:
            indicator_type = VTI_INDICATOR_TYPES.get(indicator_type, None)
            if indicator_type == 'HASH':
                indicator_type = self._detect_sha_version(indicator)
            if indicator_type == 'IP':
                indicator_type = self._detect_ip_version(indicator)

        upload_date = item.get('uploadDate', None)
        if upload_date is None:
            upload_date = utc_millisec()
        else:
            try:
                dt = datetime.strptime(upload_date, '%Y-%m-%d')
                upload_date = dt_to_millisec(dt)
            except ValueError:
                upload_date = utc_millisec()
        if upload_date > self.last_vti_run:
            self.last_vti_run = upload_date

        fields = self.fields
        if fields is None:
            fields = item.keys()
            fields.remove(self.indicator)

        if 'indicatorType' in fields:
            fields.remove('indicatorType')
        if 'uploadDate' in fields:
            fields.remove('uploadDate')

        attributes = {'type': indicator_type, 'first_seen': upload_date, 'last_seen': upload_date}
        for field in fields:
            if field not in item:
                continue
            attributes['%s_%s' % (self.prefix, field)] = item[field]

        return [[indicator, attributes]]

    def _build_iterator(self, now):
        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        if self.headers is not None:
            rkwargs['headers'] = self.headers

        if self.username is not None and self.password is not None:
            rkwargs['auth'] = (self.username, self.password)
        else:
            raise RuntimeError('%s - credentials not set' % self.name)

        if self.client_cert_required and self.key_file is not None and self.cert_file is not None:
            rkwargs['cert'] = (self.cert_file, self.key_file)
        else:
            raise RuntimeError('%s - client certificate/key not set' % self.name)

        if self.last_successful_run is None:
            self.last_successful_run = utc_millisec() - self.initial_interval * 86400000.0
        if self.last_vti_run is None:
            self.last_vti_run = self.last_successful_run

        start_date = datetime.fromtimestamp(self.last_vti_run / 1000)
        end_date = datetime.fromtimestamp(utc_millisec() / 1000)

        payload = {'startDate': start_date.strftime('%Y-%m-%d'),
                   'endDate': end_date.strftime('%Y-%m-%d')}

        if self.indicator_type is not None:
            payload['indicatorType'] = self.indicator_type

        if self.victim_type is not None:
            payload['victimType'] = self.victim_type

        r = requests.get(
            self.url,
            params=payload,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        result = self.extractor.search(r.json())

        if result is None:
            result = []

        return result

    def _detect_ip_version(self, ip_addr):
        try:
            parsed = IPNetwork(ip_addr)
        except (AddrFormatError, ValueError):
            LOG.error('{} - Unknown IP version: {}'.format(self.name, ip_addr))
            return None

        if parsed.version == 4:
            return 'IPv4'

        if parsed.version == 6:
            return 'IPv6'

        return None

    def _detect_sha_version(self, hash_value):
        for hash_type, re_obj in self.hash_patterns.iteritems():
            if re_obj.match(hash_value) is not None:
                return hash_type
        return None

    def _saved_state_restore(self, saved_state):
        super(VTI, self)._saved_state_restore(saved_state)
        self.last_vti_run = saved_state.get('last_vti_run', None)
        LOG.info('last_vti_run from sstate: %s', self.last_vti_run)

    def _saved_state_create(self):
        sstate = super(VTI, self)._saved_state_create()
        sstate['last_vti_run'] = self.last_vti_run
        return sstate

    def _saved_state_reset(self):
        super(VTI, self)._saved_state_reset()
        self.last_vti_run = None
