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
This module implements minemeld.ft.cofense.Triage, the Miner node for
Cofense Triage API.
"""

import os
import yaml
import requests
import itertools
import logging
import math
import pytz
from datetime import timedelta
from urlparse import urljoin

from . import basepoller
from .utils import interval_in_sec, EPOCH

LOG = logging.getLogger(__name__)


_TRIAGE_API_CALL_PATH = '/api/public/v1/triage_threat_indicators'
_API_USER_AGENT = 'Cofense Intelligence (minemeld)'

_RESULTS_PER_PAGE = 50


class Triage(basepoller.BasePollerFT):
    def configure(self):
        super(Triage, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)

        self.prefix = self.config.get('prefix', 'cofense')
        initial_interval = self.config.get('initial_interval', '30d')
        self.initial_interval = interval_in_sec(initial_interval)
        if self.initial_interval is None:
            LOG.error(
                '%s - wrong initial_interval format: %s',
                self.name, initial_interval
            )
            self.initial_interval = interval_in_sec('30d')

        self.source_name = self.config.get('source_name', 'cofense.triage')
        self.headers = {'user-agent': _API_USER_AGENT}
        self.confidence_map = self.config.get('confidence_map', {
            'Malicious': 100,
            'Suspicious': 50
        })

        self.verify_cert = self.config.get('verify_cert', True)
        self.api_domain = self.config.get('api_domain', None)
        self.api_account = self.config.get('api_account', None)
        self.api_token = self.config.get('api_token', None)
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

        api_domain = sconfig.get('api_domain', None)
        if api_domain is not None:
            self.api_domain = api_domain
            LOG.info('%s - API Domain set', self.name)

        api_account = sconfig.get('api_account', None)
        if api_account is not None:
            self.api_account = api_account
            LOG.info('%s - API Account set', self.name)

        api_token = sconfig.get('api_token', None)
        if api_token is not None:
            self.api_token = api_token
            LOG.info('%s - API Token set', self.name)

        verify_cert = sconfig.get('verify_cert', None)
        if verify_cert is not None:
            self.verify_cert = verify_cert
            LOG.info('%s - Verify Cert set', self.name)

    def _process_item(self, item):
        LOG.debug('{} - item: {}'.format(self.name, item))

        report_id = item.get('report_id', None)
        type_ = item.get('threat_key', None)
        indicator = item.get('threat_value', None)
        level = item.get('threat_level', None)
        if type_ is None or indicator is None:
            LOG.error('{} - entry with no value or type: {!r}'.format(self.name, item))
            return []

        if level not in self.confidence_map:
            LOG.info('{} - threat_level {} not in cofidence map: indicator ignored'.format(self.name, level))
            return []

        if type_ == 'URL':
            type_ = 'URL'
        elif type_ == 'Domain':
            type_ = 'Domain'
        elif type_ == 'MD5':
            type_ = 'md5'
        elif type_ == 'SHA256':
            type_ = 'sha256'
        else:
            LOG.error('{} - unknown indicator type: {!r}'.format(self.name, item))
            return []

        value = dict(type=type_)
        if report_id is not None:
            value['{}_report_id'.format(self.prefix)] = report_id
        if level is not None:
            value['{}_threat_level'.format(self.prefix)] = level

        value['confidence'] = self.confidence_map[level]
    
        return [[indicator, value]]

    def _build_iterator(self, now):
        if self.api_domain is None or self.api_account is None or self.api_token is None:
            raise RuntimeError('%s - credentials not set' % self.name)

        poll_start = self.last_successful_run
        if self.last_successful_run is None:
            poll_start = now - (self.initial_interval * 1000)
        dt_poll_start = EPOCH + timedelta(milliseconds=poll_start)

        LOG.debug('{} - polling start: {}'.format(self.name, dt_poll_start))
        num_of_pages = self._check_number_of_pages(dt_poll_start)
        LOG.info("{} - polling: start date: {!r} number of pages: {!r}".format(
            self.name, dt_poll_start, num_of_pages
        ))

        return self._iterate_over_pages(dt_poll_start, num_of_pages)

    def _check_number_of_pages(self, dt_poll_start):
        r = self._perform_api_call(dt_poll_start)

        total_entries = r.headers['Total']
        LOG.info('{} - polling total entries: {}'.format(self.name, total_entries))

        return int(math.ceil(int(total_entries)/float(_RESULTS_PER_PAGE)))

    def _iterate_over_pages(self, start_date, num_of_pages):
        for page_num in xrange(1, num_of_pages+1):
            r = self._perform_api_call(start_date, page_num)

            processed_data = r.json()
            for entry in processed_data:
                yield entry

    def _perform_api_call(self, start_date, page=None):
        headers = self.headers.copy()
        headers['Authorization'] = 'Token token={}:{}'.format(self.api_account, self.api_token)

        params =  {
            "per_page": _RESULTS_PER_PAGE,
            "start_date": start_date.strftime('%Y-%m-%dT%H:%M')
        }
        if page is not None:
            params['page'] = page

        request_url = urljoin(self.api_domain, _TRIAGE_API_CALL_PATH)
        r = requests.get(request_url, 
            params=params,
            verify=self.verify_cert,
            headers=headers
        )

        r.raise_for_status()

        return r

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Triage, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

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
