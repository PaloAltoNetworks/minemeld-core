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
import requests
import os
import yaml
import itertools
import csv
import gevent

from . import basepoller
from . import table
from .utils import interval_in_sec

LOG = logging.getLogger(__name__)


class DTIAPI(basepoller.BasePollerFT):
    _AGE_OUT_BASES = ['first_seen', 'last_seen', 'tmt_last_sample_timestamp']
    _DEFAULT_AGE_OUT_BASE = 'tmt_last_sample_timestamp'

    def __init__(self, name, chassis, config):
        self.ttable = None

        super(DTIAPI, self).__init__(name, chassis, config)

    def configure(self):
        super(DTIAPI, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 120)
        self.verify_cert = self.config.get('verify_cert', True)

        self.dialect = {
            'delimiter': self.config.get('delimiter', ','),
            'doublequote': self.config.get('doublequote', True),
            'escapechar': self.config.get('escapechar', None),
            'quotechar': self.config.get('quotechar', '"'),
            'skipinitialspace': self.config.get('skipinitialspace', False)
        }

        self.include_suspicious = self.config.get('include_suspicious', True)
        initial_interval = self.config.get('initial_interval', '2d')
        self.initial_interval = interval_in_sec(initial_interval)
        if initial_interval is None:
            LOG.error(
                '%s - wrong initial_interval format: %s',
                self.name, initial_interval
            )
            self.initial_interval = 3600

        self.source_name = 'themediatrust.dti'

        self.api_key = None
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

        self.api_key = sconfig.get('api_key', None)
        if self.api_key is not None:
            LOG.info('%s - authorization code set', self.name)

    def _process_row(self, row):
        ip = row.pop('ip_addres', None)
        if ip == '0.0.0.0':
            ip = None

        domain = row.pop('host_name', None)

        value = {}
        for k, v in row.iteritems():
            if k == 'last_sample_timestamp':
                value['tmt_last_sample_timestamp'] = int(v)*1000
                continue

            key = k
            if not k.startswith('tmt'):
                key = 'tmt_%s' % k

            value[key] = [v]

        return ip, domain, value

    def _process_item(self, item):
        type_, indicator = item[0].split(':', 1)

        value = {}
        for k, v in item[1].iteritems():
            value[k] = v
        value['type'] = type_

        return [[indicator, value]]

    def _tmerge(self, indicator, value):
        ov = self.ttable.get(indicator)

        if ov is None:
            self.ttable.put(indicator, value)
            return

        for k, v in value.iteritems():
            if k == 'tmt_last_sample_timestamp':
                if v > ov[k]:  # confusing, this is just for PEP8 sake
                    ov[k] = v
                continue

            if v[0] not in ov[k]:
                ov[k].append(v)

        self.ttable.put(indicator, ov)

    def _build_iterator(self, now):
        if self.api_key is None:
            raise RuntimeError('%s - api_key not set' % self.name)

        if self.ttable is not None:
            self.ttable.close()
            self.ttable = None

        self.ttable = table.Table(self.name+'_temp', truncate=True)

        last_fetch = self.last_run
        if last_fetch is None:
            last_fetch = int(now/1000) - self.initial_interval

        params = dict(
            key=self.api_key,
            action='fjord_base',
            include_suspicious=(1 if self.include_suspicious else 0),
            last_fetch=last_fetch
        )

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            params=params
        )

        r = requests.get(
            'https://www.themediatrust.com/api',
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        response = itertools.ifilter(
            lambda x: not x.startswith('got commandoptions'),
            r.raw
        )

        csvreader = csv.DictReader(
            response,
            **self.dialect
        )

        for row in csvreader:
            gevent.sleep(0)
            ip, domain, value = self._process_row(row)
            if ip is None and domain is None:
                continue

            if ip is not None:
                self._tmerge('IPv4:%s' % ip, value)

            if domain is not None:
                self._tmerge('domain:%s' % domain, value)

        return self.ttable.query(include_value=True)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(DTIAPI, self).hup(source=source)
