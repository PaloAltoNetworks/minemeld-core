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
This module implements minemeld.ft.anomali.Intelligence, the Miner node for
Anomali Intelligence API.
"""

import os
import yaml
import netaddr
import pytz
import datetime
import requests
import logging

from . import basepoller
from .utils import interval_in_sec, dt_to_millisec

LOG = logging.getLogger(__name__)


_API_BASE = 'https://api.threatstream.com'
_API_ENDPOINT = '/api/v2/intelligence/'


class Intelligence(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        super(Intelligence, self).__init__(name, chassis, config)

        self.last_run = None

    def configure(self):
        super(Intelligence, self).configure()

        self.url = self.config.get('url', None)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.prefix = self.config.get('prefix', 'anomali')
        self.fields = self.config.get('fields', None)
        self.query = self.config.get('query', None)
        initial_interval = self.config.get('initial_interval', '3600')
        self.initial_interval = interval_in_sec(initial_interval)
        if self.initial_interval is None:
            LOG.error(
                '%s - wrong initial_interval format: %s',
                self.name, initial_interval
            )
            self.initial_interval = 3600

        self.api_key = None
        self.username = None
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
            LOG.info('%s - API Key set', self.name)

        self.username = sconfig.get('username', None)
        if self.username is not None:
            LOG.info('%s - username set', self.name)

    def _calc_age_out(self, indicator, attributes):
        etsattribute = self.prefix+'_expiration_ts'
        if etsattribute in attributes:
            original_ets = attributes[etsattribute]
            LOG.debug('%s - original_ets: %s', self.name, original_ets)
            original_ets = original_ets[:19]

            ets = datetime.datetime.strptime(
                original_ets,
                '%Y-%m-%dT%H:%M:%S'
            ).replace(tzinfo=pytz.UTC)
            LOG.debug('%s - expiration_ts set for %s', self.name, indicator)
            return dt_to_millisec(ets)

        return super(Intelligence, self)._calc_age_out(indicator, attributes)

    def _process_item(self, item):
        if 'value' not in item:
            LOG.debug('%s - value not in %s', self.name, item)
            return [[None, None]]

        indicator = item['value']
        if not (isinstance(indicator, str) or
                isinstance(indicator, unicode)):
            LOG.error(
                '%s - Wrong indicator type: %s - %s',
                self.name, indicator, type(indicator)
            )
            return [[None, None]]

        fields = self.fields
        if fields is None:
            fields = item.keys()
            fields.remove('value')

        attributes = {}
        for field in fields:
            if field not in item:
                continue
            attributes['%s_%s' % (self.prefix, field)] = item[field]

        if 'confidence' in item:
            attributes['confidence'] = item['confidence']

        if item['type'] == 'domain':
            attributes['type'] = 'domain'

        elif item['type'] == 'url':
            attributes['type'] = 'URL'

        elif item['type'] == 'ip':
            try:
                n = netaddr.IPNetwork(indicator)
            except:
                LOG.error('%s - Invald IP address: %s', self.name, indicator)
                return [[None, None]]

            if n.version == 4:
                attributes['type'] = 'IPv4'
            elif n.version == 6:
                attributes['type'] = 'IPv6'
            else:
                LOG.error('%s - Unknown ip version: %d', self.name, n.version)
                return [[None, None]]

        else:
            LOG.info(
                '%s - indicator type %s not supported',
                self.name,
                item['type']
            )
            return [[None, None]]

        return [[indicator, attributes]]

    def _build_iterator(self, now):
        if self.api_key is None or self.username is None:
            raise RuntimeError('%s - credentials not set' % self.name)

        if self.last_run is None:
            now = datetime.datetime.fromtimestamp(now/1000.0, pytz.UTC)
            dtinterval = datetime.timedelta(seconds=self.initial_interval)
            origin = now - dtinterval
        else:
            origin = datetime.datetime.fromtimestamp(
                self.last_run/1000.0,
                pytz.UTC
            )

        q = '(modified_ts>=%s)' % origin.strftime('%Y-%m-%dT%H:%M:%S')
        if self.query:
            q = '(%s AND %s)' % (q, self.query)

        params = dict(
            username=self.username,
            api_key=self.api_key,
            limit=100,
            q=q
        )
        LOG.debug('%s - query params: %s', self.name, params)

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            params=params
        )

        r = requests.get(
            _API_BASE+_API_ENDPOINT,
            **rkwargs
        )

        while True:
            try:
                r.raise_for_status()
            except:
                LOG.error(
                    '%s - exception in request: %s %s',
                    self.name, r.status_code, r.content
                )
                raise

            cjson = r.json()
            if 'objects' not in cjson:
                LOG.error('%s - no objects in response', self.name)
                return

            objects = cjson['objects']
            for o in objects:
                yield o

            if 'meta' not in cjson:
                return

            if 'next' not in cjson['meta']:
                return

            next_url = cjson['meta']['next']
            if next_url is None:
                return

            LOG.debug('%s - requesting next items', self.name)
            rkwargs.pop('params', None)
            r = requests.get(
                _API_BASE+cjson['meta']['next'],
                **rkwargs
            )

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Intelligence, self).hup(source)
