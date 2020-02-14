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
import os

import arrow
import ujson
import yaml

import cifsdk.client
import cifsdk.constants

from . import basepoller

LOG = logging.getLogger(__name__)


class Feed(basepoller.BasePollerFT):
    def configure(self):
        super(Feed, self).configure()

        self.token = None

        self.remote = self.config.get('remote', None)
        self.verify_cert = self.config.get('verify_cert', True)
        self.filters = self.config.get('filters', None)
        self.initial_days = self.config.get('initial_days', 7)
        self.prefix = self.config.get('prefix', 'cif')

        self.fields = self.config.get('fields', cifsdk.constants.FIELDS)

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

        self.remote = sconfig.get('remote', self.remote)
        self.verify_cert = sconfig.get('verify_cert', self.verify_cert)
        filters = sconfig.get('filters', self.filters)
        if filters is not None:
            if self.filters is not None:
                self.filters.update(filters)
            else:
                self.filters = filters

    def _process_item(self, item):
        indicator = item.get('observable', None)
        if indicator is None:
            LOG.error('%s - no observable in item', self.name)
            return [[None, None]]

        otype = item.get('otype', None)
        if otype is None:
            LOG.error('%s - no otype in item', self.name)
            return [[None, None]]

        if otype == 'ipv4':
            type_ = 'IPv4'
        elif otype == 'ipv6':
            type_ = 'IPv6'
        elif otype == 'fqdn':
            type_ = 'domain'
        elif otype == 'url':
            type_ = 'URL'
        else:
            LOG.error('%s - unahndled otype %s', self.name, otype)
            return [[None, None]]

        attributes = {
            'type': type_
        }
        for field in self.fields:
            if field in ['observable', 'otype', 'confidence']:
                continue

            if field not in item:
                continue
            attributes['%s_%s' % (self.prefix, field)] = item[field]

        if 'confidence' in item:
            attributes['confidence'] = item['confidence']

        LOG.debug('%s - %s: %s', self.name, indicator, attributes)

        return [[indicator, attributes]]

    def _build_iterator(self, now):
        if self.token is None or self.remote is None or self.filters is None:
            LOG.info(
                '%s - token, remote or filters not set, poll not performed',
                self.name
            )
            raise RuntimeError(
                '%s - token, remote or filters not set, poll not performed' % self.name
            )

        filters = {}
        filters.update(self.filters)

        days = filters.pop('days', self.initial_days)
        now = arrow.get(now/1000.0)

        filters['reporttimeend'] = '{0}Z'.format(
            now.format('YYYY-MM-DDTHH:mm:ss')
        )
        if self.last_successful_run is None:
            filters['reporttime'] = '{0}Z'.format(
                now.shift(days=-days).format('YYYY-MM-DDTHH:mm:ss')
            )
        else:
            filters['reporttime'] = '{0}Z'.format(
                arrow.get(self.last_successful_run/1000.0).format('YYYY-MM-DDTHH:mm:ss')
            )
        LOG.debug('%s - filters: %s', self.name, filters)

        cifclient = cifsdk.client.Client(
            token=self.token,
            remote=self.remote,
            verify_ssl=self.verify_cert,
            timeout=900
        )

        try:
            ret = cifclient.search(filters=filters, decode=False)

        except SystemExit as e:
            raise RuntimeError(str(e))

        return ujson.loads(ret)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Feed, self).hup(source=source)

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
