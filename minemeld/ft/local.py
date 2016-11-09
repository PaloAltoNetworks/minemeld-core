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
import yaml
import filelock
import os

from . import basepoller

LOG = logging.getLogger(__name__)


class YamlFT(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        self.file_monitor_mtime = None

        super(YamlFT, self).__init__(name, chassis, config)

    def configure(self):
        super(YamlFT, self).configure()

        self.path = self.config.get('path', None)
        if self.path is None:
            self.path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_indicators.yml' % self.name
            )
        self.lock_path = self.path+'.lock'

    def _process_item(self, item):
        indicator = item.pop('indicator', None)
        if indicator is None:
            return [[None, None]]

        item['sources'] = [self.name]

        return [[indicator, item]]

    def _load_yaml(self):
        with filelock.FileLock(self.lock_path).acquire(timeout=10):
            with open(self.path, 'r') as f:
                result = yaml.safe_load(f)

        if type(result) != list:
            raise RuntimeError(
                '%s - %s should be a list of indicators' %
                (self.name, self.path)
            )

        return result

    def _build_iterator(self, now):
        if self.path is None:
            LOG.warning('%s - no path configured', self.name)
            raise RuntimeError('%s - no path configured' % self.name)

        try:
            mtime = os.stat(self.path).st_mtime
        except OSError as e:
            if e.errno == 2:  # no such file
                return None

            LOG.exception('%s - error checking mtime of %s',
                          self.name, self.path)
            raise RuntimeError(
                '%s - error checking indicators list' % self.name
            )

        if mtime == self.file_monitor_mtime:
            return None

        self.file_monitor_mtime = mtime

        try:
            return self._load_yaml()

        except:
            LOG.exception('%s - exception loading indicators list', self.name)
            raise


class YamlIPv4FT(YamlFT):
    def _process_item(self, item):
        item['type'] = 'IPv4'

        return super(YamlIPv4FT, self)._process_item(item)


class YamlURLFT(YamlFT):
    def _process_item(self, item):
        item['type'] = 'URL'

        return super(YamlURLFT, self)._process_item(item)


class YamlDomainFT(YamlFT):
    def _process_item(self, item):
        item['type'] = 'domain'

        return super(YamlDomainFT, self)._process_item(item)


class YamlIPv6FT(YamlFT):
    def _process_item(self, item):
        item['type'] = 'IPv6'

        return super(YamlIPv6FT, self)._process_item(item)
