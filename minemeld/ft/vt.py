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
This module implements:
- minemeld.ft.vt.Notifications, the Miner node for VirusTotal Notifications
  feed
"""

import logging
import os
import yaml

from . import json

LOG = logging.getLogger(__name__)

_VT_NOTIFICATIONS = 'https://www.virustotal.com/intelligence/hunting/notifications-feed/?key='


class Notifications(json.SimpleJSON):
    def __init__(self, name, chassis, config):
        super(Notifications, self).__init__(name, chassis, config)

        self.api_key = None

    def configure(self):
        self.config['url'] = None
        self.config['extractor'] = 'notifications'
        self.config['prefix'] = 'vt'

        super(Notifications, self).configure()

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
            LOG.info('%s - api key set', self.name)
            self.url = _VT_NOTIFICATIONS + self.api_key

    def _process_item(self, item):
        result = []

        for htype in ['md5', 'sha256', 'sha1']:
            value = {self.prefix+'_'+k: v for k, v in item.iteritems()}
            indicator = value.pop(self.prefix+'_'+htype, None)
            value['type'] = htype

            if indicator is not None:
                result.append([indicator, value])

        return result

    def _build_iterator(self, now):
        if self.api_key is None:
            LOG.info('%s - API key not set', self.name)
            raise RuntimeError(
                '%s - API Key not set' % self.name
            )

        return super(Notifications, self)._build_iterator(now)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Notifications, self).hup(source=source)
