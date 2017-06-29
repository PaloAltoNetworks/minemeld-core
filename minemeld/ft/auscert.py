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

import requests
import logging
import itertools
import os
import yaml

from . import http

LOG = logging.getLogger(__name__)


class MaliciousURLFeed(http.HttpFT):
    def configure(self):
        super(MaliciousURLFeed, self).configure()

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
            LOG.info('%s - api_key set', self.name)

    def _build_iterator(self, now):
        if self.api_key is None:
            raise RuntimeError(
                '{} - API Key not set, '
                'poll not performed'.format(self.name)
            )

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )
        
        rkwargs["headers"] = { 
            'API-Key': self.api_key 
        }

        session = requests.Session()

        r = session.get(
            self.url,
            **rkwargs
        )

        # if api_key is wrong we'll get a 403 response code
        if r.status_code == 403: 
            raise RuntimeError(
                '{} - not authorized (Invalid API Key?)'.format(self.name)
            )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        result = r.iter_lines()
        if self.ignore_regex is not None:
            result = itertools.ifilter(
                lambda x: self.ignore_regex.match(x) is None,
                result
            )

        return result

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(MaliciousURLFeed, self).hup(source)
