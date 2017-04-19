#  Copyright 2017-present Palo Alto Networks, Inc
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
This module implements minemeld.ft.mm.JSONSEQMiner, the Miner node for
MineMeld JSON-SEQ feeds over HTTP/HTTPS.
"""

import os.path
import logging

import requests
import yaml
import ujson

from . import basepoller

LOG = logging.getLogger(__name__)


class JSONSEQMiner(basepoller.BasePollerFT):
    """Implements class for miners of MineMeld JSON-SEQ feeds over http/https.

    **Config parameters**
        :url: URL of the feed.
        :polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*
        :side_config_path: path to the side config with credentials for the feed

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """
    def configure(self):
        super(JSONSEQMiner, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.url = self.config.get('url', None)

        self.username = None
        self.password = None

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

        username = sconfig.get('username', None)
        password = sconfig.get('password', None)
        if username is not None and password is not None:
            self.username = username
            self.password = password
            LOG.info('{} - Loaded credentials from side config'.format(self.name))

    def _process_item(self, item):
        return [[item['indicator'], item['value']]]

    def _json_seq_iterator(self, r):
        for line in r.iter_lines(decode_unicode=True, delimiter='\x1E'):
            if line:
                try:
                    yield ujson.loads(line)
                except ValueError:
                    LOG.error('{} - Error parsing {!r}'.format(self.name, line))

    def _build_iterator(self, now):
        if self.url is None:
            raise RuntimeError(
                '{} - feed url not set'.format(self.name)
            )

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            params={'v': 'json-seq'}
        )

        if self.username is not None and self.password is not None:
            rkwargs['auth'] = (self.username, self.password)

        r = requests.get(
            self.url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        return self._json_seq_iterator(r)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(JSONSEQMiner, self).hup(source)
