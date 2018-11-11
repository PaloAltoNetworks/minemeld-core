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
This module implements minemeld.ft.json.SimpleJSON, the Miner node for JSON
feeds over HTTP/HTTPS.
"""

import requests
import logging
import jmespath
import os
import yaml

from . import basepoller

LOG = logging.getLogger(__name__)


class SimpleJSON(basepoller.BasePollerFT):
    """Implements class for miners of JSON feeds over http/https.

    **Config parameters**
        :url: URL of the feed.
        :polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*
        :username: string, for BasicAuth authentication (*password* required)
        :password: string, for BasicAuth authentication (*username* required)
        :client_cert_required: boolean, triggers client certificate authentication
            (requires *cert_file* and *key_file*)
        :cert_file: string, path to the client certificate
        :key_file: string, path to the private key of the client certificate
        :extractor: JMESPath expression for extracting the indicators from
            the JSON document. Default: @
        :indicator: the JSON attribute to use as indicator. Default: indicator
        :fields: list of JSON attributes to include in the indicator value.
            If *null* no additional attributes are extracted. Default: *null*
        :prefix: prefix to add to field names. Default: json

        :headers: Header parameters are optional to sepcify a user-agent or an api-token
        Example: headers = {'user-agent': 'my-app/0.0.1'} or Authorization: Bearer 
        (curl -H "Authorization: Bearer " "https://api-url.com/api/v1/iocs?first_seen_since=2016-1-1")

    Example:
        Example config in YAML::

            url: https://ip-ranges.amazonaws.com/ip-ranges.json
            extractor: "prefixes[?service=='AMAZON']"
            prefix: aws
            indicator: ip_prefix
            headers: {'Authorization': '12345668900', 'user-agent': 'my-app/0.0.1'}
            fields:
                - region
                - service

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """

    def configure(self):
        super(SimpleJSON, self).configure()

        self.url = self.config.get('url', None)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.compile_error = None
        try:
            self.extractor = jmespath.compile(self.config.get('extractor', '@'))
        except Exception as e:
            LOG.debug('%s - exception in jmespath: %s',
                      self.name, e)
            self.compile_error = "{}".format(e)

        self.indicator = self.config.get('indicator', 'indicator')
        self.prefix = self.config.get('prefix', 'json')
        self.fields = self.config.get('fields', None)

        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)

        self.headers = self.config.get('headers', None)

        # option for enabling client cert, default disabled
        self.client_cert_required = self.config.get('client_cert_required', False)
        self.key_file = self.config.get('key_file', None)
        if self.key_file is None and self.client_cert_required:
            self.key_file = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s.pem' % self.name
            )
        self.cert_file = self.config.get('cert_file', None)
        if self.cert_file is None and self.client_cert_required:
            self.cert_file = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s.crt' % self.name
            )

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

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(SimpleJSON, self).hup(source)

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

        client_cert_required = False
        if config is not None:
            client_cert_required = config.get('client_cert_required', False)

        if config is not None:
            cert_path = config.get('cert_file', None)
            if cert_path is None and client_cert_required:
                cert_path = os.path.join(
                    os.environ['MM_CONFIG_DIR'],
                    '{}.crt'.format(name)
                )

            if cert_path is not None:
                try:
                    os.remove(cert_path)
                except:
                    pass

        if config is not None:
            key_path = config.get('key_file', None)
            if key_path is None and client_cert_required:
                key_path = os.path.join(
                    os.environ['MM_CONFIG_DIR'],
                    '{}.pem'.format(name)
                )

            if key_path is not None:
                try:
                    os.remove(key_path)
                except:
                    pass

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

        fields = self.fields
        if fields is None:
            fields = item.keys()
            fields.remove(self.indicator)

        attributes = {}
        for field in fields:
            if field not in item:
                continue
            attributes['%s_%s' % (self.prefix, field)] = item[field]

        return [[indicator, attributes]]

    def _build_iterator(self, now):
        if self.compile_error is not None:
            raise RuntimeError(self.compile_error)

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        if self.username is not None and self.password is not None:
            rkwargs['auth'] = (self.username, self.password)

        if self.headers is not None:
            rkwargs['headers'] = self.headers

        if self.client_cert_required and self.key_file is not None and self.cert_file is not None:
            rkwargs['cert'] = (self.cert_file, self.key_file)

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

        result = self.extractor.search(r.json())

        return result
