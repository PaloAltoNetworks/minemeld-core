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
        :extractor: JMESPath expression for extracting the indicators from
            the JSON document. Default: @
        :indicator: the JSON attribute to use as indicator. Default: indicator
        :fields: list of JSON attributes to include in the indicator value.
            If *null* no additional attributes are extracted. Default: *null*
        :prefix: prefix to add to field names. Default: json

        Header parameters are optional to sepcify a user-agent or an api-token
        :header_key: the key value for the header, e.g user-agent or Authentication
        :header_value: the value attribute for the header, e.g api-agent/1.1 or some kind of api-token
        Example: headers = {'user-agent': 'my-app/0.0.1'} or Authorization: Bearer 
        (curl -H "Authorization: Bearer " "https://api-url.com/api/v1/iocs?first_seen_since=2016-1-1")

    Example:
        Example config in YAML::

            url: https://ip-ranges.amazonaws.com/ip-ranges.json
            extractor: "prefixes[?service=='AMAZON']"
            prefix: aws
            indicator: ip_prefix
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

        self.extractor = jmespath.compile(self.config.get('extractor', '@'))
        self.indicator = self.config.get('indicator', 'indicator')
        self.prefix = self.config.get('prefix', 'json')
        self.fields = self.config.get('fields', None)

        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)

        self.header_key = self.config.get('header_key', None)
        self.header_value = self.config.get('header_value', None)

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
        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        if self.username is not None and self.password is not None:
            rkwargs['auth'] = (self.username, self.password)

        if self.header_key is not None and self.header_value is not None:
            rkwargs['headers'] = (self.header_key, self.header_value)

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
