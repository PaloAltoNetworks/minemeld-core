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

"""
This module implements minemeld.ft.http.HttpFT, the Miner node for plain
text feeds over HTTP/HTTPS.
"""

import requests
import logging
import re
import itertools

from minemeld import __version__ as MM_VERSION

from . import basepoller

LOG = logging.getLogger(__name__)


class HttpFT(basepoller.BasePollerFT):
    """Implements class for miners of plain text feeds over http/https.

    **Config parameters**
        :url: URL of the feed.
        :polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*
        :user_agent: string, value for the User-Agent header in HTTP
            request. If ``MineMeld``, MineMeld/<version> is used.
            Default: python ``requests`` default.
        :ignore_regex: Python regular expression for lines that should be
            ignored. Default: *null*
        :indicator: an *extraction dictionary* to extract the indicator from
            the line. If *null*, the text until the first whitespace or newline
            character is used as indicator. Default: *null*
        :fields: a dicionary of *extraction dictionaries* to extract
            additional attributes from each line. Default: {}
        :encoding: encoding of the feed, if not UTF-8. See
            ``str.decode`` for options. Default: *null*, meaning do
            nothing, (Assumes UTF-8).

    **Extraction dictionary**
        Extraction dictionaries contain the following keys:

        :regex: Python regular expression for searching the text.
        :transform: template to generate the final value from the result
            of the regular expression. Default: the entire match of the regex
            is used as extracted value.

        See Python `re <https://docs.python.org/2/library/re.html>`_ module for
        details about Python regular expressions and templates.

    Example:
        Example config in YAML where extraction dictionaries are used to
        extract the indicator and additional fields::

            url: https://www.dshield.org/block.txt
            ignore_regex: "[#S].*"
            indicator:
                regex: '^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\t([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})'
                transform: '\\1-\\2'
            fields:
                dshield_nattacks:
                    regex: '^.*\\t.*\\t[0-9]+\\t([0-9]+)'
                    transform: '\\1'
                dshield_name:
                    regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t([^\\t]+)'
                    transform: '\\1'
                dshield_country:
                    regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t([A-Z]+)'
                    transform: '\\1'
                dshield_email:
                    regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t[A-Z]+\\t(\\S+)'
                    transform: '\\1'

        Example config in YAML where the text in each line until the first
        whitespace is used as indicator::

            url: https://ransomwaretracker.abuse.ch/downloads/CW_C2_URLBL.txt
            ignore_regex: '^#'

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """
    def configure(self):
        super(HttpFT, self).configure()

        self.url = self.config.get('url', None)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)
        self.user_agent = self.config.get('user_agent', None)
        self.encoding = self.config.get('encoding', None)

        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)

        self.ignore_regex = self.config.get('ignore_regex', None)
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)

        self.indicator = self.config.get('indicator', None)

        if self.indicator is not None:
            if 'regex' in self.indicator:
                self.indicator['regex'] = re.compile(self.indicator['regex'])
            else:
                raise ValueError('%s - indicator stanza should have a regex',
                                 self.name)
            if 'transform' not in self.indicator:
                if self.indicator['regex'].groups > 0:
                    LOG.warning('%s - no transform string for indicator'
                                ' but pattern contains groups',
                                self.name)
                self.indicator['transform'] = '\g<0>'

        self.fields = self.config.get('fields', {})
        for f, fattrs in self.fields.iteritems():
            if 'regex' in fattrs:
                fattrs['regex'] = re.compile(fattrs['regex'])
            else:
                raise ValueError('%s - %s field does not have a regex',
                                 self.name, f)
            if 'transform' not in fattrs:
                if fattrs['regex'].groups > 0:
                    LOG.warning('%s - no transform string for field %s'
                                ' but pattern contains groups',
                                self.name, f)
                fattrs['transform'] = '\g<0>'

    def _process_item(self, line):
        line = line.strip()
        if not line:
            return [[None, None]]

        if self.indicator is None:
            indicator = line.split()[0]

        else:
            indicator = self.indicator['regex'].search(line)
            if indicator is None:
                return [[None, None]]

            indicator = indicator.expand(self.indicator['transform'])

        attributes = {}
        for f, fattrs in self.fields.iteritems():
            m = fattrs['regex'].search(line)

            if m is None:
                continue

            attributes[f] = m.expand(fattrs['transform'])

            try:
                i = int(attributes[f])
            except:
                pass
            else:
                attributes[f] = i

        return [[indicator, attributes]]

    def _build_iterator(self, now):
        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        if self.user_agent is not None:
            if self.user_agent == 'MineMeld':
                rkwargs['headers'] = {
                    'User-Agent': 'MineMeld/%s' % MM_VERSION
                }

            else:
                rkwargs['headers'] = {
                    'User-Agent': self.user_agent
                }

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

        result = r.iter_lines()
        if self.ignore_regex is not None:
            result = itertools.ifilter(
                lambda x: self.ignore_regex.match(x) is None,
                result
            )
        if self.encoding is not None:
            result = itertools.imap(
                lambda x: x.decode(self.encoding).encode('utf_8'),
                result
            )

        return result
