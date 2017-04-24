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

"""
This module implements minemeld.ft.csv.CSVFT, the Miner node for csv
feeds over HTTP/HTTPS.
"""

from __future__ import absolute_import

import logging
import re
import itertools
import csv
import requests

from . import basepoller

LOG = logging.getLogger(__name__)


class CSVFT(basepoller.BasePollerFT):
    """Implements class for miners of csv feeds over http/https.

    **Config parameters**
        :url: URL of the feed.
        :polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*
        :ignore_regex: Python regular expression for lines that should be
            ignored. Default: *null*
        :fieldnames: list of field names in the file. If *null* the values
            in the first row of the file are used as names. Default: *null*
        :delimiter: see `csv Python module <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`_.
            Default: ,
        :doublequote: see `csv Python module <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`_.
            Default: true
        :escapechar: see `csv Python module <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`_.
            Default: null
        :quotechar: see `csv Python module <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`_.
            Default: "
        :skipinitialspace: see `csv Python module <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`_.
            Default: false

    Example:
        Example config in YAML::

            url: https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
            ignore_regex: '^#'
            fieldnames:
                - indicator
                - port
                - sslblabusech_type

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """
    def configure(self):
        super(CSVFT, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.url = self.config.get('url', None)
        self.verify_cert = self.config.get('verify_cert', True)

        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)

        self.ignore_regex = self.config.get('ignore_regex', None)
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)

        self.fieldnames = self.config.get('fieldnames', None)

        self.dialect = {
            'delimiter': self.config.get('delimiter', ','),
            'doublequote': self.config.get('doublequote', True),
            'escapechar': self.config.get('escapechar', None),
            'quotechar': self.config.get('quotechar', '"'),
            'skipinitialspace': self.config.get('skipinitialspace', False)
        }

    def _process_item(self, item):
        item.pop(None, None)  # I love this

        indicator = item.pop('indicator', None)
        return [[indicator, item]]

    def _build_request(self, now):
        r = requests.Request(
            'GET',
            self.url
        )

        return r.prepare()

    def _build_iterator(self, now):
        _session = requests.Session()

        prepreq = self._build_request(now)

        if self.username is not None and self.password is not None:
            _session.auth = (self.username, self.password)

        # this is to honour the proxy environment variables
        rkwargs = _session.merge_environment_settings(
            prepreq.url,
            {}, None, None, None  # defaults
        )
        rkwargs['stream'] = True
        rkwargs['verify'] = self.verify_cert
        rkwargs['timeout'] = self.polling_timeout

        r = _session.send(prepreq, **rkwargs)

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        response = r.raw
        if self.ignore_regex is not None:
            response = itertools.ifilter(
                lambda x: self.ignore_regex.match(x) is None,
                r.raw
            )

        csvreader = csv.DictReader(
            response,
            fieldnames=self.fieldnames,
            **self.dialect
        )

        return csvreader
