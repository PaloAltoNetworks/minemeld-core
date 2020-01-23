#  Copyright 2015-2020 Palo Alto Networks, Inc
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
import os.path
import itertools
import csv
import requests
import yaml
from urllib3.response import GzipDecoder

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

        self.decode_gzip = self.config.get('decode_gzip', False)

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
        if username is not None:
            self.username = username
            LOG.info('%s - username set', self.name)

        password = sconfig.get('password', None)
        if password is not None:
            self.password = password
            LOG.info('%s - password set', self.name)

    def _process_item(self, item):
        item.pop(None, None)  # I love this

        indicator = item.pop('indicator', None)
        return [[indicator, item]]

    def _build_request(self, now):
        auth = None
        if self.username is not None and self.password is not None:
            auth = (self.username, self.password)

        r = requests.Request(
            'GET',
            self.url,
            auth=auth
        )

        return r.prepare()

    def _build_iterator(self, now):
        def _debug(x):
            LOG.info('{!r}'.format(x))
            return x

        _session = requests.Session()

        prepreq = self._build_request(now)

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
        if self.decode_gzip:
            response = self._gzipped_line_splitter(r)

        if self.ignore_regex is not None:
            response = itertools.ifilter(
                lambda x: self.ignore_regex.match(x) is None,
                response
            )

        csvreader = csv.DictReader(
            response,
            fieldnames=self.fieldnames,
            **self.dialect
        )

        return csvreader

    def _gzipped_line_splitter(self, response):
        # same logic used in urllib32.response.iter_lines
        pending = None

        decoder = GzipDecoder()
        chunks = itertools.imap(
            decoder.decompress,
            response.iter_content(chunk_size=1024*1024)
        )

        for chunk in chunks:
            if pending is not None:
                chunk = pending + chunk

            lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            for line in lines:
                yield line

        if pending is not None:
            yield pending

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(CSVFT, self).hup(source=source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

        shutil.rmtree('{}_temp'.format(name), ignore_errors=True)
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
