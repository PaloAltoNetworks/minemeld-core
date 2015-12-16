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

import xml.etree.ElementTree
import re
import os.path
import collections
import logging

MYDIR = os.path.dirname(__file__)
SUBRE = re.compile("[^A-Za-z0-9_]")

LOG = logging.getLogger(__name__)


class PanXapiMock(object):
    def __init__(self, **kwargs):
        self.hostname = kwargs.get('hostname', 'xapi')
        self.counters = collections.defaultdict(lambda: 0)

        self.user_id_calls = []

    def _parse_answer(self, cmd, arg, counter):
        file_name = '%s_%s_%s_%d' % (self.hostname, cmd, arg, counter)
        file_name = SUBRE.sub('_', file_name)
        file_name = os.path.join(MYDIR, file_name+'.xml')

        LOG.debug(file_name)

        try:
            os.stat(file_name)

        except OSError:
            file_name = '%s_%s_%s' % (self.hostname, cmd, arg)
            file_name = SUBRE.sub('_', file_name)
            file_name = os.path.join(MYDIR, file_name+'.xml')

            os.stat(file_name)

        self.element_root = xml.etree.ElementTree.parse(file_name).getroot()

    def get(self, **kwargs):
        xpath = kwargs.get('xpath', None)
        if xpath is None:
            raise RuntimeError('no xpath in get')

        c = self.counters['get:::'+xpath]
        self.counters['get:::'+xpath] += 1

        self._parse_answer('get', xpath, c)

    def show(self, **kwargs):
        xpath = kwargs.get('xpath', None)
        if xpath is None:
            raise RuntimeError('no xpath in show')

        c = self.counters['show:::'+xpath]
        self.counters['show:::'+xpath] += 1

        self._parse_answer('show', xpath, c)

    def op(self, **kwargs):
        cmd = kwargs.get('cmd', None)
        if cmd is None:
            raise RuntimeError('no cmd in op')

        c = self.counters['op:::'+cmd]
        self.counters['op:::'+cmd] += 1

        self._parse_answer('op', cmd, c)

    def user_id(self, **kwargs):
        cmd = kwargs.get('cmd', None)
        if cmd is None:
            raise RuntimeError('no cmd in user_id')

        self.user_id_calls.append(cmd)


def factory(**kwargs):
    return PanXapiMock(**kwargs)
