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

import os
import re

import yaml

from .logger import LOG


class DirSnapshot(object):
    def __init__(self, path, regex=None):
        self._entries = self._init_snapshot(path, regex)

    def _init_snapshot(self, path, regex):
        result = set()

        files = os.listdir(path)
        pattern = re.compile(regex) if regex is not None else None
        for f in files:
            if pattern is not None:
                if pattern.match(f) is None:
                    continue

            mtime = os.stat(os.path.join(path, f)).st_mtime
            result.add('%s_%d' % (f, int(mtime)))

        return result

    def __eq__(self, other):
        return self._entries == other._entries

    def __ne__(self, other):
        return self._entries != other._entries


def running_config_path():
    rcpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'running-config.yml'
    )

    return rcpath


def committed_config_path():
    ccpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'committed-config.yml'
    )

    return ccpath


def running_config():
    with open(running_config_path(), 'r') as f:
        rcconfig = yaml.safe_load(f)

    return rcconfig


def committed_config():
    with open(committed_config_path(), 'r') as f:
        ccconfig = yaml.safe_load(f)

    return ccconfig


def safe_remove(path):
    try:
        os.remove(path)
    except:
        LOG.exception('Exception removing {}'.format(path))
