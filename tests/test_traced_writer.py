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
Unit tests for minemeld.traced.writer
"""

import unittest
import tempfile
import shutil
import random
import time
import mock
import logging
import ujson

import minemeld.traced.writer

import comm_mock
import traced_mock

LOG = logging.getLogger(__name__)


class MineMeldTracedStorage(unittest.TestCase):
    def test_writer(self):
        config = {}
        comm = comm_mock.comm_factory(config)
        store = traced_mock.store_factory()

        writer = minemeld.traced.writer.Writer(comm, store, 'TESTTOPIC')
        self.assertEqual(comm.sub_channels[0]['topic'], 'TESTTOPIC')
        self.assertEqual(comm.sub_channels[0]['allowed_methods'], ['log'])

        writer.log(0, log='testlog')
        self.assertEqual(store.writes[0]['timestamp'], 0)
        self.assertEqual(store.writes[0]['log'], ujson.dumps({'log': 'testlog'}))

        writer.stop()
        writer.log(0, log='testlog')
        self.assertEqual(len(store.writes), 1)

        writer.stop()  # just for coverage
