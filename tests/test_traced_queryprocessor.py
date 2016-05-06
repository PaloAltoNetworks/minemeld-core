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
Unit tests for minemeld.traced.queryprocessor
"""

import redis
import gevent
import unittest
import tempfile
import shutil
import random
import time
import mock
import json
import logging

import minemeld.traced.queryprocessor

import traced_mock

TABLENAME = tempfile.mktemp(prefix='minemeld.traced.storagetest')

LOG = logging.getLogger(__name__)

class MineMeldTracedStorage(unittest.TestCase):
    def setUp(self):
        traced_mock.table_cleanup()

    def tearDown(self):
        traced_mock.table_cleanup()

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_query_1(self, glet_mock, SR_mock):
        store = traced_mock.store_factory()
        q = minemeld.traced.queryprocessor.Query(
            store,
            "log",
            0, 0,
            100,
            'uuid-test',
            {}
        )
        q._run()
        self.assertGreater(len(SR_mock.mock_calls), 1)

        num_logs = 0
        eoq = False
        for call in SR_mock.mock_calls[1:]:
            name, args, kwargs = call
            self.assertEqual(name, '().publish')
            self.assertEqual(args[0], 'mm-traced-q.uuid-test')

            if args[1] == '<EOQ>':
                eoq = True
            else:
                line = json.loads(args[1])
                if 'log' in line:
                    num_logs += 1

        self.assertEqual(num_logs, 0)
        self.assertEqual(eoq, True)

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_query_pos(self, glet_mock, SR_mock):
        store = traced_mock.store_factory()

        store.write(1*86400*1000, 'log0')

        q = minemeld.traced.queryprocessor.Query(
            store,
            "log",
            3*86400*1000, 0,
            100,
            'uuid-test',
            {}
        )
        q._run()
        self.assertGreater(len(SR_mock.mock_calls), 1)

        num_logs = 0
        eoq = False
        for call in SR_mock.mock_calls[1:]:
            name, args, kwargs = call
            self.assertEqual(name, '().publish')
            self.assertEqual(args[0], 'mm-traced-q.uuid-test')

            if args[1] == '<EOQ>':
                eoq = True
            else:
                line = json.loads(args[1])
                if 'log' in line:
                    num_logs += 1

        self.assertEqual(num_logs, 1)
        self.assertEqual(eoq, True)

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_query_and(self, glet_mock, SR_mock):
        store = traced_mock.store_factory()

        store.write(1*86400*1000, 'log0')
        store.write(1*86400*1000, 'log1')
        store.write(2*86400*1000, 'pog1')

        q = minemeld.traced.queryprocessor.Query(
            store,
            "log -0",
            3*86400*1000, 0,
            100,
            'uuid-test',
            {}
        )
        q._run()
        LOG.debug(SR_mock.mock_calls)
        self.assertGreater(len(SR_mock.mock_calls), 1)

        num_logs = 0
        eoq = False
        for call in SR_mock.mock_calls[1:]:
            name, args, kwargs = call
            self.assertEqual(name, '().publish')
            self.assertEqual(args[0], 'mm-traced-q.uuid-test')

            if args[1] == '<EOQ>':
                eoq = True
            else:
                line = json.loads(args[1])
                if 'log' in line:
                    num_logs += 1

        self.assertEqual(num_logs, 1)
        self.assertEqual(eoq, True)
