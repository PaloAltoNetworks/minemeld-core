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

import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import redis
import gevent
import greenlet
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
import comm_mock

TABLENAME = tempfile.mktemp(prefix='minemeld.traced.storagetest')

LOG = logging.getLogger(__name__)

class MineMeldTracedStorage(unittest.TestCase):
    def setUp(self):
        traced_mock.table_cleanup()
        traced_mock.query_cleanup()

    def tearDown(self):
        traced_mock.table_cleanup()
        traced_mock.query_cleanup()

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

    @mock.patch.object(minemeld.traced.queryprocessor, 'Query', side_effect=traced_mock.query_factory)
    def test_queryprocessor_1(self, query_mock):
        comm = comm_mock.comm_factory({})
        store = traced_mock.store_factory()

        qp = minemeld.traced.queryprocessor.QueryProcessor(comm, store)

        self.assertEqual(
            comm.rpc_server_channels[0]['name'],
            minemeld.traced.queryprocessor.QUERY_QUEUE
        )
        self.assertEqual(
            comm.rpc_server_channels[0]['allowed_methods'],
            ['query', 'kill_query']
        )

        qp.query('uuid-test-1', "test query")
        self.assertEqual(len(traced_mock.MOCK_QUERIES), 1)

        qp.query('uuid-test-2', "test query")
        self.assertEqual(len(traced_mock.MOCK_QUERIES), 2)

        gevent.sleep(0)

        traced_mock.MOCK_QUERIES[0].finish_event.set()

        gevent.sleep(0)

        qp.stop()
        gevent.sleep(0)
        gevent.sleep(0)

        self.assertEqual(traced_mock.MOCK_QUERIES[0].get(), None)
        self.assertIsInstance(
            traced_mock.MOCK_QUERIES[1].get(),
            greenlet.GreenletExit
        )
        self.assertNotIn('uuid-test-1', store.release_alls)
        self.assertIn('uuid-test-2', store.release_alls)

    @mock.patch.object(minemeld.traced.queryprocessor, 'Query', side_effect=traced_mock.query_factory)
    def test_queryprocessor_2(self, query_mock):
        comm = comm_mock.comm_factory({})
        store = traced_mock.store_factory()

        qp = minemeld.traced.queryprocessor.QueryProcessor(comm, store)

        self.assertEqual(
            comm.rpc_server_channels[0]['name'],
            minemeld.traced.queryprocessor.QUERY_QUEUE
        )
        self.assertEqual(
            comm.rpc_server_channels[0]['allowed_methods'],
            ['query', 'kill_query']
        )

        qp.query('uuid-test-1', "test query")
        self.assertEqual(len(traced_mock.MOCK_QUERIES), 1)

        qp.query('uuid-test-2', "bad")
        self.assertEqual(len(traced_mock.MOCK_QUERIES), 2)

        gevent.sleep(0)

        traced_mock.MOCK_QUERIES[0].finish_event.set()
        traced_mock.MOCK_QUERIES[1].finish_event.set()

        gevent.sleep(0)

        qp.stop()
        gevent.sleep(0)
        gevent.sleep(0)

        self.assertEqual(traced_mock.MOCK_QUERIES[0].get(), None)
        self.assertRaises(
            RuntimeError,
            traced_mock.MOCK_QUERIES[1].get
        )
        self.assertNotIn('uuid-test-1', store.release_alls)
        self.assertIn('uuid-test-2', store.release_alls)

    @mock.patch.object(minemeld.traced.queryprocessor, 'Query', side_effect=traced_mock.query_factory)
    def test_queryprocessor_3(self, query_mock):
        comm = comm_mock.comm_factory({})
        store = traced_mock.store_factory()

        qp = minemeld.traced.queryprocessor.QueryProcessor(comm, store)

        self.assertEqual(
            comm.rpc_server_channels[0]['name'],
            minemeld.traced.queryprocessor.QUERY_QUEUE
        )
        self.assertEqual(
            comm.rpc_server_channels[0]['allowed_methods'],
            ['query', 'kill_query']
        )

        qp.query('uuid-test-1', "test query")
        gevent.sleep(0)

        qp.kill_query('uuid-test-1')
        gevent.sleep(0)

        self.assertIsInstance(
            traced_mock.MOCK_QUERIES[0].get(),
            greenlet.GreenletExit
        )
        self.assertEqual(
            len(qp.queries),
            0
        )
        self.assertIn('uuid-test-1', store.release_alls)

        qp.stop()
        gevent.sleep(0)

    @mock.patch.object(minemeld.traced.queryprocessor, 'Query', side_effect=traced_mock.query_factory)
    def test_queryprocessor_4(self, query_mock):
        comm = comm_mock.comm_factory({})
        store = traced_mock.store_factory()

        qp = minemeld.traced.queryprocessor.QueryProcessor(comm, store)

        self.assertEqual(
            comm.rpc_server_channels[0]['name'],
            minemeld.traced.queryprocessor.QUERY_QUEUE
        )
        self.assertEqual(
            comm.rpc_server_channels[0]['allowed_methods'],
            ['query', 'kill_query']
        )

        qp.stop()
        gevent.sleep(0)

        self.assertRaises(
            RuntimeError,
            qp.query,
            'test-uuid-1', "test"
        )
        self.assertRaises(
            RuntimeError,
            qp.kill_query,
            'test-uuid-1'
        )

    @mock.patch.object(minemeld.traced.queryprocessor, 'Query', side_effect=traced_mock.query_factory)
    def test_queryprocessor_5(self, query_mock):
        comm = comm_mock.comm_factory({})
        store = traced_mock.store_factory()

        qp = minemeld.traced.queryprocessor.QueryProcessor(comm, store, {'max_concurrency': 2})

        qp.query('uuid-test-1', "test query")
        gevent.sleep(0)

        qp.query('uuid-test-2', "test query")
        gevent.sleep(0)

        self.assertRaises(
            RuntimeError,
            qp.query,
            'uuid-test-3', "test query"
        )
        gevent.sleep(0)

        traced_mock.MOCK_QUERIES[0].finish_event.set()
        gevent.sleep(0.2)
        self.assertEqual(len(qp.queries), 1)

        self.assertEqual(
            qp.query('uuid-test-4', "test query"),
            'OK'
        )
        gevent.sleep(0)

        qp.stop()
        gevent.sleep(0)
