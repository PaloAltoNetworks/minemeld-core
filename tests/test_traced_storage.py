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
Unit tests for minemeld.traced.storage
"""

import unittest
import tempfile
import shutil
import random
import time
import mock
import logging

from nose.plugins.attrib import attr

import minemeld.traced.storage

import traced_mock

TABLENAME = tempfile.mktemp(prefix='minemeld.traced.storagetest')

LOG = logging.getLogger(__name__)


class MineMeldTracedStorage(unittest.TestCase):
    def setUp(self):
        traced_mock.table_cleanup()

        try:
            shutil.rmtree(TABLENAME)
        except:
            pass

    def tearDown(self):
        traced_mock.table_cleanup()

        try:
            shutil.rmtree(TABLENAME)
        except:
            pass

    def test_table_constructor(self):
        self.assertRaises(
            minemeld.traced.storage.TableNotFound,
            minemeld.traced.storage.Table, TABLENAME, create_if_missing=False
        )

        table = minemeld.traced.storage.Table(TABLENAME, create_if_missing=True)
        self.assertEqual(table.max_counter, -1)

        table.close()
        table = None

        table = minemeld.traced.storage.Table(TABLENAME, create_if_missing=False)
        self.assertEqual(table.max_counter, -1)

        table.close()
        table = None

    def test_table_write(self):
        table = minemeld.traced.storage.Table(TABLENAME, create_if_missing=True)
        table.put('%016x' % 0, 'value0')
        self.assertEqual(table.max_counter, 0)
        table.close()
        table = None

        table = minemeld.traced.storage.Table(TABLENAME, create_if_missing=False)
        iterator = table.backwards_iterator(1, 0xFFFFFFFFFFFFFFFF)
        ts, line = next(iterator)
        self.assertEqual(line, 'value0')
        self.assertEqual(int(ts[:16], 16), 0)
        self.assertEqual(int(ts[16:], 16), 0)
        self.assertRaises(StopIteration, next, iterator)
        table.close()
        table = None

    def test_table_references(self):
        table = minemeld.traced.storage.Table(TABLENAME, create_if_missing=True)
        self.assertEqual(table.ref_count(), 0)

        table.add_reference('ref1')
        self.assertEqual(table.ref_count(), 1)

        table.add_reference('ref2')
        self.assertEqual(table.ref_count(), 2)

        table.remove_reference('ref1')
        self.assertEqual(table.ref_count(), 1)

        table.remove_reference('ref1')
        self.assertEqual(table.ref_count(), 1)

        table.remove_reference('ref2')
        self.assertEqual(table.ref_count(), 0)

    def test_table_oldest(self):
        old_ = '%016x' % (3*86400)
        new_ = '%016x' % (4*86400)

        oldest = minemeld.traced.storage.Table.oldest_table()
        self.assertEqual(oldest, None)

        table = minemeld.traced.storage.Table(old_, create_if_missing=True)
        table.close()

        table = minemeld.traced.storage.Table(new_, create_if_missing=True)
        table.close()

        oldest = minemeld.traced.storage.Table.oldest_table()
        self.assertEqual(oldest, old_)

        shutil.rmtree(old_)
        shutil.rmtree(new_)

    def test_store_simple(self):
        store = minemeld.traced.storage.Store()
        store.stop()
        self.assertEqual(len(store.current_tables), 0)

    @mock.patch.object(minemeld.traced.storage, 'Table', side_effect=traced_mock.table_factory)
    def test_store_write(self, table_mock):
        store = minemeld.traced.storage.Store()
        store.write(0*86400*1000, 'log0')
        self.assertEqual(traced_mock.MOCK_TABLES[0].name, '%016x' % 0)

        store.write(1*86400*1000, 'log1')
        self.assertEqual(traced_mock.MOCK_TABLES[1].name, '%016x' % (86400*1))

        store.write(2*86400*1000, 'log2')
        self.assertEqual(traced_mock.MOCK_TABLES[2].name, '%016x' % (86400*2))

        store.write(3*86400*1000, 'log3')
        self.assertEqual(traced_mock.MOCK_TABLES[3].name, '%016x' % (86400*3))

        store.write(4*86400*1000, 'log4')
        self.assertEqual(traced_mock.MOCK_TABLES[4].name, '%016x' % (86400*4))

        store.write(5*86400*1000, 'log5')
        self.assertEqual(traced_mock.MOCK_TABLES[5].name, '%016x' % (86400*5))
        self.assertNotIn('%016x' % 0, store.current_tables)

        store.write(6*86400*1000, 'log6')
        self.assertEqual(traced_mock.MOCK_TABLES[6].name, '%016x' % (86400*6))
        self.assertNotIn('%016x' % 86400, store.current_tables)

        store.stop()
        self.assertEqual(len(store.current_tables), 0)

    @mock.patch.object(minemeld.traced.storage, 'Table', side_effect=traced_mock.table_factory)
    def test_store_iterate_backwards(self, table_mock):
        _oldest_table_mock = mock.MagicMock(side_effect=traced_mock.MockTable.oldest_table)
        table_mock.attach_mock(_oldest_table_mock, 'oldest_table')

        store = minemeld.traced.storage.Store()
        store.write(1*86400*1000, 'log0')
        store.write(2*86400*1000, 'log1')
        store.write(3*86400*1000, 'log2')
        store.write(4*86400*1000, 'log3')
        store.write(5*86400*1000, 'log4')
        self.assertEqual(minemeld.traced.storage.Table.oldest_table(), '%016x' % 86400)

        iterator = store.iterate_backwards(
            ref='test-iter1',
            timestamp=6*86400*1000,
            counter=0xFFFFFFFFFFFFFFFF
        )
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-07')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-06')
        self.assertEqual(next(iterator)['log'], 'log4')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-05')
        self.assertEqual(next(iterator)['log'], 'log3')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-04')
        self.assertEqual(next(iterator)['log'], 'log2')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-03')
        self.assertEqual(next(iterator)['log'], 'log1')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-02')
        self.assertEqual(next(iterator)['log'], 'log0')
        self.assertEqual(next(iterator)['msg'], 'No more logs to check')
        self.assertRaises(StopIteration, next, iterator)

        store.stop()
        store.stop()  # just for coverage

    @mock.patch.object(minemeld.traced.storage, 'Table', side_effect=traced_mock.table_factory)
    def test_store_iterate_backwards_2(self, table_mock):
        _oldest_table_mock = mock.MagicMock(side_effect=traced_mock.MockTable.oldest_table)
        table_mock.attach_mock(_oldest_table_mock, 'oldest_table')

        store = minemeld.traced.storage.Store()
        store.write(0*86400*1000, 'log0')
        store.write(2*86400*1000, 'log1')
        self.assertEqual(minemeld.traced.storage.Table.oldest_table(), '%016x' % 0)

        iterator = store.iterate_backwards(
            ref='test-iter1',
            timestamp=3*86400*1000,
            counter=0xFFFFFFFFFFFFFFFF
        )
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-04')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-03')
        self.assertEqual(next(iterator)['log'], 'log1')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-02')
        self.assertEqual(next(iterator)['msg'], 'Checking 1970-01-01')
        self.assertEqual(next(iterator)['log'], 'log0')
        self.assertEqual(next(iterator)['msg'], 'We haved reached the origins of time')
        self.assertRaises(StopIteration, next, iterator)

        store.stop()

    @attr('slow')
    def test_stress_1(self):
        num_lines = 200000
        store = minemeld.traced.storage.Store()

        t1 = time.time()
        for j in xrange(num_lines):
            value = '{ "log": %d }' % random.randint(0, 0xFFFFFFFF)
        t2 = time.time()
        dt = t2-t1

        t1 = time.time()
        for j in xrange(num_lines):
            value = '{ "log": %d }' % random.randint(0, 0xFFFFFFFF)
            store.write(j, value)
        t2 = time.time()
        print "TIME: Inserted %d lines in %d sec" % (num_lines, (t2-t1-dt))

        store.stop()
        shutil.rmtree('1970-01-01')
