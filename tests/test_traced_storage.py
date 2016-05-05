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

import minemeld.traced.storage

import traced_mock

TABLENAME = tempfile.mktemp(prefix='minemeld.traced.storagetest')


class MineMeldTracedStorage(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree(TABLENAME)
        except:
            pass

    def tearDown(self):
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

    def test_store_simple(self):
        store = minemeld.traced.storage.Store()
        store.stop()
        self.assertEqual(len(store.current_tables), 0)

    @mock.patch.object(minemeld.traced.storage, 'Table', side_effect=traced_mock.table_factory)
    def test_store_write(self, table_mock):
        store = minemeld.traced.storage.Store()
        store.write(0*864000*1000, 'log0')
        store.write(1*864000*1000, 'log1')
        store.write(2*864000*1000, 'log2')
        store.write(3*864000*1000, 'log3')
        store.write(4*864000*1000, 'log4')
        store.write(5*864000*1000, 'log5')
        store.write(6*864000*1000, 'log6')
        store.stop()
        self.assertEqual(len(store.current_tables), 0)
