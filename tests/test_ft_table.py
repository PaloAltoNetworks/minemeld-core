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

"""FT Table tests

Unit tests for minemeld.ft.table
"""

import unittest
import tempfile
import shutil
import random
import time

import minemeld.ft.table

from nose.plugins.attrib import attr

TABLENAME = tempfile.mktemp(prefix='minemeld.fttabletest')
NUM_ELEMENTS = 10000


class MineMeldFTTableTests(unittest.TestCase):
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

    def test_truncate(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.put('key', {'a': 1})
        table = None

        table = minemeld.ft.table.Table(TABLENAME)
        self.assertEqual(table.num_indicators, 1)
        table = None

        table = minemeld.ft.table.Table(TABLENAME, truncate=True)
        self.assertEqual(table.num_indicators, 0)

    def test_insert(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        self.assertEqual(table.num_indicators, NUM_ELEMENTS)

    def test_index_query(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        j = 0
        for k, v in table.query('a', from_key=0, to_key=500,
                                include_value=True):
            j += 1

        self.assertEqual(j, NUM_ELEMENTS)

    def test_query(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        j = 0
        for k, v in table.query(include_value=True):
            j += 1

        self.assertEqual(j, NUM_ELEMENTS)

    def test_exists(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        for i in range(NUM_ELEMENTS):
            j = random.randint(0, NUM_ELEMENTS-1)
            self.assertTrue(
                table.exists('i%d' % j),
                msg="i%d does not exists" % j
            )

    def test_not_exists(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        for i in range(NUM_ELEMENTS):
            j = random.randint(NUM_ELEMENTS, 2*NUM_ELEMENTS)
            self.assertFalse(table.exists('i%d' % j))

    def test_update(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        table.put('k1', {'a': 1})
        table.put('k2', {'a': 1})
        table.put('k1', {'a': 2})

        ok = 0
        rk = None
        for k in table.query('a', from_key=0, to_key=1):
            rk = k
            ok += 1

        self.assertEqual(rk, 'k2')
        self.assertEqual(ok, 1)

    @attr('slow')
    def test_random(self):
        # create table
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        # local dict
        d = {}

        # add 10000 elements to the table
        # with an 'a' attribute in range 0,500
        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            d[key] = value
            table.put(key, value)

        # check number of indicators added
        self.assertEqual(table.num_indicators, len(d.keys()))

        # check sorted query retrieval
        flatdict = sorted(d.items(), key=lambda x: x[1]['a'])
        j = 0
        for k, v in table.query('a', from_key=0, to_key=500,
                                include_value=True):
            de = flatdict[j]
            self.assertEqual(de[1]['a'], v['a'])
            j = j+1

        # 1000 random add or delete
        for j in range(1000):
            op = random.randint(0, 1)

            if op == 0:
                # delete
                i = 'i%d' % random.randint(0, 2000)
                if i in d:
                    del d[i]
                table.delete(i)
            elif op == 1:
                # add
                i = 'i%d' % random.randint(0, 2000)
                v = {'a': random.randint(0, 500)}
                table.put(i, v)
                d[i] = v

            # check num of indicators
            self.assertEqual(table.num_indicators, len(d.keys()))
            flatdict = sorted(d.items(), key=lambda x: x[1]['a'])
            j = 0
            for k, v in table.query('a', from_key=0, to_key=500,
                                    include_value=True):
                de = flatdict[j]
                # check sorting
                self.assertEqual(de[1]['a'], v['a'])
                j = j+1

        # close table
        table = None

        # reopen
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        self.assertEqual(table.num_indicators, len(d.keys()))

        # check sort again
        flatdict = sorted(d.items(), key=lambda x: x[1]['a'])
        j = 0
        for k, v in table.query('a', from_key=0, to_key=500,
                                include_value=True):
            de = flatdict[j]
            self.assertEqual(de[1]['a'], v['a'])
            j = j+1

    @attr('slow')
    def test_write(self):
        # create table
        table = minemeld.ft.table.Table(TABLENAME)

        # local dict
        d = {}

        t1 = time.time()
        for i in xrange(100000):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            d[key] = value
            table.put(key, value)
        t2 = time.time()
        print 'TIME: Written %d elements in %s secs' % (100000, t2-t1)

        # check number of indicators added
        self.assertEqual(table.num_indicators, len(d.keys()))

        table.close()
        table = None
