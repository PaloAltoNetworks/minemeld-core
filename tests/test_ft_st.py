"""FT ST tests

Unit tests for minemeld.ft.st
"""

import unittest
import tempfile
import shutil
import random
import uuid
import time

from nose.plugins.attrib import attr

import minemeld.ft.st

TABLENAME = tempfile.mktemp(prefix='minemeld.ftsttest')
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

    def test_add_delete(self):
        st = minemeld.ft.st.ST(TABLENAME, 8, truncate=True)

        sid = uuid.uuid4().bytes

        st.put(sid, 1, 5, 1)
        st.delete(sid, 1, 5, 1)

    def test_basic_cover(self):
        st = minemeld.ft.st.ST(TABLENAME, 8, truncate=True)

        sid = uuid.uuid4().bytes

        st.put(sid, 1, 5, 1)
        for i in range(1, 6):
            ci = st.cover(i)

            interval = next(ci, None)
            self.assertEqual(interval[0], sid)
            self.assertEqual(interval[1], 1)
            self.assertEqual(interval[2], 1)
            self.assertEqual(interval[3], 5)

            interval2 = next(ci, None)
            self.assertEqual(interval2, None)

    def test_cover_overlap(self):
        st = minemeld.ft.st.ST(TABLENAME, 8, truncate=True)

        sid1 = uuid.uuid4().bytes
        sid2 = uuid.uuid4().bytes

        st.put(sid1, 1, 5, 1)
        st.put(sid2, 3, 7, 2)

        ci = st.cover(1)

        interval = next(ci, None)
        self.assertEqual(interval[0], sid1)
        self.assertEqual(interval[1], 1)
        self.assertEqual(interval[2], 1)
        self.assertEqual(interval[3], 5)

        interval = next(ci, None)
        self.assertEqual(interval, None)

        ci = st.cover(3)

        intervals = [i for i in st.cover(3)]
        self.assertEqual(len(intervals), 2)
        self.assertEqual(intervals[1][0], sid1)
        self.assertEqual(intervals[1][1], 1)
        self.assertEqual(intervals[1][2], 1)
        self.assertEqual(intervals[1][3], 5)
        self.assertEqual(intervals[0][0], sid2)
        self.assertEqual(intervals[0][1], 2)
        self.assertEqual(intervals[0][2], 3)
        self.assertEqual(intervals[0][3], 7)

        ci = st.cover(7)

        interval = next(ci, None)
        self.assertEqual(interval[0], sid2)
        self.assertEqual(interval[1], 2)
        self.assertEqual(interval[2], 3)
        self.assertEqual(interval[3], 7)

        interval = next(ci, None)
        self.assertEqual(interval, None)

    def test_cover_overlap2(self):
        st = minemeld.ft.st.ST(TABLENAME, 8, truncate=True)

        sid1 = uuid.uuid4().bytes
        sid2 = uuid.uuid4().bytes

        st.put(sid1, 3, 7, 1)
        st.put(sid2, 3, 7, 2)

        intervals = [i for i in st.cover(3)]
        self.assertEqual(len(intervals), 2)
        self.assertEqual(intervals[0][0], sid2)
        self.assertEqual(intervals[0][1], 2)
        self.assertEqual(intervals[0][2], 3)
        self.assertEqual(intervals[0][3], 7)
        self.assertEqual(intervals[1][0], sid1)
        self.assertEqual(intervals[1][1], 1)
        self.assertEqual(intervals[1][2], 3)
        self.assertEqual(intervals[1][3], 7)

    def _random_map(self, nbits=10, nintervals=1000):
        epmax = (1 << nbits)-1

        rmap = [set() for i in xrange(epmax+1)]

        st = minemeld.ft.st.ST(TABLENAME, nbits, truncate=True)

        for j in xrange(nintervals):
            sid = uuid.uuid4().bytes
            end = random.randint(0, epmax)
            start = random.randint(0, epmax)
            if end < start:
                start, end = end, start
            st.put(sid, start, end, level=1)

            for k in xrange(start, end+1):
                rmap[k].add(sid)

        eps = []
        for ep, lvl, t, id_ in st.query_endpoints():
            if ep == 0 or ep == epmax:
                self.assertTrue(len(rmap[ep]) > 0)
            else:
                c = len(rmap[ep] ^ rmap[ep-1]) + len(rmap[ep] ^ rmap[ep+1])
                self.assertTrue(
                    c > 0,
                    msg="no change detected @ep %d: "
                        "%r %r %r" % (ep, rmap[ep-1], rmap[ep], rmap[ep+1])
                )
            eps.append(ep)

        for e in eps:
            intervals = [x[0] for x in st.cover(e)]
            intervals.sort()
            self.assertListEqual(intervals, sorted(rmap[e]))

    def test_random_map_fast(self):
        self._random_map()

    def test_random_map_fast2(self):
        self._random_map(nintervals=2000)

    @attr('slow')
    def test_stress_1(self):
        num_intervals = 100000
        st = minemeld.ft.st.ST(TABLENAME, 32, truncate=True)

        t1 = time.time()
        for j in xrange(num_intervals):
            end = random.randint(0, 0xFFFFFFFF)
            start = random.randint(0, end)
            sid = uuid.uuid4().bytes
        t2 = time.time()
        dt = t2-t1

        t1 = time.time()
        for j in xrange(num_intervals):
            end = random.randint(0, 0xFFFFFFFF)
            start = random.randint(0, end)
            sid = uuid.uuid4().bytes
            st.put(sid, start, end)
            t2 = time.time()
        print "TIME: Inserted %d intervals in %d" % (num_intervals, (t2-t1-dt))

        num_queries = 100000

        t1 = time.time()
        j = 0
        for j in xrange(num_queries):
            q = random.randint(0, 0xFFFFFFFF)
            next(st.cover(q), None)
        t2 = time.time()
        print "TIME: Queried %d times in %d" % (num_queries, (t2-t1))
