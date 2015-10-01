#!/usr/bin/env python

import uuid
import random
import tempfile
import time

import minemeld.ft.st

TABLENAME = tempfile.mktemp(prefix='minemeld.ftsttest')


def queries(st):
    # t1 = time.time()
    # j = 0
    # for j in xrange(num_queries):
    #     q = random.randint(0, 0xFFFFFFFF)
    # t2 = time.time()
    # dt = t2-t1

    # t1 = time.time()

    j = 0
    for j in xrange(num_queries):
        q = random.randint(0, 0xFFFFFFFF)
        next(st.cover(q), None)
    # t2 = time.time()

    # print "TIME: Queried %d times in %d" % (num_queries, (t2-t1-dt))

if __name__ == '__main__':
    num_intervals = 100000
    num_queries = num_intervals

    st = minemeld.ft.st.ST(TABLENAME, 32, truncate=True)

    t1 = time.time()
    for j in xrange(num_intervals):
        end = random.randint(0, 0xFFFFFFFF)
        if random.randint(0, 1) == 0:
            end = end & 0xFFFFFF00
            start = end + 0xFF
        else:
            start = end
        sid = uuid.uuid4().bytes
    t2 = time.time()
    dt = t2-t1

    t1 = time.time()
    for j in xrange(num_intervals):
        end = random.randint(0, 0xFFFFFFFF)
        if random.randint(0, 1) == 0:
            start = end & 0xFFFFFF00
            end = start + 0xFF
        else:
            start = end
        sid = uuid.uuid4().bytes
        st.put(sid, start, end)
    t2 = time.time()
    print "TIME: Inserted %d intervals in %d" % (num_intervals, (t2-t1-dt))

    queries(st)
