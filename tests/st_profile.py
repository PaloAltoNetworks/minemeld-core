#!/usr/bin/env python

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
