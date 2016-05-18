#!/usr/bin/env python

import shutil
import minemeld.traced.storage
import random
import time

if __name__ == "__main__":
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
    # shutil.rmtree('1970-01-01')

