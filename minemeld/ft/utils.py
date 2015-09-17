import time
import calendar
import operator
import functools

import gevent.lock
import gevent.event


def utc_millisec():
    return int(calendar.timegm(time.gmtime())*1000)


def _merge_atomic_values(op, v1, v2):
    if op(v1, v2):
        return v2
    return v1


def _merge_array(v1, v2):
    for e in v2:
        if e not in v1:
            v1.append(e)
    return v1


RESERVED_ATTRIBUTES = {
    'sources': _merge_array,
    'first_seen': functools.partial(_merge_atomic_values, operator.gt),
    'last_seen': functools.partial(_merge_atomic_values, operator.lt),
    'type': functools.partial(_merge_atomic_values, operator.eq),
    'direction': functools.partial(_merge_atomic_values, operator.eq),
    'confidence': functools.partial(_merge_atomic_values, operator.lt),
    'country': functools.partial(_merge_atomic_values, operator.eq),
    'AS': functools.partial(_merge_atomic_values, operator.eq)
}


class RWLock(object):
    def __init__(self):
        self.mwrite = gevent.lock.Semaphore(1)
        self.mread = gevent.lock.Semaphore(1)
        self.num_readers = 0
        self.waitableobject = gevent.event.Event()

    def lock(self):
        self.mwrite.acquire()
        self.waitableobject.wait()

    def unlock(self):
        self.mwrite.release()

    def rlock(self):
        self.mwrite.acquire()
        self.mread.acquire()

        self.num_readers += 1
        if self.num_readers == 1:
            self.waitableobject.clear()

        self.mread.release()
        self.mwrite.release()

    def runlock(self):
        self.mread.acquire()

        self.num_readers -= 1
        if self.num_readers == 0:
            self.waitableobject.set()

        self.mread.release()
