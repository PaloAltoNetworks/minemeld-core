import time
import calendar
import operator
import functools
import datetime
import pytz

import gevent.lock
import gevent.event


EPOCH = datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.UTC)


def utc_millisec():
    return int(calendar.timegm(time.gmtime())*1000)


def dt_to_millisec(dt):
    delta = dt - EPOCH
    return int(delta.total_seconds()*1000)


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
        self.num_readers = 0
        self.num_writers = 0

        self.m1 = gevent.lock.Semaphore(1)
        self.m2 = gevent.lock.Semaphore(1)
        self.m3 = gevent.lock.Semaphore(1)
        self.w = gevent.lock.Semaphore(1)
        self.r = gevent.lock.Semaphore(1)

    def lock(self):
        self.m2.acquire()

        self.num_writers += 1
        if self.num_writers == 1:
            self.r.acquire()

        self.m2.release()
        self.w.acquire()

    def unlock(self):
        self.w.release()
        self.m2.acquire()

        self.num_writers -= 1
        if self.num_writers == 0:
            self.r.release()

        self.m2.release()

    def rlock(self):
        self.m3.acquire()
        self.r.acquire()
        self.m1.acquire()

        self.num_readers += 1
        if self.num_readers == 1:
            self.w.acquire()

        self.m1.release()
        self.r.release()
        self.m3.release()

    def runlock(self):
        self.m1.acquire()

        self.num_readers -= 1
        if self.num_readers == 0:
            self.w.release()

        self.m1.release()
