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

import time
import operator
import functools
import datetime
import pytz
import re

import gevent.lock
import gevent.event


EPOCH = datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.UTC)


def utc_millisec():
    return int(time.time()*1000)


def dt_to_millisec(dt):
    delta = dt - EPOCH
    return int(delta.total_seconds()*1000)


def interval_in_sec(val):
    multipliers = {
        '': 1,
        'm': 60,
        'h': 3600,
        'd': 86400
    }

    mo = re.match("([0-9]+)([dmh]?)", val)
    if mo is None:
        return None

    return int(mo.group(1))*multipliers[mo.group(2)]


def age_out_in_millisec(val):
    multipliers = {
        '': 1000,
        'm': 60000,
        'h': 3600000,
        'd': 86400000
    }

    mo = re.match("([0-9]+)([dmh]?)", val)
    if mo is None:
        return None

    return int(mo.group(1))*multipliers[mo.group(2)]


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


_AGE_OUT_BASES = ['last_seen', 'first_seen']


def parse_age_out(s, age_out_bases=None, default_base=None):
    if s is None:
        return None

    if age_out_bases is None:
        age_out_bases = _AGE_OUT_BASES

    if default_base is None:
        default_base = 'first_seen'

    if default_base not in age_out_bases:
        raise ValueError('%s not in %s' % (default_base, age_out_bases))

    result = {}

    toks = s.split('+', 1)
    if len(toks) == 1:
        t = toks[0].strip()
        if t in age_out_bases:
            result['base'] = t
            result['offset'] = 0
        else:
            result['base'] = default_base
            result['offset'] = age_out_in_millisec(t)
            if result['offset'] is None:
                raise ValueError('Invalid age out offset %s' % t)
    else:
        base = toks[0].strip()
        if base not in age_out_bases:
            raise ValueError('Invalid age out base %s' % base)
        result['base'] = base
        result['offset'] = age_out_in_millisec(toks[1].strip())
        if result['offset'] is None:
            raise ValueError('Invalid age out offset %s' % t)

    return result
