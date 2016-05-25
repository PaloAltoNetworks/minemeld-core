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
This module implements mock classes for minemed.traced tests
"""

import gevent
import gevent.event

import logging

from minemeld.traced.storage import TableNotFound

LOG = logging.getLogger(__name__)


CLOCK = -1
def _get_clock():
    global CLOCK

    CLOCK += 1
    return CLOCK

MOCK_TABLES = []

class MockTable(object):
    def __init__(self, name, create_if_missing=True):
        self.name = name
        self.create_if_missing = create_if_missing

        self.last_used = None
        self.refs = []

        self.db_open = True
        self.db = {}

        self.max_counter = -1

    def add_reference(self, refid):
        self.refs.append(refid)

    def remove_reference(self, refid):
        try:
            self.refs.remove(refid)

        except ValueError:
            pass

    def ref_count(self):
        return len(self.refs)

    def put(self, key, value):
        self.last_used = _get_clock()

        self.max_counter += 1
        new_max_counter = '%016x' % self.max_counter

        self.db[key+new_max_counter] = value

    def backwards_iterator(self, timestamp, counter):
        starting_key = '%016x%016x' % (timestamp, counter)
        items = [[k, v] for k, v in self.db.iteritems() if k <= starting_key]
        items = sorted(items, cmp=lambda x, y: cmp(x[0], y[0]), reverse=True)
        return items

    def close(self):
        self.db_open = False

    @staticmethod
    def oldest_table():
        tables = [t.name for t in MOCK_TABLES]
        LOG.debug(tables)
        if len(tables) == 0:
            return None

        return sorted(tables)[0]

def table_factory(name, create_if_missing=True):
    table = next((t for t in MOCK_TABLES if t.name == name), None)
    if table is not None:
        return table

    if not create_if_missing:
        raise TableNotFound()

    mt = MockTable(name, create_if_missing=create_if_missing)
    MOCK_TABLES.append(mt)
    return mt

def table_cleanup():
    global MOCK_TABLES
    MOCK_TABLES = []

class MockStore(object):
    def __init__(self, config=None):
        if config is None:
            config = {}

        self.config = config
        self.writes = []
        self.db = {}
        self.counter = 0
        self.release_alls = []

    def write(self, timestamp, log):
        self.writes.append({
            'timestamp': timestamp,
            'log': log
        })
        self.db['%016x%016x' % (timestamp, self.counter)] = log
        self.counter += 1

    def iterate_backwards(self, ref, timestamp, counter):
        starting_key = '%016x%016x' % (timestamp, counter)
        items = [[k, v] for k, v in self.db.iteritems() if k <= starting_key]
        items = sorted(items, cmp=lambda x, y: cmp(x[0], y[0]), reverse=True)

        for c, i in enumerate(items):
            if c % 1 == 0:
                yield {'msg': 'test message'}
            yield {'timestamp': i[0], 'log': i[1]}

    def release_all(self, ref):
        self.release_alls.append(ref)

def store_factory(config=None):
    return MockStore(config=config)

MOCK_QUERIES = []

class MockQuery(gevent.Greenlet):
    def __init__(self, store, query, timestamp, counter, 
                 num_lines, uuid, redis_config):
        self.store = store
        self.query = query
        self.timestamp = timestamp
        self.counter = counter
        self.num_lines = num_lines
        self.uuid = uuid
        self.redis_config = redis_config

        self.finish_event = gevent.event.Event()

        super(MockQuery, self).__init__()

    def kill(self):
        LOG.debug("%s killed", self.uuid)
        super(MockQuery, self).kill()

    def _run(self):
        LOG.debug("%s started", self.uuid)
        self.finish_event.wait()
        LOG.debug("%s finished", self.uuid)

class MockEQuery(gevent.Greenlet):
    def __init__(self, store, query, timestamp, counter, 
                 num_lines, uuid, redis_config):
        self.store = store
        self.query = query
        self.timestamp = timestamp
        self.counter = counter
        self.num_lines = num_lines
        self.uuid = uuid
        self.redis_config = redis_config

        self.finish_event = gevent.event.Event()

        super(MockEQuery, self).__init__()

    def kill(self):
        LOG.debug("%s killed", self.uuid)
        super(MockEQuery, self).kill()

    def _run(self):
        LOG.debug("%s started", self.uuid)
        self.finish_event.wait()
        raise RuntimeError("BAD BAD QUERY!")

def query_factory(store, query, timestamp, counter, 
                 num_lines, uuid, redis_config):

    if query == "bad":
        mqf = MockEQuery
    else:
        mqf = MockQuery

    mq = mqf(store, query, timestamp, counter, 
                num_lines, uuid, redis_config)
    MOCK_QUERIES.append(mq)

    return mq

def query_cleanup():
    global MOCK_QUERIES
    MOCK_QUERIES = []
