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
This module implements the query processor for mm-traced daemon
"""

import logging
import calendar
import time
import ujson
import re

import gevent
import greenlet
import gevent.lock
import gevent.event
import redis

LOG = logging.getLogger(__name__)

QUERY_QUEUE = 'mmtraced:query'


class Query(gevent.Greenlet):
    def __init__(self, store, query, timestamp, counter,
                 num_lines, uuid, redis_config):
        self.uuid = uuid
        self.store = store

        self.query = query

        self.starting_timestamp = timestamp
        self.starting_counter = counter
        self.num_lines = num_lines

        self.redis_host = redis_config.get('host', 'localhost')
        self.redis_port = redis_config.get('port', 6379)
        self.redis_password = redis_config.get('password', None)
        self.redis_db = redis_config.get('db', 0)

        super(Query, self).__init__()

        LOG.info("Query %s - %s", uuid, query)
        self._parse_query(query)

    def _parse_query(self, query):
        query = query.strip()
        components = query.lower().split()

        field_specific = re.compile('^[\w$]+:.*$')

        self.parsed_query = []
        for c in components:
            negate = False
            if c[0] == '-':
                negate = True
                c = c[1:]

            matching_re = c
            if field_specific.match(c) is not None:
                field, value = c.split(':', 1)
                matching_re = (
                    '"%(field)s":(?:\[(?:".*",)*)?"*[^"]*%(value)s' %
                    {
                        'field': field,
                        'value': value
                    }
                )

            self.parsed_query.append({
                're': re.compile(matching_re, re.IGNORECASE),
                'negate': negate
            })

    def _check_query(self, log):
        for q in self.parsed_query:
            occ = q['re'].search(log)
            if not ((occ is not None) ^ q['negate']):
                return False
        return True

    def _run(self):
        LOG.debug("Query %s started", self.uuid)

        SR = redis.StrictRedis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password,
            db=self.redis_db
        )

        line_generator = self.store.iterate_backwards(
            self.uuid,
            self.starting_timestamp,
            self.starting_counter
        )

        num_generated_lines = 0
        while num_generated_lines < self.num_lines:
            line = next(line_generator, None)
            if not line:
                break

            gevent.sleep(0)

            if 'log' not in line:
                SR.publish('mm-traced-q.'+self.uuid, ujson.dumps(line))
                continue

            if self._check_query(line['log']):
                SR.publish('mm-traced-q.'+self.uuid, ujson.dumps(line))
                num_generated_lines += 1

        SR.publish(
            'mm-traced-q.'+self.uuid,
            '{"msg": "Loaded %d lines"}' % num_generated_lines
        )
        SR.publish('mm-traced-q.'+self.uuid, '<EOQ>')
        LOG.info("Query %s finished - %d", self.uuid, num_generated_lines)

        # make sure we release the tables if we stop in the middle
        # of an iteration
        self.store.release_all(self.uuid)


class QueryProcessor(object):
    def __init__(self, comm, store, config=None):
        if config is None:
            config = {}

        self._stop = gevent.event.Event()

        self.max_concurrency = config.get('max_concurrency', 10)
        self.redis_config = config.get('redis', {})
        self.store = store

        self.queries_lock = gevent.lock.BoundedSemaphore()
        self.queries = {}

        comm.request_rpc_server_channel(
            QUERY_QUEUE,
            self,
            allowed_methods=['query', 'kill_query']
        )

    def _query_finished(self, gquery):
        self.queries_lock.acquire()
        self.queries.pop(gquery.uuid, None)
        self.queries_lock.release()

        try:
            result = gquery.get()

        except:
            self.store.release_all(gquery.uuid)
            LOG.exception('Query finished with exception')
            return

        if isinstance(result, greenlet.GreenletExit):
            self.store.release_all(gquery.uuid)

    def query(self, uuid, query, timestamp=None, counter=None, num_lines=None):
        if self._stop.is_set():
            raise RuntimeError('stopping')

        if timestamp is None:
            timestamp = int(calendar.timegm(time.gmtime())*1000)

        if counter is None:
            counter = 0xFFFFFFFFFFFFFFFF

        if num_lines is None:
            num_lines = 100

        self.queries_lock.acquire()

        if len(self.queries) >= self.max_concurrency:
            self.queries_lock.release()
            raise RuntimeError('max number of concurrent queries reached')

        if uuid in self.queries:
            self.queries_lock.release()
            raise RuntimeError('UUID not unique')

        try:
            gquery = Query(
                self.store,
                query,
                timestamp,
                counter,
                num_lines,
                uuid,
                self.redis_config
            )
            gquery.link(self._query_finished)
            self.queries[uuid] = gquery
            gquery.start()

        finally:
            self.queries_lock.release()

        return 'OK'

    def kill_query(self, uuid):
        if self._stop.is_set():
            raise RuntimeError('stopping')

        self.queries_lock.acquire()
        if uuid in self.queries:
            self.queries[uuid].kill()
        self.queries_lock.release()

        return 'OK'

    def stop(self):
        LOG.info('QueryProcessor - stop called')

        if self._stop.is_set():
            return

        self._stop.set()
        self.queries_lock.acquire()
        for q, gquery in self.queries.iteritems():
            gquery.kill()
        self.queries_lock.release()
