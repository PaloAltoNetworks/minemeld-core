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
This module implements the storage mechansim for the mm-traced daemon
"""

import logging
import datetime
import time
import Queue

import gevent.queue
import gevent.event

import plyvel
import pytz

LOG = logging.getLogger(__name__)


class Table(object):
    def __init__(self, name):
        LOG.debug('New table: %s', name)

        self.name = name
        self.last_used = None
        self.refs = []

        self.db = plyvel.DB(
            name,
            create_if_missing=True
        )

    def add_reference(self, refid):
        self.refs.append(refid)

    def remove_reference(self, refid):
        try:
            self.refs.remove(refid)

        except ValueError:
            LOG.warning(
                'Attempt to remove non existing reference: %s - %s',
                refid,
                self.name
            )

    def ref_count(self):
        return len(self.refs)

    def put(self, key, value):
        LOG.debug('table %s - writing %s', self.name, key)
        self.last_used = time.time()

        self.db.put(key, value)

class Store(object):
    def __init__(self, config=None):
        if config is None:
            config = {}

        self.max_tables = config.get('max_tables', 5)

        self.current_tables = {}

        self.last_timestamp = None
        self.last_counter = 0

        self.add_queue = gevent.queue.PriorityQueue()

    def _open_table(self, name):
        LOG.debug('_open_table: %s', name)
        table = Table(name)
        self.current_tables[name] = table

        return table

    def _close_table(self, table):
        table.close()
        self.current_tables.pop(table.name)

    def _add_table(self, name, priority):
        LOG.debug('_add_table: %s', name)
        if len(self.current_tables) < self.max_tables:
            return self._open_table(name)

        future_table = gevent.event.AsyncResult()
        self.add_queue.put((priority, (future_table, name)))
        
        return future_table.get()

    def _get_table(self, day, ref):
        table = self.current_tables.get(day, None)
        if table is None:
            prio = 99 if ref != 'write' else 1
            table = self._add_table(day, prio)

        table.add_reference(ref)

        return table

    def _process_queue_element(self, name, ftable):
        if name in self.current_tables:
            ftable.set(self.current_tables[name])
            return True

        if len(self.current_tables) < self.max_tables:
            new_table = self._open_table(name)
            ftable.set(new_table)
            return True

        # garbage collect
        candidate = None
        for tname, table in self.current_tables.iteritems():
            if table.ref_count() != 0:
                continue

            if candidate is None or candidate.last_used > table.last_used:
                candidate = table

        if candidate is None:
            return False

        self._close_table(candidate)

        new_table = self._open_table(name)
        ftable.set(new_table)

        return True

    def _process_queue(self):
        try:
            while True:
                prio, (ftable, name) = self.add_queue.get_nowait()

                if not self._process_queue_element(name, ftable):
                    prio = (prio - 1) if prio > 2 else prio
                    self.add_queue.put((prio, (ftable, name)))
                    return

        except IndexError:
            return

        except Queue.Empty:
            return

    def _release(self, table, ref):
        table.remove_reference(ref)

        self._process_queue()

    def write(self, timestamp, log):
        dt = datetime.datetime.fromtimestamp(
            timestamp/1000.0,
            pytz.UTC
        )
        day = '%04d-%02d-%02d' % (dt.year, dt.month, dt.day)

        table = self._get_table(day, 'write')

        LOG.debug('%s %s', timestamp, self.last_timestamp)
        if timestamp == self.last_timestamp:
            self.last_counter += 1
        else:
            self.last_timestamp = timestamp
            self.last_counter = 0

        try:
            table.put(
                '%016x%08x' % (self.last_timestamp, self.last_counter),
                log
            )

        finally:
            self._release(table, 'write')
