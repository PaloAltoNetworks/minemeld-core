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
import os
import os.path

import gevent.queue
import gevent.event
import gevent.lock

import plyvel
import pytz

LOG = logging.getLogger(__name__)

START_KEY = '%016x%015x' % (0, 0)

TABLE_MAX_COUNTER_KEY = 'MAX_COUNTER'


class TableNotFound(Exception):
    pass


class Table(object):
    def __init__(self, name, create_if_missing=True):
        LOG.debug('New table: %s %s', name, create_if_missing)

        self.name = name
        self.last_used = None
        self.refs = []

        if not create_if_missing and not os.path.exists(name):
            raise TableNotFound('Table does not exists')

        try:
            self.db = plyvel.DB(
                name,
                create_if_missing=create_if_missing
            )

        except plyvel.Error as e:
            if not create_if_missing:
                raise TableNotFound(str(e))
            raise

        self.max_counter = None
        try:
            self.max_counter = self.db.get(TABLE_MAX_COUNTER_KEY)

        except KeyError:
            pass

        if self.max_counter is None:
            LOG.warning(
                'MAX_ID key not found in %s',
                self.name
            )
            self.max_counter = -1

        else:
            self.max_counter = int(self.max_counter, 16)

        LOG.debug('Table %s - max id: %d', self.name, self.max_counter)

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
        self.last_used = time.time()

        self.max_counter += 1
        new_max_counter = '%016x' % self.max_counter

        batch = self.db.write_batch()
        batch.put(key+new_max_counter, value)
        batch.put(TABLE_MAX_COUNTER_KEY, new_max_counter)
        batch.write()

    def backwards_iterator(self, timestamp, counter):
        return self.db.iterator(
            start=START_KEY,
            stop=('%016x%016x' % (timestamp, counter)),
            include_start=False,
            include_stop=True,
            reverse=True
        )

    def close(self):
        self.db.close()

    @staticmethod
    def oldest_table():
        # XXX we should switch to something iterative
        entries = os.listdir('.')
        if len(entries) == 0:
            return None

        tables = []
        for e in entries:
            try:
                int(e, 16)
            except:
                continue

            tables.append(e)

        if len(tables) == 0:
            return None

        tables = sorted(tables)
        return tables[0]


def _lock_current_tables():
    """Decorator for locking current_tables
    """
    def _lock_out(f):
        def _lock_in(self, *args, **kwargs):
            self.current_tables_lock.acquire()

            try:
                result = f(self, *args, **kwargs)

            finally:
                self.current_tables_lock.release()

            return result
        return _lock_in
    return _lock_out


class Store(object):
    def __init__(self, config=None):
        if config is None:
            config = {}

        self._stop = gevent.event.Event()

        self.max_tables = config.get('max_tables', 5)

        self.current_tables = {}
        self.current_tables_lock = gevent.lock.BoundedSemaphore()

        self.max_written_timestamp = None
        self.max_written_counter = 0

        self.add_queue = gevent.queue.PriorityQueue()

    def _open_table(self, name, create_if_missing):
        table = Table(name, create_if_missing=create_if_missing)
        self.current_tables[name] = table

        return table

    def _close_table(self, table):
        table.close()
        self.current_tables.pop(table.name)

    def _add_table(self, name, priority, create_if_missing=True):
        self.current_tables_lock.acquire()
        if len(self.current_tables) < self.max_tables:
            try:
                result = self._open_table(
                    name,
                    create_if_missing=create_if_missing
                )
            finally:
                self.current_tables_lock.release()
            return result
        self.current_tables_lock.release()

        future_table = gevent.event.AsyncResult()
        self.add_queue.put((
            priority,
            (future_table, name, create_if_missing)
        ))
        self._process_queue()

        return future_table.get()

    def _get_table(self, day, ref, create_if_missing=True):
        self.current_tables_lock.acquire()
        table = self.current_tables.get(day, None)
        self.current_tables_lock.release()

        if table is None:
            prio = 99 if ref != 'write' else 1
            table = self._add_table(
                day,
                prio,
                create_if_missing=create_if_missing
            )

        table.add_reference(ref)

        return table

    @_lock_current_tables()
    def _process_queue_element(self, name, ftable, create_if_missing):
        if name in self.current_tables:
            ftable.set(self.current_tables[name])
            return True

        if len(self.current_tables) < self.max_tables:
            new_table = self._open_table(
                name,
                create_if_missing=create_if_missing
            )
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

        new_table = self._open_table(
            name,
            create_if_missing=create_if_missing
        )
        ftable.set(new_table)

        return True

    def _process_queue(self):
        # this is for perf improvement
        if self.add_queue.empty():
            return

        try:
            while True:
                prio, (ftable, name, create_if_missing) = \
                    self.add_queue.get_nowait()

                result = self._process_queue_element(
                    name,
                    ftable,
                    create_if_missing
                )
                if not result:
                    prio = (prio - 1) if prio > 2 else prio
                    self.add_queue.put((
                        prio,
                        (ftable, name, create_if_missing)
                    ))
                    return

        except IndexError:
            return

        except Queue.Empty:
            return

    def _release(self, table, ref):
        table.remove_reference(ref)

        self._process_queue()

    def write(self, timestamp, log):
        if self._stop.is_set():
            raise RuntimeError('stopping')

        tssec = timestamp/1000
        day = '%016x' % (tssec - (tssec % 86400))

        table = self._get_table(day, 'write')

        try:
            table.put(
                '%016x' % timestamp,
                log
            )

        finally:
            self._release(table, 'write')

    def iterate_backwards(self, ref, timestamp, counter):
        if self._stop.is_set():
            raise RuntimeError('stopping')

        tssec = timestamp/1000
        current_day = (tssec - (tssec % 86400))

        oldest_table = Table.oldest_table()
        if oldest_table is None:
            yield {'msg': 'No more logs to check'}
            return

        while True:
            table_name = '%016x' % current_day
            if table_name < oldest_table:
                yield {'msg': 'No more logs to check'}
                return

            day = datetime.datetime.fromtimestamp(
                current_day,
                pytz.UTC
            )
            day = '%04d-%02d-%02d' % (
                day.year,
                day.month,
                day.day
            )
            yield {'msg': 'Checking %s' % day}

            try:
                table = self._get_table(
                    table_name,
                    ref,
                    create_if_missing=False
                )
            except TableNotFound:
                if current_day == 0:
                    # XXX this is unreachable
                    yield {'msg': 'This should be unreachable'}
                    return

                current_day -= 86400
                continue

            table_iterator = table.backwards_iterator(
                timestamp=timestamp,
                counter=counter
            )

            for linets, line in table_iterator:
                yield {
                    'timestamp': int(linets[:16], 16),
                    'counter': int(linets[16:], 16),
                    'log': line
                }

            self._release(table, ref)

            if current_day == 0:
                yield {'msg': 'We haved reached the origins of time'}
                return

            current_day -= 86400

    def release_all(self, ref):
        if self._stop.is_set():
            raise RuntimeError('stopping')

        self.current_tables_lock.acquire()
        for t in self.current_tables.values():
            t.remove_reference(ref)
        self.current_tables_lock.release()

        self._process_queue()

    def stop(self):
        LOG.info('Store - stop called')

        if self._stop.is_set():
            return

        self._stop.set()
        self.current_tables_lock.acquire()
        for t in self.current_tables.keys():
            self.current_tables[t].close()
            self.current_tables.pop(t, None)
        self.current_tables_lock.release()
