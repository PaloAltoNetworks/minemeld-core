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
This module implements the writer class for logs
"""

import logging

import psutil
import ujson
import gevent
import gevent.event

LOG = logging.getLogger(__name__)


class DiskSpaceMonitor(gevent.Greenlet):
    def __init__(self, threshold, low_disk):
        self._threshold = threshold
        self._low_disk = low_disk

        super(DiskSpaceMonitor, self).__init__()

    def _run(self):
        while True:
            perc_used = psutil.disk_usage('.').percent

            if perc_used >= self._threshold:
                if not self._low_disk.is_set():
                    self._low_disk.set()
                    LOG.critical(
                        'Disk space used above threshold ({}%), writing disabled'.format(self._threshold)
                    )

            else:
                if self._low_disk.is_set():
                    self._low_disk.clear()
                    LOG.info('Disk space used below threshold, writing restored')

            gevent.sleep(60)


class Writer(object):
    def __init__(self, comm, store, topic, config):
        self._stop = gevent.event.Event()
        self._low_disk = gevent.event.Event()

        self.store = store
        self.comm = comm
        self.comm.request_sub_channel(
            topic,
            self,
            allowed_methods=['log'],
            name='mbus:log:writer',
            multi_write=True
        )

        self._disk_monitor_glet = DiskSpaceMonitor(
            threshold=config.get('threshold', 70),
            low_disk=self._low_disk
        )
        self._disk_monitor_glet.start()

    def log(self, timestamp, **kwargs):
        if self._stop.is_set():
            return

        if self._low_disk.is_set():
            return

        self.store.write(timestamp, ujson.dumps(kwargs))

    def stop(self):
        LOG.info('Writer - stop called')

        if self._stop.is_set():
            return

        self._stop.set()
        self._disk_monitor_glet.kill()
