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
import ujson
import gevent.event

LOG = logging.getLogger(__name__)


class Writer(object):
    def __init__(self, comm, store, topic):
        self._stop = gevent.event.Event()

        self.store = store
        self.comm = comm
        self.comm.request_sub_channel(
            topic,
            self,
            allowed_methods=['log'],
            name='mbus:log:writer'
        )

    def log(self, timestamp, **kwargs):
        if self._stop.is_set():
            return

        self.store.write(timestamp, ujson.dumps(kwargs))

    def stop(self):
        LOG.info('Writer - stop called')

        if self._stop.is_set():
            return

        self._stop.set()
