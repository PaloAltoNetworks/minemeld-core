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

from __future__ import absolute_import

import logging
import ujson
import datetime
import socket

from . import base
from . import actorbase

LOG = logging.getLogger(__name__)


class LogstashOutput(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        super(LogstashOutput, self).__init__(name, chassis, config)

        self._ls_socket = None

    def configure(self):
        super(LogstashOutput, self).configure()

        self.logstash_host = self.config.get('logstash_host', '127.0.0.1')
        self.logstash_port = int(self.config.get('logstash_port', '5514'))

    def connect(self, inputs, output):
        output = False
        super(LogstashOutput, self).connect(inputs, output)

    def _connect_logstash(self):
        if self._ls_socket is not None:
            return

        _ls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _ls_socket.connect((self.logstash_host, self.logstash_port))

        self._ls_socket = _ls_socket

    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    def _send_logstash(self, message, source=None, indicator=None, value=None):
        now = datetime.datetime.now()

        fields = {
            '@timestamp': now.isoformat()+'Z',
            '@version': 1,
            'logstash_output_node': self.name,
            'message': message
        }

        if indicator is not None:
            fields['@indicator'] = indicator

        if source is not None:
            fields['@origin'] = source

        if value is not None:
            fields.update(value)

        if 'last_seen' in fields:
            last_seen = datetime.datetime.fromtimestamp(
                float(fields['last_seen'])/1000.0
            )
            fields['last_seen'] = last_seen.isoformat()+'Z'

        if 'first_seen' in fields:
            first_seen = datetime.datetime.fromtimestamp(
                float(fields['first_seen'])/1000.0
            )
            fields['first_seen'] = first_seen.isoformat()+'Z'

        try:
            self._connect_logstash()
            self._ls_socket.sendall(ujson.dumps(fields)+'\n')
        except:
            self._ls_socket = None
            raise

        self.statistics['message.sent'] += 1

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        self._send_logstash(
            'update',
            source=source,
            indicator=indicator,
            value=value
        )

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        self._send_logstash(
            'withdraw',
            source=source,
            indicator=indicator,
            value=value
        )

    def length(self, source=None):
        return 0
