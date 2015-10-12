from __future__ import absolute_import

import logging
import ujson
import datetime
import socket

from . import base

LOG = logging.getLogger(__name__)


class LogstashOutput(base.BaseFT):
    def __init__(self, name, chassis, config):
        super(LogstashOutput, self).__init__(name, chassis, config)

        self._ls_socket = None

    def configure(self):
        super(LogstashOutput, self).configure()

        self.logstash_host = self.config.get('logstash_host', 'localhost')
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
            fields['$indicator'] = indicator

        if source is not None:
            fields['$origin'] = source

        if value is not None:
            fields.update(value)

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
        return self.statistics['message.sent']
