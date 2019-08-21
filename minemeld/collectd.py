#  Copyright 2015-2016 Palo Alto Networks, Inc
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
minemeld.collectd

Provides a client to collectd for storing metrics.
"""

import socket
import logging

LOG = logging.getLogger(__name__)


class CollectdClient(object):
    """Collectd client.

    Args:
        path (str): path to the collectd unix socket
    """
    def __init__(self, path):
        self.path = path
        self.socket = None

    def _open_socket(self):
        if self.socket is not None:
            return

        if self.path.startswith('tcp://'):
            hostinfo = self.path[6:].split(':')
            _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _socket.connect((hostinfo[0], int(hostinfo[1])))
        else:
            _socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            _socket.connect(self.path)

        self.socket = _socket

    def _readline(self):
        result = ''

        data = None
        while data != '\n':
            data = self.socket.recv(1)
            if data == '\n' or data is None:
                return result
            result += data

    def _send_cmd(self, command):
        self._open_socket()
        self.socket.send(command+'\n')

        ans = self._readline()
        status, message = ans.split(None, 1)

        status = int(status)
        if status < 0:
            raise RuntimeError('Error communicating with collectd %s' %
                               message)
        message = [message]
        for _ in range(status):
            message.append(self._readline())

        return status, '\n'.join(message)

    def flush(self, identifier=None, timeout=None):
        cmd = 'FLUSH'
        if timeout is not None:
            cmd += ' timeout=%d' % timeout
        if identifier is not None:
            cmd += ' identifier=%s' % identifier

        self._send_cmd(
            cmd
        )

    def putval(self, identifier, value, timestamp='N',
               type_='minemeld_counter', hostname='minemeld', interval=None):
        if isinstance(timestamp, int):
            timestamp = '%d' % timestamp

        identifier = '/'.join([hostname, identifier, type_])
        command = 'PUTVAL %s' % identifier
        if interval is not None:
            command += ' interval=%d' % interval

        command += ' %s:%d' % (timestamp, value)

        self._send_cmd(command)
