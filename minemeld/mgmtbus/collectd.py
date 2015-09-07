import socket
import logging

LOG = logging.getLogger(__name__)

class CollectdClient(object):
    def __init__(self, path):
        self.path = path
        self.socket = None

    def _open_socket(self):
        if self.socket is not None:
            return

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
        LOG.debug('sending command %s', command)

        self._open_socket()
        self.socket.send(command+'\n')

        ans = self._readline()
        status, message = ans.split(None, 1)

        status = int(status)
        if status < 0:
            raise RuntimeError('Error communicating with collectd %s' %
                               message)
        message = [message]
        for i in range(status):
            message.append(self._readline())

        LOG.debug('command result %d %s', status, '\n'.join(message))

        return status, '\n'.join(message)

    def flush(self, timeout=None):
        self._send_cmd(
            'FLUSH'+('' if timeout is None else ' timeout=%d' % timeout)
        )

    def putval(self, identifier, value, timestamp='N', type_='minemeld_counter',
               hostname='minemeld', interval=None):
        if type(timestamp) == int:
            timestamp = '%d' % timestamp

        identifier = '/'.join([hostname, identifier, type_])
        command = 'PUTVAL %s' % identifier
        if interval is not None:
            command += ' interval=%d' % interval

        command += ' %s:%d' % (timestamp, value)

        self._send_cmd(command)
