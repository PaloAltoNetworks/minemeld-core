"""gevent_openssl.SSL - gevent compatibility with OpenSSL.SSL (pyOpenSSL)
"""

import logging

import OpenSSL.SSL
from gevent.socket import wait_read, wait_write

_real_connection = OpenSSL.SSL.Connection


LOG = logging.getLogger(__name__)


class Connection(object):
    """OpenSSL Connection wrapper
    """

    _reverse_mapping = _real_connection._reverse_mapping

    def __init__(self, context, sock):
        self._context = context
        self._sock = sock
        self._connection = _real_connection(context, sock)

    def __getattr__(self, attr):
        return getattr(self._connection, attr)

    def __iowait(self, io_func, *args, **kwargs):
        fd = self._sock.fileno()
        timeout = self._sock.gettimeout()
        while True:
            try:
                return io_func(*args, **kwargs)
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                wait_read(fd, timeout=timeout)
            except OpenSSL.SSL.WantWriteError:
                wait_write(fd, timeout=timeout)

    def accept(self):
        sock, addr = self._sock.accept()
        return Connection(self._context, sock), addr

    def do_handshake(self):
        # handshake is blocking as some sites are super sensible
        # to handshake timeouts (to avoid DDoS)
        return self._connection.do_handshake()

    def connect(self, *args, **kwargs):
        return self.__iowait(self._connection.connect, *args, **kwargs)

    def send(self, data, flags=0):
        return self.__send(self._connection.send, data, flags)

    def sendall(self, data, flags=0):
        # see https://github.com/mjs/gevent_openssl/issues/12
        # Note: all of the types supported by OpenSSL's Connection.sendall,
        # basestring, memoryview, and buffer, support len(...) and slicing,
        # so they are safe to use here.
        while len(data) > 0:
            res = self.send(data, flags)
            data = data[res:]

    def __send(self, send_method, data, flags=0):
        try:
            return self.__iowait(send_method, data, flags)
        except OpenSSL.SSL.SysCallError as e:
            if e[0] == -1 and not data:
                # errors when writing empty strings are expected and can be
                # ignored
                return 0
            raise

    def recv(self, bufsiz, flags=0):
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        try:
            return self.__iowait(self._connection.recv, bufsiz, flags)
        except OpenSSL.SSL.ZeroReturnError:
            return ''
        except OpenSSL.SSL.SysCallError as e:
            if e[0] == -1 and 'Unexpected EOF' in e[1]:
                # errors when reading empty strings are expected and can be
                # ignored
                return ''
            raise

    def shutdown(self):
        return self.__iowait(self._connection.shutdown)
