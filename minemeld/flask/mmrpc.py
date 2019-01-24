import json

import gevent
import gevent.event
import gevent.queue
import werkzeug.local

from flask import g

import minemeld.comm
from minemeld.mgmtbus import MGMTBUS_PREFIX, MGMTBUS_MASTER

from . import config
from .logger import LOG


__all__ = ['init_app', 'MMMaster', 'MMRpcClient']


class _MMMasterConnection(object):
    def __init__(self):
        self.comm = None

        tconfig = config.get('MGMTBUS', {})
        self.comm_class = tconfig.get('class', 'ZMQRedis')
        self.comm_config = tconfig.get('config', {})

    def _open_channel(self):
        if self.comm is not None:
            return

        self.comm = minemeld.comm.factory(
            self.comm_class,
            self.comm_config
        )
        self.comm.start()

    def _send_cmd(self, method, params={}):
        self._open_channel()

        return self.comm.send_rpc(
            MGMTBUS_MASTER,
            method,
            params,
            timeout=10.0
        )

    def status(self):
        return self._send_cmd('status')

    def stop(self):
        if self.comm is not None:
            self.comm.stop()
            self.comm = None


class _MMRpcClient(object):
    def __init__(self):
        self.comm = None

        tconfig = config.get('MGMTBUS', {})
        self.comm_class = tconfig.get('class', 'ZMQRedis')
        self.comm_config = tconfig.get('config', {})

    def _open_channel(self):
        if self.comm is not None:
            return

        self.comm = minemeld.comm.factory(
            self.comm_class,
            self.comm_config
        )
        self.comm.start()

    def send_raw_cmd(self, target, method, params={}, timeout=10):
        self._open_channel()

        return self.comm.send_rpc(target, method, params, timeout=timeout)

    def send_cmd(self, target, method, params={}, timeout=10):
        target = '{}directslave:{}'.format(MGMTBUS_PREFIX, target)

        return self.send_raw_cmd(target, method, params=params, timeout=timeout)

    def stop(self):
        if self.comm is not None:
            self.comm.stop()
            self.comm = None


def get_mmmaster():
    r = getattr(g, 'MMMaster', None)
    if r is None:
        r = _MMMasterConnection()
        g.MMMaster = r
    return r


MMMaster = werkzeug.LocalProxy(get_mmmaster)  # pylint:disable=E1101


def get_mmrpcclient():
    r = getattr(g, 'MMRpcClient', None)
    if r is None:
        r = _MMRpcClient()
        g.MMRpcClient = r
    return r


MMRpcClient = werkzeug.LocalProxy(get_mmrpcclient)  # pylint:disable=E1101


def teardown(exception):
    r = getattr(g, 'MMMaster', None)
    if r is not None:
        g.MMMaster.stop()
        g.MMMaster = None

    r = getattr(g, 'MMRpcClient', None)
    if r is not None:
        g.MMRpcClient.stop()
        g.MMRpcClient = None


def init_app(app):
    app.teardown_appcontext(teardown)
