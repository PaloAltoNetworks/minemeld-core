# amqp connection
import json
import logging

import gevent
import gevent.event
import gevent.queue
import amqp
import werkzeug.local

from flask import g

import minemeld.comm
from minemeld.mgmtbus import MGMTBUS_PREFIX

from . import config


__all__ = ['init_app', 'MMMaster', 'MMRpcClient', 'MMStateFanout']


LOG = logging.getLogger(__name__)


class _MMMasterConnection(object):
    def __init__(self):
        self.comm = None

        tconfig = config.get('MGMTBUS', {})
        self.comm_class = tconfig.get('class', 'AMQP')
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
            'mbus:master',
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
        self.comm_class = tconfig.get('class', 'AMQP')
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
        LOG.debug('MMRpcClient channel open')

        return self.comm.send_rpc(target, method, params, timeout=timeout)

    def send_cmd(self, target, method, params={}, timeout=10):
        target = '{}directslave:{}'.format(MGMTBUS_PREFIX, target)

        return self.send_raw_cmd(target, method, params=params, timeout=timeout)

    def stop(self):
        if self.comm is not None:
            self.comm.stop()
            self.comm = None


class _MMStateFanout(object):
    def __init__(self):
        self.subscribers = {}
        self.next_subscriber_id = 0

        self._connection = amqp.connection.Connection(
            **config.get('FABRIC', {})
        )
        self._channel = self._connection.channel()
        q = self._channel.queue_declare(exclusive=True)
        self._channel.queue_bind(
            queue=q.queue,
            exchange='mw_chassis_state'
        )
        self._channel.basic_consume(
            callback=self._callback,
            no_ack=True,
            exclusive=True
        )

        self.g_ioloop = gevent.spawn(self._ioloop)

    def _ioloop(self):
        while True:
            self._connection.drain_events()

    def _callback(self, msg):
        try:
            msg = json.loads(msg.body)
        except ValueError:
            LOG.error("invalid message received")
            return

        method = msg.get('method', None)
        if method is None:
            LOG.error("Message without method field")
            return

        if method != 'state':
            LOG.error("Method not allowed: %s", method)
            return

        params = msg.get('params', {})

        for s in self.subscribers.values():
            state = params.get('state', {})
            data = {
                'type': 'state',
                'data': state
            }
            s.put("data: %s\n\n" %
                  json.dumps(data))

    def subscribe(self):
        csid = self.next_subscriber_id
        self.next_subscriber_id += 1

        self.subscribers[csid] = gevent.queue.Queue()

        return csid

    def unsubscribe(self, sid):
        self.subscribers.pop(sid, None)

    def get(self, sid):
        if sid not in self.subscribers:
            return None

        return self.subscribers[sid].get()

    def stop(self):
        self.g_ioloop.kill()

        self._channel.close()
        self._connection.close()
        self._connection = None


def get_mmmaster():
    r = getattr(g, 'MMMaster', None)
    if r is None:
        r = _MMMasterConnection()
        g.MMMaster = r
    return r


MMMaster = werkzeug.LocalProxy(get_mmmaster)


def get_mmrpcclient():
    r = getattr(g, 'MMRpcClient', None)
    if r is None:
        r = _MMRpcClient()
        g.MMRpcClient = r
    return r


MMRpcClient = werkzeug.LocalProxy(get_mmrpcclient)


def get_mmstatefanout():
    r = getattr(g, '_mmstatefanout', None)
    if r is None:
        r = _MMStateFanout()
        g._mmstatefanout = r
    return r


MMStateFanout = werkzeug.LocalProxy(get_mmstatefanout)


def teardown(exception):
    r = getattr(g, 'MMMaster', None)
    if r is not None:
        g.MMMaster.stop()
        g.MMMaster = None

    r = getattr(g, 'MMRpcClient', None)
    if r is not None:
        g.MMRpcClient.stop()
        g.MMRpcClient = None

    r = getattr(g, '_mmstatefanout', None)
    if r is not None:
        g._mmstatefanout.stop()
        g._mmstatefanout = None


def init_app(app):
    app.teardown_appcontext(teardown)
