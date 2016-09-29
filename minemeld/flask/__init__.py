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

import sys

from flask import Flask
from flask import g

import werkzeug.local
import logging

from . import config
from . import aaa
from . import session


LOG = logging.getLogger(__name__)

REDIS_URL = config.get('REDIS_URL', 'redis://127.0.0.1:6379/0')


# create flask app and load config from vmsh.config.api module
app = Flask(__name__)

app.logger.addHandler(logging.StreamHandler())
if config.get('DEBUG', False):
    app.logger.setLevel(logging.DEBUG)
else:
    app.logger.setLevel(logging.INFO)

aaa.LOGIN_MANAGER.init_app(app)
session.init_app(app, REDIS_URL)


try:
    # amqp connection
    import minemeld.comm
    import gevent
    import gevent.event
    import gevent.queue
    import amqp
    import json
    import psutil  # noqa

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

            return self.comm.send_rpc('mbus:master', method, params)

        def status(self):
            return self._send_cmd('status')

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

    @app.teardown_appcontext
    def tearwdown_mmmaster(exception):
        r = getattr(g, 'MMMaster', None)
        if r is not None:
            g.MMMaster.stop()
            g.MMMaster = None

    MMMaster = werkzeug.LocalProxy(get_mmmaster)

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

        def send_cmd(self, target, method, params={}, timeout=10):
            self._open_channel()
            LOG.debug('MMRpcClient channel open')

            return self.comm.send_rpc(target, method, params, timeout=timeout)

        def stop(self):
            if self.comm is not None:
                self.comm.stop()
                self.comm = None

    def get_mmrpcclient():
        r = getattr(g, 'MMRpcClient', None)
        if r is None:
            r = _MMRpcClient()
            g.MMRpcClient = r
        return r

    @app.teardown_appcontext
    def tearwdown_mmrpcclient(exception):
        r = getattr(g, 'MMRpcClient', None)
        if r is not None:
            g.MMRpcClient.stop()
            g.MMRpcClient = None

    MMRpcClient = werkzeug.LocalProxy(get_mmrpcclient)

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

    def get_mmstatefanout():
        r = getattr(g, '_mmstatefanout', None)
        if r is None:
            r = _MMStateFanout()
            g._mmstatefanout = r
        return r

    @app.teardown_appcontext
    def tearwdown_mmstatefanout(exception):
        r = getattr(g, '_mmstatefanout', None)
        if r is not None:
            g._mmstatefanout.stop()
            g._mmstatefanout = None

    MMStateFanout = werkzeug.LocalProxy(get_mmstatefanout)

except ImportError:
    LOG.exception("amqp, psutil and gevent needed for the status entrypoint")

try:
    import rrdtool  # noqa

    from . import metricsapi  # noqa

except ImportError:
    LOG.exception("rrdtool needed for metrics endpoint")


# redis connections
try:
    import redis

    def get_SR():
        SR = getattr(g, '_redis_client', None)
        if SR is None:
            SR = redis.StrictRedis.from_url(REDIS_URL)
            g._redis_client = SR
        return SR

    @app.teardown_appcontext
    def teardown_redis(exception):
        SR = getattr(g, '_redis_client', None)
        if SR is not None:
            g._redis_client = None

    SR = werkzeug.local.LocalProxy(get_SR)

    # load entry points
    from . import feedredis  # noqa
    from . import configapi  # noqa
    from . import taxiidiscovery  # noqa
    from . import taxiicollmgmt  # noqa
    from . import taxiipoll  # noqa

    configapi.init_app(app)

except ImportError:
    LOG.exception("redis is needed for feed and config entrypoints")

try:
    import psutil  # noqa
    import xmlrpclib
    import supervisor.xmlrpc

    def get_Supervisor():
        sserver = getattr(g, '_supervisor', None)
        if sserver is None:
            supervisorurl = config.get('SUPERVISOR_URL',
                                       'unix:///var/run/supervisor.sock')
            sserver = xmlrpclib.ServerProxy(
                'http://127.0.0.1',
                transport=supervisor.xmlrpc.SupervisorTransport(
                    None,
                    None,
                    supervisorurl
                )
            )
            g._supervisor = sserver

        return sserver

    @app.teardown_appcontext
    def teardown_Supervisor(exception):
        SR = getattr(g, '_supervisor', None)
        if SR is not None:
            g._supervisor = None

    MMSupervisor = werkzeug.local.LocalProxy(get_Supervisor)

    # load entry points
    from . import supervisorapi  # noqa

except ImportError:
    LOG.exception("supervisor and psutil needed for supervisor entrypoint")

# login
from . import login

# prototypes
from . import prototypeapi  # noqa

# validate
from . import validateapi  # noqa

if 'psutil' in sys.modules and 'amqp' in sys.modules:
    from . import status  # noqa
    from . import tracedapi  # noqa
