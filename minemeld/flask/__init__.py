from flask import Flask
from flask import g

import werkzeug.local
import logging

from . import config


LOG = logging.getLogger(__name__)


# create flask app and load config from vmsh.config.api module
app = Flask(__name__)

app.logger.addHandler(logging.StreamHandler())
if config.get('DEBUG', False):
    app.logger.setLevel(logging.DEBUG)
else:
    app.logger.setLevel(logging.INFO)


# redis connections
try:
    import redis

    def get_SR():
        SR = getattr(g, '_redis_client', None)
        if SR is None:
            redis_url = config.get('REDIS_URL', 'redis://localhost:6379/0')
            SR = redis.StrictRedis.from_url(redis_url)
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

except ImportError:
    LOG.exception("redis is needed for feed entrypoint")


try:
    # amqp connection
    import gevent
    import gevent.queue
    import amqp
    import json
    import psutil  # noqa

    class _MWStateFanout():
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

    def get_mwstatefanout():
        r = getattr(g, '_mwstatefanout', None)
        if r is None:
            r = _MWStateFanout()
            g._mwstatefanout = r
        return r

    @app.teardown_appcontext
    def tearwdown_mwstatefanout(exception):
        r = getattr(g, '_mwstatefanout', None)
        if r is not None:
            g._mwstatefanout.stop()
            g._mwstatefanout = None

    MWStateFanout = werkzeug.LocalProxy(get_mwstatefanout)

    from . import status  # noqa

except ImportError:
    LOG.exception("amqp, psutil and gevent needed for the status entrypoint")
