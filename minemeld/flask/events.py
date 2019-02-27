import gevent
import gevent.queue
import redis
import werkzeug.local
import ujson as json
from blinker import signal

from flask import g

from .logger import LOG


STATUS_EVENTS_SUBSCRIBER = None


class StatusEventsSubscriber(object):
    """Subscribes to mm-status events from engine
    """

    def __init__(self, connection_pool):
        self.SR = redis.StrictRedis(connection_pool=connection_pool)
        self._g = None
        self._signal = signal('mm-status')

    def _retry_wrap(self):
        while True:
            try:
                self._listen()

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('Exception in event listener')

    def _listen(self):
        pubsub = self.SR.pubsub(ignore_subscribe_messages=True)
        pubsub.psubscribe('mm-engine-status.*')

        while pubsub.subscribed:
            response = pubsub.get_message(timeout=30.0)
            if response is None:
                continue

            if not bool(self._signal.receivers):
                LOG.info('no receivers')
                continue

            data = json.loads(response['data'])
            source = data.pop('source', '<unknown-node>')

            self._signal.send(source, data=data)

    def start(self):
        if self._g is not None:
            return
        self._g = gevent.spawn(self._retry_wrap)


class EventsReceiver(object):
    def __init__(self):
        self._signal = signal('mm-status')
        self._signal.connect(self._signal_receiver)
        self._q = gevent.queue.Queue()
        self._iterator = self._generator()

    def _signal_receiver(self, sender, data):
        message = {
            'source': sender
        }
        message.update(data)
        self._q.put(message)

    def _generator(self):
        yield 'data: ok\n\n'

        while True:
            try:
                message = self._q.get(timeout=5.0)
                yield 'data: '+json.dumps(message)+'\n\n'

            except gevent.queue.Empty:
                yield 'data: ping\n\n'
                continue

        yield 'data: { "msg": "<EOQ>" }\n\n'

    def __iter__(self):
        return self

    def next(self):
        result = next(self._iterator)

        return result

    def close(self):
        self._signal.disconnect(self._signal_receiver)


def get_EventsGenerator():
    result = getattr(g, '_events_generator', None)
    if result is None:
        result = EventsReceiver()
        g._events_generator = result

    return result


EventsGenerator = werkzeug.local.LocalProxy(get_EventsGenerator)


def teardown(exception):
    eg = getattr(g, '_events_generator', None)
    if eg is not None:
        g._events_generator.close()
        g._events_generator = None


def init_app(app, redis_url):
    """Initalize event generator in the app
    
    Args:
        app (object): Flask App
        redis_url (str): Redis URL for communicating with engine
    """

    global STATUS_EVENTS_SUBSCRIBER

    redis_cp = redis.ConnectionPool.from_url(
        redis_url,
        max_connections=1
    )
    STATUS_EVENTS_SUBSCRIBER = StatusEventsSubscriber(connection_pool=redis_cp)
    STATUS_EVENTS_SUBSCRIBER.start()

    app.teardown_appcontext(teardown)
