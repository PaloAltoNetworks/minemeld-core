from __future__ import absolute_import

import amqp.connection
import amqp
import gevent
import gevent.event
import json
import logging
import uuid

LOG = logging.getLogger(__name__)


class AMQPPubChannel(object):
    def __init__(self, topic):
        self.topic = topic
        self.channel = None
        self.ioloop = None

    def connect(self, conn):
        if self.channel is not None:
            return

        self.channel = conn.channel()
        self.channel.exchange_declare(self.topic, 'fanout', auto_delete=True)

    def disconnect(self):
        if self.channel is None:
            return

        self.channel.exchange_delete(self.topic)
        self.channel.close()
        self.channel = None

    def publish(self, method, params={}):
        if self.channel is None:
            return

        msg = {
            'method': method,
            'params': params
        }
        self.channel.basic_publish(
            amqp.Message(body=json.dumps(msg)),
            exchange=self.topic
        )


class AMQPRpcFanoutClientChannel(object):
    def __init__(self, fanout):
        self.fanout = fanout
        self.active_rpcs = {}

        self._in_channel = None
        self._out_channel = None

    def _in_callback(self, msg):
        try:
            msg = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return

        id_ = msg.get('id', None)
        if id_ is None:
            LOG.error("No id field in RPC reply")
            return
        if id_ not in self.active_rpcs:
            LOG.error("Unknown id received in RPC reply: %s", id_)
            return

        source = msg.get('source', None)
        if source is None:
            LOG.error('No source field in RPC reply')
            return

        actreq = self.active_rpcs[id_]

        result = msg.get('result', None)
        if result is None:
            actreq['errors'] += 1
            errmsg = msg.get('error', 'no error in reply')
            LOG.error('Error in RPC reply from %s: %s', source, errmsg)
        else:
            actreq['answers'][source] = result

        if len(actreq['answers'])+actreq['errors'] >= actreq['num_results']:
            actreq['event'].set({
                'answers': actreq['answers'],
                'errors': actreq['errors']
            })
            self.active_rpcs.pop(id_)

    def send_rpc(self, method, params={}, num_results=0, and_discard=False):
        if self._in_channel is None:
            raise RuntimeError('Not connected')

        id_ = str(uuid.uuid1())

        body = {
            'reply_to': self._in_queue.queue,
            'method': method,
            'id': id_,
            'params': params
        }
        LOG.debug('sending %s to %s', body, self.fanout)
        msg = amqp.Message(
            body=json.dumps(body),
            reply_to=self._in_queue.queue,
            exchange=self.fanout
        )

        self.active_rpcs[id_] = {
            'cmd': method,
            'answers': {},
            'num_results': num_results,
            'event': gevent.event.AsyncResult(),
            'errors': 0,
            'discard': and_discard
        }

        self._out_channel.basic_publish(msg, exchange=self.fanout)

        return self.active_rpcs[id_]['event']

    def connect(self, conn):
        if self._in_channel is not None:
            return

        self._in_channel = conn.channel()
        self._in_queue = self._in_channel.queue_declare(exclusive=True)
        self._in_channel.basic_consume(
            callback=self._in_callback,
            no_ack=True,
            exclusive=True
        )

        self._out_channel = conn.channel()
        self._out_channel.exchange_declare(
            self.fanout,
            'fanout',
            auto_delete=True
        )

    def disconnect(self):
        if self._in_channel is None:
            return

        self._in_channel.close()
        self._out_channel.close()


class AMQPRpcServerChannel(object):
    def __init__(self, name, obj, allowed_methods=[],
                 method_prefix='', fanout=None):
        self.name = name
        self.obj = obj
        self.channel = None
        self.allowed_methods = allowed_methods
        self.fanout = fanout
        self.method_prefix = method_prefix

    def _send_result(self, replyq, id_, result=None, error=None):
        ans = {
            'source': self.name,
            'id': id_,
            'result': result,
            'error': error
        }
        ans = json.dumps(ans)
        msg = amqp.Message(body=ans)
        self.channel.basic_publish(msg, routing_key=replyq)

    def _callback(self, msg):
        try:
            body = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return
        LOG.debug('in callback - %s', body)

        reply_to = body.get('reply_to', None)
        if reply_to is None:
            LOG.error('No reply_to in RPC request')
            return

        method = body.get('method', None)
        id_ = body.get('id', None)
        params = body.get('params', {})

        if method is None:
            LOG.error('No method in msg body')
            return
        if id_ is None:
            LOG.error('No id in msg body')
            return

        method = self.method_prefix+method

        if method not in self.allowed_methods:
            LOG.error("method not allowed: %s", method)
            self._send_result(reply_to, id_, error="Method not allowed")

        m = getattr(self.obj, method, None)
        if m is None:
            LOG.error("Method %s not defined for %s", method, self.name)
            self._send_result(reply_to, id_, error="Method not defined")

        try:
            result = m(**params)
        except Exception as e:
            self._send_result(reply_to, id_, error=str(e))
        else:
            self._send_result(reply_to, id_, result=result)

    def _g_callback(self, msg):
        gevent.spawn(self._callback, msg)

    def connect(self, conn):
        if self.channel is not None:
            return

        self.channel = conn.channel()

        LOG.debug('opening queue %s', self.name+':rpc')

        q = self.channel.queue_declare(
            queue=self.name+':rpc',
            exclusive=False
        )

        if self.fanout:
            LOG.debug("Binding queue to fanout %s", self.fanout)
            self.channel.exchange_declare(
                self.fanout,
                'fanout',
                auto_delete=True
            )
            self.channel.queue_bind(
                queue=q.queue,
                exchange=self.fanout
            )

        self.channel.basic_consume(
            callback=self._g_callback,
            no_ack=True,
            exclusive=True
        )

    def disconnect(self):
        if self.channel is None:
            return

        self.channel.close()
        self.channel = None


class AMQPSubChannel(object):
    def __init__(self, topic, listeners=[]):
        self.topic = topic
        self.channel = None
        self.listeners = listeners

    def add_listener(self, obj, allowed_methods=[]):
        self.listeners.append((obj, allowed_methods))

    def _callback(self, msg):
        try:
            msg = json.loads(msg.body)
        except ValueError:
            LOG.error("invalid message received")
            return

        method = msg.get('method', None)
        params = msg.get('params', {})
        if method is None:
            LOG.error("Message without method field")
            return

        for obj, allowed_methods in self.listeners:
            if method not in allowed_methods:
                LOG.error("Method not allowed: %s", method)
                continue

            m = getattr(obj, method, None)
            if m is None:
                LOG.error('Method %s not defined', method)
                continue

            try:
                m(**params)
            except:
                LOG.exception('Exception in handling %s on topic %s '
                              'with params %s', method, topic, params)

    def connect(self, conn):
        if self.channel is not None:
            return

        LOG.debug("Subscribing to %s", self.topic)

        self.channel = conn.channel()
        self.channel.exchange_declare(
            self.topic,
            'fanout',
            auto_delete=True
        )
        q = self.channel.queue_declare(
            exclusive=False
        )
        self.channel.queue_bind(
            queue=q.queue,
            exchange=self.topic
        )
        self.channel.basic_consume(
            callback=self._callback,
            no_ack=True,
            exclusive=True
        )

    def disconnect(self):
        if self.channel is None:
            return

        self.channel.close()
        self.channel = None


class AMQP(object):
    def __init__(self, config):
        self.num_connections = config.pop('num_connections', 1)
        self.amqp_config = config

        self.rpc_server_channels = {}
        self.pub_channels = {}
        self.sub_channels = {}
        self.rpc_fanout_clients_channels = []

        self.rpc_out_channel = None
        self.active_rpcs = {}

        self._connections = []
        self.ioloops = []

        self.failure_listeners = []

    def add_failure_listener(self, listener):
        self.failure_listeners.append(listener)

    def request_rpc_server_channel(self, name, obj=None, allowed_methods=[],
                                   method_prefix='', fanout=None):
        if name in self.rpc_server_channels:
            return

        self.rpc_server_channels[name] = AMQPRpcServerChannel(
            name,
            obj,
            method_prefix=method_prefix,
            allowed_methods=allowed_methods,
            fanout=fanout
        )

    def request_rpc_fanout_client_channel(self, topic):
        c = AMQPRpcFanoutClientChannel(topic)
        self.rpc_fanout_clients_channels.append(c)
        return c

    def request_pub_channel(self, topic):
        if topic not in self.pub_channels:
            self.pub_channels[topic] = AMQPPubChannel(topic)

        return self.pub_channels[topic]

    def request_sub_channel(self, topic, obj=None, allowed_methods=[]):
        if topic in self.sub_channels:
            self.sub_channels[topic].add_listener(obj, allowed_methods)
            return

        subchannel = AMQPSubChannel(
            topic,
            [(obj, allowed_methods)]
        )
        self.sub_channels[topic] = subchannel

    def _rpc_callback(self, msg):
        try:
            msg = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return
        id_ = msg.get('id', None)
        if id_ is None:
            LOG.error("No id field in RPC reply")
            return
        if id_ not in self.active_rpcs:
            LOG.error("Unknown id received in RPC reply: %s", id_)
            return
        ar = self.active_rpcs.pop(id_)
        ar.set({
            'error': msg.get('error', None),
            'result': msg.get('result', None)
        })

    def send_rpc(self, dest, method, params,
                 block=True, timeout=None):
        if len(self._connections) == 0:
            raise RuntimeError('Not connected')

        id_ = str(uuid.uuid1())

        body = {
            'reply_to': self.rpc_out_queue.queue,
            'method': method,
            'id': id_,
            'params': params
        }
        LOG.debug('sending %s to %s', body, dest+':rpc')
        msg = amqp.Message(
            body=json.dumps(body),
            reply_to=self.rpc_out_queue.queue
        )

        self.active_rpcs[id_] = gevent.event.AsyncResult()
        self.rpc_out_channel.basic_publish(msg, routing_key=dest+':rpc')

        try:
            result = self.active_rpcs[id_].get(block=block, timeout=timeout)
        except gevent.timeout.Timeout:
            self.active_rpcs.pop(id_)
            raise

        return result

    def _ioloop(self, j):
        LOG.debug('start draining events on connection %d', j)

        while True:
            self._connections[j].drain_events()

    def _ioloop_failure(self, g):
        LOG.debug('_ioloop_failure')

        try:
            g.get()

        except gevent.GreenletExit:
            return

        except:
            LOG.exception("_ioloop_failure: exception in ioloop")
            for l in self.failure_listeners:
                l()

    def start(self):
        for j in range(self.num_connections):
            self._connections.append(
                amqp.connection.Connection(**self.amqp_config)
            )

        csel = 0

        for rpcc in self.rpc_server_channels.values():
            rpcc.connect(self._connections[csel % self.num_connections])
            csel += 1

        for pc in self.pub_channels.values():
            pc.connect(self._connections[csel % self.num_connections])
            csel += 1

        for sc in self.sub_channels.values():
            sc.connect(self._connections[csel % self.num_connections])
            csel += 1

        for rfc in self.rpc_fanout_clients_channels:
            rfc.connect(self._connections[csel % self.num_connections])
            csel += 1

        # create rpc out channel
        self.rpc_out_channel = \
            self._connections[csel % self.num_connections].channel()
        self.rpc_out_queue = self.rpc_out_channel.queue_declare(
            exclusive=False
        )
        self.rpc_out_channel.basic_consume(
            callback=self._rpc_callback,
            no_ack=True,
            exclusive=True
        )

        for j in range(self.num_connections):
            g = gevent.spawn(self._ioloop, j)
            self.ioloops.append(g)
            g.link_exception(self._ioloop_failure)

    def stop(self):
        if len(self._connections) is 0 or \
           self.num_connections == 0:
            return

        for j in range(len(self.ioloops)):
            self.ioloops[j].unlink(self._ioloop_failure)
            self.ioloops[j].kill()
            self.ioloops[j] = None
        self.ioloops = None

        for rpcc in self.rpc_server_channels.values():
            try:
                rpcc.disconnect()
            except amqp.AMQPError:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for pc in self.pub_channels.values():
            try:
                pc.disconnect()
            except amqp.AMQPError:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for sc in self.sub_channels.values():
            try:
                sc.disconnect()
            except amqp.AMQPError:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for rfc in self.rpc_fanout_clients_channels:
            try:
                rfc.disconnect()
            except amqp.AMQPError:
                LOG.debug("exception in disconnect: ", exc_info=True)

        self.rpc_out_channel.close()

        for j in range(len(self._connections)):
            self._connections[j].close()
            self._connections[j] = None
