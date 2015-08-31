from __future__ import absolute_import

import amqp.connection
import amqp
import gevent
import gevent.event
import json
import logging
import uuid
import functools

LOG = logging.getLogger(__name__)

QUEUE_TTL = 15*60*1000  # TTL on messages: 15 minutes


class FabricNotConnectedError(Exception):
    pass


class AMQPPubChannel(object):
    def __init__(self, ftname):
        self.ftname = ftname
        self.channel = None
        self.ioloop = None

    def connect(self, conn):
        if self.channel is not None:
            return

        self.channel = conn.channel()
        self.channel.exchange_declare(self.ftname, 'fanout', auto_delete=False)

    def disconnect(self):
        if self.channel is None:
            return

        self.channel.exchange_delete(self.ftname)
        self.channel.close()
        self.channel = None

    def publish(self, method, params={}):
        if self.channel is None:
            return

        params['source'] = self.ftname
        msg = {
            'method': method,
            'params': params
        }
        self.channel.basic_publish(
            amqp.Message(body=json.dumps(msg)),
            exchange=self.ftname
        )

AMQPStateReportChannel = functools.partial(AMQPPubChannel, "mw_chassis_state")


class AMQPRpcChannel(object):
    def __init__(self, ftname, ft, allowed_methods):
        self.ftname = ftname
        self.ft = ft
        self.channel = None
        self.allowed_methods = allowed_methods

    def _send_result(self, replyq, id_, result=None, error=None):
        ans = {
            'id': id_,
            'result': result,
            'error': error
        }
        ans = json.dumps(ans)
        msg = amqp.Message(body=ans)
        self.channel.basic_publish(msg, routing_key=replyq)

    def _callback(self, msg):
        if not hasattr(msg, 'reply_to'):
            LOG.error('No reply_to in RPC request')
            return

        try:
            body = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
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
        if method not in self.allowed_methods:
            LOG.error("method not allowed: %s", method)
            self._send_result(msg.reply_to, id_, error="Method not allowed")

        m = getattr(self.ft, method, None)
        if m is None:
            LOG.error("Method %s not defined for %s", method, self.ftname)
            self._send_result(msg.reply_to, id_, error="Method not defined")

        try:
            result = m(**params)
        except Exception as e:
            self._send_result(msg.reply_to, id_, error=str(e))
        else:
            self._send_result(msg.reply_to, id_, result=result)

    def _g_callback(self, msg):
        gevent.spawn(self._callback, msg)

    def connect(self, conn):
        if self.channel is not None:
            return

        self.channel = conn.channel()
        self.channel.queue_declare(
            queue=self.ftname+':rpc',
            exclusive=False,
            auto_delete=False,
            arguments={'x-expires': QUEUE_TTL}
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
    def __init__(self, ftname, ft, subname, allowed_methods):
        LOG.debug("New sub channel for %s from %s", ftname, subname)

        self.ftname = ftname
        self.ft = ft
        self.subname = subname
        self.channel = None
        self.allowed_methods = allowed_methods

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

        if method not in self.allowed_methods:
            LOG.error("Method not allowed: %s", method)
            return

        m = getattr(self.ft, method, None)
        if m is None:
            LOG.error('Method %s not defined for %s', method, self.ftname)
            return

        params = msg.get('params', {})

        try:
            m(**params)
        except:
            LOG.exception('Exception in handling %s in %s',
                          method, self.ftname)

    def connect(self, conn):
        if self.channel is not None:
            return

        LOG.debug("Subscribing %s to %s", self.ftname, self.subname)

        self.channel = conn.channel()
        self.channel.exchange_declare(
            self.subname,
            'fanout',
            auto_delete=False
        )
        q = self.channel.queue_declare(
            exclusive=False,
            auto_delete=False,
            arguments={'x-expires': QUEUE_TTL}
        )
        self.channel.queue_bind(
            queue=q.queue,
            exchange=self.subname
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
    def __init__(self, chassis, config):
        self.chassis = chassis

        self.num_connections = config.pop('num_connections', 5)
        self.config = config

        self.rpc_channels = {}
        self.pub_channels = {}
        self.sub_channels = {}
        self.state_report_channels = []
        self.rpc_out_channel = None
        self.active_rpcs = {}

        self._connections = []

    def request_rpc_channel(self, ftname, ft, allowed_methods):
        if ftname in self.rpc_channels:
            return
        self.rpc_channels[ftname] = AMQPRpcChannel(ftname, ft, allowed_methods)

    def request_pub_channel(self, ftname):
        if ftname not in self.pub_channels:
            self.pub_channels[ftname] = AMQPPubChannel(ftname)
        return self.pub_channels[ftname]

    def request_state_report_channel(self):
        srchannel = AMQPStateReportChannel()
        self.state_report_channels.append(srchannel)
        return srchannel

    def request_sub_channel(self, ftname, ft, subname, allowed_methods):
        key = ftname+':'+subname
        if key in self.sub_channels:
            return
        self.sub_channels[key] = AMQPSubChannel(
            ftname,
            ft,
            subname,
            allowed_methods
        )

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

    def send_rpc(self, sftname, dftname, method, params,
                 block=True, timeout=None):
        if len(self._connections) == 0:
            raise FabricNotConnectedError()

        id_ = str(uuid.uuid1())

        params['source'] = sftname
        body = {
            'method': method,
            'id': id_,
            'params': params
        }
        msg = amqp.Message(
            body=json.dumps(body),
            reply_to=self.rpc_out_queue.queue
        )

        self.active_rpcs[id_] = gevent.event.AsyncResult()
        self.rpc_out_channel.basic_publish(msg, routing_key=dftname+":rpc")

        try:
            result = self.active_rpcs[id_].get(block=block, timeout=timeout)
        except gevent.timeout.Timeout:
            self.active_rpcs.pop(id_)
            raise

        return result

    def _ioloop(self, nc):
        while True:
            self._connections[nc].drain_events()

    def _ioloop_failure(self, g):
        try:
            g.get()

        except gevent.GreenletExit:
            return

        except:
            LOG.exception("fabric _ioloop_failure: exception in ioloop")
            self.chassis.fabric_failed()

    def start(self):
        LOG.debug("fabric start called")

        for j in range(self.num_connections):
            self._connections.append(
                amqp.connection.Connection(**self.config)
            )

        nc = 0
        for rpcc in self.rpc_channels.values():
            rpcc.connect(self._connections[nc % self.num_connections])
            nc += 1

        for pc in self.pub_channels.values():
            pc.connect(self._connections[nc % self.num_connections])
            nc += 1

        for sc in self.sub_channels.values():
            sc.connect(self._connections[nc % self.num_connections])
            nc += 1

        for src in self.state_report_channels:
            src.connect(self._connections[nc % self.num_connections])
            nc += 1

        # create rpc out channel
        self.rpc_out_channel = \
            self._connections[nc % self.num_connections].channel()
        self.rpc_out_queue = self.rpc_out_channel.queue_declare(
            exclusive=False,
            auto_delete=False,
            arguments={'x-expires': QUEUE_TTL}
        )
        self.rpc_out_channel.basic_consume(
            callback=self._rpc_callback,
            no_ack=True,
            exclusive=True
        )

        self.ioloops = []
        for j in range(self.num_connections):
            g = gevent.spawn(self._ioloop, j)
            self.ioloops.append(g)
            g.link_exception(self._ioloop_failure)

    def stop(self):
        LOG.debug("fabric stop called")

        if self._connections is None or \
           len(self._connections) == 0:
            return

        for g in self.ioloops:
            g.unlink(self._ioloop_failure)
            g.kill()
        self.ioloops = None

        for rpcc in self.rpc_channels.values():
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

        for src in self.state_report_channels:
            try:
                src.disconnect()
            except amqp.AMQPError:
                LOG.debug("exception in disconnect: ", exc_info=True)

        self.rpc_out_channel.close()

        for c in self._connections:
            c.close()
        self._connections = None
