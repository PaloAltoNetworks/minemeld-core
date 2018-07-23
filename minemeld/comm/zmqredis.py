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

# disable import error
# pylint:disable=E1101

"""
This module implements ZMQ and Redis communication class for mgmtbus and fabric.
"""

from __future__ import absolute_import

import logging
import uuid
import os
import time

import gevent
import gevent.event
import ujson as json
from errno import EAGAIN

import redis
import zmq.green as zmq

LOG = logging.getLogger(__name__)


class RedisPubChannel(object):
    def __init__(self, topic, connection_pool):
        self.topic = topic
        self.prefix = 'mm:topic:{}'.format(self.topic)

        self.connection_pool = connection_pool
        self.SR = None

        self.num_publish = 0

    def connect(self):
        if self.SR is not None:
            return

        self.SR = redis.StrictRedis(
            connection_pool=self.connection_pool
        )

        tkeys = self.SR.keys(pattern='{}:*'.format(self.prefix))
        if len(tkeys) > 0:
            LOG.info('Deleting {} old keys for {}'.format(len(tkeys), self.prefix))
            self.SR.delete(*tkeys)

    def disconnect(self):
        if self.SR is None:
            return

        self.SR = None

    def lagger(self):
        # get status of subscribers
        subscribersc = self.SR.lrange(
            '{}:subscribers'.format(self.prefix),
            0, -1
        )
        subscribersc = [int(sc) for sc in subscribersc]

        # check the lagger
        minsubc = self.num_publish
        if len(subscribersc) != 0:
            minsubc = min(subscribersc)

        return minsubc

    def gc(self, lagger):
        minhighbits = lagger >> 12

        minqname = '{}:queue:{:013X}'.format(
            self.prefix,
            minhighbits
        )

        # delete all the lists before the lagger
        queues = self.SR.keys('{}:queue:*'.format(self.prefix))
        LOG.debug('topic {} - queues: {!r}'.format(self.topic, queues))
        queues = [q for q in queues if q < minqname]
        LOG.debug('topic {} - queues to be deleted: {!r}'.format(self.topic, queues))
        if len(queues) != 0:
            LOG.debug('topic {} - deleting {!r}'.format(
                self.topic,
                queues
            ))
            self.SR.delete(*queues)

    def publish(self, method, params=None):
        high_bits = self.num_publish >> 12
        low_bits = self.num_publish & 0xfff

        if (low_bits % 128) == 127:
            lagger = self.lagger()
            LOG.debug('topic {} - sent {} lagger {}'.format(
                self.topic,
                self.num_publish,
                lagger
            ))

            while (self.num_publish - lagger) > 1024:
                LOG.debug('topic {} - waiting lagger delta: {}'.format(
                    self.topic,
                    self.num_publish - lagger
                ))
                gevent.sleep(0.1)
                lagger = self.lagger()

            if low_bits == 0xfff:
                # we are switching to a new list, gc
                self.gc(lagger)

        msg = {
            'method': method,
            'params': params
        }

        qname = '{}:queue:{:013X}'.format(
            self.prefix,
            high_bits
        )

        self.SR.rpush(qname, json.dumps(msg))
        self.num_publish += 1


class ZMQRpcFanoutClientChannel(object):
    def __init__(self, fanout):
        self.socket = None
        self.reply_socket = None
        self.context = None

        self.fanout = fanout
        self.active_rpcs = {}

    def run(self):
        while True:
            LOG.debug('RPC Fanout reply recving from {}:reply'.format(self.fanout))
            body = self.reply_socket.recv_json()
            LOG.debug('RPC Fanout reply from {}:reply recvd: {!r}'.format(self.fanout, body))
            self.reply_socket.send('OK')
            LOG.debug('RPC Fanout reply from {}:reply recvd: {!r} - ok'.format(self.fanout, body))

            source = body.get('source', None)
            if source is None:
                LOG.error('No source in reply in ZMQRpcFanoutClientChannel {}'.format(self.fanout))
                continue

            id_ = body.get('id', None)
            if id_ is None:
                LOG.error('No id in reply in ZMQRpcFanoutClientChannel {} from {}'.format(self.fanout, source))
                continue
            actreq = self.active_rpcs.get(id_, None)
            if actreq is None:
                LOG.error('Unknown id {} in reply in ZMQRpcFanoutClientChannel {} from {}'.format(id_, self.fanout, source))
                continue

            result = body.get('result', None)
            if result is None:
                actreq['errors'] += 1
                errmsg = body.get('error', 'no error in reply')
                LOG.error('Error in RPC reply from {}: {}'.format(source, errmsg))

            else:
                actreq['answers'][source] = result
            LOG.debug('RPC Fanout state: {!r}'.format(actreq))

            if len(actreq['answers'])+actreq['errors'] >= actreq['num_results']:
                actreq['event'].set({
                    'answers': actreq['answers'],
                    'errors': actreq['errors']
                })
                self.active_rpcs.pop(id_)

            gevent.sleep(0)

    def send_rpc(self, method, params=None, num_results=0, and_discard=False):
        if self.socket is None:
            raise RuntimeError('Not connected')

        if params is None:
            params = {}

        id_ = str(uuid.uuid1())

        body = {
            'reply_to': '{}:reply'.format(self.fanout),
            'method': method,
            'id': id_,
            'params': params
        }

        event = gevent.event.AsyncResult()

        if num_results == 0:
            event.set({
                'answers': {},
                'errors': 0
            })
            return event

        self.active_rpcs[id_] = {
            'cmd': method,
            'answers': {},
            'num_results': num_results,
            'event': event,
            'errors': 0,
            'discard': and_discard
        }

        LOG.debug('RPC Fanout Client: send multipart to {}: {!r}'.format(self.fanout, json.dumps(body)))
        self.socket.send_multipart([
            '{}'.format(self.fanout),
            json.dumps(body)
        ])
        LOG.debug('RPC Fanout Client: send multipart to {}: {!r} - done'.format(self.fanout, json.dumps(body)))

        gevent.sleep(0)

        return event

    def connect(self, context):
        if self.socket is not None:
            return

        self.context = context

        self.socket = context.socket(zmq.PUB)
        self.socket.bind('ipc:///var/run/minemeld/{}'.format(self.fanout))

        self.reply_socket = context.socket(zmq.REP)
        self.reply_socket.bind('ipc:///var/run/minemeld/{}:reply'.format(self.fanout))

    def disconnect(self):
        if self.socket is None:
            return

        self.socket.close(linger=0)
        self.reply_socket.close(linger=0)

        self.socket = None
        self.reply_socket = None


class ZMQRpcServerChannel(object):
    def __init__(self, name, obj, allowed_methods=None,
                 method_prefix='', fanout=None):
        if allowed_methods is None:
            allowed_methods = []

        self.name = name
        self.obj = obj

        self.allowed_methods = allowed_methods
        self.method_prefix = method_prefix

        self.fanout = fanout
        self.context = None
        self.socket = None

    def _send_result(self, reply_to, id_, result=None, error=None):
        ans = {
            'source': self.name,
            'id': id_,
            'result': result,
            'error': error
        }

        if self.fanout is not None:
            reply_socket = self.context.socket(zmq.REQ)
            reply_socket.connect('ipc:///var/run/minemeld/{}'.format(reply_to))
            LOG.debug('RPC Server {} result to {}'.format(self.name, reply_to))
            reply_socket.send_json(ans)
            reply_socket.recv()
            LOG.debug('RPC Server {} result to {} - done'.format(self.name, reply_to))
            reply_socket.close(linger=0)
            LOG.debug('RPC Server {} result to {} - closed'.format(self.name, reply_to))
            reply_socket = None

        else:
            self.socket.send_multipart([reply_to, '', json.dumps(ans)])

    def run(self):
        if self.socket is None:
            LOG.error('Run called with invalid socket in RPC server channel: {}'.format(self.name))

        while True:
            LOG.debug('RPC Server receiving from {} - {}'.format(self.name, self.fanout))
            toks = self.socket.recv_multipart()
            LOG.debug('RPC Server recvd from {} - {}: {!r}'.format(self.name, self.fanout, toks))

            if self.fanout is not None:
                reply_to, body = toks
                reply_to = reply_to+':reply'
            else:
                reply_to, _, body = toks

            body = json.loads(body)
            LOG.debug('RPC command to {}: {!r}'.format(self.name, body))

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
                LOG.error('Method not allowed in RPC server channel {}: {}'.format(self.name, method))
                self._send_result(reply_to, id_, error='Method not allowed')

            m = getattr(self.obj, method, None)
            if m is None:
                LOG.error('Method {} not defined in RPC server channel {}'.format(method, self.name))
                self._send_result(reply_to, id_, error='Method not defined')

            try:
                result = m(**params)

            except gevent.GreenletExit:
                raise

            except Exception as e:
                self._send_result(reply_to, id_, error=str(e))

            else:
                self._send_result(reply_to, id_, result=result)

    def connect(self, context):
        if self.socket is not None:
            return

        self.context = context

        if self.fanout is not None:
            # we are subscribers
            self.socket = self.context.socket(zmq.SUB)
            self.socket.connect('ipc:///var/run/minemeld/{}'.format(self.fanout))
            self.socket.setsockopt(zmq.SUBSCRIBE, b'')  # set the filter to empty to recv all messages

        else:
            # we are a router
            self.socket = self.context.socket(zmq.ROUTER)

            if self.name[0] == '@':
                address = 'ipc://@/var/run/minemeld/{}:rpc'.format(
                    self.name[1:]
                )
            else:
                address = 'ipc:///var/run/minemeld/{}:rpc'.format(
                    self.name
                )
            self.socket.bind(address)

    def disconnect(self):
        if self.socket is not None:
            self.socket.close(linger=0)
            self.socket = None


class RedisSubChannel(object):
    def __init__(self, topic, connection_pool, object_,
                 allowed_methods, name=None):
        self.topic = topic
        self.prefix = 'mm:topic:{}'.format(self.topic)
        self.channel = None
        self.name = name
        self.object = object_
        self.allowed_methods = allowed_methods

        self.num_callbacks = 0

    def _callback(self, msg):
        try:
            msg = json.loads(msg)
        except ValueError:
            LOG.error("invalid message received")
            return

        method = msg.get('method', None)
        params = msg.get('params', {})
        if method is None:
            LOG.error("Message without method field")
            return

        if method not in self.allowed_methods:
            LOG.error("Method not allowed: %s", method)
            return

        m = getattr(self.object, method, None)
        if m is None:
            LOG.error('Method %s not defined', method)
            return

        try:
            m(**params)

        except gevent.GreenletExit:
            raise

        except:
            LOG.exception('Exception in handling %s on topic %s '
                          'with params %s', method, self.topic, params)

        self.num_callbacks += 1

    def connect(self):
        pass

    def disconnect(self):
        pass


class ZMQRedis(object):
    def __init__(self, config):
        self.context = None
        self.rpc_server_channels = {}
        self.pub_channels = []
        self.sub_channels = []
        self.rpc_fanout_clients_channels = []

        self.active_rpcs = {}

        self.ioloops = []

        self.failure_listeners = []

        self.redis_config = {
            'url': os.environ.get('REDIS_URL', 'unix:///var/run/redis/redis.sock')
        }
        self.redis_cp = redis.ConnectionPool.from_url(
            self.redis_config['url']
        )

    def add_failure_listener(self, listener):
        self.failure_listeners.append(listener)

    def request_rpc_server_channel(self, name, obj=None, allowed_methods=None,
                                   method_prefix='', fanout=None):
        if allowed_methods is None:
            allowed_methods = []

        if name in self.rpc_server_channels:
            return

        self.rpc_server_channels[name] = ZMQRpcServerChannel(
            name,
            obj,
            method_prefix=method_prefix,
            allowed_methods=allowed_methods,
            fanout=fanout
        )

    def request_rpc_fanout_client_channel(self, topic):
        c = ZMQRpcFanoutClientChannel(topic)
        self.rpc_fanout_clients_channels.append(c)
        return c

    def request_pub_channel(self, topic):
        redis_pub_channel = RedisPubChannel(
            topic=topic,
            connection_pool=self.redis_cp
        )
        self.pub_channels.append(redis_pub_channel)

        return redis_pub_channel

    def request_sub_channel(self, topic, obj=None, allowed_methods=None,
                            name=None, max_length=None):
        if allowed_methods is None:
            allowed_methods = []

        subchannel = RedisSubChannel(
            topic=topic,
            connection_pool=self.redis_cp,
            object_=obj,
            allowed_methods=allowed_methods,
            name=name
        )
        self.sub_channels.append(subchannel)

    def send_rpc(self, dest, method, params,
                 block=True, timeout=None):
        if self.context is None:
            LOG.error('send_rpc to {} when not connected'.format(dest))
            return

        id_ = str(uuid.uuid1())

        body = {
            'method': method,
            'id': id_,
            'params': params
        }

        socket = self.context.socket(zmq.REQ)

        if dest[0] == '@':
            address = 'ipc://@/var/run/minemeld/{}:rpc'.format(
                dest[1:]
            )
        else:
            address = 'ipc:///var/run/minemeld/{}:rpc'.format(
                dest
            )

        socket.connect(address)
        socket.setsockopt(zmq.LINGER, 0)
        socket.send_json(body)
        LOG.debug('RPC sent to {}:rpc for method {}'.format(dest, method))

        if not block:
            socket.close(linger=0)
            return

        if timeout is not None:
            # zmq green does not support RCVTIMEO
            if socket.poll(flags=zmq.POLLIN, timeout=int(timeout*1000)) != 0:
                result = socket.recv_json(flags=zmq.NOBLOCK)

            else:
                socket.close(linger=0)
                raise RuntimeError('Timeout in RPC')

        else:
            result = socket.recv_json()

        socket.close(linger=0)

        return result

    def _ioloop(self, executor):
        executor.run()

    def _sub_ioloop(self, schannel):
        LOG.debug('start draining messages on topic {}'.format(schannel.topic))

        counter = 0
        SR = redis.StrictRedis(connection_pool=self.redis_cp)
        subscribers_key = '{}:subscribers'.format(schannel.prefix)
        sub_number = None

        while True:
            base = counter & 0xfff
            top = min(base + 127, 0xfff)

            msgs = SR.lrange(
                '{}:queue:{:013X}'.format(schannel.prefix, counter >> 12),
                base,
                top
            )

            for m in msgs:
                LOG.debug('topic {} - {!r}'.format(
                    schannel.topic,
                    m
                ))
                schannel._callback(m)

            counter += len(msgs)

            if len(msgs) > 0:
                if sub_number is None:
                    sub_number = SR.rpush(
                        subscribers_key,
                        len(msgs)
                    )
                    sub_number -= 1
                    LOG.debug('Sub Number {} on {}'.format(sub_number, subscribers_key))

                else:
                    SR.lset(
                        subscribers_key,
                        sub_number,
                        counter
                    )

            if len(msgs) < (top - base + 1):
                gevent.sleep(1.0)
            else:
                gevent.sleep(0)

    def _ioloop_failure(self, g):
        LOG.error('_ioloop_failure')

        try:
            g.get()

        except gevent.GreenletExit:
            return

        except:
            LOG.exception("_ioloop_failure: exception in ioloop")
            for l in self.failure_listeners:
                l()

    def start(self, start_dispatching=True):
        self.context = zmq.Context()

        for rfcc in self.rpc_fanout_clients_channels:
            rfcc.connect(self.context)

        for rpcc in self.rpc_server_channels.values():
            rpcc.connect(self.context)

        for sc in self.sub_channels:
            sc.connect()

        for pc in self.pub_channels:
            pc.connect()

        if start_dispatching:
            self.start_dispatching()

    def start_dispatching(self):
        for rfcc in self.rpc_fanout_clients_channels:
            g = gevent.spawn(self._ioloop, rfcc)
            self.ioloops.append(g)
            g.link_exception(self._ioloop_failure)

        for rpcc in self.rpc_server_channels.values():
            g = gevent.spawn(self._ioloop, rpcc)
            self.ioloops.append(g)
            g.link_exception(self._ioloop_failure)

        for schannel in self.sub_channels:
            g = gevent.spawn(self._sub_ioloop, schannel)
            self.ioloops.append(g)
            g.link_exception(self._ioloop_failure)

    def stop(self):
        # kill ioloops
        for j in xrange(len(self.ioloops)):
            self.ioloops[j].unlink(self._ioloop_failure)
            self.ioloops[j].kill()
            self.ioloops[j] = None
        self.ioloops = None

        # close channels
        for rpcc in self.rpc_server_channels.values():
            try:
                rpcc.disconnect()
            except Exception:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for pc in self.pub_channels:
            try:
                pc.disconnect()
            except Exception:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for sc in self.sub_channels:
            try:
                sc.disconnect()
            except Exception:
                LOG.debug("exception in disconnect: ", exc_info=True)

        for rfc in self.rpc_fanout_clients_channels:
            try:
                rfc.disconnect()
            except Exception:
                LOG.debug("exception in disconnect: ", exc_info=True)

        self.context.destroy()
