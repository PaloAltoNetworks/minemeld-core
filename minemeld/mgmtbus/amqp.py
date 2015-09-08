from __future__ import absolute_import

import amqp.connection
import amqp
import gevent
import gevent.event
import json
import logging
import uuid

from .collectd import CollectdClient

LOG = logging.getLogger(__name__)

AMQP_PREFIX = "mbus:"

AMQP_BUS_EXCHANGE = AMQP_PREFIX+"bus"


class AMQPMaster(gevent.Greenlet):
    def __init__(self, ftlist, config):
        super(AMQPMaster, self).__init__()

        self.ftlist = ftlist
        self.config = config

        self.status_glet = None
        self._status = {}

        self._connection = amqp.connection.Connection(**self.config)

        self._out_channel = self._connection.channel()
        self._out_channel.exchange_declare(
            AMQP_BUS_EXCHANGE,
            'fanout',
            auto_delete=False
        )

        self._in_channel = self._connection.channel()
        self._in_channel.queue_declare(
            queue=AMQP_PREFIX+'master',
            exclusive=True,
            auto_delete=True
        )
        self._in_channel.basic_consume(
            callback=self._in_callback,
            no_ack=True,
            exclusive=True
        )

        self._rpc_out_channel = self._connection.channel()

        self.active_requests = {}

    def rpc_status(self):
        return self._status

    def _in_callback(self, msg):
        try:
            body = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return

        LOG.debug('master _in_callback %s', body)

        if 'method' in body:
            self._rpc_call(body)
            return

        self._rpc_reply(body)

    def _rpc_call(self, body):
        method = body.get('method', None)
        id_ = body.get('id', None)
        reply_to = body.get('reply_to', None)
        params = body.get('params', {})

        if method is None:
            LOG.error('RPC request with no method, ignored')
            return

        if id_ is None:
            LOG.error('RPC request with no id, ignored')
            return

        if reply_to is None:
            LOG.error('RPC request with no reply_to, ignored')
            return

        m = getattr(self, 'rpc_'+method, None)
        if m is None:
            self._send_result(reply_to, id_, error='Not implemented')
            return

        try:
            result = m(**params)
        except Exception as e:
            self._send_result(reply_to, id_, error=str(e))
            return

        self._send_result(reply_to, id_, result=result)

    def _rpc_reply(self, body):
        id_ = body.get('id', None)
        if id_ is None:
            LOG.error('No id in msg body, msg ignored')
            return
        if id_ not in self.active_requests:
            LOG.error('Wrong id in reply, msg ignored (%s)', id_)
            return

        actreq = self.active_requests[id_]

        source = body.get('source', None)
        if source is None:
            LOG.error('No source in msg body, msg ignored')
            actreq['errors'] += 1
            return

        result = body.get('result', None)
        if result is None:
            LOG.error('error in reply from %s: %s',
                      source, body.get('error', None))
            actreq['errors'] += 1
            return
        actreq['answers'][source] = result

        if len(actreq['answers']) + actreq['errors'] == len(self.ftlist):
            actreq['event'].set()
            if actreq['discard']:
                self.active_requests.pop(id_)

    def _send_cmd(self, method, params={}, and_discard=False):
        LOG.debug('_send_cmd %s', method)

        id_ = str(uuid.uuid1())
        msg = {
            'id': id_,
            'method': method,
            'params': params
        }
        self.active_requests[id_] = {
            'cmd': method,
            'answers': {},
            'event': gevent.event.Event(),
            'errors': 0,
            'discard': and_discard
        }

        self._out_channel.basic_publish(
            amqp.Message(body=json.dumps(msg)),
            exchange=AMQP_BUS_EXCHANGE
        )

        return id_

    def _send_result(self, reply_to, id_, result=None, error=None):
        ans = {
            'id': id_,
            'result': result,
            'error': error
        }
        ans = json.dumps(ans)
        msg = amqp.Message(body=ans)
        self._rpc_out_channel.basic_publish(msg, routing_key=reply_to)

    def init_graph(self, newconfig):
        if newconfig:
            self._send_cmd('rebuild', and_discard=True)
            return

        siid = self._send_cmd('state_info')
        success = self.active_requests[siid]['event'].wait(timeout=30)
        if not success:
            LOG.error('timeout in state_info, sending reset')
            self._send_cmd('reset', and_discard=True)
            return

        actreq = self.active_requests[siid]

        if actreq['errors'] > 0:
            LOG.critical('errors reported from nodes in init_graph')
            raise RuntimeError('errors reported from nodes in init_graph')

        checkpoints = set([a.get('checkpoint', None)
                           for a in actreq['answers'].values()])
        if len(checkpoints) == 1:
            c = next(iter(checkpoints))
            if c is not None:
                LOG.info('all nodes at the same checkpoint (%s) '
                         ' sending initialize', c)
                self._send_cmd('initialize', and_discard=True)
                return

        source_chkps = set([a.get('checkpoint', None)
                            for a in actreq['answers'].values()
                            if a['is_source']])
        if len(source_chkps) == 1:
            c = next(iter(source_chkps))
            if c is not None:
                LOG.info('all source nodes at the same checkpoint (%s) '
                         ' sending rebuild', c)
                self._send_cmd('rebuild', and_discard=True)
                return

        self._send_cmd('reset', and_discard=True)

    def checkpoint_graph(self):
        chkp = str(uuid.uuid4())

        reqid = self._send_cmd('checkpoint', params={'value': chkp})
        success = self.active_requests[reqid]['event'].wait(timeout=30)
        if not success:
            LOG.error('Timeout waiting for answers to checkpoint')
            return

        ntries = 0
        while ntries < 2:
            reqid = self._send_cmd('state_info')
            success = self.active_requests[reqid]['event'].wait(timeout=10)
            if not success:
                LOG.error("Error retrieving nodes states after checkpoint")
                break

            ok = True
            for a in self.active_requests[reqid]['answers'].values():
                ok &= (a['checkpoint'] == chkp)
            if ok:
                break

            gevent.sleep(5)
            ntries += 1

    def _send_collectd_metrics(self, answers, interval):
        collectd_socket = self.config.get(
            'COLLECTD_SOCKET',
            '/var/run/collectd.sock'
        )

        cc = CollectdClient(collectd_socket)

        for source, a in answers.iteritems():
            stats = a.get('statistics', {})
            length = a.get('length', None)

            for m, v in stats.iteritems():
                cc.putval(source+'.'+m, v, interval=interval)
            if length is not None:
                cc.putval(
                    source+'.length',
                    length,
                    interval=interval
                )

    def _status_loop(self):
        loop_interval = self.config.get('STATUS_INTERVAL', '60')
        try:
            loop_interval = int(loop_interval)
        except ValueError:
            LOG.error('invalid STATUS_INTERVAL settings, '
                      'reverting to default')
            loop_interval = 60

        while True:
            reqid = self._send_cmd('status')
            actreq = self.active_requests[reqid]
            success = actreq['event'].wait(timeout=30)
            if success is None:
                LOG.error('timeout in waiting for status updates from nodes')
            else:
                self._status = actreq['answers']

                try:
                    self._send_collectd_metrics(
                        actreq['answers'],
                        loop_interval
                    )
                except Exception as e:
                    LOG.exception('Exception in _status_loop')

            gevent.sleep(loop_interval)

    def start_status_monitor(self):
        if self.status_glet is not None:
            LOG.error('double call to start_status')
            return

        self.status_glet = gevent.spawn(self._status_loop)

    def _run(self):
        while True:
            self._connection.drain_events()


class AMQPSlave(object):
    def __init__(self, config):
        self.fts = []

        self.config = config

        self._connection = amqp.connection.Connection(**self.config)

        self._in_channel = self._connection.channel()
        self._in_channel.exchange_declare(
            AMQP_BUS_EXCHANGE,
            'fanout',
            auto_delete=False
        )
        q = self._in_channel.queue_declare(
            queue=AMQP_PREFIX+str(uuid.uuid4()),
            exclusive=True,
            auto_delete=True
        )
        self._in_channel.queue_bind(
            queue=q.queue,
            exchange=AMQP_BUS_EXCHANGE
        )
        self._in_channel.basic_consume(
            callback=self._in_callback,
            no_ack=True,
            exclusive=True
        )

        self._out_channel = self._connection.channel()

        gevent.spawn(self._io_loop)

    def _in_callback(self, msg):
        try:
            body = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return

        LOG.debug('_in_callback %s', body)

        method = body.get('method', None)
        id_ = body.get('id', None)
        params = body.get('params', {})

        if method is None:
            LOG.error('No method in msg body')
            return

        if id_ is None:
            LOG.error('No id in msg body')
            return

        for ft in self.fts:
            m = getattr(ft, 'mgmtbus_'+method, None)
            if m is None:
                self._send_result(ft.name, id_, error='Not implemented')
                continue

            try:
                result = m(**params)
            except Exception as e:
                self._send_result(ft.name, id_, error=str(e))
            else:
                self._send_result(ft.name, id_, result=result)

    def _send_result(self, name, id_, result=None, error=None):
        ans = {
            'id': id_,
            'source': name,
            'result': result,
            'error': error
        }
        ans = json.dumps(ans)
        msg = amqp.Message(body=ans)
        self._out_channel.basic_publish(msg, routing_key=AMQP_PREFIX+'master')

    def request_channel(self, ft):
        self.fts.append(ft)

    def _io_loop(self):
        LOG.debug("in _io_loop")

        while True:
            self._connection.drain_events()
