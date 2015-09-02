from __future__ import absolute_import

import amqp.connection
import amqp
import gevent
import gevent.event
import json
import logging
import uuid

LOG = logging.getLogger(__name__)

QUEUE_TTL = 15*60*1000  # TTL on messages: 15 minutes

AMQP_PREFIX = "mbus:"

AMQP_BUS_EXCHANGE = AMQP_PREFIX+"bus"


class AMQPMaster(gevent.Greenlet):
    def __init__(self, ftlist, config):
        super(AMQPMaster, self).__init__()

        self.ftlist = ftlist
        self.config = config

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

        self.cur_status = None
        self.answers = []

    def _in_callback(self, msg):
        try:
            body = json.loads(msg.body)
        except ValueError:
            LOG.error("Invalid JSON in msg body")
            return

        LOG.debug('master _in_callback %s', body)

        id_ = body.get('id', None)
        if id_ is None:
            LOG.error('No id in msg body')
            return
        if id_ != self.cur_id:
            LOG.debug('Wrong id in reply, msg ignored (%s, %s)',
                      id_, self.cur_id)
            return

        result = body.get('result', None)
        if result is None:
            LOG.error('error in reply: %s', body.get('error', None))
            self.answers.append(None)

        self.answers.append(result)

        if len(self.answers) == len(self.ftlist):
            self.answerevent.set()

    def _send_cmd(self, method, params={}):
        LOG.debug('_send_cmd %s', method)

        id_ = str(uuid.uuid1())
        msg = {
            'id': id_,
            'method': method,
            'params': params
        }
        self.cur_status = method
        self.cur_id = id_
        self.answers = []
        self.answerevent = gevent.event.Event()

        self._out_channel.basic_publish(
            amqp.Message(body=json.dumps(msg)),
            exchange=AMQP_BUS_EXCHANGE
        )

    def init_graph(self, newconfig):
        if newconfig:
            self._send_cmd('rebuild')
            return

        self._send_cmd('state_info')

        success = self.answerevent.wait(timeout=30)
        if not success:
            self._send_cmd('reset')
            return

        source_chkp = None
        checkpoint = None
        goflag = True
        sourceflag = True
        for a in self.answers:
            if a is None:
                goflag = False

            c = a['checkpoint']
            if checkpoint is None:
                checkpoint = c
            elif checkpoint != c:
                goflag = False

            if a['is_source']:
                if source_chkp is None:
                    source_chkp = c
                elif source_chkp != c:
                    sourceflag = False

        if goflag:
            self._send_cmd('initialize')
            return

        if sourceflag:
            self._send_cmd('rebuild')
            return

        self._send_cmd('reset')

    def checkpoint_graph(self):
        chkp = str(uuid.uuid4())

        self._send_cmd('checkpoint', params={'value': chkp})
        success = self.answerevent.wait(timeout=30)
        if not success:
            LOG.error('Timeout waiting for answers to checkpoint')
            return

        ntries = 0
        while ntries < 2:
            self._send_cmd('state_info')

            success = self.answerevent.wait(timeout=10)
            if not success:
                LOG.error("Error retrieving FT states after checkpoint")
                break

            ok = True
            for a in self.answers:
                ok &= (a['checkpoint'] == chkp)
            if ok:
                break

            gevent.sleep(5)
            ntries += 1

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
                self._send_result(id_, error='Not implemented')
                continue

            try:
                result = m(**params)
            except Exception as e:
                self._send_result(id_, error=str(e))
            else:
                self._send_result(id_, result=result)

    def _send_result(self, id_, result=None, error=None):
        ans = {
            'id': id_,
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
