from __future__ import absolute_import

import gevent
import gevent.event
import logging
import uuid

import minemeld.comm.amqp

from .collectd import CollectdClient

LOG = logging.getLogger(__name__)

AMQP_PREFIX = "mbus:"

AMQP_BUS_EXCHANGE = AMQP_PREFIX+"bus"


class MgmtbusMaster(object):
    def __init__(self, ftlist, config, comm_class, comm_config):
        super(MgmtbusMaster, self).__init__()

        self.ftlist = ftlist
        self.config = config
        self.comm_config = comm_config
        self.comm_class = comm_class

        self.status_glet = None
        self._status = {}

        self.comm = self.comm_class(self.comm_config)
        self._out_channel = self.comm.request_pub_channel(AMQP_BUS_EXCHANGE)
        self.comm.request_rpc_server_channel(
            AMQP_PREFIX+'master',
            self,
            allowed_methods=['rpc_status'],
            method_prefix='rpc'
        )
        self._rpc_client = self.comm.request_rpc_fanout_client_channel(
            AMQP_BUS_EXCHANGE
        )

    def rpc_status(self):
        return self._status

    def _send_cmd(self, command, params={}, and_discard=False):
        return self._rpc_client.send_rpc(
            command,
            params=params,
            and_discard=and_discard,
            num_results=len(self.ftlist)
        )

    def init_graph(self, newconfig):
        if newconfig:
            self._send_cmd('rebuild', and_discard=True)
            return

        revt = self._send_cmd('state_info')
        success = revt.wait(timeout=30)
        if success is None:
            LOG.error('timeout in state_info, sending reset')
            self._send_cmd('reset', and_discard=True)
            return
        result = revt.get(block=False)

        if result['errors'] > 0:
            LOG.critical('errors reported from nodes in init_graph')
            raise RuntimeError('errors reported from nodes in init_graph')

        checkpoints = set([a.get('checkpoint', None)
                           for a in result['answers'].values()])
        if len(checkpoints) == 1:
            c = next(iter(checkpoints))
            if c is not None:
                LOG.info('all nodes at the same checkpoint (%s) '
                         ' sending initialize', c)
                self._send_cmd('initialize', and_discard=True)
                return

        source_chkps = set([a.get('checkpoint', None)
                            for a in result['answers'].values()
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

        revt = self._send_cmd('checkpoint', params={'value': chkp})
        success = revt.wait(timeout=30)
        if success is None:
            LOG.error('Timeout waiting for answers to checkpoint')
            return

        ntries = 0
        while ntries < 2:
            revt = self._send_cmd('state_info')
            success = revt.wait(timeout=10)
            if success is None:
                LOG.error("Error retrieving nodes states after checkpoint")
                break
            result = revt.get(block=False)

            ok = True
            for a in result['answers'].values():
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
            revt = self._send_cmd('status')
            success = revt.wait(timeout=30)
            if success is None:
                LOG.error('timeout in waiting for status updates from nodes')
            else:
                result = revt.get(block=False)
                self._status = result['answers']

                try:
                    self._send_collectd_metrics(
                        result['answers'],
                        loop_interval
                    )
                except:
                    LOG.exception('Exception in _status_loop')

            gevent.sleep(loop_interval)

    def start_status_monitor(self):
        if self.status_glet is not None:
            LOG.error('double call to start_status')
            return

        self.status_glet = gevent.spawn(self._status_loop)

    def start(self):
        self.comm.start()

    def stop(self):
        self.comm.stop()


class MgmtbusSlaveHub(object):
    def __init__(self, config, comm_class, comm_config):
        self.config = config
        self.comm_config = comm_config
        self.comm_class = comm_class

        self.comm = self.comm_class(self.comm_config)

    def request_channel(self, ft):
        self.comm.request_rpc_server_channel(
            AMQP_PREFIX+'slave:'+ft.name,
            ft,
            allowed_methods=[
                'mgmtbus_state_info',
                'mgmtbus_initialize',
                'mgmtbus_rebuild',
                'mgmtbus_reset',
                'mgmtbus_status',
                'mgmtbus_checkpoint'
            ],
            method_prefix='mgmtbus_',
            fanout=AMQP_BUS_EXCHANGE
        )

    def start(self):
        self.comm.start()

    def stop(self):
        self.comm.stop()


def master_factory(config, comm_class, comm_config, fts):
    return MgmtbusMaster(
        fts,
        config,
        minemeld.comm.amqp.AMQP,
        comm_config
    )


def slave_hub_factory(config, comm_class, comm_config):
    return MgmtbusSlaveHub(
        config,
        minemeld.comm.amqp.AMQP,
        comm_config
    )
