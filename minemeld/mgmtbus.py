from __future__ import absolute_import

import gevent
import gevent.event
import logging
import uuid
import collections

import minemeld.comm
import minemeld.ft

from .collectd import CollectdClient

LOG = logging.getLogger(__name__)

MGMTBUS_PREFIX = "mbus:"
MGMTBUS_TOPIC = MGMTBUS_PREFIX+'bus'
MGMTBUS_MASTER = MGMTBUS_PREFIX+'master'


class MgmtbusMaster(object):
    def __init__(self, ftlist, config, comm_class, comm_config):
        super(MgmtbusMaster, self).__init__()

        self.ftlist = ftlist
        self.config = config
        self.comm_config = comm_config
        self.comm_class = comm_class

        self.status_glet = None
        self._status = {}

        self.comm = minemeld.comm.factory(self.comm_class, self.comm_config)
        self._out_channel = self.comm.request_pub_channel(MGMTBUS_TOPIC)
        self.comm.request_rpc_server_channel(
            MGMTBUS_PREFIX+'master',
            self,
            allowed_methods=['rpc_status'],
            method_prefix='rpc_'
        )
        self._rpc_client = self.comm.request_rpc_fanout_client_channel(
            MGMTBUS_TOPIC
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
            LOG.info("new config: sending rebuild")
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

        LOG.info("sending reset")
        self._send_cmd('reset', and_discard=True)

    def checkpoint_graph(self, max_tries=12, try_interval=5):
        LOG.info('checkpoint_graph called, checking current state')

        while True:
            revt = self._send_cmd('state_info')
            success = revt.wait(timeout=30)
            if success is None:
                LOG.error('timeout in state_info')
                gevent.sleep(60)
                continue
            LOG.debug(revt)

            result = revt.get(block=False)
            if result['errors'] > 0:
                LOG.critical('errors reported from nodes in checkpoint_graph: %s',
                             result['errors'])
                gevent.sleep(60)
                continue

            all_started = True
            for a in result['answers'].values():
                if a.get('state', None) != minemeld.ft.ft_states.STARTED:
                    all_started = False
                    break
            if not all_started:
                LOG.error('some nodes not started yet, waiting')
                gevent.sleep(60)
                continue

            break

        chkp = str(uuid.uuid4())

        revt = self._send_cmd('checkpoint', params={'value': chkp})
        success = revt.wait(timeout=60)
        if success is None:
            LOG.error('Timeout waiting for answers to checkpoint')
            return

        ntries = 0
        while ntries < max_tries:
            revt = self._send_cmd('state_info')
            success = revt.wait(timeout=60)
            if success is None:
                LOG.error("Error retrieving nodes states after checkpoint")
                gevent.sleep(30)
                continue

            result = revt.get(block=False)

            ok = True
            for a in result['answers'].values():
                ok &= (a['checkpoint'] == chkp)
            if ok:
                LOG.info('checkpoint graph - all good')
                break

            gevent.sleep(10)
            ntries += 1

        if ntries == max_tries:
            LOG.error('checkpoint_graph: nodes still not in '
                      'checkpoint state after max_tries')

        LOG.debug('checkpoint_graph done')

    def _send_collectd_metrics(self, answers, interval):
        collectd_socket = self.config.get(
            'COLLECTD_SOCKET',
            '/var/run/collectd.sock'
        )

        cc = CollectdClient(collectd_socket)

        gstats = collections.defaultdict(lambda: 0)

        for source, a in answers.iteritems():
            ntype = 'processors'
            if len(a.get('inputs', [])) == 0:
                ntype = 'miners'
            elif not a.get('output', False):
                ntype = 'outputs'

            stats = a.get('statistics', {})
            length = a.get('length', None)

            _, _, source = source.split(':', 2)

            for m, v in stats.iteritems():
                gstats[ntype+'.'+m] += v
                cc.putval(source+'.'+m, v,
                          interval=interval,
                          type_='minemeld_delta')

            if length is not None:
                gstats['length'] += length
                gstats[ntype+'.length'] += length
                cc.putval(
                    source+'.length',
                    length,
                    type_='minemeld_counter',
                    interval=interval
                )

        for gs, v in gstats.iteritems():
            type_ = 'minemeld_delta'
            if gs.endswith('length'):
                type_ = 'minemeld_counter'

            cc.putval('minemeld.'+gs, v, type_=type_, interval=interval)

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

        self.comm = minemeld.comm.factory(self.comm_class, self.comm_config)

    def request_channel(self, ft):
        self.comm.request_rpc_server_channel(
            MGMTBUS_PREFIX+'slave:'+ft.name,
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
            fanout=MGMTBUS_TOPIC
        )

    def start(self):
        self.comm.start()

    def stop(self):
        self.comm.stop()


def master_factory(config, comm_class, comm_config, fts):
    return MgmtbusMaster(
        fts,
        config,
        'AMQP',
        comm_config
    )


def slave_hub_factory(config, comm_class, comm_config):
    return MgmtbusSlaveHub(
        config,
        'AMQP',
        comm_config
    )
