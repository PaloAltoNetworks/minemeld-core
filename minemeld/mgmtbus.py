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

"""
This module implements master and slave hub classes for MineMeld engine
management bus.

Management bus master sends commands to all managemnt bus slaves by
posting a message to a specific topic (MGMTBUS_PREFIX+'bus').
Slaves subscribe to the topic, and when a command is received they
reply back to the master by sending the answer to the queue
MGMTBUS_PREFIX+'master'. Slaves connections are multiplexed via
slave hub class.

Management bus is used to control the MineMeld engine graph and to
periodically retrieve metrics from all the nodes.
"""

from __future__ import absolute_import

import logging
import uuid
import collections
import time

import gevent
import gevent.event
import gevent.lock
import gevent.timeout

import redis
import ujson

import minemeld.comm
import minemeld.ft

from .collectd import CollectdClient
from .startupplanner import plan

LOG = logging.getLogger(__name__)

MGMTBUS_PREFIX = "mbus:"
MGMTBUS_TOPIC = MGMTBUS_PREFIX+'bus'
MGMTBUS_CHASSIS_TOPIC = MGMTBUS_PREFIX+'chassisbus'
MGMTBUS_MASTER = MGMTBUS_PREFIX+'master'
MGMTBUS_LOG_TOPIC = MGMTBUS_PREFIX+'log'
MGMTBUS_STATUS_TOPIC = MGMTBUS_PREFIX+'status'


class MgmtbusMaster(object):
    """MineMeld engine management bus master

    Args:
        ftlist (list): list of nodes
        config (dict): config
        comm_class (string): communication backend to be used
        comm_config (dict): config for the communication backend
    """
    def __init__(self, ftlist, config, comm_class, comm_config, num_chassis):
        super(MgmtbusMaster, self).__init__()

        self.ftlist = ftlist
        self.config = config
        self.comm_config = comm_config
        self.comm_class = comm_class
        self.num_chassis = num_chassis

        self._chassis = []
        self._all_chassis_ready = gevent.event.Event()

        self.graph_status = None

        self._start_timestamp = int(time.time())*1000
        self._status_lock = gevent.lock.Semaphore()
        self.status_glet = None
        self._status = {}

        self.SR = redis.StrictRedis.from_url(
            self.config.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
        )

        self.comm = minemeld.comm.factory(self.comm_class, self.comm_config)
        self._out_channel = self.comm.request_pub_channel(MGMTBUS_TOPIC)
        self.comm.request_rpc_server_channel(
            MGMTBUS_PREFIX+'master',
            self,
            allowed_methods=['rpc_status', 'rpc_chassis_ready'],
            method_prefix='rpc_'
        )
        self._slaves_rpc_client = self.comm.request_rpc_fanout_client_channel(
            MGMTBUS_TOPIC
        )
        self._chassis_rpc_client = self.comm.request_rpc_fanout_client_channel(
            MGMTBUS_CHASSIS_TOPIC
        )
        self.comm.request_sub_channel(
            MGMTBUS_STATUS_TOPIC,
            self,
            allowed_methods=['status'],
            name=MGMTBUS_STATUS_TOPIC+':master',
            max_length=100
        )

    def rpc_status(self):
        """Returns collected status via RPC
        """
        return self._status

    def rpc_chassis_ready(self, chassis_id=None):
        """Chassis signal ready state via this RPC
        """
        if chassis_id in self._chassis:
            LOG.error('duplicate chassis_id received in rpc_chassis_ready')
            return 'ok'

        self._chassis.append(chassis_id)
        if len(self._chassis) == self.num_chassis:
            self._all_chassis_ready.set()

        return 'ok'

    def wait_for_chassis(self, timeout=60):
        """Wait for all the chassis signal ready state
        """
        if self.num_chassis == 0:  # empty config
            return

        if not self._all_chassis_ready.wait(timeout=timeout):
            raise RuntimeError('Timeout waiting for chassis')

    def start_chassis(self):
        self._send_cmd_and_wait(
            'start',
            to_slaves=False,  # chassis
            timeout=60
        )

    def _send_cmd(self, command, to_slaves=True, params=None, and_discard=False):
        """Sends command to slaves or chassis over mgmt bus.

        Args:
            command (str): command
            params (dict): params of the command
            and_discard (bool): discard answer, don't wait
            to_slaves (bool): send command to nodes, otherwise to chassis

        Returns:
            returns a gevent.event.AsyncResult that is signaled
            when all the answers are collected
        """
        if params is None:
            params = {}

        rpc_client = self._slaves_rpc_client
        num_results = len(self.ftlist)
        if not to_slaves:
            rpc_client = self._chassis_rpc_client
            num_results = self.num_chassis

        return rpc_client.send_rpc(
            command,
            params=params,
            and_discard=and_discard,
            num_results=num_results
        )

    def _send_cmd_and_wait(self, command, to_slaves=True, timeout=60):
        """Simple wrapper around _send_cmd for raising exceptions
        """
        revt = self._send_cmd(command, to_slaves=to_slaves)
        success = revt.wait(timeout=timeout)
        if success is None:
            LOG.critical('Timeout in {}'.format(command))
            raise RuntimeError('Timeout in {}'.format(command))
        result = revt.get(block=False)
        if result['errors'] > 0:
            LOG.critical('Errors reported in {}'.format(command))
            raise RuntimeError('Errors reported in {}'.format(command))

        return result

    def _send_node_cmd(self, nodename, command, params=None):
        """Send command to a single node
        """
        if params is None:
            params = {}

        try:
            result = self.comm.send_rpc(
                dest='{}directslave:{}'.format(MGMTBUS_PREFIX, nodename),
                method=command,
                params=params,
                timeout=60
            )
        except gevent.timeout.Timeout:
            msg = 'Timeout in {} to node {}'.format(command, nodename)
            LOG.error(msg)
            raise RuntimeError(msg)

        if result.get('result', None) is None:
            raise RuntimeError('Error in {} to node {}: {}'.format(
                command, nodename, result.get('error', '<unknown>')
            ))

        return result['result']

    def init_graph(self, config):
        """Initalizes graph by sending startup messages.

        Args:
            config (MineMeldConfig): config
        """
        result = self._send_cmd_and_wait('state_info', timeout=60)
        LOG.info('state: {}'.format(result['answers']))
        LOG.info('changes: {!r}'.format(config.changes))

        state_info = {k.split(':', 2)[-1]: v for k, v in result['answers'].iteritems()}

        startup_plan = plan(config, state_info)
        for node, command in startup_plan.iteritems():
            LOG.info('{} <= {}'.format(node, command))
            self._send_node_cmd(node, command)

        self.graph_status = 'INIT'

    def checkpoint_graph(self, max_tries=60):
        """Checkpoints the graph.

        Args:
            max_tries (int): number of minutes before giving up
        """
        LOG.info('checkpoint_graph called, checking current state')

        if self.graph_status != 'INIT':
            LOG.info('graph status {}, checkpoint_graph ignored'.format(self.graph_status))
            return

        while True:
            revt = self._send_cmd('state_info')
            success = revt.wait(timeout=30)
            if success is None:
                LOG.error('timeout in state_info')
                gevent.sleep(60)
                continue

            result = revt.get(block=False)
            if result['errors'] > 0:
                LOG.critical('errors reported from nodes in ' +
                             'checkpoint_graph: %s',
                             result['errors'])
                gevent.sleep(60)
                continue

            all_started = True
            for answer in result['answers'].values():
                if answer.get('state', None) != minemeld.ft.ft_states.STARTED:
                    all_started = False
                    break
            if not all_started:
                LOG.error('some nodes not started yet, waiting')
                gevent.sleep(60)
                continue

            break

        chkp = str(uuid.uuid4())
        LOG.info('Sending checkpoint {} to nodes'.format(chkp))
        for nodename in self.ftlist:
            self._send_node_cmd(nodename, 'checkpoint', params={'value': chkp})

        ntries = 0
        while ntries < max_tries:
            revt = self._send_cmd('state_info')
            success = revt.wait(timeout=60)
            if success is None:
                LOG.error("Error retrieving nodes states after checkpoint")
                gevent.sleep(30)
                continue

            result = revt.get(block=False)

            cgraphok = True
            for answer in result['answers'].values():
                cgraphok &= (answer['checkpoint'] == chkp)
            if cgraphok:
                LOG.info('checkpoint graph - all good')
                break

            gevent.sleep(2)
            ntries += 1

        if ntries == max_tries:
            LOG.error('checkpoint_graph: nodes still not in '
                      'checkpoint state after max_tries')

        self.graph_status = 'CHECKPOINT'

    def _send_collectd_metrics(self, answers, interval):
        """Send collected metrics from nodes to collectd.

        Args:
            answers (list): list of metrics
            interval (int): collection interval
        """
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

    def _merge_status(self, nodename, status):
        currstatus = self._status.get(nodename, None)
        if currstatus is not None:
            if currstatus.get('clock', -1) > status.get('clock', -2):
                LOG.error('old clock: {} > {} - dropped'.format(
                    currstatus.get('clock', -1),
                    status.get('clock', -2)
                ))
                return

        self._status[nodename] = status

        try:
            source = nodename.split(':', 2)[2]
            self.SR.publish(
                'mm-engine-status.'+source,
                ujson.dumps({
                    'source': source,
                    'timestamp': int(time.time())*1000,
                    'status': status
                })
            )

        except:
            LOG.exception('Error publishing status')

    def _status_loop(self):
        """Greenlet that periodically retrieves metrics from nodes and sends
        them to collected.
        """
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

                with self._status_lock:
                    for nodename, nodestatus in result['answers'].iteritems():
                        self._merge_status(nodename, nodestatus)

                try:
                    self._send_collectd_metrics(
                        result['answers'],
                        loop_interval
                    )

                except:
                    LOG.exception('Exception in _status_loop')

            gevent.sleep(loop_interval)

    def status(self, timestamp, **kwargs):
        source = kwargs.get('source', None)
        if source is None:
            LOG.error('no source in status report - dropped')
            return

        status = kwargs.get('status', None)
        if status is None:
            LOG.error('no status in status report - dropped')
            return

        if self._status_lock.locked():
            return

        with self._status_lock:
            if timestamp < self._start_timestamp:
                return

            self._merge_status('mbus:slave:'+source, status)

    def start_status_monitor(self):
        """Starts status monitor greenlet.
        """
        if self.status_glet is not None:
            LOG.error('double call to start_status')
            return

        self.status_glet = gevent.spawn(self._status_loop)

    def stop_status_monitor(self):
        """Stops status monitor greenlet.
        """
        if self.status_glet is None:
            return
        self.status_glet.kill()
        self.status_glet = None

    def start(self):
        self.comm.start()

    def stop(self):
        self.comm.stop()


class MgmtbusSlaveHub(object):
    """Hub MineMeld engine management bus slaves. Each chassis
        has an instance of this class, and each node in the chassis
        request a channel to the management bus via this instance.

    Args:
        config (dict): config
        comm_class (string): communication backend to be used
        comm_config (dict): config for the communication backend
    """

    def __init__(self, config, comm_class, comm_config):
        self.config = config
        self.comm_config = comm_config
        self.comm_class = comm_class

        self.comm = minemeld.comm.factory(self.comm_class, self.comm_config)

    def request_log_channel(self):
        LOG.debug("Adding log channel")
        return self.comm.request_pub_channel(
            MGMTBUS_LOG_TOPIC
        )

    def request_status_channel(self):
        LOG.debug("Adding status channel")
        return self.comm.request_pub_channel(
            MGMTBUS_STATUS_TOPIC
        )

    def request_chassis_rpc_channel(self, chassis):
        self.comm.request_rpc_server_channel(
            '{}chassis:{}'.format(MGMTBUS_PREFIX, chassis.chassis_id),
            chassis,
            allowed_methods=[
                'mgmtbus_start'
            ],
            method_prefix='mgmtbus_',
            fanout=MGMTBUS_CHASSIS_TOPIC
        )

    def request_channel(self, node):
        self.comm.request_rpc_server_channel(
            '{}directslave:{}'.format(MGMTBUS_PREFIX, node.name),
            node,
            allowed_methods=[
                'mgmtbus_state_info',
                'mgmtbus_initialize',
                'mgmtbus_rebuild',
                'mgmtbus_reset',
                'mgmtbus_status',
                'mgmtbus_checkpoint',
                'mgmtbus_hup',
                'mgmtbus_signal'
            ],
            method_prefix='mgmtbus_'
        )
        self.comm.request_rpc_server_channel(
            '{}slave:{}'.format(MGMTBUS_PREFIX, node.name),
            node,
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

    def add_failure_listener(self, f):
        self.comm.add_failure_listener(f)

    def send_master_rpc(self, command, params=None, timeout=None):
        return self.comm.send_rpc(
            MGMTBUS_MASTER,
            command,
            params,
            timeout=timeout
        )

    def start(self):
        LOG.debug('mgmtbus start called')
        self.comm.start()

    def stop(self):
        self.comm.stop()


def master_factory(config, comm_class, comm_config, nodes, num_chassis):
    """Factory of management bus master instances

    Args:
        config (dict): management bus master config
        comm_class (string): communication backend.
            Unused, AMQP is always used
        comm_config (dict): config of the communication backend
        fts (list): list of nodes

    Returns:
        Instance of minemeld.mgmtbus.MgmtbusMaster class
    """
    _ = comm_class  # noqa

    return MgmtbusMaster(
        ftlist=nodes,
        config=config,
        comm_class='AMQP',
        comm_config=comm_config,
        num_chassis=num_chassis
    )


def slave_hub_factory(config, comm_class, comm_config):
    """Factory of management bus slave hub instances

    Args:
        config (dict): management bus master config
        comm_class (string): communication backend.
            Unused, AMQP is always used
        comm_config (dict): config of the communication backend.

    Returns:
        Instance of minemeld.mgmtbus.MgmtbusSlaveHub class
    """
    _ = comm_class  # noqa

    return MgmtbusSlaveHub(
        config,
        'AMQP',
        comm_config
    )
