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
minemeld.chassis

A chassis instance contains a list of nodes and a fabric.
Nodes communicate using the fabric.
"""

import os
import logging

import gevent
import gevent.queue
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import minemeld.mgmtbus
import minemeld.ft
import minemeld.fabric

LOG = logging.getLogger(__name__)
STATE_REPORT_INTERVAL = 10


class Chassis(object):
    """Chassis class

    Args:
        fabricclass (str): class for the fabric
        fabricconfig (dict): config dictionary for fabric,
            class specific
        mgmtbusconfig (dict): config dictionary for mgmt bus
    """
    def __init__(self, fabricclass, fabricconfig, mgmtbusconfig):
        self.chassis_id = os.getpid()

        self.fts = {}
        self.poweroff = gevent.event.AsyncResult()

        self.fabric_class = fabricclass
        self.fabric_config = fabricconfig
        self.fabric = minemeld.fabric.factory(
            self.fabric_class,
            self,
            self.fabric_config
        )

        self.mgmtbus = minemeld.mgmtbus.slave_hub_factory(
            mgmtbusconfig['slave'],
            mgmtbusconfig['transport']['class'],
            mgmtbusconfig['transport']['config']
        )
        self.mgmtbus.add_failure_listener(self.mgmtbus_failed)
        self.mgmtbus.request_chassis_rpc_channel(self)

        self.log_channel_queue = gevent.queue.Queue(maxsize=128)
        self.log_channel = self.mgmtbus.request_log_channel()
        self.log_glet = None

        self.status_channel_queue = gevent.queue.Queue(maxsize=128)
        self.status_glet = None

    def _dynamic_load(self, classname):
        modname, classname = classname.rsplit('.', 1)
        imodule = __import__(modname, globals(), locals(), [classname])
        cls = getattr(imodule, classname)
        return cls

    def get_ft(self, ftname):
        return self.fts.get(ftname, None)

    def configure(self, config):
        """configures the chassis instance

        Args:
            config (list): list of FTs
        """
        newfts = {}
        for ft in config:
            ftconfig = config[ft]
            LOG.debug(ftconfig)

            # new FT
            newfts[ft] = minemeld.ft.factory(
                ftconfig['class'],
                name=ft,
                chassis=self,
                config=ftconfig.get('config', {})
            )
            newfts[ft].connect(
                ftconfig.get('inputs', []),
                ftconfig.get('output', False)
            )

        self.fts = newfts

        # XXX should be moved to constructor
        self.mgmtbus.start()
        self.fabric.start()

        self.mgmtbus.send_master_rpc(
            'chassis_ready',
            params={'chassis_id': self.chassis_id},
            timeout=10
        )

    def request_mgmtbus_channel(self, ft):
        self.mgmtbus.request_channel(ft)

    def request_rpc_channel(self, ftname, ft, allowed_methods=None):
        if allowed_methods is None:
            allowed_methods = []
        self.fabric.request_rpc_channel(ftname, ft, allowed_methods)

    def request_pub_channel(self, ftname):
        return self.fabric.request_pub_channel(ftname)

    def request_sub_channel(self, ftname, ft, subname, allowed_methods=None):
        if allowed_methods is None:
            allowed_methods = []
        self.fabric.request_sub_channel(ftname, ft, subname, allowed_methods)

    def send_rpc(self, sftname, dftname, method, params, block, timeout):
        return self.fabric.send_rpc(sftname, dftname, method, params,
                                    block=block, timeout=timeout)

    def _log_actor(self):
        while True:
            try:
                params = self.log_channel_queue.get()
                self.log_channel.publish(
                    method='log',
                    params=params
                )

            except Exception:
                LOG.exception('Error sending log')

    def log(self, timestamp, nodename, log_type, value):
        self.log_channel_queue.put({
            'timestamp': timestamp,
            'source': nodename,
            'log_type': log_type,
            'log': value
        })

    def _status_actor(self):
        while True:
            try:
                params = self.status_channel_queue.get()
                self.mgmtbus.send_status(
                    params=params
                )

            except Exception:
                LOG.exception('Error publishing status')

    def publish_status(self, timestamp, nodename, status):
        self.status_channel_queue.put({
            'timestamp': timestamp,
            'source': nodename,
            'status': status
        })

    def fabric_failed(self):
        self.stop()

    def mgmtbus_failed(self):
        LOG.critical('chassis - mgmtbus failed')
        self.stop()

    def mgmtbus_start(self):
        LOG.info('chassis - start received from mgmtbus')
        self.start()
        return 'ok'

    def fts_init(self):
        for ft in self.fts.values():
            if ft.get_state() < minemeld.ft.ft_states.INIT:
                return False
        return True

    def stop(self):
        LOG.info("chassis stop called")

        if self.log_glet is not None:
            self.log_glet.kill()

        if self.status_glet is not None:
            self.status_glet.kill()

        if self.fabric is None:
            return

        for ftname, ft in self.fts.iteritems():
            try:
                ft.stop()
            except:
                LOG.exception('Error stopping {}'.format(ftname))

        LOG.info('Stopping fabric')
        self.fabric.stop()

        LOG.info('Stopping mgmtbus')
        self.mgmtbus.stop()

        LOG.info('chassis - stopped')
        self.poweroff.set(value='stop')

    def start(self):
        LOG.info("chassis start called")

        self.log_glet = gevent.spawn(self._log_actor)
        self.status_glet = gevent.spawn(self._status_actor)

        for ftname, ft in self.fts.iteritems():
            LOG.debug("starting %s", ftname)
            ft.start()

        self.fabric.start_dispatching()
