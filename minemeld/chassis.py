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

import logging

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import ujson

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
        self.fts = {}
        self.poweroff = None

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
        self.log_channel = self.mgmtbus.request_log_channel()

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

    def log(self, nodename, log):
        self.log_channel.publish(
            method='log',
            params={
                'source': nodename,
                'log': ujson.dumps(log)
            }
        )

    def fabric_failed(self):
        self.stop()

    def fts_init(self):
        for ft in self.fts.values():
            if ft.get_state() < minemeld.ft.ft_states.INIT:
                return False
        return True

    def stop(self):
        LOG.info("chassis stop called")

        if self.fabric is None:
            return

        for _, ft in self.fts.iteritems():
            ft.stop()

        self.fabric.stop()
        self.mgmtbus.stop()

        self.poweroff.set(value='stop')

    def start(self):
        LOG.info("chassis start called")

        if self.fabric is None:
            return

        self.fabric.start()

        for ftname, ft in self.fts.iteritems():
            LOG.debug("starting %s", ftname)
            ft.start()

        self.poweroff = gevent.event.AsyncResult()
