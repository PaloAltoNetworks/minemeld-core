"""Chassis module

A chassis instance contains a list of FT and a fabric.
FTs communicate using the fabric.
"""

import logging

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import minemeld.mgmtbus
import minemeld.ft
import minemeld.fabric

LOG = logging.getLogger(__name__)
STATE_REPORT_INTERVAL = 10


class Chassis(object):
    def __init__(self, fabricclass, fabricconfig, mgmtbusconfig):
        """Chassis class

        Args:
            fabricclass (str): class for the fabric
            fabricconfig (dict): config dictionary for fabric,
                class specific
        """
        self.fts = {}

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

    def _dynamic_load(self, classname):
        modname, classname = classname.rsplit('.', 1)
        t = __import__(modname, globals(), locals(), [classname])
        cls = getattr(t, classname)
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
        return self.mgmtbus.request_channel(ft)

    def request_rpc_channel(self, ftname, ft, allowed_methods=[]):
        self.fabric.request_rpc_channel(ftname, ft, allowed_methods)

    def request_pub_channel(self, ftname):
        return self.fabric.request_pub_channel(ftname)

    def request_sub_channel(self, ftname, ft, subname, allowed_methods=[]):
        self.fabric.request_sub_channel(ftname, ft, subname, allowed_methods)

    def send_rpc(self, sftname, dftname, method, params, block, timeout):
        return self.fabric.send_rpc(sftname, dftname, method, params,
                                    block=block, timeout=timeout)

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

        for ftname, ft in self.fts.iteritems():
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
