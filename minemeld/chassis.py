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

LOG = logging.getLogger(__name__)
STATE_REPORT_INTERVAL = 10


class Chassis(object):
    def __init__(self, fabricclass, fabricconfig,
                 mgmtbusclass, mgmtbusconfig):
        """Chassis class

        Args:
            fabricclass (str): class for the fabric
            fabricconfig (dict): config dictionary for fabric,
                class specific
        """
        self.fts = {}

        self.fabric_class = fabricclass
        self.fabric_config = fabricconfig
        self.fabric = self._dynamic_load(self.fabric_class)(
            chassis=self,
            config=self.fabric_config
        )

        self.mgmtbus_class = mgmtbusclass
        self.mgmtbus_config = mgmtbusconfig
        self.mgmtbus = minemeld.mgmtbus.slave_factory(
            self.mgmtbus_class,
            self.mgmtbus_config
        )

    def _diff(self, A, B):
        setA = set(A.keys())
        setB = set(B.keys())
        if len(setA) != len(setB):
            return True
        if len(setA.union(setB)) != len(setA):
            return True
        for k, v in A.iteritems():
            if B[k] != v:
                return True
        return False

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
            newfts[ft] = self._dynamic_load(ftconfig['class'])(
                name=ft,
                chassis=self,
                config=ftconfig['args']
            )
            newfts[ft].connect(
                ftconfig.get('inputs', []),
                ftconfig.get('output', False)
            )

        self.fts = newfts

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

        self.poweroff.set(value='stop')

    def start(self):
        if self.fabric is None:
            return

        self.fabric.start()

        for ftname, ft in self.fts.iteritems():
            ft.start()

        self.poweroff = gevent.event.AsyncResult()
