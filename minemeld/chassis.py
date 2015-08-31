"""Chassis module

A chassis instance contains a list of FT and a fabric.
FTs communicate using the fabric.
"""

import logging
import time

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

LOG = logging.getLogger(__name__)
STATE_REPORT_INTERVAL = 10


class Chassis(object):
    def __init__(self, fabricclass, fabricconfig,
                 report_state=True, reinit=True):
        """Chassis class

        Args:
            fabricclass (str): class for the fabric
            fabricconfig (dict): config dictionary for fabric,
                class specific
        """
        LOG.debug("reinit: %s", reinit)

        self.fts = {}

        self.fabric_class = fabricclass
        self.fabric_config = fabricconfig
        self.fabric = self._dynamic_load(self.fabric_class)(
            chassis=self,
            config=self.fabric_config
        )

        self.g_state_report = None
        self.rs_flag = report_state
        if self.rs_flag:
            self.state_report_channel = \
                self.fabric.request_state_report_channel()

        self.reinit_flag = reinit

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

    def _state_report(self):
        while True:
            try:
                state = {
                    'FTs': {}
                }
                for ft in self.fts:
                    state['FTs'][ft] = self.fts[ft].state()

                params = {
                    'timestamp': time.time(),
                    'state': state
                }
                self.state_report_channel.publish('state', params=params)

                LOG.debug("Reported state")
            except gevent.GreenletExit:
                return
            except:
                LOG.exception("Exception in report_state greenlet")

            gevent.sleep(STATE_REPORT_INTERVAL)

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
            if ft not in self.fts:
                # new FT
                newfts[ft] = self._dynamic_load(ftconfig['class'])(
                    name=ft,
                    chassis=self,
                    config=ftconfig['args'],
                    reinit=self.reinit_flag
                )
                newfts[ft].connect(
                    ftconfig.get('inputs', []),
                    ftconfig.get('output', False)
                )
            else:
                # FT already exists
                cft = self.fts[ft]
                if self._diff(cft.config, ftconfig['args']):
                    # configuration changed
                    if cft.hasattr('reconfigure'):
                        cft.reconfigure(ftconfig['args'])
                        newfts[ft] = cft
                    else:
                        cft.destroy()
                        newfts[ft] = self._dynamic_load(ftconfig['class'])(
                            name=ft,
                            chassis=self,
                            config=ftconfig['args']
                        )

        removed = set(self.fts.keys())-set(newfts.keys())
        for ft in removed:
            self.fts[ft].destroy()

        self.fts = newfts

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

    def stop(self):
        LOG.info("chassis stop called")

        if self.fabric is None:
            return

        for ftname, ft in self.fts.iteritems():
            ft.stop()

        if self.g_state_report is not None:
            self.g_state_report.kill()
            self.g_state_report = None

        self.fabric.stop()

        self.poweroff.set(value='stop')

    def start(self):
        if self.fabric is None:
            return

        self.fabric.start()

        if self.rs_flag:
            self.g_state_report = gevent.spawn(self._state_report)

        for ftname, ft in self.fts.iteritems():
            ft.start()

        self.poweroff = gevent.event.AsyncResult()
