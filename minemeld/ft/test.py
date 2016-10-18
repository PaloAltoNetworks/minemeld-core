from __future__ import absolute_import

import logging
import gevent

from . import base
from .utils import utc_millisec

import netaddr


LOG = logging.getLogger(__name__)


class TestMiner(base.BaseFT):
    def __init__(self, name, chassis, config):
        super(TestMiner, self).__init__(name, chassis, config)

        self._glet = None

    def configure(self):
        super(TestMiner, self).configure()

        self.num_messages = self.config.get('num_messages', 100000)
        self.mps = self.config.get('mps', 1000)

    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    def _run(self):
        cip = 0x0A000000

        v = {
            'type': 'IPv4',
            'confidence': 0,
            'share_level': 'red'
        }

        LOG.info('%s - start sending messages: %d', self.name, utc_millisec())

        t1 = utc_millisec()
        for i in xrange(self.num_messages):
            ip = str(netaddr.IPAddress(i+cip))
            self.emit_update(ip, v)

            if ((i+1) % self.mps) == 0:
                now = utc_millisec()
                LOG.info('%d: %d', i+1, now - t1)

                if now - t1 < 1000:
                    gevent.sleep((1000 - now + t1)/1000.0)

                t1 = now

        LOG.info('%s - all messages sent: %d', self.name, utc_millisec())

    def length(self, source=None):
        return 0

    def start(self):
        super(TestMiner, self).start()

        self._glet = gevent.spawn_later(
            2,
            self._run
        )

    def stop(self):
        super(TestMiner, self).stop()

        if self._glet is None:
            return

        self._glet.kill()


class TestFeed(base.BaseFT):
    def __init__(self, name, chassis, config):
        super(TestFeed, self).__init__(name, chassis, config)

    def configure(self):
        super(TestFeed, self).configure()

        self.num_messages = self.config.get('num_messages', 100000)

    def read_checkpoint(self):
        self.last_checkpoint = None

    def create_checkpoint(self, value):
        pass

    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        if self.statistics['update.processed'] == 1:
            LOG.info('%s - first message: %d', self.name, utc_millisec())
        elif self.statistics['update.processed'] == self.num_messages:
            LOG.info('%s - last message: %d', self.name, utc_millisec())

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        pass

    def length(self, source=None):
        pass


class FaultyConfig(base.BaseFT):
    def configure(self):
        super(FaultyConfig, self).configure()

        raise RuntimeError('fault !')

    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    def length(self, source=None):
        return 0


class FaultyInit(base.BaseFT):
    def __init__(self, name, chassis, config):
        raise RuntimeError('fault !')

    def configure(self):
        pass

    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    def length(self, source=None):
        return 0
