"""FT basepoller tests

Unit tests for minemeld.ft.basepoller
"""

import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest
import mock
import time
import shutil
import logging
import gc
import calendar

import minemeld.ft.basepoller

FTNAME = 'testft-%d' % int(time.time())

LOG = logging.getLogger(__name__)

CUR_LOGICAL_TIME = 0


def logical_millisec(*args):
    return CUR_LOGICAL_TIME


class DeltaFeed(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'age_out': {
                'default': 'last_seen+4',
                'sudden_death': False
            }
        }
        super(DeltaFeed, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.iterators = [
            ['A', 'B', 'C'],
            ['D', 'E', 'F']
        ]

    def _build_iterator(self, now):
        r = []
        if self.cur_iterator < len(self.iterators):
            r = self.iterators[self.cur_iterator]

        self.cur_iterator += 1

        return r

    def _process_item(self, item):
        return [[item, {'type': 'IPv4'}]]


class RollingFeed(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'age_out': {
                'default': 'last_seen+4',
                'sudden_death': True
            }
        }
        super(RollingFeed, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.iterators = [
            ['A', 'B', 'C'],
            ['B', 'C', 'D']
        ]

    def _build_iterator(self, now):
        r = []
        if self.cur_iterator < len(self.iterators):
            r = self.iterators[self.cur_iterator]

        self.cur_iterator += 1

        return r

    def _process_item(self, item):
        return [[item, {'type': 'IPv4'}]]


class PermanentFeed(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'age_out': {
                'default': None,
                'sudden_death': True
            }
        }
        super(PermanentFeed, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.iterators = [
            ['A', 'B', 'C'],
            ['B', 'C', 'D']
        ]

    def _build_iterator(self, now):
        r = []
        if self.cur_iterator < len(self.iterators):
            r = self.iterators[self.cur_iterator]

        self.cur_iterator += 1

        return r

    def _process_item(self, item):
        return [[item, {'type': 'IPv4'}]]


class MineMeldFTBasePollerTests(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    def test_delta_feed(self, um_mock, sleep_mock, spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = DeltaFeed(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        CUR_LOGICAL_TIME = 1
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(um_mock.call_count, 1)

        CUR_LOGICAL_TIME = 2
        a._run()
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 4
        a._run()
        self.assertEqual(a.statistics['added'], 6)
        self.assertEqual(a.statistics.get('removed', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)

        CUR_LOGICAL_TIME = 5
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 6
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 7
        a._age_out_run()
        self.assertEqual(a.statistics['aged_out'], 3)

        CUR_LOGICAL_TIME = 8
        a._run()
        self.assertEqual(a.statistics['added'], 6)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 3)
        self.assertEqual(a.length(), 3)

        a.stop()
        a.table.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    def test_rolling_feed(self, um_mock, sleep_mock, spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = RollingFeed(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        CUR_LOGICAL_TIME = 1
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(um_mock.call_count, 1)

        CUR_LOGICAL_TIME = 2
        a._run()
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 4
        a._run()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('removed', 0), 1)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)

        CUR_LOGICAL_TIME = 5
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 6
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 7
        a._age_out_run()
        self.assertEqual(a.statistics['aged_out'], 3)

        CUR_LOGICAL_TIME = 8
        a._run()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 3)
        self.assertEqual(a.length(), 1)

        a.stop()
        a.table.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    def test_permanent_feed(self, um_mock, sleep_mock,
                            spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = PermanentFeed(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        CUR_LOGICAL_TIME = 1
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(um_mock.call_count, 1)

        CUR_LOGICAL_TIME = 2
        a._run()
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 4
        a._run()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('removed', 0), 1)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)

        CUR_LOGICAL_TIME = 5
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 6
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 7
        a._age_out_run()
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 8
        a._run()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 1)
        self.assertEqual(a.length(), 3)

        a.stop()
        a.table.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
