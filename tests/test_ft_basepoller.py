#  Copyright 2015 Palo Alto Networks, Inc
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

"""FT basepoller tests

Unit tests for minemeld.ft.basepoller
"""

import gevent.hub
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest
import mock
import time
import shutil
import logging
import gc

import minemeld.ft.basepoller

FTNAME = 'testft-%d' % int(time.time())

LOG = logging.getLogger(__name__)

CUR_LOGICAL_TIME = 0


def logical_millisec(*args):
    return CUR_LOGICAL_TIME*1000


def gevent_event_mock_factory():
    result = mock.Mock()
    result.wait.side_effect = gevent.GreenletExit()

    return result


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


class SuperPermanentFeed(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'age_out': {
                'interval': None,
                'default': None,
                'sudden_death': True
            }
        }
        super(SuperPermanentFeed, self).__init__(name, chassis, config)

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
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_delta_feed(self, um_mock, event_mock, sleep_mock, spawnl_mock, spawn_mock):
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
        self.assertEqual(spawn_mock.call_count, 3)

        CUR_LOGICAL_TIME = 1
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(um_mock.call_count, 1)

        CUR_LOGICAL_TIME = 2
        a._poll()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 4
        a._poll()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 6)
        self.assertEqual(a.statistics.get('removed', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)

        CUR_LOGICAL_TIME = 5
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 6
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 7
        a._age_out()
        self.assertEqual(a.statistics['aged_out'], 3)

        CUR_LOGICAL_TIME = 8
        a._poll()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 6)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 3)
        self.assertEqual(a.length(), 3)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_rolling_feed(self, um_mock, event_mock, sleep_mock,
                          spawnl_mock, spawn_mock):
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
        self.assertEqual(spawn_mock.call_count, 3)

        CUR_LOGICAL_TIME = 1
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(um_mock.call_count, 1)

        CUR_LOGICAL_TIME = 2
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 4
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('removed', 0), 1)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 1)

        CUR_LOGICAL_TIME = 5
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 6
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 7
        a._age_out()
        self.assertEqual(a.statistics['aged_out'], 3)

        CUR_LOGICAL_TIME = 8
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 4)
        self.assertEqual(a.length(), 0)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_permanent_feed(self, um_mock, event_mock,
                            sleep_mock, spawnl_mock, spawn_mock):
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
        self.assertEqual(spawn_mock.call_count, 3)

        CUR_LOGICAL_TIME = 1
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(um_mock.call_count, 1)

        CUR_LOGICAL_TIME = 2
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        CUR_LOGICAL_TIME = 4
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('removed', 0), 1)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 1)

        CUR_LOGICAL_TIME = 5
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 6
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 7
        a._age_out()
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 8
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 4)
        self.assertEqual(a.length(), 0)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_superpermanent_feed(self, um_mock, event_mock,
                                 sleep_mock, spawnl_mock, spawn_mock):
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
        self.assertEqual(spawn_mock.call_count, 3)

        CUR_LOGICAL_TIME = 1
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(um_mock.call_count, 1)

        CUR_LOGICAL_TIME = 2
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 4
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('removed', 0), 1)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 1)
        self.assertEqual(a.statistics.get('aged_out', 0), 1)

        CUR_LOGICAL_TIME = 8
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 4)
        self.assertEqual(a.length(), 0)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_drop_old_ops(self, um_mock, event_mock, sleep_mock, spawnl_mock, spawn_mock):
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
        self.assertEqual(spawn_mock.call_count, 3)

        a._actor_queue.put((0, 'age_out'))
        a._actor_queue.put((999, 'age_out'))

        CUR_LOGICAL_TIME = 1
        try:
            a._actor_loop()
        except gevent.hub.LoopExit:
            pass
        self.assertEqual(a.last_ageout_run, 1000)
        self.assertEqual(um_mock.call_count, 2)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
