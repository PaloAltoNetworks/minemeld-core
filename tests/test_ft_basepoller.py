# -*- coding: utf-8 -*-
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
import minemeld.ft.table

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


class RollingFeedFirst(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'age_out': {
                'default': 'first_seen+1',
                'sudden_death': True
            }
        }
        super(RollingFeedFirst, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.iterators = [
            ['A', 'B', 'C'],
            ['B', 'C', 'D'],
            ['B', 'E', 'F'],
            ['E', 'F', 'G'],
            ['B', 'F', 'G']
        ]

    def _build_iterator(self, now):
        r = []
        if self.cur_iterator < len(self.iterators):
            r = self.iterators[self.cur_iterator]

        self.cur_iterator += 1

        return r

    def _process_item(self, item):
        return [[item, {'type': 'IPv4'}]]


class RollingFeedFirst2(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'age_out': {
                'default': 'first_seen+1',
                'sudden_death': True
            }
        }
        super(RollingFeedFirst2, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.iterators = [
            ['A'],
            ['A'],
            ['A'],
            [],
            ['A']
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


class PermanentFeedWithType(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'multiple_indicator_types': True,
            'age_out': {
                'default': None,
                'sudden_death': True
            }
        }
        super(PermanentFeedWithType, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.iterators = [
            ['IPv4@A', 'domain@B', 'domain@C'],
            ['IPv4@B', 'domain@C', 'IPv4@D']
        ]

    def _build_iterator(self, now):
        r = []
        if self.cur_iterator < len(self.iterators):
            r = self.iterators[self.cur_iterator]

        self.cur_iterator += 1

        return r

    def _process_item(self, item):
        it, i = item.split('@', 1)
        return [[i, {'type': it}]]


class PermanentFeedWithTypeAggregated(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'multiple_indicator_types': True,
            'aggregate_indicators': True,
            'age_out': {
                'default': None,
                'sudden_death': True
            }
        }
        super(PermanentFeedWithTypeAggregated, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.iterators = [
            ['IPv4@A@1', 'domain@B@1', 'domain@C@1', 'IPv4@A@2'],
            ['IPv4@B@1', 'domain@C@1', 'IPv4@D@1', 'IPv4@D@2']
        ]

    def _build_iterator(self, now):
        r = []
        if self.cur_iterator < len(self.iterators):
            r = self.iterators[self.cur_iterator]

        self.cur_iterator += 1

        return r

    def _process_item(self, item):
        it, i, v = item.split('@', 2)
        return [[i, {'type': it, 'attribute': v}]]


class DeltaFeedWithTypeAggregatedFaulty(minemeld.ft.basepoller.BasePollerFT):
    def __init__(self, name, chassis):
        config = {
            'multiple_indicator_types': True,
            'aggregate_indicators': True,
            'aggregate_use_partial': True,
            'age_out': {
                'default': 'last_seen+4',
                'sudden_death': False
            }
        }
        super(DeltaFeedWithTypeAggregatedFaulty, self).__init__(name, chassis, config)

        self.cur_iterator = 0

        self.cur_iterator = 1
        self.last_time = None

        self.iterators = [
            ['IPv4@A@1', 'domain@B@1', 'domain@C@1', 'IPv4@A@2'],
            ['IPv4@B@1', 'domain@C@1', 'IPv4@D@1', 'IPv4@D@2']
        ]

    def _iterator(self, iterator):
        for i in iterator:
            yield i
        raise RuntimeError('BAM !')

    def _build_iterator(self, now):
        if self.last_time is None:
            self.last_time = CUR_LOGICAL_TIME

        if self.last_time == CUR_LOGICAL_TIME:
            self.cur_iterator -= 1

        self.last_time = CUR_LOGICAL_TIME

        LOG.info('cur_iterator: {} time: {}'.format(self.cur_iterator, CUR_LOGICAL_TIME))
        r = []
        if self.cur_iterator < len(self.iterators):
            r = self._iterator(self.iterators[self.cur_iterator])

        self.cur_iterator += 1

        return r

    def _process_item(self, item):
        it, i, v = item.split('@', 2)
        return [[i, {'type': it, 'attribute': v}]]


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
        self.assertEqual(spawnl_mock.call_count, 2)
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
        self.assertEqual(spawnl_mock.call_count, 2)
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
    def test_rolling_feed_first(self, um_mock, event_mock, sleep_mock,
                                spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = RollingFeedFirst(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 2)
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
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 4)
        self.assertEqual(a.statistics.get('removed', 0), 1)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 1)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 4
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 6)
        self.assertEqual(a.statistics.get('removed', 0), 3)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 3)
        self.assertEqual(a.statistics['aged_out'], 4)

        CUR_LOGICAL_TIME = 5
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 7)
        self.assertEqual(a.statistics.get('removed', 0), 4)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 4)
        self.assertEqual(a.statistics['aged_out'], 4)

        CUR_LOGICAL_TIME = 6
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 8)
        self.assertEqual(a.statistics.get('removed', 0), 5)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 5)
        self.assertEqual(a.statistics['aged_out'], 6)

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
    def test_rolling_feed_first2(self, um_mock, event_mock, sleep_mock,
                                spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = RollingFeedFirst2(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 2)
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
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics.get('aged_out', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out()
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics.get('removed', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)
        self.assertEqual(a.statistics['aged_out'], 0)

        CUR_LOGICAL_TIME = 4
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics.get('removed', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 5
        a._age_out()
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics.get('removed', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 6
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics.get('removed', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 7
        a._age_out()
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics.get('removed', 0), 0)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 0)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 8
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics['removed'], 1)
        self.assertEqual(a.statistics['garbage_collected'], 1)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 9
        a._age_out()
        self.assertEqual(a.statistics['added'], 1)
        self.assertEqual(a.statistics['removed'], 1)
        self.assertEqual(a.statistics['garbage_collected'], 1)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 10
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 2)
        self.assertEqual(a.statistics['removed'], 1)
        self.assertEqual(a.statistics['garbage_collected'], 1)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 11
        a._age_out()
        self.assertEqual(a.statistics['added'], 2)
        self.assertEqual(a.statistics['removed'], 1)
        self.assertEqual(a.statistics['garbage_collected'], 1)
        self.assertEqual(a.statistics['aged_out'], 1)

        CUR_LOGICAL_TIME = 12
        a._age_out()
        self.assertEqual(a.statistics['added'], 2)
        self.assertEqual(a.statistics['removed'], 1)
        self.assertEqual(a.statistics['garbage_collected'], 1)
        self.assertEqual(a.statistics['aged_out'], 2)
        self.assertEqual(a.statistics['withdraw.tx'], 2)

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
        self.assertEqual(spawnl_mock.call_count, 2)
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
        self.assertEqual(spawnl_mock.call_count, 2)
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
        self.assertEqual(spawnl_mock.call_count, 2)
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

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_permanentwithtype_feed(self, um_mock, event_mock,
                                    sleep_mock, spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = PermanentFeedWithType(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 2)
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
        self.assertEqual(a.statistics['added'], 5)
        self.assertEqual(a.statistics.get('removed', 0), 2)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 2)

        CUR_LOGICAL_TIME = 5
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 2)

        CUR_LOGICAL_TIME = 6
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 2)

        CUR_LOGICAL_TIME = 7
        a._age_out()
        self.assertEqual(a.statistics['aged_out'], 2)

        CUR_LOGICAL_TIME = 8
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 5)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 5)
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
    def test_bptable_1(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt0 = minemeld.ft.basepoller._BPTable_v0(t)

        bpt0.put('A', {'v': 1})
        A = bpt0.get('A')
        self.assertEqual(A['v'], 1)

        A, V = next(bpt0.query(include_value=True))
        self.assertEqual(V['v'], 1)

        bpt0.delete('A')
        A = bpt0.get('A')
        self.assertEqual(A, None)

        bpt0.close()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_bptable_2(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt1 = minemeld.ft.basepoller._BPTable_v1(t, type_in_key=True)

        bpt1.put('A', {'type': 1})

        A = next(bpt1.query(include_value=False))
        self.assertEqual(A, 'A')

        bpt1.close()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_bptable_3(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt1 = minemeld.ft.basepoller._BPTable_v1(t, type_in_key=True)
        bpt1.close()

        with self.assertRaises(RuntimeError):
            t = minemeld.ft.table.Table(FTNAME, truncate=False)
            minemeld.ft.basepoller._BPTable_v1(t, type_in_key=False)

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_bptable_4(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt1 = minemeld.ft.basepoller._BPTable_v1(t, type_in_key=True)

        with self.assertRaises(RuntimeError):
            bpt1.put('A', {'a': 1})

        bpt1.close()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_bptable_5(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt1 = minemeld.ft.basepoller._BPTable_v1(t, type_in_key=True)
        bpt1.close()

        bpt1 = minemeld.ft.basepoller._bptable_factory(FTNAME, truncate=False, type_in_key=True)
        bpt1.close()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_bptable_6(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt0 = minemeld.ft.basepoller._BPTable_v0(t)
        bpt0.put('A', {'v': 1})
        bpt0.close()

        bpt1 = minemeld.ft.basepoller._bptable_factory(FTNAME, truncate=False, type_in_key=False)
        bpt1.close()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_bptable_7(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt0 = minemeld.ft.basepoller._BPTable_v0(t)
        bpt0.put('A', {'v': 1})
        bpt0.delete('A')
        bpt0.close()

        bpt1 = minemeld.ft.basepoller._bptable_factory(FTNAME, truncate=False, type_in_key=True)
        bpt1.close()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_bptable_8(self, um_mock, event_mock,
                       sleep_mock, spawnl_mock, spawn_mock):
        t = minemeld.ft.table.Table(FTNAME, truncate=True)
        bpt1 = minemeld.ft.basepoller._BPTable_v1(t, type_in_key=True)
        bpt1.put(indicator=u'☃.net/påth', value={u'☃.net/påth': 1, 'type': u'☃.net/påth'})
        t = bpt1.get(u'☃.net/påth', itype=u'☃.net/påth')
        self.assertNotEqual(t, None)

        k, v = next(bpt1.query(include_value=True))
        self.assertEqual(k, u'☃.net/påth')
        self.assertEqual(v, {u'☃.net/påth': 1, 'type': u'☃.net/påth'})

        bpt1.close()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_permanentwithtype_feed_agg(self, um_mock, event_mock,
                                        sleep_mock, spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = PermanentFeedWithTypeAggregated(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 2)
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
        self.assertEqual(a.statistics['added'], 5)
        self.assertEqual(a.statistics.get('removed', 0), 2)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 2)

        CUR_LOGICAL_TIME = 5
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 2)

        CUR_LOGICAL_TIME = 6
        a._age_out()
        self.assertEqual(a.statistics.get('aged_out', 0), 2)

        CUR_LOGICAL_TIME = 7
        a._age_out()
        self.assertEqual(a.statistics['aged_out'], 2)

        CUR_LOGICAL_TIME = 8
        a._poll()
        a._sudden_death()
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['added'], 5)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 5)
        self.assertEqual(a.length(), 0)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep')
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_permanentwithtype_feed_agg2(self, um_mock, event_mock,
                                         sleep_mock, spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = DeltaFeedWithTypeAggregatedFaulty(FTNAME, chassis)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 2)
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
        self.assertEqual(a.statistics['added'], 5)
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
        self.assertEqual(a.statistics['added'], 5)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 3)
        self.assertEqual(a.length(), 2)

        CUR_LOGICAL_TIME = 9
        a._age_out()
        a._collect_garbage()
        self.assertEqual(a.statistics['aged_out'], 5)
        self.assertEqual(a.length(), 0)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
