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

"""FT dag tests

Unit tests for minemeld.ft.dag
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
import os
import yaml
import functools
import pan.xapi
import panos_mock

import minemeld.ft.dag

FTNAME = 'testft-%d' % int(time.time())
DLIST_NAME = 'dag-dlist-%d.yml' % int(time.time())

LOG = logging.getLogger(__name__)

CUR_LOGICAL_TIME = 0

MYDIR = os.path.dirname(__file__)

GEVENT_SLEEP = gevent.sleep


def logical_millisec(*args):
    return CUR_LOGICAL_TIME


def gevent_event_mock_factory():
    result = mock.Mock()
    result.wait.side_effect = gevent.GreenletExit()

    return result


def device_pusher_mock_factory(device, prefix, watermark, attributes, persistence):
    def _start_se(x):
        x.started = True

    result = mock.MagicMock(started=False, device=device, value=None)
    result.start = mock.Mock(side_effect=functools.partial(_start_se, result))

    return result


class MineMeldFTDagPusherTests(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            os.remove(DLIST_NAME)
        except:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            os.remove(DLIST_NAME)
        except:
            pass

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch.object(minemeld.ft.dag.DagPusher, '_huppable_wait', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    @mock.patch('minemeld.ft.dag.DevicePusher',
                side_effect=device_pusher_mock_factory)
    def test_device_list_load(self, dp_mock, timegm_mock, event_mock, hw_mock,
                              sleep_mock, spawnl_mock, spawn_mock):
        device_list_path = os.path.join(MYDIR, 'test_device_list.yml')
        device_list_path2 = os.path.join(MYDIR, 'test_device_list2.yml')

        with open(device_list_path, 'r') as f:
            dlist = yaml.safe_load(f)

        with open(device_list_path2, 'r') as f:
            dlist2 = yaml.safe_load(f)

        shutil.copyfile(device_list_path, DLIST_NAME)

        config = {
            'device_list': DLIST_NAME
        }

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.dag.DagPusher(FTNAME, chassis, config)

        inputs = []
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        # 1st round
        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass
        hw_mock.assert_called_with(5)
        self.assertEqual(len(a.devices), len(dlist))
        self.assertEqual(len(a.device_pushers), len(dlist))
        self.assertEqual(dp_mock.call_count, len(dlist))

        for i, d in enumerate(dlist):
            self.assertEqual(a.devices[i], d)
            self.assertEqual(a.device_pushers[i].start.call_count, 1)
            self.assertEqual(a.device_pushers[i].device, d)

        # 2nd round
        GEVENT_SLEEP(1)
        shutil.copyfile(device_list_path, DLIST_NAME)

        hw_mock.reset_mock()
        dp_mock.reset_mock()

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass
        hw_mock.assert_called_with(5)
        self.assertEqual(len(a.devices), len(dlist))
        self.assertEqual(len(a.device_pushers), len(dlist))
        self.assertEqual(dp_mock.call_count, 0)

        for i, d in enumerate(dlist):
            self.assertEqual(a.devices[i], d)
            self.assertEqual(a.device_pushers[i].start.call_count, 1)
            self.assertEqual(a.device_pushers[i].device, d)

        # 3rd round
        GEVENT_SLEEP(1)
        shutil.copyfile(device_list_path2, DLIST_NAME)

        hw_mock.reset_mock()
        dp_mock.reset_mock()

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass
        hw_mock.assert_called_with(5)
        self.assertEqual(len(a.devices), len(dlist2))
        self.assertEqual(len(a.device_pushers), len(dlist2))
        self.assertEqual(dp_mock.call_count, 1)

        for i, d in enumerate(dlist2):
            self.assertEqual(a.devices[i], d)
            self.assertEqual(a.device_pushers[i].start.call_count, 1)
            self.assertEqual(a.device_pushers[i].device, d)

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
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    @mock.patch('minemeld.ft.dag.DevicePusher',
                side_effect=device_pusher_mock_factory)
    def test_uw(self, dp_mock, timegm_mock, event_mock,
                sleep_mock, spawnl_mock, spawn_mock):
        device_list_path = os.path.join(MYDIR, 'test_device_list.yml')

        shutil.copyfile(device_list_path, DLIST_NAME)

        config = {
            'device_list': DLIST_NAME
        }

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.dag.DagPusher(FTNAME, chassis, config)

        inputs = ['a']
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass

        a.update('a', indicator='127.0.0.1', value={
            'type': 'IPv4',
            'confidence': 100
        })

        for d in a.device_pushers:
            d.put.assert_called_with(
                'register',
                '127.0.0.1',
                {
                    'type': 'IPv4',
                    'confidence': 100
                }
            )

        for d in a.device_pushers:
            d.put.reset_mock()

        a.withdraw('a', indicator='127.0.0.1')
        for d in a.device_pushers:
            d.put.assert_called_with(
                'unregister',
                '127.0.0.1',
                {
                    'type': 'IPv4',
                    'confidence': 100
                }
            )

        for d in a.device_pushers:
            d.put.reset_mock()

        a.withdraw('a', indicator='127.0.0.1')
        for d in a.device_pushers:
            self.assertEqual(d.put.call_count, 0)

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
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    @mock.patch('minemeld.ft.dag.DevicePusher',
                side_effect=device_pusher_mock_factory)
    def test_uinvalid(self, dp_mock, timegm_mock, event_mock,
                      sleep_mock, spawnl_mock, spawn_mock):
        device_list_path = os.path.join(MYDIR, 'test_device_list.yml')

        shutil.copyfile(device_list_path, DLIST_NAME)

        config = {
            'device_list': DLIST_NAME
        }

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.dag.DagPusher(FTNAME, chassis, config)

        inputs = ['a']
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass

        a.update('a', indicator='1.1.1.1-1.1.1.3', value={
            'type': 'IPv4',
            'confidence': 100
        })

        self.assertEqual(a.length(), 0)

        a.update('a', indicator='1.1.1.0/24', value={
            'type': 'IPv4',
            'confidence': 100
        })

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
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    @mock.patch('minemeld.ft.dag.DevicePusher',
                side_effect=device_pusher_mock_factory)
    def test_unicast1(self, dp_mock, timegm_mock, event_mock,
                      sleep_mock, spawnl_mock, spawn_mock):
        device_list_path = os.path.join(MYDIR, 'test_device_list.yml')

        shutil.copyfile(device_list_path, DLIST_NAME)

        config = {
            'device_list': DLIST_NAME
        }

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.dag.DagPusher(FTNAME, chassis, config)

        inputs = ['a']
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass

        a.update('a', indicator='1.1.1.1-1.1.1.1', value={
            'type': 'IPv4',
            'confidence': 100
        })

        for d in a.device_pushers:
            d.put.assert_called_with(
                'register',
                '1.1.1.1',
                {
                    'type': 'IPv4',
                    'confidence': 100
                }
            )

        for d in a.device_pushers:
            d.put.reset_mock()

        a.withdraw('a', indicator='1.1.1.1-1.1.1.1')
        for d in a.device_pushers:
            d.put.assert_called_with(
                'unregister',
                '1.1.1.1',
                {
                    'type': 'IPv4',
                    'confidence': 100
                }
            )

        for d in a.device_pushers:
            d.put.reset_mock()

        a.withdraw('a', indicator='1.1.1.1-1.1.1.1')
        for d in a.device_pushers:
            self.assertEqual(d.put.call_count, 0)

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
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    @mock.patch('minemeld.ft.dag.DevicePusher',
                side_effect=device_pusher_mock_factory)
    def test_unicast2(self, dp_mock, timegm_mock, event_mock,
                      sleep_mock, spawnl_mock, spawn_mock):
        device_list_path = os.path.join(MYDIR, 'test_device_list.yml')

        shutil.copyfile(device_list_path, DLIST_NAME)

        config = {
            'device_list': DLIST_NAME
        }

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.dag.DagPusher(FTNAME, chassis, config)

        inputs = ['a']
        output = False

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 1)

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass

        a.update('a', indicator='1.1.1.1/32', value={
            'type': 'IPv4',
            'confidence': 100
        })

        for d in a.device_pushers:
            d.put.assert_called_with(
                'register',
                '1.1.1.1',
                {
                    'type': 'IPv4',
                    'confidence': 100
                }
            )

        for d in a.device_pushers:
            d.put.reset_mock()

        a.withdraw('a', indicator='1.1.1.1/32')
        for d in a.device_pushers:
            d.put.assert_called_with(
                'unregister',
                '1.1.1.1',
                {
                    'type': 'IPv4',
                    'confidence': 100
                }
            )

        for d in a.device_pushers:
            d.put.reset_mock()

        a.withdraw('a', indicator='1.1.1.1/32')
        for d in a.device_pushers:
            self.assertEqual(d.put.call_count, 0)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(pan.xapi, 'PanXapi', side_effect=panos_mock.factory)
    def test_devicepusher_dag_message(self, panxapi_mock):
        RESULT_REG = '<uid-message><version>1.0</version><type>update</type><payload><register><entry ip="192.168.1.1" persistent="0"><tag><member>a</member><member>b</member></tag></entry></register></payload></uid-message>'
        RESULT_UNREG = '<uid-message><version>1.0</version><type>update</type><payload><unregister><entry ip="192.168.1.1"><tag><member>a</member><member>b</member></tag></entry></unregister></payload></uid-message>'

        dp = minemeld.ft.dag.DevicePusher(
            {'tag': 'test'},
            'mmeld_',
            'test',
            [],
            False
        )

        reg = dp._dag_message('register', {'192.168.1.1': ['a', 'b']})
        self.assertEqual(reg, RESULT_REG)

        unreg = dp._dag_message('unregister', {'192.168.1.1': ['a', 'b']})
        self.assertEqual(unreg, RESULT_UNREG)

    @mock.patch.object(pan.xapi, 'PanXapi', side_effect=panos_mock.factory)
    def test_devicepusher_tags_from_value(self, panxapi_mock):
        dp = minemeld.ft.dag.DevicePusher(
            {'tag': 'test'},
            'mmeld_',
            'test',
            ['confidence', 'direction'],
            False
        )

        tags = dp._tags_from_value({'confidence': 49, 'direction': 'inbound'})
        self.assertEqual(tags, set(['mmeld_confidence_low', 'mmeld_direction_inbound']))

        tags = dp._tags_from_value({'confidence': 50})
        self.assertEqual(tags, set(['mmeld_confidence_medium', 'mmeld_direction_unknown']))

        tags = dp._tags_from_value({'confidence': 75, 'direction': 'outbound'})
        self.assertEqual(tags, set(['mmeld_confidence_high', 'mmeld_direction_outbound']))

    @mock.patch.object(pan.xapi, 'PanXapi', side_effect=panos_mock.factory)
    def test_devicepusher_get_all_registered_ips(self, panxapi_mock):
        dp = minemeld.ft.dag.DevicePusher(
            {'hostname': 'test_ft_dag_devicepusher'},
            'mmeld_',
            'test',
            ['confidence', 'direction'],
            False
        )

        result = dp._get_all_registered_ips()
        self.assertEqual(next(result), ('192.168.1.1', ['mmeld_test', 'mmeld_confidence_100', 'mmeld_pushed']))
        self.assertEqual(next(result), ('192.168.1.2', ['mmeld_test', 'mmeld_confidence_100']))

    @mock.patch.object(pan.xapi, 'PanXapi', side_effect=panos_mock.factory)
    def test_devicepusher_push(self, panxapi_mock):
        dp = minemeld.ft.dag.DevicePusher(
            {'hostname': 'test_ft_dag_devicepusher'},
            'mmeld_',
            'test',
            ['confidence', 'direction'],
            False
        )

        dp._push('register', '192.168.1.10', {'confidence': 40, 'direction': 'inbound'})
        self.assertEqual(
            dp.xapi.user_id_calls[0],
            '<uid-message><version>1.0</version><type>update</type><payload><register><entry ip="192.168.1.10" persistent="0"><tag><member>mmeld_confidence_low</member><member>mmeld_direction_inbound</member><member>mmeld_test</member></tag></entry></register></payload></uid-message>'
        )

    @mock.patch.object(pan.xapi, 'PanXapi', side_effect=panos_mock.factory)
    def test_devicepusher_init_resync(self, panxapi_mock):
        dp = minemeld.ft.dag.DevicePusher(
            {'hostname': 'test_ft_dag_devicepusher'},
            'mmeld_',
            'test',
            ['confidence', 'direction'],
            False
        )

        dp.put('init', '192.168.1.1', {'confidence': 75, 'direction': 'inbound'})
        dp.put('init', '192.168.1.10', {'confidence': 80})
        dp.put('EOI', None, None)
        dp._init_resync()

        self.assertEqual(
            dp.xapi.user_id_calls[0],
            '<uid-message><version>1.0</version><type>update</type><payload><register><entry ip="192.168.1.1" persistent="0"><tag><member>mmeld_confidence_high</member><member>mmeld_direction_inbound</member></tag></entry><entry ip="192.168.1.10" persistent="0"><tag><member>mmeld_confidence_high</member><member>mmeld_direction_unknown</member><member>mmeld_test</member></tag></entry></register></payload></uid-message>'
        )
        self.assertEqual(
            dp.xapi.user_id_calls[1],
            '<uid-message><version>1.0</version><type>update</type><payload><unregister><entry ip="192.168.1.1"><tag><member>mmeld_confidence_100</member><member>mmeld_pushed</member></tag></entry><entry ip="192.168.1.2"><tag><member>mmeld_confidence_100</member><member>mmeld_test</member></tag></entry></unregister></payload></uid-message>'
        )
