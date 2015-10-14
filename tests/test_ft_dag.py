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

import minemeld.ft.dag

FTNAME = 'testft-%d' % int(time.time())
DLIST_NAME = 'dag-dlist-%d.yml' % int(time.time())

LOG = logging.getLogger(__name__)

CUR_LOGICAL_TIME = 0

MYDIR = os.path.dirname(__file__)

GEVENT_SLEEP = gevent.sleep


def logical_millisec(*args):
    return CUR_LOGICAL_TIME


def device_pusher_mock_factory(device, prefix, attributes):
    def _start_se(x):
        x._started = True

    result = mock.MagicMock(_started=False, device=device, value=None)
    result.start = mock.Mock(side_effect=functools.partial(_start_se, result))
    result.started = mock.Mock(side_effect=functools.partial(lambda x: x._started, result))

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
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    @mock.patch('minemeld.ft.dag.DevicePusher',
                side_effect=device_pusher_mock_factory)
    def test_device_list_load(self, dp_mock, timegm_mock,
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
        sleep_mock.assert_called_with(5)
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

        sleep_mock.reset_mock()
        dp_mock.reset_mock()

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass
        sleep_mock.assert_called_with(5)
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

        sleep_mock.reset_mock()
        dp_mock.reset_mock()

        try:
            a._device_list_monitor()
        except gevent.GreenletExit:
            pass
        sleep_mock.assert_called_with(5)
        self.assertEqual(len(a.devices), len(dlist2))
        self.assertEqual(len(a.device_pushers), len(dlist2))
        self.assertEqual(dp_mock.call_count, 1)

        for i, d in enumerate(dlist2):
            self.assertEqual(a.devices[i], d)
            self.assertEqual(a.device_pushers[i].start.call_count, 1)
            self.assertEqual(a.device_pushers[i].device, d)

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
    @mock.patch('minemeld.ft.dag.DevicePusher',
                side_effect=device_pusher_mock_factory)
    def test_uw(self, dp_mock, timegm_mock,
                sleep_mock, spawnl_mock, spawn_mock):
        device_list_path = os.path.join(MYDIR, 'test_device_list.yml')

        with open(device_list_path, 'r') as f:
            dlist = yaml.safe_load(f)

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
                    'confidence': 100,
                    '_age_out': 3600000
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
                    'confidence': 100,
                    '_age_out': 3600000
                }
            )

        for d in a.device_pushers:
            d.put.reset_mock()

        a.withdraw('a', indicator='127.0.0.1')
        for d in a.device_pushers:
            self.assertEqual(d.put.call_count, 0)

        a.stop()
        a.table.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
