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

"""FT autofocus tests

Unit tests for minemeld.ft.autofocus
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
import os.path

import minemeld.ft.autofocus

FTNAME = 'testft-%d' % int(time.time())

LOG = logging.getLogger(__name__)

CUR_LOGICAL_TIME = 0

MYDIR = os.path.dirname(__file__)


def logical_millisec(*args):
    return CUR_LOGICAL_TIME


def gevent_event_mock_factory():
    result = mock.Mock()
    result.wait.side_effect = gevent.GreenletExit()

    return result


class MineMeldAutofocusFTTests(unittest.TestCase):
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
    @mock.patch.object(calendar, 'timegm', side_effect=logical_millisec)
    def test_type_of_indicators(self, um_mock, sleep_mock, event_mock,
                                spawnl_mock, spawn_mock):
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        config = {
            'side_config': os.path.join(MYDIR, 'dummy.yml')
        }

        a = minemeld.ft.autofocus.ExportList(FTNAME, chassis, config)

        inputs = []
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)
        self.assertEqual(spawn_mock.call_count, 3)

        self.assertEqual(a._type_of_indicator('1.1.1.1'), 'IPv4')
        self.assertEqual(a._type_of_indicator('1.1.1.2-1.1.1.5'), 'IPv4')
        self.assertEqual(a._type_of_indicator('1.1.1.0/24'), 'IPv4')
        self.assertEqual(a._type_of_indicator('www.google.com'), 'domain')
        self.assertEqual(a._type_of_indicator('www.google.com/test'), 'URL')
        self.assertEqual(a._type_of_indicator('https://www.google.com'), 'URL')

        a.stop()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
