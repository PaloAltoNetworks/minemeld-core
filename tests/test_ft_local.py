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

"""FT local tests

Unit tests for minemeld.ft.local
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
import yaml

import minemeld.ft.local

FTNAME = 'testft-%d' % int(time.time())
LOCALDB_NAME = 'local-%d.yml' % int(time.time())

LOG = logging.getLogger(__name__)

CUR_LOGICAL_TIME = 0

MYDIR = os.path.dirname(__file__)


def logical_millisec(*args):
    return CUR_LOGICAL_TIME


def gevent_event_mock_factory():
    result = mock.Mock()
    result.wait.side_effect = gevent.GreenletExit()

    return result


class MineMeldYamlFTTests(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            os.remove(LOCALDB_NAME)
        except:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            os.remove(LOCALDB_NAME)
        except:
            pass

    @mock.patch.object(gevent, 'spawn')
    @mock.patch.object(gevent, 'spawn_later')
    @mock.patch.object(gevent, 'sleep', side_effect=gevent.GreenletExit())
    @mock.patch('gevent.event.Event', side_effect=gevent_event_mock_factory)
    @mock.patch('minemeld.ft.basepoller.utc_millisec', side_effect=logical_millisec)
    def test_yaml(self, um_mock, sleep_mock, event_mock,
                  spawnl_mock, spawn_mock):
        global CUR_LOGICAL_TIME

        localdb_path = os.path.join(MYDIR, 'test_localdb.yml')
        localdb_path2 = os.path.join(MYDIR, 'test_localdb2.yml')

        with open(localdb_path, 'r') as f:
            localdb = yaml.safe_load(f)
        localdb = [k['indicator'] for k in localdb]

        with open(localdb_path2, 'r') as f:
            localdb2 = yaml.safe_load(f)
        localdb2 = [k['indicator'] for k in localdb2]

        shutil.copyfile(localdb_path, LOCALDB_NAME)

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        config = {
            'path': LOCALDB_NAME,
            'age_out': {
                'default': None,
                'sudden_death': True
            }
        }

        a = minemeld.ft.local.YamlFT(FTNAME, chassis, config)

        inputs = []
        output = True

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
        self.assertEqual(a.statistics['added'], len(localdb))
        self.assertEqual(a.statistics.get('removed', 0), 0)

        CUR_LOGICAL_TIME = 3
        a._age_out_run()
        self.assertEqual(a.statistics.get('aged_out', 0), 0)

        shutil.copyfile(localdb_path2, LOCALDB_NAME)

        CUR_LOGICAL_TIME = 4
        a._run()
        self.assertEqual(
            a.statistics['added'],
            len(set(localdb) | set(localdb2))
        )
        self.assertEqual(
            a.statistics.get('removed', 0),
            len(set(localdb2)-set(localdb))
        )
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
        self.assertEqual(a.statistics['added'], 3)
        self.assertEqual(a.statistics.get('garbage_collected', 0), 1)
        self.assertEqual(a.length(), 2)

        a.stop()
        a.table.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
