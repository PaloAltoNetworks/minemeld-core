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

"""FT Redis tests

Unit tests for minemeld.ft.redis
"""

import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest
import mock
import redis
import time

import minemeld.ft.redis

FTNAME = 'testft-%d' % int(time.time())


class MineMeldFTRedisTests(unittest.TestCase):
    def setUp(self):
        SR = redis.StrictRedis()
        SR.delete(FTNAME)

    def tearDown(self):
        SR = redis.StrictRedis()
        SR.delete(FTNAME)

    def test_init(self):
        config = {}
        chassis = mock.Mock()

        b = minemeld.ft.redis.RedisSet(FTNAME, chassis, config)

        self.assertEqual(b.name, FTNAME)
        self.assertEqual(b.chassis, chassis)
        self.assertEqual(b.config, config)
        self.assertItemsEqual(b.inputs, [])
        self.assertEqual(b.output, None)
        self.assertEqual(b.redis_skey, FTNAME)
        self.assertNotEqual(b.SR, None)
        self.assertEqual(b.redis_url, 'unix:///var/run/redis/redis.sock')

    def test_connect_io(self):
        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None

        b = minemeld.ft.redis.RedisSet(FTNAME, chassis, config)

        inputs = ['a', 'b', 'c']
        output = True

        b.connect(inputs, output)
        b.mgmtbus_initialize()

        self.assertItemsEqual(b.inputs, inputs)
        self.assertEqual(b.output, None)

        icalls = []
        for i in inputs:
            icalls.append(
                mock.call(
                    FTNAME, b, i,
                    allowed_methods=[
                        'update', 'withdraw', 'checkpoint'
                    ]
                )
            )
        chassis.request_sub_channel.assert_has_calls(
            icalls,
            any_order=True
        )

        chassis.request_rpc_channel.assert_called_once_with(
            FTNAME,
            b,
            allowed_methods=[
                'update',
                'withdraw',
                'checkpoint',
                'get',
                'get_all',
                'get_range',
                'length'
            ]
        )

        chassis.request_pub_channel.assert_not_called()

    def test_uw(self):
        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.redis.RedisSet(FTNAME, chassis, config)

        inputs = ['a', 'b', 'c']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_initialize()

        b.start()
        time.sleep(1)

        SR = redis.StrictRedis()

        b.filtered_update('a', indicator='testi', value={'test': 'v'})
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 1)
        self.assertIn('testi', sm)

        b.filtered_withdraw('a', indicator='testi')
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 0)

        b.stop()
        self.assertNotEqual(b.SR, None)

    def test_stats(self):
        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.redis.RedisSet(FTNAME, chassis, config)

        inputs = ['a', 'b', 'c']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_reset()

        b.start()
        time.sleep(1)

        b.filtered_update('a', indicator='testi', value={'test': 'v'})
        self.assertEqual(b.length(), 1)
        status = b.mgmtbus_status()
        self.assertEqual(status['statistics']['added'], 1)

        b.filtered_update('a', indicator='testi', value={'test': 'v2'})
        self.assertEqual(b.length(), 1)
        status = b.mgmtbus_status()
        self.assertEqual(status['statistics']['added'], 1)
        self.assertEqual(status['statistics']['removed'], 0)

        b.filtered_withdraw('a', indicator='testi')
        self.assertEqual(b.length(), 0)
        status = b.mgmtbus_status()
        self.assertEqual(status['statistics']['removed'], 1)

        b.stop()

    def test_store_value(self):
        config = {'store_value': True}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.redis.RedisSet(FTNAME, chassis, config)

        inputs = ['a', 'b', 'c']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_reset()

        b.start()
        time.sleep(1)

        SR = redis.StrictRedis()

        b.filtered_update('a', indicator='testi', value={'test': 'v'})
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 1)
        self.assertIn('testi', sm)
        sm = SR.hlen(FTNAME+'.value')
        self.assertEqual(sm, 1)

        b.filtered_withdraw('a', indicator='testi')
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 0)
        sm = SR.hlen(FTNAME+'.value')
        self.assertEqual(sm, 0)

        b.stop()
        self.assertNotEqual(b.SR, None)

    def test_store_value_overflow(self):
        config = {'store_value': True}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.redis.RedisSet(FTNAME, chassis, config)
        b.max_entries = 1

        inputs = ['a', 'b', 'c']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_reset()

        b.start()
        time.sleep(1)

        SR = redis.StrictRedis()

        b.filtered_update('a', indicator='testi', value={'test': 'v'})
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 1)
        self.assertIn('testi', sm)
        sm = SR.hlen(FTNAME+'.value')
        self.assertEqual(sm, 1)

        b.filtered_update('a', indicator='testio', value={'test': 'v'})
        self.assertEqual(b.statistics['drop.overflow'], 1)
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 1)
        self.assertIn('testi', sm)
        sm = SR.hlen(FTNAME+'.value')
        self.assertEqual(sm, 1)

        b.filtered_withdraw('a', indicator='testi')
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 0)
        sm = SR.hlen(FTNAME+'.value')
        self.assertEqual(sm, 0)

        b.filtered_update('a', indicator='testio', value={'test': 'v'})
        self.assertEqual(b.statistics['drop.overflow'], 1)
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 1)
        self.assertIn('testio', sm)
        sm = SR.hlen(FTNAME+'.value')
        self.assertEqual(sm, 1)

        b.stop()
        self.assertNotEqual(b.SR, None)
