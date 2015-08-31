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
        self.assertEqual(b.SR, None)
        self.assertItemsEqual(b.active_requests, [])
        self.assertEqual(b.redis_host, 'localhost')
        self.assertEqual(b.redis_port, 6379)
        self.assertEqual(b.redis_password, None)
        self.assertEqual(b.redis_db, 0)

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

        self.assertItemsEqual(b.inputs, inputs)
        self.assertEqual(b.output, None)

        icalls = []
        for i in inputs:
            icalls.append(
                mock.call(FTNAME, b, i,
                          allowed_methods=['update', 'withdraw'])
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

        b.start()
        time.sleep(1)

        SR = redis.StrictRedis()

        b.update('a', indicator='testi', value={'test': 'v'})
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 1)
        self.assertIn('testi', sm)

        b.withdraw('a', indicator='testi')
        sm = SR.zrange(FTNAME, 0, -1)
        self.assertEqual(len(sm), 0)

        b.stop()
        self.assertEqual(b.SR, None)
