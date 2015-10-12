"""FT Logstash tests

Unit tests for minemeld.ft.logstash
"""

import unittest
import mock
import time

import minemeld.ft.logstash

FTNAME = 'testft-%d' % int(time.time())


class MineMeldFTLogstashOutputTests(unittest.TestCase):
    def test_uw(self):
        config = {
            'logstash_host': '127.0.0.1',
            'logstash_port': 5514
        }
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.logstash.LogstashOutput(FTNAME, chassis, config)

        inputs = ['a', 'b', 'c']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_initialize()

        b.start()
        time.sleep(1)

        b.update('a', indicator='testi', value={'test': 'v'})
        self.assertEqual(b.statistics['message.sent'], 1)

        b.withdraw('a', indicator='testi')
        self.assertEqual(b.statistics['message.sent'], 2)

        b.stop()
