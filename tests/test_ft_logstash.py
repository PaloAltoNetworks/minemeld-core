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
