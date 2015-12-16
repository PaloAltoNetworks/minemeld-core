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

import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest

import minemeld.comm.amqp


class MineMeldCommAMQP(unittest.TestCase):
    def test_01_rpc(self):
        class A(object):
            def f(self):
                return 'ok'

        a = A()

        ac = minemeld.comm.amqp.AMQP({})
        ac.request_rpc_server_channel('a', a, allowed_methods=['f'])
        ac.start()

        result = ac.send_rpc('a', 'f', {}, timeout=1)
        self.assertEqual(result['result'], 'ok')

        ac.stop()

    def test_02_pubsub(self):
        class A(object):
            counter = 0

            def f(self):
                self.counter += 1

        a = A()

        ac = minemeld.comm.amqp.AMQP({})
        ac.request_sub_channel('a', a, allowed_methods=['f'])
        pc = ac.request_pub_channel('a')
        ac.start()

        pc.publish('f')
        gevent.sleep(0.1)

        self.assertEqual(a.counter, 1)

        ac.stop()

    def test_03_rpc_fanout(self):
        class A(object):
            def __init__(self, n):
                self.n = n

            def f(self):
                return self.n

        a1 = A(1)
        a2 = A(2)

        ac = minemeld.comm.amqp.AMQP({})
        ac.request_rpc_server_channel('a1', a1, allowed_methods=['f'],
                                      fanout='test')
        ac.request_rpc_server_channel('a2', a2, allowed_methods=['f'],
                                      fanout='test')
        client = ac.request_rpc_fanout_client_channel('test')
        ac.start()

        evt = client.send_rpc('f', params={}, num_results=2)
        success = evt.wait(timeout=5)

        self.assertNotEqual(success, None)

        result = evt.get(block=False)

        self.assertEqual(result['answers'], {'a1': 1, 'a2': 2})

        ac.stop()
