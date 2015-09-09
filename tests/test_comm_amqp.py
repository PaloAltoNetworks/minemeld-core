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
