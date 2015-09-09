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
