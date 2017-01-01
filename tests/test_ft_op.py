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

"""FT op tests

Unit tests for minemeld.ft.op
"""

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest
import mock
import time
import shutil
import logging

import guppy  # noqa
import pdb  # noqa
import gc  # noqa

import minemeld.ft.op

FTNAME = 'testft-%d' % int(time.time())

LOG = logging.getLogger(__name__)


def check_for_rpc(call_args_list, check_list, all_here=False, offset=0):
    LOG.debug("call_args_list: %s", call_args_list)

    found = []
    for chk in check_list:
        LOG.debug("checking: %s", chk)

        for j in xrange(len(call_args_list)):
            if j in found:
                continue

            args = call_args_list[j][0]
            LOG.debug("args: %s", args[offset+0])

            if args[offset+0] != chk['method']:
                continue
            if args[offset+1]['indicator'] != chk['indicator']:
                continue

            chkvalue = chk.get('value', None)
            if chkvalue is None:
                found.append(j)
                LOG.debug("found @%d", j)
                break

            argsvalue = args[offset+1].get('value', None)
            if chkvalue is not None and argsvalue is None:
                continue

            failed = False
            for k in chkvalue.keys():
                if k not in argsvalue:
                    failed = True
                    break
                if chkvalue[k] != argsvalue[k]:
                    failed = True
                    break
            if failed:
                continue

            found.append(j)
            LOG.debug("found @%d", j)
            break

    c1 = len(found) == len(check_list)

    if not all_here:
        return c1

    c2 = len(found) == len(call_args_list)

    return c1+c2 == 2


class MineMeldFTOpTests(unittest.TestCase):
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

    def test_aggregate_2u(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'sources': ['s1s']})
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertEqual(pargs[1]['indicator'], 'i')
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])
        self.assertEqual(pargs[1]['value']['s1$a'], 1)

        a.filtered_update('s2', indicator='i', value={'s2$a': 1, 'sources': ['s2s']})
        self.assertEqual(ochannel.publish.call_count, 2)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertEqual(pargs[1]['indicator'], 'i')
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s', 's2s'])
        self.assertEqual(pargs[1]['value']['s2$a'], 1)
        self.assertEqual(pargs[1]['value']['s1$a'], 1)

        a.stop()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_aggregate_uwl(self):
        config = {
            'whitelist_prefixes': ['s2']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'sources': ['s1s']})
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertEqual(pargs[1]['indicator'], 'i')
        self.assertEqual(pargs[1]['value']['s1$a'], 1)
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        a.filtered_update('s2', indicator='i', value={'s2$a': 1, 'sources': ['s2s']})
        self.assertEqual(ochannel.publish.call_count, 2)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'withdraw')
        self.assertEqual(pargs[1]['indicator'], 'i')

        a.stop()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_aggregate_2uw(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'sources': ['s1s']})
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        a.filtered_update('s2', indicator='i', value={'s2$a': 1, 'sources': ['s2s']})
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s', 's2s'])

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'sources': ['s1s']})
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s', 's2s'])

        a.filtered_withdraw('s2', indicator='i')
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        a.stop()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_aggregate_2u2w(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'sources': ['s1s']})
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        a.filtered_update('s2', indicator='i', value={'s2$a': 1, 'sources': ['s2s']})
        self.assertEqual(ochannel.publish.call_count, 2)
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s', 's2s'])

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'sources': ['s1s']})
        self.assertEqual(ochannel.publish.call_count, 3)
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s', 's2s'])

        a.filtered_withdraw('s2', indicator='i')
        self.assertEqual(ochannel.publish.call_count, 4)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        a.filtered_withdraw('s1', indicator='i')
        self.assertEqual(ochannel.publish.call_count, 5)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'withdraw')

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_aggregate_u2w_difftypes(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'type': 'a', 'sources': ['s1s']})
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='i2', value={'s1$a': 1, 'type': 'a', 'sources': ['s1s']})
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s1', indicator='i', value={'type': 'b'})
        self.assertEqual(ochannel.publish.call_count, 0)

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s1', indicator='i', value={'type': 'a'})
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'withdraw')

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s2', indicator='i2')
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'withdraw')

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_aggregate_uwlwl(self):
        config = {
            'whitelist_prefixes': ['s2', 's3']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2', 's3']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='i', value={'s1$a': 1, 'sources': ['s1s']})
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertEqual(pargs[1]['indicator'], 'i')
        self.assertEqual(pargs[1]['value']['s1$a'], 1)
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        a.filtered_update('s2', indicator='i', value={'s2$a': 1, 'sources': ['s2s']})
        self.assertEqual(ochannel.publish.call_count, 2)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'withdraw')
        self.assertEqual(pargs[1]['indicator'], 'i')

        a.filtered_update('s3', indicator='i', value={'s3$a': 1, 'sources': ['s3s']})
        self.assertEqual(ochannel.publish.call_count, 2)

        a.filtered_withdraw('s3', indicator='i')
        self.assertEqual(ochannel.publish.call_count, 2)

        a.filtered_withdraw('s2', indicator='i')
        self.assertEqual(ochannel.publish.call_count, 3)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertEqual(pargs[1]['indicator'], 'i')
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_infilters(self):
        config = {
            'infilters': [
                {
                    'name': 'rule1',
                    'conditions': [
                        'type(sources) == null'
                    ],
                    'actions': [
                        'drop'
                    ]
                }
            ]
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2', 's3']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.update(source='s1', indicator='i', value={'s1a': 1, 'sources': ['s1s']})
        gevent.sleep(0.1)
        self.assertEqual(ochannel.publish.call_count, 1)

        ochannel.publish.reset_mock()
        a.update(source='s2', indicator='i', value={'s2a': 1})
        gevent.sleep(0.1)
        self.assertEqual(ochannel.publish.call_count, 0)

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_infilters_2u(self):
        config = {
            'infilters': [
                {
                    'name': 'rule1',
                    'conditions': [
                        'type(sources) == null'
                    ],
                    'actions': [
                        'drop'
                    ]
                }
            ]
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2', 's3']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.update(source='s1', indicator='i', value={'s1a': 1, 'sources': ['s1s']})
        gevent.sleep(0.1)
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertEqual(pargs[1]['indicator'], 'i')
        self.assertEqual(pargs[1]['value']['s1a'], 1)
        self.assertListEqual(pargs[1]['value']['sources'], ['s1s'])

        ochannel.publish.reset_mock()
        a.update(source='s1', indicator='i', value={'s1a': 1})
        gevent.sleep(0.1)
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'withdraw')
        self.assertEqual(pargs[1]['indicator'], 'i')

        a.stop()


        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    def test_attr_override(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2', 's3']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='10.1.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            'direction': 'inbound',
            'first_seen': 10,
            'last_seen': 25,
            'confidence': 20
        })
        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='10.1.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            'direction': 'inbound',
            'first_seen': 5,
            'last_seen': 20,
            'confidence': 30
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.0/16',
                        'value': {
                            'sources': ['s1s', 's2s'],
                            'direction': 'inbound',
                            'first_seen': 5,
                            'last_seen': 25,
                            'confidence': 30
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a = None
        gc.collect()

    def test_get_all(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        chassis.send_rpc.return_value = {'error': None, 'result': 'OK'}

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2', 's3']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='10.1.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            'direction': 'inbound',
            'first_seen': 10,
            'last_seen': 25,
            'confidence': 20
        })
        a.filtered_update('s2', indicator='10.1.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            'direction': 'inbound',
            'first_seen': 5,
            'last_seen': 20,
            'confidence': 30
        })
        a.filtered_update('s3', indicator='10.1.1.0/24', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            'direction': 'inbound',
            'first_seen': 5,
            'last_seen': 20,
            'confidence': 30
        })
        a.get_all(source='test')
        self.assertTrue(
            check_for_rpc(
                chassis.send_rpc.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.0/16',
                        'value': {
                            'sources': ['s2s'],
                            'direction': 'inbound',
                            'first_seen': 5,
                            'last_seen': 25,
                            'confidence': 30
                        }
                    },
                    {
                        'method': 'update',
                        'indicator': '10.1.1.0/24',
                        'value': {
                            'sources': ['s1s'],
                            'direction': 'inbound',
                            'first_seen': 5,
                            'last_seen': 20,
                            'confidence': 30
                        }
                    }
                ],
                all_here=True,
                offset=2
            )
        )

        a.stop()

        a = None
        gc.collect()

    def test_get_range(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        chassis.send_rpc.return_value = {'error': None, 'result': 'OK'}

        a = minemeld.ft.op.AggregateFT(FTNAME, chassis, config)

        inputs = ['s1', 's2', 's3']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='10.1.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            'direction': 'inbound',
            'first_seen': 10,
            'last_seen': 25,
            'confidence': 20
        })
        a.filtered_update('s2', indicator='10.1.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            'direction': 'inbound',
            'first_seen': 5,
            'last_seen': 20,
            'confidence': 30
        })
        a.filtered_update('s3', indicator='10.1.1.0/24', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            'direction': 'inbound',
            'first_seen': 5,
            'last_seen': 20,
            'confidence': 30
        })
        a.get_range(source='test', from_key='10.1.0.0/16',
                    to_key='10.1.1.0/24')
        self.assertTrue(
            check_for_rpc(
                chassis.send_rpc.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.0/16',
                        'value': {
                            'sources': ['s2s'],
                            'direction': 'inbound',
                            'first_seen': 5,
                            'last_seen': 25,
                            'confidence': 30
                        }
                    },
                    {
                        'method': 'update',
                        'indicator': '10.1.1.0/24',
                        'value': {
                            'sources': ['s1s'],
                            'direction': 'inbound',
                            'first_seen': 5,
                            'last_seen': 20,
                            'confidence': 30
                        }
                    }
                ],
                all_here=True,
                offset=2
            )
        )

        a.stop()

        a = None
        gc.collect()
