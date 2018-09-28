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

"""FT ipop tests

Unit tests for minemeld.ft.ipop
"""

import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest
import mock
import time
import shutil
import logging
import netaddr
import random

import guppy  # noqa
import pdb  # noqa
import gc  # noqa

from nose.plugins.attrib import attr

import minemeld.ft.ipop

LOG = logging.getLogger(__name__)
FTNAME = 'testft-%d' % int(time.time())


def check_for_rpc(call_args_list, check_list, all_here=False):
    LOG.debug("call_args_list: %s", call_args_list)

    found = []
    for chk in check_list:
        LOG.debug("checking: %s", chk)

        for j in xrange(len(call_args_list)):
            if j in found:
                continue

            args = call_args_list[j][0]

            if args[0] != chk['method']:
                continue
            if args[1]['indicator'] != chk['indicator']:
                continue

            chkvalue = chk.get('value', None)
            if chkvalue is None:
                found.append(j)
                LOG.debug("found @%d", j)
                break

            argsvalue = args[1].get('value', None)
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


class MineMeldFTIPOpTests(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            shutil.rmtree(FTNAME+"_st")
        except:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            shutil.rmtree(FTNAME+"_st")
        except:
            pass

    def test_calc_ipranges(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.1', value={
            'type': 'IPv4',
            's1$a': 1,
            'sources': ['s1s']
        })
        self.assertEqual(ochannel.publish.call_count, 1)
        pargs = ochannel.publish.call_args[0]
        self.assertEqual(pargs[0], 'update')
        self.assertEqual(pargs[1]['indicator'], '192.168.0.1-192.168.0.1')

        ochannel.publish.reset_mock()
        a.filtered_update('s1', indicator='192.168.0.1-192.168.0.3', value={
            'type': 'IPv4',
            's1$b': 1,
            'sources': ['s1s']
        })
        self.assertTrue(check_for_rpc(
            ochannel.publish.call_args_list,
            [
                {
                    'method': 'update',
                    'indicator': '192.168.0.1-192.168.0.1',
                    'value': {
                        's1$a': 1,
                        's1$b': 1,
                        'sources': ['s1s']
                    }
                },
                {
                    'method': 'update',
                    'indicator': '192.168.0.2-192.168.0.3',
                    'value': {
                        's1$b': 1,
                        'sources': ['s1s']
                    }
                }
            ],
            all_here=True
        ))

        ochannel.publish.reset_mock()
        a.filtered_update('s1', indicator='192.168.0.2-192.168.0.2', value={
            'type': 'IPv4',
            's1$c': 1,
            'sources': ['s1s']
        })
        self.assertTrue(check_for_rpc(
            ochannel.publish.call_args_list,
            [
                {
                    'method': 'update',
                    'indicator': '192.168.0.2-192.168.0.2',
                    'value': {
                        's1$b': 1,
                        's1$c': 1,
                        'sources': ['s1s']
                    }
                },
                {
                    'method': 'withdraw',
                    'indicator': '192.168.0.2-192.168.0.3',
                    'value': {
                        's1$b': 1,
                        'sources': ['s1s']
                    }
                },
                {
                    'method': 'update',
                    'indicator': '192.168.0.3-192.168.0.3',
                    'value': {
                        's1$b': 1,
                        'sources': ['s1s']
                    }
                }
            ],
            all_here=True
        ))

        ochannel.publish.reset_mock()
        a.filtered_update('s1', indicator='255.255.255.255', value={
            'type': 'IPv4',
            's1$e': 1,
            'sources': ['s1s']
        })
        self.assertTrue(check_for_rpc(
            ochannel.publish.call_args_list,
            [
                {
                    'method': 'update',
                    'indicator': '255.255.255.255-255.255.255.255',
                    'value': {
                        'sources': ['s1s']
                    }
                }
            ],
            all_here=True
        ))

        ochannel.publish.reset_mock()
        a.filtered_update('s1', indicator='0.0.0.0', value={
            'type': 'IPv4',
            's1$e': 1,
            'sources': ['s1s']
        })
        self.assertTrue(check_for_rpc(
            ochannel.publish.call_args_list,
            [
                {
                    'method': 'update',
                    'indicator': '0.0.0.0-0.0.0.0',
                    'value': {
                        'sources': ['s1s']
                    }
                }
            ],
            all_here=True
        ))

        a.stop()

        a.st.db.close()
        a = None

    def test_uwl(self):
        config = {
            'whitelist_prefixes': ['s2']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='192.168.0.0/24', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$b': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.1.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_uwl2(self):
        config = {
            'whitelist_prefixes': ['s2']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='192.168.0.1', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$b': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.0.0',
                        'value': {
                            's1$a': 1
                        }
                    },
                    {
                        'method': 'update',
                        'indicator': '192.168.0.2-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_uwl3(self):
        config = {
            'whitelist_prefixes': ['s2']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='192.168.0.1', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$b': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.0.0',
                        'value': {
                            's1$a': 1
                        }
                    },
                    {
                        'method': 'update',
                        'indicator': '192.168.0.2-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='192.168.0.2', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$b': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.3-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.2-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_overlap_by_one(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.1-192.168.0.3', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.1-192.168.0.3'
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='192.168.0.3-192.168.0.4', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$b': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.1-192.168.0.2'
                    },
                    {
                        'method': 'update',
                        'indicator': '192.168.0.3-192.168.0.3'
                    },
                    {
                        'method': 'update',
                        'indicator': '192.168.0.4-192.168.0.4'
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.1-192.168.0.3'
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_overlap_by_lastrange(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='8.8.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '8.8.0.0-8.8.255.255'
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='8.8.255.0/24', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$b': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '8.8.0.0-8.8.254.255'
                    },
                    {
                        'method': 'update',
                        'indicator': '8.8.255.0-8.8.255.255'
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '8.8.0.0-8.8.255.255'
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_3overlaps(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='10.1.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.0-10.1.255.255'
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='10.1.1.0/24', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$b': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.0-10.1.0.255'
                    },
                    {
                        'method': 'update',
                        'indicator': '10.1.1.0-10.1.1.255'
                    },
                    {
                        'method': 'update',
                        'indicator': '10.1.2.0-10.1.255.255'
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '10.1.0.0-10.1.255.255'
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='10.1.1.128/25', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$c': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.1.128-10.1.1.255',
                        's1$a': 1,
                        's1$b': 1,
                        's1$c': 1
                    },
                    {
                        'method': 'update',
                        'indicator': '10.1.1.0-10.1.1.127'
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '10.1.1.0-10.1.1.255'
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_2overlaps(self):
        config = {
            'whitelist_prefixes': ['s2']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='10.1.0.0/24', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.0-10.1.0.255'
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='10.1.0.10', value={
            'type': 'IPv4',
            'sources': ['s2s']
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.11-10.1.0.255'
                    },
                    {
                        'method': 'update',
                        'indicator': '10.1.0.0-10.1.0.9'
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '10.1.0.0-10.1.0.255'
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s2', indicator='10.1.0.25', value={
            'type': 'IPv4',
            'sources': ['s2s']
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '10.1.0.11-10.1.0.24',
                        's1$a': 1
                    },
                    {
                        'method': 'update',
                        'indicator': '10.1.0.26-10.1.0.255'
                    },
                    {
                        'method': 'withdraw',
                        'indicator': '10.1.0.11-10.1.0.255'
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_attr_override(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

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
                        'indicator': '10.1.0.0-10.1.255.255',
                        'value': {
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

        a.st.db.close()
        a = None

    def test_uw(self):
        config = {
            'whitelist_prefixes': ['s2']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s1', indicator='192.168.0.0/16')
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_2uw(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.0', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        a.filtered_update('s1', indicator='192.168.1.0', value={
            'type': 'IPv4',
            'sources': ['s2s'],
            's1$a': 1
        })

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s1', indicator='192.168.0.0')
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.0-192.168.0.0',
                        'value': {
                            'type': 'IPv4',
                            'sources': ['s1s'],
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        a.filtered_update('s1', indicator='192.168.0.0', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s1', indicator='192.168.1.0')
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.1.0-192.168.1.0'
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_uw_wrongtype(self):
        config = {
            'whitelist_prefixes': ['s2']
        }
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        a.filtered_update('s1', indicator='192.168.0.0/16', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.255.255',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s1', indicator='192.168.0.0/16', value={'type': 'domain'})
        self.assertEqual(ochannel.publish.call_count, 0)

        ochannel.publish.reset_mock()
        a.filtered_withdraw('s1', indicator='192.168.0.0/16', value={'type': 'IPv4'})
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'withdraw',
                        'indicator': '192.168.0.0-192.168.255.255'
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    def test_updated_indicator(self):
        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        ochannel.publish.reset_mock()
        a.filtered_update('s1', indicator='192.168.0.0', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 1
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.0.0',
                        'value': {
                            's1$a': 1
                        }
                    }
                ],
                all_here=True
            )
        )

        ochannel.publish.reset_mock()
        a.filtered_update('s1', indicator='192.168.0.0', value={
            'type': 'IPv4',
            'sources': ['s1s'],
            's1$a': 2
        })
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '192.168.0.0-192.168.0.0',
                        'value': {
                            's1$a': 2
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()

        a.st.db.close()
        a = None

    @attr('slow')
    def test_stress_1(self):
        num_intervals = 100000

        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        t1 = time.time()
        for j in xrange(num_intervals):
            start = random.randint(0, 0xFFFFFFFF)
            if random.randint(0, 4) == 0:
                start = start & 0xFFFFFF00
                end = start + 255
            else:
                end = start
            end = netaddr.IPAddress(end)
            start = netaddr.IPAddress(start)
            ochannel.publish.reset_mock()
        t2 = time.time()
        dt = t2-t1

        t1 = time.time()
        for j in xrange(num_intervals):
            start = random.randint(0, 0xFFFFFFFF)
            if random.randint(0, 4) == 0:
                start = start & 0xFFFFFF00
                end = start + 255
            else:
                end = start
            end = netaddr.IPAddress(end)
            start = netaddr.IPAddress(start)
            ochannel.publish.reset_mock()
            a.filtered_update('s1', indicator='%s-%s' % (start, end), value={
                'type': 'IPv4',
                'sources': ['s1s']
            })
        t2 = time.time()
        print "TIME: Inserted %d intervals in %d" % (num_intervals, (t2-t1-dt))

        t1 = time.time()
        for j in xrange(num_intervals):
            ochannel.publish.reset_mock()
            a.filtered_update('s1', indicator='%s' % (start), value={
                'type': 'IPv4',
                'sources': ['s1s'],
                'count': j
            })
        t2 = time.time()
        print "TIME: Updated %d intervals in %d" % (num_intervals, (t2-t1-dt))

        a.stop()

        a.st.db.close()
        a = None

    @attr('slow')
    def test_stress_2(self):
        num_intervals = 200

        config = {}
        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.ipop.AggregateIPv4FT(FTNAME, chassis, config)

        inputs = ['s1', 's2']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()

        t1 = time.time()
        for _ in xrange(num_intervals):
            end = random.randint(0, 0xFFFFFFFF)
            start = random.randint(0, end)
            end = netaddr.IPAddress(end)
            start = netaddr.IPAddress(start)
            ochannel.publish.reset_mock()
        t2 = time.time()
        dt = t2-t1

        t1 = time.time()
        for j in xrange(num_intervals):
            end = random.randint(0, 0xFFFFFFFF)
            start = random.randint(0, end)
            end = netaddr.IPAddress(end)
            start = netaddr.IPAddress(start)
            ochannel.publish.reset_mock()
            a.filtered_update('s1', indicator='%s-%s' % (start, end), value={
                'type': 'IPv4',
                'sources': ['s1s']
            })
        t2 = time.time()
        print "TIME: Inserted %d intervals in %d" % (num_intervals, (t2-t1-dt))

        a.stop()

        a.st.db.close()
        a = None
