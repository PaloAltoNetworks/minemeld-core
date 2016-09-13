#  Copyright 2016 Palo Alto Networks, Inc
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

"""FT TAXII tests

Unit tests for minemeld.ft.taxii
"""

import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest
import mock

import redis
import gevent
import greenlet
import time
import xmltodict

import minemeld.ft.taxii
import minemeld.ft

FTNAME = 'testft-%d' % int(time.time())


class MineMeldFTTaxiiTests(unittest.TestCase):
    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_datafeed_init(self, glet_mock, SR_mock):
        config = {}
        chassis = mock.Mock()

        b = minemeld.ft.taxii.DataFeed(FTNAME, chassis, config)

        self.assertEqual(b.name, FTNAME)
        self.assertEqual(b.chassis, chassis)
        self.assertEqual(b.config, config)
        self.assertItemsEqual(b.inputs, [])
        self.assertEqual(b.output, None)
        self.assertEqual(b.redis_skey, FTNAME)
        self.assertEqual(b.redis_skey_chkp, FTNAME+'.chkp')
        self.assertEqual(b.redis_skey_value, FTNAME+'.value')

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_datafeed_update_ip(self, glet_mock, SR_mock):
        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.taxii.DataFeed(FTNAME, chassis, config)

        inputs = ['a']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_initialize()

        b.start()
        # __init__ + get chkp + delete chkp
        self.assertEqual(len(SR_mock.mock_calls), 3)
        SR_mock.reset_mock()

        # unicast
        b.update(
            'a',
            indicator='1.1.1.1',
            value={
                'type': 'IPv4',
                'confidence': 100,
                'share_level': 'green',
                'sources': ['test.1']
            }
        )
        for call in SR_mock.mock_calls:
            name, args, kwargs = call
            if name == '().pipeline().__enter__().hset':
                break
        else:
            self.fail(msg='hset not found')

        stixdict = xmltodict.parse(args[2])
        indicator = stixdict['stix:STIX_Package']['stix:Indicators']['stix:Indicator']
        cyboxprops = indicator['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['AddressObj:Address_Value'], '1.1.1.1')
        SR_mock.reset_mock()

        # CIDR
        b.update(
            'a',
            indicator='1.1.1.0/24',
            value={
                'type': 'IPv4',
                'confidence': 100,
                'share_level': 'green',
                'sources': ['test.1']
            }
        )
        for call in SR_mock.mock_calls:
            name, args, kwargs = call
            if name == '().pipeline().__enter__().hset':
                break
        else:
            self.fail(msg='hset not found')

        stixdict = xmltodict.parse(args[2])
        indicator = stixdict['stix:STIX_Package']['stix:Indicators']['stix:Indicator']
        cyboxprops = indicator['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['AddressObj:Address_Value'], '1.1.1.0/24')
        SR_mock.reset_mock()

        # fake range
        b.update(
            'a',
            indicator='1.1.1.1-1.1.1.1',
            value={
                'type': 'IPv4',
                'confidence': 100,
                'share_level': 'green',
                'sources': ['test.1']
            }
        )
        for call in SR_mock.mock_calls:
            name, args, kwargs = call
            if name == '().pipeline().__enter__().hset':
                break
        else:
            self.fail(msg='hset not found')

        stixdict = xmltodict.parse(args[2])
        indicator = stixdict['stix:STIX_Package']['stix:Indicators']['stix:Indicator']
        cyboxprops = indicator['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['AddressObj:Address_Value'], '1.1.1.1')
        SR_mock.reset_mock()

        # fake range 2
        b.update(
            'a',
            indicator='1.1.1.0-1.1.1.31',
            value={
                'type': 'IPv4',
                'confidence': 100,
                'share_level': 'green',
                'sources': ['test.1']
            }
        )
        for call in SR_mock.mock_calls:
            name, args, kwargs = call
            if name == '().pipeline().__enter__().hset':
                break
        else:
            self.fail(msg='hset not found')

        stixdict = xmltodict.parse(args[2])
        indicator = stixdict['stix:STIX_Package']['stix:Indicators']['stix:Indicator']
        cyboxprops = indicator['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['AddressObj:Address_Value'], '1.1.1.0/27')
        SR_mock.reset_mock()

        # real range
        b.update(
            'a',
            indicator='1.1.1.0-1.1.1.33',
            value={
                'type': 'IPv4',
                'confidence': 100,
                'share_level': 'green',
                'sources': ['test.1']
            }
        )
        for call in SR_mock.mock_calls:
            name, args, kwargs = call
            if name == '().pipeline().__enter__().hset':
                break
        else:
            self.fail(msg='hset not found')

        stixdict = xmltodict.parse(args[2])
        indicator = stixdict['stix:STIX_Package']['stix:Indicators']['stix:Indicator']
        cyboxprops = indicator[0]['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['AddressObj:Address_Value'], '1.1.1.0/27')
        cyboxprops = indicator[1]['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['AddressObj:Address_Value'], '1.1.1.32/31')
        SR_mock.reset_mock()

        b.stop()

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_datafeed_update_domain(self, glet_mock, SR_mock):
        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.taxii.DataFeed(FTNAME, chassis, config)

        inputs = ['a']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_initialize()

        b.start()
        # __init__ + get chkp + delete chkp
        self.assertEqual(len(SR_mock.mock_calls), 3)
        SR_mock.reset_mock()

        # unicast
        b.update(
            'a',
            indicator='example.com',
            value={
                'type': 'domain',
                'confidence': 100,
                'share_level': 'green',
                'sources': ['test.1']
            }
        )
        for call in SR_mock.mock_calls:
            name, args, kwargs = call
            if name == '().pipeline().__enter__().hset':
                break
        else:
            self.fail(msg='hset not found')

        stixdict = xmltodict.parse(args[2])
        indicator = stixdict['stix:STIX_Package']['stix:Indicators']['stix:Indicator']
        cyboxprops = indicator['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['DomainNameObj:Value'], 'example.com')
        SR_mock.reset_mock()

        b.stop()

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_datafeed_update_url(self, glet_mock, SR_mock):
        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.taxii.DataFeed(FTNAME, chassis, config)

        inputs = ['a']
        output = False

        b.connect(inputs, output)
        b.mgmtbus_initialize()

        b.start()
        # __init__ + get chkp + delete chkp
        self.assertEqual(len(SR_mock.mock_calls), 3)
        SR_mock.reset_mock()

        # unicast
        b.update(
            'a',
            indicator='www.example.com/admin.php',
            value={
                'type': 'URL',
                'confidence': 100,
                'share_level': 'green',
                'sources': ['test.1']
            }
        )
        for call in SR_mock.mock_calls:
            name, args, kwargs = call
            if name == '().pipeline().__enter__().hset':
                break
        else:
            self.fail(msg='hset not found')

        stixdict = xmltodict.parse(args[2])
        indicator = stixdict['stix:STIX_Package']['stix:Indicators']['stix:Indicator']
        cyboxprops = indicator['indicator:Observable']['cybox:Object']['cybox:Properties']
        self.assertEqual(cyboxprops['URIObj:Value'], 'www.example.com/admin.php')
        SR_mock.reset_mock()

        b.stop()
