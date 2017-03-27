# -*- coding: utf-8 -*-

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
import os
import libtaxii.constants
import re
import lz4
import json

import minemeld.ft.taxii
import minemeld.ft

FTNAME = 'testft-%d' % int(time.time())

MYDIR = os.path.dirname(__file__)


class MockTaxiiContentBlock(object):
    def __init__(self, stix_xml):
        class _Binding(object):
            def __init__(self, id_):
                self.binding_id = id_

        self.content = stix_xml
        self.content_binding = _Binding(libtaxii.constants.CB_STIX_XML_111)


class MineMeldFTTaxiiTests(unittest.TestCase):
    @mock.patch.object(gevent, 'Greenlet')
    def test_taxiiclient_parse(self, glet_mock):
        config = {
            'side_config': 'dummy.yml',
            'ca_file': 'dummy.crt'
        }
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None
        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        b = minemeld.ft.taxii.TaxiiClient(FTNAME, chassis, config)

        inputs = []
        output = False

        b.connect(inputs, output)
        b.mgmtbus_initialize()

        b.start()

        testfiles = os.listdir(MYDIR)
        testfiles = filter(
            lambda x: x.startswith('test_ft_taxii_stix_package_'),
            testfiles
        )

        for t in testfiles:
            with open(os.path.join(MYDIR, t), 'r') as f:
                sxml = f.read()

            mo = re.match('test_ft_taxii_stix_package_([A-Za-z0-9]+)_([0-9]+)_.*', t)
            self.assertNotEqual(mo, None)
            type_ = mo.group(1)
            num_indicators = int(mo.group(2))

            stix_objects = {
                'observables': {},
                'indicators': {},
                'ttps': {}
            }

            content_blocks = [
                MockTaxiiContentBlock(sxml)
            ]

            b._handle_content_blocks(
                content_blocks,
                stix_objects
            )

            params = {
                'ttps': stix_objects['ttps'],
                'observables': stix_objects['observables']
            }
            indicators = [[iid, iv, params] for iid, iv in stix_objects['indicators'].iteritems()]

            for i in indicators:
                result = b._process_item(i)

                self.assertEqual(len(result), num_indicators)

                if type_ != 'any':
                    for r in result:
                        self.assertEqual(r[1]['type'], type_)

        b.stop()

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
        self.assertEqual(len(SR_mock.mock_calls), 6)
        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = 1

        # unicast
        b.filtered_update(
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.uncompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['address_value'], '1.1.1.1')
        self.assertEqual(cyboxprops['xsi:type'], 'AddressObjectType')
        SR_mock.reset_mock()

        # CIDR
        b.filtered_update(
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.uncompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['address_value'], '1.1.1.0/24')
        self.assertEqual(cyboxprops['xsi:type'], 'AddressObjectType')
        SR_mock.reset_mock()

        # fake range
        b.filtered_update(
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.uncompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['address_value'], '1.1.1.1')
        self.assertEqual(cyboxprops['xsi:type'], 'AddressObjectType')
        SR_mock.reset_mock()

        # fake range 2
        b.filtered_update(
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.uncompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['address_value'], '1.1.1.0/27')
        self.assertEqual(cyboxprops['xsi:type'], 'AddressObjectType')
        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = 1

        # real range
        b.filtered_update(
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.uncompress(args[2][3:]))

        indicator = stixdict['indicators']
        cyboxprops = indicator[0]['observable']['object']['properties']
        self.assertEqual(cyboxprops['address_value'], '1.1.1.0/27')
        self.assertEqual(cyboxprops['xsi:type'], 'AddressObjectType')
        cyboxprops = indicator[1]['observable']['object']['properties']
        self.assertEqual(cyboxprops['address_value'], '1.1.1.32/31')
        self.assertEqual(cyboxprops['xsi:type'], 'AddressObjectType')
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
        self.assertEqual(len(SR_mock.mock_calls), 6)
        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = 1

        # unicast
        b.filtered_update(
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.decompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['value'], 'example.com')
        self.assertEqual(cyboxprops['type'], 'FQDN')
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
        self.assertEqual(len(SR_mock.mock_calls), 6)
        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = 1

        # unicast
        b.filtered_update(
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.decompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['type'], 'URL')
        self.assertEqual(cyboxprops['value'], 'www.example.com/admin.php')
        SR_mock.reset_mock()

        b.stop()

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_datafeed_unicode_url(self, glet_mock, SR_mock):
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
        self.assertEqual(len(SR_mock.mock_calls), 6)
        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = 1

        # unicast
        b.filtered_update(
            'a',
            indicator=u'☃.net/påth',
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.decompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['type'], 'URL')
        self.assertEqual(cyboxprops['value'], u'\u2603.net/p\xe5th')
        SR_mock.reset_mock()

        b.stop()

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_datafeed_overflow(self, glet_mock, SR_mock):
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
        self.assertEqual(len(SR_mock.mock_calls), 6)
        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = b.max_entries

        # unicast
        b.filtered_update(
            'a',
            indicator=u'☃.net/påth',
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
                self.fail(msg='hset found')

        self.assertEqual(b.statistics['drop.overflow'], 1)

        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = b.max_entries - 1

        # unicast
        b.filtered_update(
            'a',
            indicator=u'☃.net/påth',
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.decompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['type'], 'URL')
        self.assertEqual(cyboxprops['value'], u'\u2603.net/p\xe5th')

        b.stop()

    @mock.patch.object(redis, 'StrictRedis')
    @mock.patch.object(gevent, 'Greenlet')
    def test_datafeed_update_hash(self, glet_mock, SR_mock):
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
        self.assertEqual(len(SR_mock.mock_calls), 6)
        SR_mock.reset_mock()
        SR_mock.return_value.zcard.return_value = 1

        # sha1
        b.filtered_update(
            'a',
            indicator='a6a5418b4d67d9f3a33cbf184b25ac7f9fa87d33',
            value={
                'type': 'sha1',
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.decompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['hashes'][0]['simple_hash_value'], 'a6a5418b4d67d9f3a33cbf184b25ac7f9fa87d33')
        self.assertEqual(cyboxprops['hashes'][0]['type']['value'], 'SHA1')
        SR_mock.reset_mock()

        # md5
        b.filtered_update(
            'a',
            indicator='e23fadd6ceef8c618fc1c65191d846fa',
            value={
                'type': 'md5',
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.decompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['hashes'][0]['simple_hash_value'], 'e23fadd6ceef8c618fc1c65191d846fa')
        self.assertEqual(cyboxprops['hashes'][0]['type']['value'], 'MD5')
        SR_mock.reset_mock()

        # sha256
        b.filtered_update(
            'a',
            indicator='a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9',
            value={
                'type': 'sha256',
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

        self.assertEqual(args[2].startswith('lz4'), True)
        stixdict = json.loads(lz4.decompress(args[2][3:]))

        indicator = stixdict['indicators'][0]
        cyboxprops = indicator['observable']['object']['properties']
        self.assertEqual(cyboxprops['hashes'][0]['simple_hash_value'], 'a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9')
        self.assertEqual(cyboxprops['hashes'][0]['type']['value'], 'SHA256')
        SR_mock.reset_mock()

        b.stop()
