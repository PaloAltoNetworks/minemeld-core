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

"""FT Table tests

Unit tests for minemeld.ft.base
"""

import unittest
import mock

import minemeld.ft.base
import minemeld.ft


class MineMeldFTBaseTests(unittest.TestCase):
    @mock.patch.object(minemeld.ft.base.BaseFT, 'configure',
                       return_value=None)
    def test_init(self, configure_mock):
        config = {minemeld.ft.base.BaseFT}
        chassis = mock.Mock()

        bcls = minemeld.ft.base.BaseFT

        b = bcls('test', chassis, config)

        self.assertEqual(b.name, 'test')
        self.assertEqual(b.chassis, chassis)
        self.assertEqual(b.config, config)
        self.assertItemsEqual(b.inputs, [])
        self.assertEqual(b.output, None)
        self.assertEqual(b.configure.call_count, 1)
        self.assertEqual(b.state, minemeld.ft.ft_states.READY)

    def test_connect_io(self):
        ftname = 'test'

        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None

        b = minemeld.ft.base.BaseFT(ftname, chassis, config)

        inputs = ['a', 'b', 'c']
        output = True

        b.connect(inputs, output)

        self.assertItemsEqual(b.inputs, inputs)
        self.assertEqual(b.output, ochannel)

        icalls = []
        for i in inputs:
            icalls.append(
                mock.call(ftname, b, i,
                          allowed_methods=['update', 'withdraw', 'checkpoint'])
            )

        chassis.request_sub_channel.assert_has_calls(
            icalls,
            any_order=True
        )

        chassis.request_rpc_channel.assert_called_once_with(
            ftname,
            b,
            allowed_methods=[
                'update',
                'withdraw',
                'checkpoint',
                'get',
                'get_all',
                'get_range',
                'length',
                'hup'
            ]
        )

        chassis.request_pub_channel.assert_called_once_with(ftname)

    def test_rpc(self):
        ftname = 'test'

        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None

        b = minemeld.ft.base.BaseFT(ftname, chassis, config)

        inputs = []
        output = False

        b.connect(inputs, output)

        chassis.request_sub_channel.assert_not_called()
        chassis.request_pub_channel.assert_not_called()
        chassis.request_rpc_channel.assert_called_once_with(
            ftname,
            b,
            allowed_methods=[
                'update',
                'withdraw',
                'checkpoint',
                'get',
                'get_all',
                'get_range',
                'length',
                'hup'
            ]
        )

        b.do_rpc('destft', 'rpcmethod', a=1, b=1)

        chassis.send_rpc.assert_called_once_with(
            ftname,
            'destft',
            'rpcmethod',
            {'a': 1, 'b': 1},
            timeout=30,
            block=True
        )

    def test_emit(self):
        ftname = 'test'

        config = {}
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None

        b = minemeld.ft.base.BaseFT(ftname, chassis, config)

        inputs = []
        output = True

        b.connect(inputs, output)

        chassis.request_sub_channel.assert_not_called()
        chassis.request_pub_channel.assert_called_once_with(ftname)
        chassis.request_rpc_channel.assert_called_once_with(
            ftname,
            b,
            allowed_methods=[
                'update',
                'withdraw',
                'checkpoint',
                'get',
                'get_all',
                'get_range',
                'length',
                'hup'
            ]
        )

        b.emit_update('testi', {'test': 'v'})

        self.assertEqual(ochannel.publish.call_count, 1)
        self.assertEqual(ochannel.publish.call_args[0][0],
                         'update')
        self.assertEqual(ochannel.publish.call_args[0][1]['indicator'],
                         'testi')
        self.assertEqual(ochannel.publish.call_args[0][1]['value']['test'],
                         'v')

        b.emit_withdraw('testi', {'test': 'v'})

        self.assertEqual(ochannel.publish.call_count, 2)
        self.assertEqual(ochannel.publish.call_args[0][0],
                         'withdraw')
        self.assertEqual(ochannel.publish.call_args[0][1]['indicator'],
                         'testi')
        self.assertEqual(ochannel.publish.call_args[0][1]['value']['test'],
                         'v')

    def test_emit_filtered(self):
        ftname = 'test'

        config = {
            'outfilters': [
                {
                    'name': 'rule1',
                    'conditions': [
                        "direction == 'inbound'",
                        "type == 'IPv4'"
                    ],
                    'actions': ['accept']
                },
                {
                    'name': 'rule2',
                    'actions': ['drop']
                }
            ]
        }
        chassis = mock.Mock()

        chassis.request_sub_channel.return_value = None
        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel
        chassis.request_rpc_channel.return_value = None

        b = minemeld.ft.base.BaseFT(ftname, chassis, config)

        inputs = []
        output = True

        b.connect(inputs, output)

        chassis.request_sub_channel.assert_not_called()
        chassis.request_pub_channel.assert_called_once_with(ftname)
        chassis.request_rpc_channel.assert_called_once_with(
            ftname,
            b,
            allowed_methods=[
                'update',
                'withdraw',
                'checkpoint',
                'get',
                'get_all',
                'get_range',
                'length',
                'hup'
            ]
        )

        b.emit_update('testi', {'type': 'IPv6', 'direction': 'inbound'})
        self.assertEqual(ochannel.publish.call_count, 0)

        ochannel.publish.reset_mock()
        b.emit_withdraw('testi', {'type': 'IPv6', 'direction': 'inbound'})
        self.assertEqual(ochannel.publish.call_count, 0)

        ochannel.publish.reset_mock()
        b.emit_update('testi', {'type': 'IPv4', 'direction': 'inbound'})
        self.assertEqual(ochannel.publish.call_count, 1)

        ochannel.publish.reset_mock()
        b.emit_update('testi', {'type': 'IPv4', 'direction': 'outbound'})
        self.assertEqual(ochannel.publish.call_count, 0)

        ochannel.publish.reset_mock()
        b.emit_update('testi', {'type': 'IPv6', 'direction': 'inbound'})
        self.assertEqual(ochannel.publish.call_count, 0)

        ochannel.publish.reset_mock()
        b.emit_update('testi', {'type': 'IPv6', 'direction': 'outbound'})
        self.assertEqual(ochannel.publish.call_count, 0)
