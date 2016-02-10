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

"""FT run config tests

Unit tests for minemeld.run.config
"""

import unittest
import mock

import os
import os.path

import minemeld.run.config

MYDIR = os.path.dirname(__file__)


class MineMeldRunConfigTests(unittest.TestCase):
    def test_defaults_from_file(self):
        emptypath = os.path.join(MYDIR, 'empty.yml')

        config = minemeld.run.config.load_config(emptypath)

        self.assertEqual(config['fabric']['class'], 'AMQP')
        self.assertEqual(config['fabric']['config'], {'num_connections': 5})
        self.assertEqual(config['mgmtbus']['transport']['class'], 'AMQP')
        self.assertEqual(config['mgmtbus']['transport']['config'], {})
        self.assertEqual(config['mgmtbus']['master'], {})
        self.assertEqual(config['mgmtbus']['slave'], {})

    @mock.patch.object(os, 'getenv',
                       return_value=MYDIR)
    def test_prototype_1(self, getenv_mock):
        protopath = os.path.join(MYDIR, 'test-prototype-1.yml')

        config = minemeld.run.config.load_config(protopath)

        self.assertEqual(config['nodes']['testprototype']['class'], 'A')
        self.assertEqual(
            config['nodes']['testprototype']['config'],
            {'useless1': 1}
        )

    def test_validate_config_1(self):
        config = {
            'nodes': {
                'n1': {
                    'inputs': ['n2', 'n3']
                },
                'n2': {
                    'output': True
                }
            }
        }

        msgs = minemeld.run.config.validate_config(config)

        self.assertEqual(len(msgs), 1)

    def test_validate_config_2(self):
        config = {
            'nodes': {
                'n1': {
                    'inputs': ['n2']
                },
                'n2': {
                    'output': False
                }
            }
        }

        msgs = minemeld.run.config.validate_config(config)

        self.assertEqual(len(msgs), 1)

    def test_validate_config_3(self):
        config = {
            'nodes': {
                'n1': {
                    'output': True,
                    'inputs': ['n2', 'n4']
                },
                'n2': {
                    'output': True
                },
                'n3': {
                    'output': True,
                    'inputs': ['n1']
                },
                'n4': {
                    'output': True,
                    'inputs': ['n3']
                }
            }
        }

        msgs = minemeld.run.config.validate_config(config)

        self.assertEqual(len(msgs), 1)

    def test_validate_config_4(self):
        config = {
            'nodes': {
                '../config/running-config.yml': {
                    'output': True
                },
                '<script>alert("ciao")</script>': {
                    'output': True
                }
            }
        }

        msgs = minemeld.run.config.validate_config(config)

        self.assertEqual(len(msgs), 2)
