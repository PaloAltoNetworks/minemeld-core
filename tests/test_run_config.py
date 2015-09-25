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
