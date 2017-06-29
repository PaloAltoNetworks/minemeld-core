#  Copyright 2015-2016 Palo Alto Networks, Inc
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

from minemeld.run.config import CHANGE_ADDED, CHANGE_DELETED, CHANGE_INPUT_ADDED, CHANGE_INPUT_DELETED
from minemeld.run.config import MineMeldConfig, MineMeldConfigChange
import minemeld.startupplanner


class MineMeldStartupPlanner(unittest.TestCase):
    def test_subgraphs_1(self):
        nodes = {
            'm1': {
                'inputs': []
            },
            'm2': {},
            'm3': {},
            'p1': {
                'inputs': ['m1', 'm2']
            },
            'p2': {
                'inputs': ['m3']
            },
            'o1': {
                'inputs': ['m1']
            },
            'o2': {
                'inputs': ['p1']
            },
            'o3': {
                'inputs': ['p2']
            }
        }
        state_info = {
            'm1': {
                'checkpoint': None,
                'is_source': True
            },
            'm2': {
                'checkpoint': None,
                'is_source': True
            },
            'm3': {
                'checkpoint': 'a',
                'is_source': True
            },
            'p1': {
                'checkpoint': None,
                'is_source': False
            },
            'p2': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o1': {
                'checkpoint': None,
                'is_source': False
            },
            'o2': {
                'checkpoint': None,
                'is_source': False
            },
            'o3': {
                'checkpoint': 'a',
                'is_source': False
            }
        }

        config = MineMeldConfig.from_dict(dict(nodes=nodes))
        config.compute_changes(config)

        self.assertEqual(len(config.changes), 0)

        plan = minemeld.startupplanner.plan(config, state_info)

        self.assertEqual(plan['m1'], 'reset')
        self.assertEqual(plan['m2'], 'reset')
        self.assertEqual(plan['p1'], 'reset')
        self.assertEqual(plan['o1'], 'reset')
        self.assertEqual(plan['o2'], 'reset')
        self.assertEqual(plan['m3'], 'initialize')
        self.assertEqual(plan['p2'], 'initialize')
        self.assertEqual(plan['o3'], 'initialize')

    def test_new_miner(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'm2': {},
            'p1': {
                'inputs': ['m1', 'm2']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': None,
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 2)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'initialize')
        self.assertEqual(plan['m2'], 'reset')
        self.assertEqual(plan['p1'], 'initialize')
        self.assertEqual(plan['o1'], 'initialize')

    def test_removed_output(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
            'o2': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': 'a',
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 1)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'initialize')
        self.assertEqual(plan['p1'], 'initialize')
        self.assertEqual(plan['o1'], 'initialize')

    def test_added_chain(self):
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'm2']
            },
            'p2': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
            'o2': {
                'inputs': ['p2']
            }
        }
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            }
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': None,
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'p2': {
                'checkpoint': None,
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o2': {
                'checkpoint': None,
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 4)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'rebuild')
        self.assertEqual(plan['m2'], 'reset')
        self.assertEqual(plan['p1'], 'reset')
        self.assertEqual(plan['p2'], 'reset')
        self.assertEqual(plan['o1'], 'reset')
        self.assertEqual(plan['o2'], 'reset')

    def test_invalid_chain_1(self):
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'm3': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'm2', 'm3']
            },
            'p2': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
            'o2': {
                'inputs': ['p2']
            }
        }
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'm3': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'm2', 'm3']
            },
            'o1': {
                'inputs': ['p1']
            }
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': 'b',
                'is_source': True
            },
            'm3': {
                'checkpoint': 'b',
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'p2': {
                'checkpoint': None,
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o2': {
                'checkpoint': None,
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 2)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'reset')
        self.assertEqual(plan['m2'], 'rebuild')
        self.assertEqual(plan['m3'], 'rebuild')
        self.assertEqual(plan['p1'], 'reset')
        self.assertEqual(plan['p2'], 'reset')
        self.assertEqual(plan['o1'], 'reset')
        self.assertEqual(plan['o2'], 'reset')

    def test_invalid_node_1(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'p1': {
                'checkpoint': 'b',
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 0)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'rebuild')
        self.assertEqual(plan['p1'], 'reset')
        self.assertEqual(plan['o1'], 'reset')

    def test_invalid_node_2(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'p1': {
                'checkpoint': None,
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 0)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'rebuild')
        self.assertEqual(plan['p1'], 'reset')
        self.assertEqual(plan['o1'], 'reset')

    def test_invalid_node_3(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'm2']
            },
            'p2': {
                'inputs': ['m1', 'm2']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'm2']
            },
            'p2': {
                'inputs': ['m2']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': 'a',
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'p2': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 1)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'rebuild')
        self.assertEqual(plan['m2'], 'rebuild')
        self.assertEqual(plan['p1'], 'reset')
        self.assertEqual(plan['p2'], 'reset')
        self.assertEqual(plan['o1'], 'reset')

    def test_existing_source_added(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'm2']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': 'a',
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 1)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'initialize')
        self.assertEqual(plan['m2'], 'rebuild')
        self.assertEqual(plan['p1'], 'initialize')
        self.assertEqual(plan['o1'], 'initialize')

    def test_non_existing_source_added(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'm2']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': None,
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 2)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'initialize')
        self.assertEqual(plan['m2'], 'reset')
        self.assertEqual(plan['p1'], 'initialize')
        self.assertEqual(plan['o1'], 'initialize')

    def test_non_source_existing_input_added(self):
        nodes_before = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1']
            },
            'p2': {
                'inputs': ['m2']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        nodes_after = {
            'm1': {
                'inputs': []
            },
            'm2': {
                'inputs': []
            },
            'p1': {
                'inputs': ['m1', 'p2']
            },
            'p2': {
                'inputs': ['m2']
            },
            'o1': {
                'inputs': ['p1']
            },
        }
        state_info = {
            'm1': {
                'checkpoint': 'a',
                'is_source': True
            },
            'm2': {
                'checkpoint': 'a',
                'is_source': True
            },
            'p1': {
                'checkpoint': 'a',
                'is_source': False
            },
            'p2': {
                'checkpoint': 'a',
                'is_source': False
            },
            'o1': {
                'checkpoint': 'a',
                'is_source': False
            },
        }

        config_after = MineMeldConfig.from_dict(dict(nodes=nodes_after))
        config_before = MineMeldConfig.from_dict(dict(nodes=nodes_before))
        config_after.compute_changes(config_before)

        self.assertEqual(len(config_after.changes), 1)

        plan = minemeld.startupplanner.plan(config_after, state_info)

        self.assertEqual(plan['m1'], 'rebuild')
        self.assertEqual(plan['m2'], 'rebuild')
        self.assertEqual(plan['p1'], 'reset')
        self.assertEqual(plan['p2'], 'reset')
        self.assertEqual(plan['o1'], 'reset')
