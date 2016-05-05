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

"""
This module implements mock classes for minemed.traced tests
"""

CLOCK = -1
def _get_clock():
    global CLOCK

    CLOCK += 1
    return CLOCK

class MockTable(object):
    def __init__(self, name, create_if_missing=True):
        self.name = name
        self.create_if_missing = create_if_missing

        self.last_used = None
        self.refs = []

        self.db_open = True
        self.db = {}

        self.max_counter = -1

    def add_reference(self, refid):
        self.refs.append(refid)

    def remove_reference(self, refid):
        try:
            self.refs.remove(refid)

        except ValueError:
            pass

    def ref_count(self):
        return len(self.refs)

    def put(self, key, value):
        self.last_used = _get_clock()

        self.max_counter += 1
        new_max_counter = '%016x' % self.max_counter

        self.db[key+new_max_counter] = value

    def backwards_iterator(self, timestamp, counter):
        raise NotImplementedError('You kiddin\' right ?')

    def close(self):
        self.db_open = False

def table_factory(name, create_if_missing=True):
    return MockTable(name, create_if_missing=create_if_missing)
