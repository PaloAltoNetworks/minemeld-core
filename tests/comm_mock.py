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
This module implements mock classes for minemed.comm tests
"""

class MockComm(object):
    def __init__(self, config):
        self.config = config

        self.sub_channels = []
        self.rpc_server_channels = []

    def request_sub_channel(self, topic, obj=None, allowed_methods=None, name=None):
        self.sub_channels.append({
            'topic': topic,
            'obj': obj,
            'allowed_methods': allowed_methods,
            'name': name
        })

    def request_rpc_server_channel(self, name, obj=None, allowed_methods=[],
                                   method_prefix='', fanout=None):
        self.rpc_server_channels.append({
            'name': name,
            'obj': obj,
            'allowed_methods': allowed_methods,
            'method_prefix': method_prefix,
            'fanout': fanout
        })

def comm_factory(config):
    return MockComm(config)
