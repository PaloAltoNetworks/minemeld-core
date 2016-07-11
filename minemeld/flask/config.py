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

import os
import yaml

CONFIG = {}

_config_path = os.environ.get('MM_CONFIG', None)

if _config_path is not None:
    with open(_config_path, 'r') as f:
        CONFIG = yaml.safe_load(f)


def get(key, default=None):
    try:
        result = CONFIG[key]
    except KeyError:
        pass
    else:
        return result

    try:
        result = os.environ[key]
    except KeyError:
        pass
    else:
        if result == 'False':
            result = False
        if result == 'True':
            result = True

        return result

    return default
