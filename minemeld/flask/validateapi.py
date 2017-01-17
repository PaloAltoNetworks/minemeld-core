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

import yaml

from flask import jsonify, request

import minemeld.ft.condition
from .aaa import MMBlueprint
from .logger import LOG


__all__ = ['BLUEPRINT']


BLUEPRINT = MMBlueprint('validate', __name__, url_prefix='/validate')


def _return_validation_error(msg):
    return jsonify(error={
        'message': msg
    }), 400


@BLUEPRINT.route('/syslogminerrule', methods=['POST'], read_write=False)
def validate_syslogminerrule():
    try:
        crule = request.data

    except Exception as e:
        return _return_validation_error(
            'Error accessing request body: %s' % str(e)
        )

    try:
        crule = yaml.safe_load(crule)

    except Exception as e:
        return _return_validation_error(
            'YAML not valid: %s' % str(e)
        )

    if 'name' not in crule:
        return _return_validation_error('"name" is required')

    conditions = crule.get('conditions', None)
    if conditions is None or len(conditions) == 0:
        return _return_validation_error(
            'no "conditions" in rule'
        )

    for c in conditions:
        try:
            minemeld.ft.condition.Condition(c)
        except Exception as e:
            return _return_validation_error(
                'Condition %s is not valid' % c
            )

    indicators = crule.get('indicators', None)
    if type(indicators) != list:
        return _return_validation_error(
            'no "indicators" in rule'
        )

    for i in indicators:
        if type(i) != str:
            return _return_validation_error(
                'wrong indicator format: %s' % i
            )

    return jsonify(result='ok')
