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

import logging

import uuid

from flask import request
from flask import jsonify

import flask.ext.login

from . import app

# for hup API
from . import MMRpcClient

import minemeld.traced

LOG = logging.getLogger(__name__)


@app.route('/traced/query')
@flask.ext.login.login_required
def traced_query():
    query_uuid = request.args.get('uuid', None)
    if query_uuid is None:
        return jsonify(error={'message': 'query UUID missing'}), 400
    try:
        uuid.UUID(query_uuid)
    except ValueError:
        return jsonify(error={'message': 'invalid query UUID'}), 400

    timestamp = request.args.get('ts', None)
    if timestamp is not None:
        try:
            timestamp = int(timestamp)
        except ValueError:
            return jsonify(error={'message': 'invalid timestamp'}), 400

    counter = request.args.get('c', None)
    if counter is not None:
        try:
            counter = int(counter)
        except ValueError:
            return jsonify(error={'message': 'invalid counter'}), 400

    num_lines = request.args.get('nl', None)
    if num_lines is not None:
        try:
            num_lines = int(num_lines)
        except ValueError:
            return jsonify(error={'message': 'invalid num_lines'}), 400

    query = request.args.get('q', "")

    result = MMRpcClient.send_cmd(minemeld.traced.QUERY_QUEUE, 'query', {
        'uuid': query_uuid,
        'timestamp': timestamp,
        'counter': counter,
        'num_lines': num_lines,
        'query': query
    })

    return jsonify(result=result), 200


@app.route('/traced/query/<query_uuid>/kill')
@flask.ext.login.login_required
def traced_kill_query(query_uuid):
    try:
        uuid.UUID(query_uuid)
    except ValueError:
        return jsonify(error={'message': 'invalid query UUID'}), 400

    result = MMRpcClient.send_cmd(minemeld.traced.QUERY_QUEUE, 'kill_query', {
        'uuid': query_uuid
    })

    return jsonify(result=result), 200
