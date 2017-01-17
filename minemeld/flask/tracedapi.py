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

import uuid

from flask import request, jsonify

from . import config
from .mmrpc import MMRpcClient
from .jobs import JOBS_MANAGER
from .aaa import MMBlueprint
from .logger import LOG

import minemeld.traced


__all__ = ['BLUEPRINT']


BLUEPRINT = MMBlueprint('traced', __name__, url_prefix='/traced')


@BLUEPRINT.route('/query', read_write=False)
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

    result = MMRpcClient.send_raw_cmd(minemeld.traced.QUERY_QUEUE, 'query', {
        'uuid': query_uuid,
        'timestamp': timestamp,
        'counter': counter,
        'num_lines': num_lines,
        'query': query
    })

    return jsonify(result=result), 200


@BLUEPRINT.route('/query/<query_uuid>/kill', read_write=False)
def traced_kill_query(query_uuid):
    try:
        uuid.UUID(query_uuid)
    except ValueError:
        return jsonify(error={'message': 'invalid query UUID'}), 400

    result = MMRpcClient.send_raw_cmd(minemeld.traced.QUERY_QUEUE, 'kill_query', {
        'uuid': query_uuid
    })

    return jsonify(result=result), 200


@BLUEPRINT.route('/purge-all', read_write=True)
def traced_purge_all():
    traced_purge_path = config.get('MINEMELD_TRACED_PURGE_PATH', None)
    if traced_purge_path is None:
        return jsonify(error={'message': 'MINEMELD_TRACED_PURGE_PATH not set'}), 500

    jobs = JOBS_MANAGER.get_jobs(job_group='traced-purge')
    for jobid, jobdata in jobs.iteritems():
        if jobdata == 'RUNNING':
            return jsonify(error={'message': 'a trace purge job is already running'}), 400

    jobid = JOBS_MANAGER.exec_job(
        job_group='traced-purge',
        description='purge all traces',
        args=[traced_purge_path, '--all'],
        data={}
    )

    return jsonify(result=jobid)
