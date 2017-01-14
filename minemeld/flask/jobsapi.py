#  Copyright 2015-2017 Palo Alto Networks, Inc
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
import os.path
import logging

from flask import send_from_directory, Blueprint, jsonify
from flask.ext.login import login_required

from .jobs import JOBS_MANAGER


__all__ = ['BLUEPRINT']


LOG = logging.getLogger(__name__)

BLUEPRINT = Blueprint('jobs', __name__, url_prefix='/jobs')


@BLUEPRINT.route('/<job_group>', methods=['GET'])
@login_required
def get_jobs(job_group):
    jobs = JOBS_MANAGER.get_jobs(job_group)

    return jsonify(result=jobs)


@BLUEPRINT.route('/<job_group>/<jobid>', methods=['GET'])
@login_required
def get_job(job_group, jobid):
    jobs = JOBS_MANAGER.get_jobs(job_group)
    if jobid not in jobs:
        return jsonify(error={'message': 'job unknown'}), 400

    return jsonify(result=jobs[jobid])


@BLUEPRINT.route('/<job_group>/<jobid>/log', methods=['GET'])
@login_required
def get_job_log(job_group, jobid):
    jobs = JOBS_MANAGER.get_jobs(job_group)
    if jobid not in jobs:
        return jsonify(error={'message': 'job unknown'}), 400

    job = jobs[jobid]

    return send_from_directory(
        os.path.dirname(job['logfile']),
        os.path.basename(job['logfile']),
        as_attachment=True
    )
