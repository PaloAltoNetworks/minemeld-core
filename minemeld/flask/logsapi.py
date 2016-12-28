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

import logging

from flask import send_from_directory, Blueprint, jsonify
from flask.ext.login import login_required

from . import config


__all__ = ['BLUEPRINT']


LOG = logging.getLogger(__name__)

BLUEPRINT = Blueprint('logs', __name__, url_prefix='/logs')


@BLUEPRINT.route('/minemeld-engine.log', methods=['GET'])
@login_required
def get_minemeld_engine_log():
    log_directory = config.get('MINEMELD_LOG_DIRECTORY_PATH', None)
    if log_directory is None:
        return jsonify(error={'message': 'LOG_DIRECTORY not set'}), 500

    return send_from_directory(log_directory, 'minemeld-engine.log', as_attachment=True)


@BLUEPRINT.route('/minemeld-web.log', methods=['GET'])
@login_required
def get_minemeld_web_log():
    log_directory = config.get('MINEMELD_LOG_DIRECTORY_PATH', None)
    if log_directory is None:
        return jsonify(error={'message': 'LOG_DIRECTORY not set'}), 500

    return send_from_directory(log_directory, 'minemeld-web.log', as_attachment=True)
