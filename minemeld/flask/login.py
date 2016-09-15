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

from flask import request
from flask import jsonify

import flask.ext.login

from . import app
from . import aaa

LOG = logging.getLogger(__name__)


@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.values.get('u')
    if username is None:
        return jsonify(error='Missing username'), 400

    password = request.values.get('p')
    if password is None:
        return jsonify(error='Missing password'), 400

    user = aaa.check_user(username, password)
    if user is None:
        return jsonify(error="Wrong credentials"), 401

    flask.ext.login.login_user(user)
    return 'OK'


@app.route('/logout', methods=['GET'])
def logout():
    flask.ext.login.logout_user()
    return 'OK'
