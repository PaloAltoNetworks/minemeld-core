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

import flask.ext.login

import logging
import base64
import passlib.apache
import os
import os.path

from . import config


LOG = logging.getLogger(__name__)

_users_db = config.get('USERS_DB', None)
if _users_db is None:
    USERS = passlib.apache.HtpasswdFile(new=True)
else:
    _users_db = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG', '')),
        _users_db
    )
    USERS = passlib.apache.HtpasswdFile(path=_users_db)


_feeds_users_db = config.get('FEEDS_USERS_DB', None)
if _feeds_users_db is None:
    FEEDS_USERS = passlib.apache.HtpasswdFile(new=True)
else:
    _feeds_users_db = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG', '')),
        _feeds_users_db
    )
    FEEDS_USERS = passlib.apache.HtpasswdFile(path=_feeds_users_db)

LOGIN_MANAGER = flask.ext.login.LoginManager()
LOGIN_MANAGER.session_protection = None
API_AUTH_ENABLED = config.get('API_AUTH_ENABLED', True)
FEEDS_AUTH_ENABLED = config.get('FEEDS_AUTH_ENABLED', False)
TAXII_AUTH_ENABLED = config.get('TAXII_AUTH_ENABLED', False)


class MMAuthenticatedUser(object):
    def __init__(self, id=None):
        self._id = unicode(id)

    def get_id(self):
        return self._id

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False


def _feeds_request_loader(request):
    if not FEEDS_AUTH_ENABLED:
        return MMAuthenticatedUser(id='feeds_auth_disabled')

    api_key = request.headers.get('Authorization')
    if api_key is not None:
        api_key = api_key.replace('Basic', '', 1)

        try:
            api_key = base64.b64decode(api_key)
        except TypeError:
            return None

        try:
            user, password = api_key.split(':', 1)
        except ValueError:
            return None

        if not FEEDS_USERS.check_password(user, password):
            return None

        return MMAuthenticatedUser(id=user)

    return None


def _taxii_request_loader(request):
    if not TAXII_AUTH_ENABLED:
        return MMAuthenticatedUser(id='taxii_auth_disabled')

    api_key = request.headers.get('Authorization')
    if api_key is not None:
        api_key = api_key.replace('Basic', '', 1)

        try:
            api_key = base64.b64decode(api_key)
        except TypeError:
            return None

        try:
            user, password = api_key.split(':', 1)
        except ValueError:
            return None

        if not FEEDS_USERS.check_password(user, password):
            return None

        return MMAuthenticatedUser(id=user)

    return None


@LOGIN_MANAGER.request_loader
def request_loader(request):
    if request.path.startswith('/taxii-'):
        return _taxii_request_loader(request)

    if request.path.startswith('/feeds/'):
        return _feeds_request_loader(request)

    if not API_AUTH_ENABLED:
        return MMAuthenticatedUser(id='api_auth_disabled')

    api_key = request.headers.get('Authorization')
    if api_key is not None:
        api_key = api_key.replace('Basic', '', 1)

        try:
            api_key = base64.b64decode(api_key)
        except TypeError:
            return None

        try:
            user, password = api_key.split(':', 1)
        except ValueError:
            return None

        if not USERS.check_password(user, password):
            return None

        return MMAuthenticatedUser(id=user)

    return None


@LOGIN_MANAGER.unauthorized_handler
def unauthorized():
    return 'Unauthorized', 401
