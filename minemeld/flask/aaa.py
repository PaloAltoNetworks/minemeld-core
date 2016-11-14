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

import flask.ext.login

import logging
import base64

from . import config


LOG = logging.getLogger(__name__)

LOGIN_MANAGER = flask.ext.login.LoginManager()
LOGIN_MANAGER.session_protection = None
ANONYMOUS = 'mm-anonymous'


class MMAuthenticatedUser(object):
    def __init__(self, _id=None):
        self._id = unicode(_id)

    def get_id(self):
        return self._id

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False


class MMAuthenticatedAdminUser(MMAuthenticatedUser):
    def check_feed(self, feedname):
        return True


class MMAnonymousAdminUser(MMAuthenticatedUser):
    def __init__(self):
        super(MMAnonymousAdminUser, self).__init__(_id=ANONYMOUS)

    def is_anonymous(self):
        return True

    def check_feed(self, feedname):
        return False


class MMAuthenticatedFeedUser(MMAuthenticatedUser):
    def check_feed(self, feedname):
        fattributes = config.get('FEEDS_ATTRS', None)
        if fattributes is None or feedname not in fattributes:
            return False
        ftags = set(fattributes[feedname].get('tags', []))

        # if 'any' is present, any authenticated user can access
        # the feed
        if 'any' in ftags:
            return True

        uattributes = config.get('FEEDS_USERS_ATTRS', None)
        if uattributes is None or self._id not in uattributes:
            return False
        tags = set(uattributes[self._id].get('tags', []))

        return len(tags.intersection(ftags)) != 0


class MMAnonymousFeedUser(MMAuthenticatedUser):
    def __init__(self, auth_enabled=False):
        super(MMAnonymousFeedUser, self).__init__(_id=ANONYMOUS)

        self.auth_enabled = auth_enabled

    def check_feed(self, feedname):
        if not self.auth_enabled:
            return True

        fattributes = config.get('FEEDS_ATTRS', None)
        if fattributes is None or feedname not in fattributes:
            return False
        ftags = set(fattributes[feedname].get('tags', []))

        if 'anonymous' in ftags:
            return True

        return False

    def is_anonymous(self):
        return True


def _feeds_request_loader(request):
    if not config.get('FEEDS_AUTH_ENABLED', False):
        return MMAnonymousFeedUser(auth_enabled=False)

    api_key = request.headers.get('Authorization')
    if api_key is None:
        return MMAnonymousFeedUser(auth_enabled=True)

    api_key = api_key.replace('Basic', '', 1)

    try:
        api_key = base64.b64decode(api_key)
    except TypeError:
        return None

    try:
        user, password = api_key.split(':', 1)
    except ValueError:
        return None

    if not config.get('FEEDS_USERS_DB').check_password(user, password):
        if config.get('USERS_DB').check_password(user, password):
            return MMAuthenticatedAdminUser(_id=user)

        return None

    return MMAuthenticatedFeedUser(_id=user)


@LOGIN_MANAGER.request_loader
def request_loader(request):
    # check if this is a feed request
    if request.path.startswith('/taxii-'):
        return _feeds_request_loader(request)

    if request.path.startswith('/feeds/'):
        return _feeds_request_loader(request)

    # if auth is disabled, proceed
    if not config.get('API_AUTH_ENABLED', True):
        return MMAnonymousAdminUser()

    api_key = request.headers.get('Authorization')
    if api_key is None:
        return None

    api_key = api_key.replace('Basic', '', 1)

    try:
        api_key = base64.b64decode(api_key)
    except TypeError:
        return None

    try:
        user, password = api_key.split(':', 1)
    except ValueError:
        return None

    if not config.get('USERS_DB').check_password(user, password):
        return None

    return MMAuthenticatedAdminUser(_id=user)


@LOGIN_MANAGER.user_loader
def user_loader(_id):
    return MMAuthenticatedAdminUser(_id=_id)


def check_user(username, password):
    if not config.get('USERS_DB').check_password(username, password):
        return None

    return MMAuthenticatedAdminUser(_id=username)


@LOGIN_MANAGER.unauthorized_handler
def unauthorized():
    return 'Unauthorized', 401
