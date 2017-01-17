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

import json
import base64
from functools import wraps

import flask.ext.login
from flask import current_app, Blueprint, request

from . import config
from .logger import LOG


ANONYMOUS = 'mm-anonymous'


class MMBlueprint(Blueprint):
    def _audit(self, f, audit_required):
        if not audit_required:
            return f

        @wraps(f)
        def audited_view(*args, **kwargs):
            if request and flask.ext.login.current_user:
                params = []

                for key, values in request.values.iterlists():
                    if key == '_':
                        continue

                    params.append(('value:{}'.format(key), values))

                for filename, files in request.files.iterlists():
                    params.append(('file:{}'.format(filename), [file.filename for file in files]))

                body = request.get_json(silent=True)
                if body is not None:
                    params.append(['jsonbody', json.dumps(body)[:1024]])

                LOG.audit(
                    user_id=flask.ext.login.current_user.get_id(),
                    action_name='{} {}'.format(request.method, request.path),
                    params=params
                )

            else:
                LOG.critical('no request or current_user in audited_view')

            return f(*args, **kwargs)

        return audited_view

    def _login_required(self, f, login_required, read_write, feeds):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if not login_required:
                return f(*args, **kwargs)

            if not config.get('API_AUTH_ENABLED', True) and not feeds:
                return f(*args, **kwargs)

            if not config.get('FEEDS_AUTH_ENABLED', False) and feeds:
                return f(*args, **kwargs)

            if not feeds:
                if not flask.ext.login.current_user.is_authenticated():
                    return current_app.login_manager.unauthorized()
                if flask.ext.login.current_user.get_id().startswith('feeds/'):
                    return current_app.login_manager.unauthorized()

            if read_write and not flask.ext.login.current_user.is_read_write():
                return 'Forbidden', 403

            return f(*args, **kwargs)

        return decorated_view

    def route(self, rule, **options):
        def decorator(f):
            login_required = options.pop('login_required', True)
            read_write = options.pop('read_write', True)
            feeds = options.pop("feeds", False)

            super_decorator = super(MMBlueprint, self).route(rule, **options)

            return super_decorator(
                self._audit(
                    self._login_required(f, login_required, read_write, feeds),
                    read_write
                )
            )

        return decorator


class MMAnonynmousUser(object):
    def __init__(self):
        self._id = ANONYMOUS

    def get_id(self):
        return self._id

    def is_authenticated(self):
        return False

    def is_active(self):
        return True

    def is_anonymous(self):
        return True

    def is_read_write(self):
        return False

    def check_feed(self, feedname):
        if not config.get('FEEDS_AUTH_ENABLED', False):
            return True

        fattributes = config.get('FEEDS_ATTRS', None)
        if fattributes is None or feedname not in fattributes:
            return False
        ftags = set(fattributes[feedname].get('tags', []))

        if 'anonymous' in ftags:
            return True

        return False

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
    def __init__(self, _id):
        super(MMAuthenticatedAdminUser, self).__init__(_id=u'admin/{}'.format(_id))

    def is_read_write(self):
        read_write = config.get('READ_WRITE', None)
        if read_write is None:
            return True

        if isinstance(read_write, str) or isinstance(read_write, unicode):
            read_write = read_write.split(',')
        elif not isinstance(read_write, list):
            LOG.error('Unknown READ_WRITE format')
            return False

        if self._id[6:] in read_write:
            return True

        return False

    def check_feed(self, feedname):
        return True


class MMAuthenticatedFeedUser(MMAuthenticatedUser):
    def __init__(self, _id):
        super(MMAuthenticatedFeedUser, self).__init__(_id=u'feeds/{}'.format(_id))

    def is_read_write(self):
        # this should never be called
        return False

    def check_feed(self, feedname):
        if not config.get('FEEDS_AUTH_ENABLED', False):
            return True

        fattributes = config.get('FEEDS_ATTRS', None)
        if fattributes is None or feedname not in fattributes:
            return False
        ftags = set(fattributes[feedname].get('tags', []))

        # if 'any' is present, any authenticated user can access
        # the feed
        if 'any' in ftags:
            return True

        uattributes = config.get('FEEDS_USERS_ATTRS', None)
        if uattributes is None or self._id[6:] not in uattributes:
            return False
        tags = set(uattributes[self._id[6:]].get('tags', []))

        return len(tags.intersection(ftags)) != 0


def authenticated_user_factory(_id):
    if _id.startswith('feeds/'):
        return MMAuthenticatedFeedUser(_id=_id[6:])

    if _id.startswith('admin/'):
        return MMAuthenticatedAdminUser(_id=_id[6:])

    if _id == ANONYMOUS:
        return MMAnonynmousUser()

    raise RuntimeError('Unknown user_id prefix: {}'.format(_id))


LOGIN_MANAGER = flask.ext.login.LoginManager()
LOGIN_MANAGER.session_protection = None
LOGIN_MANAGER.anonymous_user = MMAnonynmousUser


@LOGIN_MANAGER.request_loader
def request_loader(request):
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

    auth_user = check_feeds_user(user, password)
    if auth_user is not None:
        return auth_user

    auth_user = check_admin_user(user, password)
    if auth_user is not None:
        return auth_user

    return None


@LOGIN_MANAGER.user_loader
def user_loader(_id):
    return authenticated_user_factory(_id)


def check_feeds_user(username, password):
    if not config.get('FEEDS_USERS_DB').check_password(username, password):
        return None

    return MMAuthenticatedFeedUser(_id=username)


def check_admin_user(username, password):
    if not config.get('USERS_DB').check_password(username, password):
        return None

    return MMAuthenticatedAdminUser(_id=username)


@LOGIN_MANAGER.unauthorized_handler
def unauthorized():
    return 'Unauthorized', 401


def init_app(app):
    app.config['REMEMBER_COOKIE_NAME'] = None  # to block remember cookie
    LOGIN_MANAGER.init_app(app)
