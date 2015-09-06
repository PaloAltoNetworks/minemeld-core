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

LOGIN_MANAGER = flask.ext.login.LoginManager()
LOGIN_MANAGER.session_protection = None


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


@LOGIN_MANAGER.request_loader
def request_loader(request):
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
