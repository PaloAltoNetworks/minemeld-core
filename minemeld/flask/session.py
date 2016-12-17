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

import os
import logging
from datetime import timedelta
from uuid import uuid4

import ujson
import redis
import werkzeug.datastructures
import flask.sessions

LOG = logging.getLogger(__name__)

SESSION_EXPIRATION_ENV = 'SESSION_EXPIRATION'
DEFAULT_SESSION_EXPIRATION = 10


class RedisSession(werkzeug.datastructures.CallbackDict, flask.sessions.SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        def on_update(self):
            self.modified = True
        werkzeug.datastructures.CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False


class RedisSessionInterface(flask.sessions.SessionInterface):
    serializer = ujson
    session_class = RedisSession

    def __init__(self, redis_=None, prefix='mm-session:'):
        if redis_ is None:
            redis_ = redis.StrictRedis()
        self.redis = redis_
        self.prefix = prefix
        self.expirtaion_delta = timedelta(
            minutes=int(os.environ.get(
                SESSION_EXPIRATION_ENV,
                DEFAULT_SESSION_EXPIRATION
            ))
        )

    def generate_sid(self):
        return str(uuid4())

    def get_redis_expiration_time(self, app, session):
        return timedelta(minutes=10)

    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = self.generate_sid()
            return self.session_class(sid=sid, new=True)

        val = self.redis.get(self.prefix + sid)
        if val is not None:
            data = self.serializer.loads(val)
            return self.session_class(data, sid=sid)

        return self.session_class(sid=sid, new=True)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        if 'user_id' not in session:
            self.redis.delete(self.prefix + session.sid)

            if session.modified:
                response.delete_cookie(
                    app.session_cookie_name,
                    domain=domain
                )
            return

        redis_exp = self.get_redis_expiration_time(app, session)
        cookie_exp = self.get_expiration_time(app, session)
        val = self.serializer.dumps(dict(session))
        self.redis.setex(
            self.prefix + session.sid,
            int(redis_exp.total_seconds()),
            val
        )

        response.set_cookie(
            app.session_cookie_name,
            session.sid,
            expires=cookie_exp,
            httponly=True,
            domain=domain
        )


def init_app(app, redis_url):
    app.session_interface = RedisSessionInterface(
        redis_=redis.StrictRedis.from_url(redis_url)
    )
    app.config.update(
        SESSION_COOKIE_NAME='mm-session',
        SESSION_COOKIE_SECURE=True
    )
