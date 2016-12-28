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

import os
import logging

from flask import Flask

import minemeld.loader


LOG = logging.getLogger(__name__)
REDIS_URL = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')


def create_app():
    app = Flask(__name__)
    app.logger.addHandler(logging.StreamHandler())

    # extension code
    from . import config
    from . import aaa
    from . import session
    from . import mmrpc
    from . import redisclient
    from . import supervisorclient

    session.init_app(app, REDIS_URL)
    aaa.LOGIN_MANAGER.init_app(app)

    config.init()
    if config.get('DEBUG', False):
        app.logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)

    mmrpc.init_app(app)
    redisclient.init_app(app)
    supervisorclient.init_app(app)

    # entrypoints
    from . import metricsapi  # noqa
    from . import feedredis  # noqa
    from . import configapi  # noqa
    from . import taxiidiscovery  # noqa
    from . import taxiicollmgmt  # noqa
    from . import taxiipoll  # noqa
    from . import supervisorapi  # noqa
    from . import loginapi  # noqa
    from . import prototypeapi  # noqa
    from . import validateapi  # noqa
    from . import aaaapi  # noqa
    from . import statusapi  # noqa
    from . import tracedapi  # noqa
    from . import logsapi  # noqa

    configapi.init_app(app)

    app.register_blueprint(metricsapi.BLUEPRINT)
    app.register_blueprint(statusapi.BLUEPRINT)
    app.register_blueprint(feedredis.BLUEPRINT)
    app.register_blueprint(configapi.BLUEPRINT)
    app.register_blueprint(taxiidiscovery.BLUEPRINT)
    app.register_blueprint(taxiicollmgmt.BLUEPRINT)
    app.register_blueprint(taxiipoll.BLUEPRINT)
    app.register_blueprint(supervisorapi.BLUEPRINT)
    app.register_blueprint(loginapi.BLUEPRINT)
    app.register_blueprint(prototypeapi.BLUEPRINT)
    app.register_blueprint(prototypeapi.BLUEPRINT)
    app.register_blueprint(aaaapi.BLUEPRINT)
    app.register_blueprint(tracedapi.BLUEPRINT)
    app.register_blueprint(logsapi.BLUEPRINT)

    # install blueprints from extensions
    for apiname, apimmep in minemeld.loader.map(minemeld.loader.MM_API_ENTRYPOINT).iteritems():
        LOG.info('Loading blueprint from {}'.format(apiname))
        if not apimmep.loadable:
            LOG.info('API entrypoint {} not loadable, ignored'.format(apiname))
            continue

        try:
            bprint = apimmep.ep.load()
            app.register_blueprint(bprint)

        except (ImportError, RuntimeError):
            LOG.exception('Error loading API entry point {}'.format(apiname))

    for r in app.url_map.iter_rules():
        LOG.debug('app rule: {!r}'.format(r))

    return app
