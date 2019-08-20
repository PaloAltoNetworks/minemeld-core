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

import yaml
from flask import Flask

import minemeld.loader
from minemeld.flask import config
from minemeld.utils import get_config_value, initialize_default_nodes_distribution
from .logger import LOG


def create_app():
    yaml.SafeLoader.add_constructor(
        u'tag:yaml.org,2002:timestamp',
        yaml.SafeLoader.construct_yaml_str
    )

    app = Flask(__name__)

    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # max 5MB for uploads

    LOG.init_app(app)

    from . import config
    config.init()
    initialize_default_nodes_distribution(config)

    # extension code
    from . import aaa
    from . import session
    from . import mmrpc
    from . import redisclient
    from . import supervisorclient
    from . import jobs
    from . import sns
    from . import events

    redis_url = get_config_value(config, 'MGMTBUS.config.redis_url', 'unix:///var/run/redis/redis.sock')

    session.init_app(app, redis_url)
    aaa.init_app(app)

    if config.get('DEBUG', False):
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    mmrpc.init_app(app)
    redisclient.init_app(app)
    supervisorclient.init_app(app)
    jobs.init_app(app)
    sns.init_app()
    events.init_app(app, redis_url)

    # entrypoints
    from . import metricsapi  # noqa
    from . import feedredis  # noqa
    from . import configapi  # noqa
    from . import configdataapi  # noqa
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
    from . import extensionsapi  # noqa
    from . import jobsapi  # noqa

    configapi.init_app(app)
    extensionsapi.init_app(app)

    app.register_blueprint(metricsapi.BLUEPRINT)
    app.register_blueprint(statusapi.BLUEPRINT)
    app.register_blueprint(feedredis.BLUEPRINT)
    app.register_blueprint(configapi.BLUEPRINT)
    app.register_blueprint(configdataapi.BLUEPRINT)
    app.register_blueprint(taxiidiscovery.BLUEPRINT)
    app.register_blueprint(taxiicollmgmt.BLUEPRINT)
    app.register_blueprint(taxiipoll.BLUEPRINT)
    app.register_blueprint(supervisorapi.BLUEPRINT)
    app.register_blueprint(loginapi.BLUEPRINT)
    app.register_blueprint(prototypeapi.BLUEPRINT)
    app.register_blueprint(validateapi.BLUEPRINT)
    app.register_blueprint(aaaapi.BLUEPRINT)
    app.register_blueprint(tracedapi.BLUEPRINT)
    app.register_blueprint(logsapi.BLUEPRINT)
    app.register_blueprint(extensionsapi.BLUEPRINT)
    app.register_blueprint(jobsapi.BLUEPRINT)

    # install blueprints from extensions
    for apiname, apimmep in minemeld.loader.map(minemeld.loader.MM_API_ENTRYPOINT).iteritems():
        LOG.info('Loading blueprint from {}'.format(apiname))
        if not apimmep.loadable:
            LOG.info('API entrypoint {} not loadable, ignored'.format(apiname))
            continue

        try:
            bprint = apimmep.ep.load()
            app.register_blueprint(bprint())

        except (ImportError, RuntimeError):
            LOG.exception('Error loading API entry point {}'.format(apiname))

    # install webui blueprints from extensions
    for webuiname, webuimmep in minemeld.loader.map(minemeld.loader.MM_WEBUI_ENTRYPOINT).iteritems():
        LOG.info('Loading blueprint from {}'.format(webuiname))
        if not webuimmep.loadable:
            LOG.info('API entrypoint {} not loadable, ignored'.format(webuiname))
            continue

        try:
            bprint = webuimmep.ep.load()
            app.register_blueprint(
                bprint(),
                url_prefix='/extensions/webui/{}'.format(webuiname)
            )

        except (ImportError, RuntimeError):
            LOG.exception('Error loading WebUI entry point {}'.format(webuiname))

    for r in app.url_map.iter_rules():
        LOG.debug('app rule: {!r}'.format(r))

    return app
