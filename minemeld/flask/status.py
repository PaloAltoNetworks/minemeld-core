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

import psutil
import os
import yaml
import uuid
import time

from flask import Response
from flask import stream_with_context
from flask import jsonify

import flask.ext.login

from . import app
from . import MMMaster
from . import MMStateFanout
from . import SR

# for hup API
from . import MMRpcClient

LOG = logging.getLogger(__name__)


def stream_events():
    sid = MMStateFanout.subscribe()

    try:
        while True:
            yield MMStateFanout.get(sid)

    except GeneratorExit:
        MMStateFanout.unsubscribe(sid)

    except:
        LOG.exception("Exception stream_events")
        MMStateFanout.unsubscribe(sid)


# @app.route('/status/events', methods=['GET'])
# @flask.ext.login.login_required
def get_events():
    r = Response(stream_with_context(stream_events()),
                 mimetype="text/event-stream")
    return r


def _stream_redis_events(subscription, pattern=False):
    pubsub = SR.pubsub(ignore_subscribe_messages=True)

    if pattern:
        pubsub.psubscribe(subscription)
    else:
        pubsub.subscribe(subscription)

    yield 'data: ok\n\n'

    for message in pubsub.listen():
        message = message['data']

        if message == '<EOQ>':
            break

        yield 'data: '+message+'\n\n'

    yield 'data: { "msg": "<EOQ>" }\n\n'

    if pattern:
        pubsub.punsubscribe(subscription)
    else:
        pubsub.unsubscribe(subscription)

    pubsub.close()


@app.route('/status/events/query/<quuid>')
@flask.ext.login.login_required
def get_query_events(quuid):
    try:
        uuid.UUID(quuid)
    except ValueError:
        return jsonify(error={'message': 'Bad query uuid'}), 400

    swc_response = stream_with_context(
        _stream_redis_events('mm-traced-q.'+quuid)
    )
    r = Response(swc_response, mimetype='text/event-stream')

    return r


@app.route('/status/events/status')
@flask.ext.login.login_required
def get_status_events():
    swc_response = stream_with_context(
        _stream_redis_events('mm-engine-status.*', pattern=True)
    )
    r = Response(swc_response, mimetype='text/event-stream')

    return r


@app.route('/status/system', methods=['GET'])
@flask.ext.login.login_required
def get_system_status():
    res = {}
    res['cpu'] = psutil.cpu_percent(interval=1, percpu=True)
    res['memory'] = psutil.virtual_memory().percent
    res['swap'] = psutil.swap_memory().percent
    res['disk'] = psutil.disk_usage('/').percent

    return jsonify(result=res, timestamp=int(time.time()*1000))


@app.route('/status/minemeld', methods=['GET'])
@flask.ext.login.login_required
def get_minemeld_status():
    status = MMMaster.status()

    tr = status.get('result', None)
    if tr is None:
        return jsonify(error={'message': status.get('error', 'error')})

    result = []
    for f, v in tr.iteritems():
        LOG.debug(f)
        _, _, v['name'] = f.split(':', 2)
        result.append(v)

    return jsonify(result=result)


@app.route('/status/config', methods=['GET'])
@flask.ext.login.login_required
def get_minemeld_running_config():
    rcpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'running-config.yml'
    )
    with open(rcpath, 'r') as f:
        rcconfig = yaml.safe_load(f)

    return jsonify(result=rcconfig)


# this should be moved to a different endpoint
@app.route('/status/<nodename>/hup')
@flask.ext.login.login_required
def hup_node(nodename):
    status = MMMaster.status()
    tr = status.get('result', None)
    if tr is None:
        return jsonify(error={'message': status.get('error', 'error')})

    nname = 'mbus:slave:'+nodename
    if nname not in tr:
        return jsonify(error={'message': 'Unknown node'}), 404

    MMRpcClient.send_cmd(nodename, 'hup', {'source': 'minemeld-web'})

    return jsonify(result='ok'), 200
