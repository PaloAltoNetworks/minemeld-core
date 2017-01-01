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

from flask import Response, stream_with_context, jsonify, Blueprint, request
from flask.ext.login import login_required

from .mmrpc import MMMaster
from .mmrpc import MMStateFanout
from .mmrpc import MMRpcClient
from .redisclient import SR


__all__ = ['BLUEPRINT']


LOG = logging.getLogger(__name__)


BLUEPRINT = Blueprint('status', __name__, url_prefix='/status')


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


class _PubSubWrapper(object):
    def __init__(self, subscription, pattern=False):
        self.subscription = subscription
        self.pattern = pattern

        self.pubsub = SR.pubsub(ignore_subscribe_messages=True)
        if pattern:
            self.pubsub.psubscribe(subscription)
        else:
            self.pubsub.subscribe(subscription)

        self.generator = self._msg_generator()

    def _listen(self):
        while self.pubsub.subscribed:
            response = self.pubsub.get_message(timeout=5.0)
            yield response

    def _msg_generator(self):
        yield 'data: ok\n\n'

        for message in self._listen():
            if message is None:
                yield 'data: ping\n\n'
                continue

            message = message['data']

            if message == '<EOQ>':
                break

            yield 'data: '+message+'\n\n'

        yield 'data: { "msg": "<EOQ>" }\n\n'

    def __iter__(self):
        return self

    def next(self):
        return next(self.generator)

    def close(self):
        if self.pattern:
            self.pubsub.punsubscribe(self.subscription)
        else:
            self.pubsub.unsubscribe(self.subscription)

        self.pubsub.close()
        self.pubsub = None


@BLUEPRINT.route('/events/query/<quuid>')
@login_required
def get_query_events(quuid):
    try:
        uuid.UUID(quuid)
    except ValueError:
        return jsonify(error={'message': 'Bad query uuid'}), 400

    swc_response = stream_with_context(
        _PubSubWrapper('mm-traced-q.'+quuid)
    )
    r = Response(swc_response, mimetype='text/event-stream')

    return r


@BLUEPRINT.route('/events/status')
@login_required
def get_status_events():
    swc_response = stream_with_context(
        _PubSubWrapper('mm-engine-status.*', pattern=True)
    )
    r = Response(swc_response, mimetype='text/event-stream')

    return r


@BLUEPRINT.route('/system', methods=['GET'])
@login_required
def get_system_status():
    res = {}
    res['cpu'] = psutil.cpu_percent(interval=1, percpu=True)
    res['memory'] = psutil.virtual_memory().percent
    res['swap'] = psutil.swap_memory().percent
    res['disk'] = psutil.disk_usage('/').percent

    return jsonify(result=res, timestamp=int(time.time()*1000))


@BLUEPRINT.route('/minemeld', methods=['GET'])
@login_required
def get_minemeld_status():
    status = MMMaster.status()

    tr = status.get('result', None)
    if tr is None:
        return jsonify(error={'message': status.get('error', 'error')})

    result = []
    for f, v in tr.iteritems():
        _, _, v['name'] = f.split(':', 2)
        result.append(v)

    return jsonify(result=result)


@BLUEPRINT.route('/config', methods=['GET'])
@login_required
def get_minemeld_running_config():
    rcpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'running-config.yml'
    )
    with open(rcpath, 'r') as f:
        rcconfig = yaml.safe_load(f)

    return jsonify(result=rcconfig)


# XXX this should be moved to a different endpoint
@BLUEPRINT.route('/<nodename>/hup', methods=['GET', 'POST'])
@login_required
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


# XXX this should be moved to a different endpoint
@BLUEPRINT.route('/<nodename>/signal/<signalname>', methods=['GET', 'POST'])
@login_required
def signal_node(nodename, signalname):
    status = MMMaster.status()
    tr = status.get('result', None)
    if tr is None:
        return jsonify(error={'message': status.get('error', 'error')})

    nname = 'mbus:slave:'+nodename
    if nname not in tr:
        return jsonify(error={'message': 'Unknown node'}), 404

    params = request.get_json(silent=True)
    if params is None:
        params = {}

    params.update({
        'source': 'minemeld-web',
        'signal': signalname
    })

    MMRpcClient.send_cmd(
        target=nodename,
        method='signal',
        params=params
    )

    return jsonify(result='ok'), 200
