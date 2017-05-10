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
import os.path
import uuid
import functools
import time
from zipfile import ZipFile
from tempfile import NamedTemporaryFile

import gevent
import psutil
import yaml
from flask import Response, stream_with_context, jsonify, request, send_file

from . import config
from .mmrpc import MMMaster
from .mmrpc import MMStateFanout
from .mmrpc import MMRpcClient
from .redisclient import SR
from .aaa import MMBlueprint
from .logger import LOG
from .jobs import JOBS_MANAGER


__all__ = ['BLUEPRINT']


BLUEPRINT = MMBlueprint('status', __name__, url_prefix='/status')


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


@BLUEPRINT.route('/events/query/<quuid>', read_write=False)
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


@BLUEPRINT.route('/events/status', read_write=False)
def get_status_events():
    swc_response = stream_with_context(
        _PubSubWrapper('mm-engine-status.*', pattern=True)
    )
    r = Response(swc_response, mimetype='text/event-stream')

    return r


@BLUEPRINT.route('/system', methods=['GET'], read_write=False)
def get_system_status():
    data_path = config.get('MINEMELD_LOCAL_PATH', None)
    if data_path is None:
        jsonify(error={'message': 'MINEMELD_LOCAL_PATH not set'}), 500

    res = {}
    res['cpu'] = psutil.cpu_percent(interval=1, percpu=True)
    res['memory'] = psutil.virtual_memory().percent
    res['swap'] = psutil.swap_memory().percent
    res['disk'] = psutil.disk_usage(data_path).percent

    return jsonify(result=res, timestamp=int(time.time()*1000))


@BLUEPRINT.route('/minemeld', methods=['GET'], read_write=False)
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


@BLUEPRINT.route('/config', methods=['GET'], read_write=False)
def get_minemeld_running_config():
    rcpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'running-config.yml'
    )
    with open(rcpath, 'r') as f:
        rcconfig = yaml.safe_load(f)

    return jsonify(result=rcconfig)


# XXX this should be moved to a different endpoint
@BLUEPRINT.route('/<nodename>/hup', methods=['GET', 'POST'], read_write=False)
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
@BLUEPRINT.route('/<nodename>/signal/<signalname>', methods=['GET', 'POST'], read_write=False)
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


def _clean_local_backup(local_backup_file, g):
    def _safe_remove(path):
        LOG.info('Removing backup {}'.format(local_backup_file))
        try:
            os.remove(path)
        except:
            pass

    if g.value != 0:
        _safe_remove(local_backup_file)
        return

    LOG.info('Removing backup {} in 300s'.format(local_backup_file))
    gevent.spawn_later(300, _safe_remove, local_backup_file)


# XXX this should be moved to a different endpoint
@BLUEPRINT.route('/backup', methods=['POST'], read_write=True)
def generate_local_backup():
    params = request.get_json(silent=True)
    if params is None:
        return jsonify(error={'message': 'missing request body'}), 400

    password = params.get('p', None)
    if password is None:
        return jsonify(error={'message': 'missing p paramater in request body'}), 400

    sevenz_path = config.get('MINEMELD_7Z_PATH', None)
    if sevenz_path is None:
        return jsonify(error={'message': 'MINEMELD_7Z_PATH not set'}), 500

    # create temp zip file
    tf = NamedTemporaryFile(prefix='mm-local-backup', suffix='.zip', delete=False)
    tf.close()
    # initialize the zip structure inside the file
    ZipFile(tf.name, 'w').close()

    # build args
    args = [sevenz_path, 'a', '-p{}'.format(password), '-y', tf.name]

    library_path = config.get('MINEMELD_LOCAL_LIBRARY_PATH', None)
    if library_path is not None:
        args.append(library_path)
    proto_path = config.get('MINEMELD_LOCAL_PROTOTYPE_PATH', None)
    if proto_path is not None:
        args.append(proto_path)
    certs_path = config.get('MINEMELD_LOCAL_CERTS_PATH', None)
    if certs_path is not None:
        args.append(certs_path)
    config_path = os.path.dirname(os.environ.get('MM_CONFIG'))
    args.append(config_path)

    jobs = JOBS_MANAGER.get_jobs(job_group='status-backup')
    for jobid, jobdata in jobs.iteritems():
        if jobdata == 'RUNNING':
            return jsonify(error={'message': 'a backup job is already running'}), 400

    jobid = JOBS_MANAGER.exec_job(
        job_group='status-backup',
        description='local backup',
        args=args,
        data={
            'result-file': tf.name
        },
        callback=functools.partial(_clean_local_backup, tf.name)
    )

    return jsonify(result=jobid)


# XXX this should be moved to a different endpoint
@BLUEPRINT.route('/backup/<jobid>', methods=['GET'], read_write=True)
def get_local_backup(jobid):
    jobs = JOBS_MANAGER.get_jobs(job_group='status-backup')

    if jobid not in jobs:
        return jsonify(error={'message': 'unknown job'}), 404

    return send_file(jobs[jobid]['result-file'])
