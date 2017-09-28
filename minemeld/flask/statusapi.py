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
from tempfile import NamedTemporaryFile, gettempdir

import gevent
import psutil
import yaml
from flask import Response, stream_with_context, jsonify, request, send_file

from . import config
from .mmrpc import MMMaster
from .mmrpc import MMStateFanout
from .mmrpc import MMRpcClient
from .redisclient import SR
from .aaa import MMBlueprint, enable_prevent_write, disable_prevent_write
from .logger import LOG
from .jobs import JOBS_MANAGER
from .utils import safe_remove, committed_config_path
from .sns import SNS_OBJ, SNS_AVAILABLE

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

            yield 'data: ' + message + '\n\n'

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
        _PubSubWrapper('mm-traced-q.' + quuid)
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
    res['sns'] = SNS_AVAILABLE

    return jsonify(result=res, timestamp=int(time.time() * 1000))


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

    nname = 'mbus:slave:' + nodename
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

    nname = 'mbus:slave:' + nodename
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


@BLUEPRINT.route('/backup/import', methods=['POST'], read_write=True)
def import_local_backup():
    if 'file' not in request.files:
        return jsonify(error={'messsage': 'No file in request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify(error={'message': 'No file'}), 400

    tf = NamedTemporaryFile(prefix='mm-import-backup', delete=False)
    try:
        file.save(tf)
        tf.close()

        with ZipFile(tf.name, 'r') as zf:
            contents = zf.namelist()

    except Exception, e:
        safe_remove(tf.name)
        raise e

    ibid = os.path.basename(tf.name)[16:]
    result = {
        'id': ibid,
        'configuration': 'config/committed-config.yml' in contents,
        'localPrototypes': 'prototypes/minemeldlocal.yml' in contents,
        'feedsAAA': True,
        'localCertificates': False
    }

    # check for feeds AAA files
    testfile = os.path.join(
        'config/api',
        config.APIConfigDict(attribute='FEEDS_USERS_ATTRS', level=50).filename
    )
    result['feedsAAA'] &= testfile in contents

    testfile = os.path.join(
        'config/api',
        config.APIConfigDict(attribute='FEEDS_ATTRS', level=50).filename
    )
    result['feedsAAA'] &= testfile in contents

    testfile = os.path.join(
        'config/api',
        'feeds.htpasswd'
    )
    result['feedsAAA'] &= testfile in contents

    # check for local certificates, there should be at least one
    # to flag certs as available
    for fname in contents:
        if fname.startswith('certs/site/') and not fname.endswith('/'):
            result['localCertificates'] = True
            break

    if not (result['configuration'] or result['localPrototypes'] or result['feedsAAA']):
        safe_remove(tf.name)
        return jsonify(error={'message': 'Invalid MineMeld backup'}), 400

    return jsonify(result=result)


def _cleanup_after_restore(backup_file, locker, g):
    disable_prevent_write(locker)
    safe_remove(backup_file)


@BLUEPRINT.route('/backup/import/<backup_id>/restore', methods=['POST'], read_write=True)
def restore_local_backup(backup_id):
    restore_path = config.get('MINEMELD_RESTORE_PATH', None)
    if restore_path is None:
        return jsonify(error={'message': 'MINEMELD_RESTORE_PATH not set'}), 500

    params = request.get_json(silent=True)
    if params is None:
        return jsonify(error={'message': 'missing request body'}), 400

    password = params.get('p', None)
    restore_configuration = params.get('configuration', False)
    restore_prototypes = params.get('localPrototypes', False)
    restore_feeds_aaa = params.get('feedsAAA', False)
    restore_certificates = params.get('localCertificates', False)

    if not (restore_configuration or restore_prototypes or restore_feeds_aaa):
        return jsonify(error={'message': 'Nothing to do'}), 400

    backup_file = os.path.join(gettempdir(), 'mm-import-backup{}'.format(backup_id))
    if not os.path.samefile(os.path.dirname(backup_file), gettempdir()):
        return jsonify(error={'message': 'Invalid backup id'}), 400
    if not os.path.exists(backup_file):
        return jsonify(error={'message': 'Invalid backup id'}), 404

    locker = 'restore-backup-{}-{}'.format(backup_id, int(time.time()))
    enable_prevent_write(locker)
    try:
        jobs = JOBS_MANAGER.get_jobs(job_group='status-backup')
        for jobid, jobdata in jobs.iteritems():
            if jobdata == 'RUNNING':
                disable_prevent_write(locker)
                return jsonify(error={'message': 'a backup job is running'}), 400

        jobs = JOBS_MANAGER.get_jobs(job_group='restore-backup')
        for jobid, jobdata in jobs.iteritems():
            if jobdata == 'RUNNING':
                disable_prevent_write(locker)
                return jsonify(error={'message': 'a restore job is running'}), 400

        args = [restore_path]
        if restore_configuration:
            p = os.path.dirname(committed_config_path())
            args.extend(['--configuration-path', p])

        if restore_prototypes:
            p = config.get('MINEMELD_LOCAL_PROTOTYPE_PATH', None)
            if p is None:
                return jsonify(error={'message': 'MINEMELD_LOCAL_PROTOTYPE_PATH not set'}), 500

            args.extend(['--prototypes-path', p])

        if restore_feeds_aaa:
            args.extend([
                '--feeds-aaa-path',
                os.path.join(os.path.dirname(committed_config_path()), 'api')
            ])
            args.extend([
                '--feeds-aaa',
                'feeds.htpasswd'
            ])
            args.extend([
                '--feeds-aaa',
                config.APIConfigDict(attribute='FEEDS_ATTRS', level=50).filename
            ])
            args.extend([
                '--feeds-aaa',
                config.APIConfigDict(attribute='FEEDS_USERS_ATTRS', level=50).filename
            ])

        if restore_certificates:
            p = config.get('MINEMELD_LOCAL_CERTS_PATH', None)
            if p is None:
                LOG.error('MINEMELD_LOCAL_CERTS_PATH not set, local certificates not restored')

            else:
                args.extend([
                    '--certificates-path',
                    p
                ])

        if password is not None:
            args.extend(['--password', password])

        args.append(backup_file)

        jobid = JOBS_MANAGER.exec_job(
            job_group='restore-backup',
            description='restore backup',
            args=args,
            callback=functools.partial(_cleanup_after_restore, backup_file, locker),
            timeout=200
        )

    except:
        disable_prevent_write(locker)
        raise

    return jsonify(result=jobid)


@BLUEPRINT.route('/mkwish', methods=['POST'], read_write=False)
def sns_wish():
    request.get_data()
    message = request.data
    success = SNS_OBJ.make_wish(message)
    if success:
        return jsonify(result='ok')
    return jsonify(error={'messsage': 'Error sending the message'}), 400
