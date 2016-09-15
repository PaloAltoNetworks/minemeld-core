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

import os.path
import os
import yaml
import uuid
import time
import json
import filelock

import minemeld.run.config

from flask import request
from flask import jsonify

import flask.ext.login

from . import app
from . import SR
from . import MMRpcClient

LOG = logging.getLogger(__name__)
FEED_INTERVAL = 100
REDIS_KEY_PREFIX = 'mm:config:'
REDIS_KEY_CONFIG = REDIS_KEY_PREFIX+'candidate'
REDIS_NODES_LIST = 'nodes'
LOCK_TIMEOUT = 3000


class VersionMismatchError(Exception):
    pass


class MMConfigVersion(object):
    def __init__(self, version=None):
        if version is None:
            self.config = str(uuid.uuid4())
            self.counter = 0
            return

        LOG.error('version: %s', version)

        self.config, self.counter = version.split('+', 1)
        self.counter = int(self.counter)

    def __str__(self):
        return '%s+%d' % (self.config, self.counter)

    def __repr__(self):
        return 'MMConfigVersion(%s+%d)' % (self.config, self.counter)

    def __eq__(self, other):
        return self.config == other.config and self.counter == other.counter

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iadd__(self, y):
        self.counter += y
        return self


def _lock(resource):
    resname = resource+':lock'
    value = str(uuid.uuid4())
    result = SR.set(resname, value,
                    nx=True, px=LOCK_TIMEOUT)

    if result is None:
        return None

    return value


def _lock_timeout(resource, timeout=30):
    t1 = time.time()
    tt = t1+timeout

    while t1 < tt:
        result = _lock(resource)
        if result is not None:
            return result

        t1 = time.sleep(0.01)

    return None


def _unlock(resource, value):
    resname = resource+':lock'
    result = SR.get(resname)

    if result == value:
        SR.delete(resname)
        return True

    LOG.error('lost lock %s - %s', value, result)

    return False


def _redlock(f):
    def _redlocked(*args, **kwargs):
        lock = kwargs.pop('lock', False)
        timeout = kwargs.pop('timeout', 30)

        if lock:
            clock = _lock_timeout(REDIS_KEY_CONFIG, timeout=timeout)
            if clock is None:
                raise ValueError('Unable to lock config')
            LOG.info('lock set %s', clock)

        result = f(*args, **kwargs)

        if lock:
            _unlock(REDIS_KEY_CONFIG, clock)
            LOG.info('lock cleared %s', clock)

        return result

    return _redlocked


def _set_stanza(stanza, value, version, config_key=REDIS_KEY_CONFIG):
    version_key = stanza+':version'
    cversion = SR.hget(config_key, version_key)
    if cversion is not None:
        if version != MMConfigVersion(version=cversion):
            raise VersionMismatchError('version mismatch, current version %s' %
                                       cversion)
        version += 1

    SR.hset(config_key, version_key, str(version))
    SR.hset(config_key, stanza, json.dumps(value))

    return version


@_redlock
def _get_stanza(stanza, config_key=REDIS_KEY_CONFIG):
    version_key = stanza+':version'

    version = SR.hget(config_key, version_key)
    if version is None:
        return None

    value = SR.hget(config_key, stanza)
    if value is None:
        return None

    value = json.loads(value)
    value['version'] = version

    return value


def _load_running_config():
    rcpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'running-config.yml'
    )
    return _load_config_from_file(rcpath)


def _load_committed_config():
    rcpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'committed-config.yml'
    )
    return _load_config_from_file(rcpath)


def _load_config_from_file(rcpath):
    with open(rcpath, 'r') as f:
        rcconfig = yaml.safe_load(f)

    version = MMConfigVersion()
    tempconfigkey = REDIS_KEY_PREFIX+str(version)

    SR.hset(tempconfigkey, 'version', version.config)
    SR.hset(tempconfigkey, 'changed', 0)

    if 'fabric' in rcconfig:
        _set_stanza(
            'fabric',
            {'name': 'fabric', 'properties': rcconfig['fabric']},
            config_key=tempconfigkey,
            version=version
        )

    if 'mgmtbus' in rcconfig:
        _set_stanza(
            'mgmtbus',
            {'name': 'mgmtbus', 'properties': rcconfig['mgmtbus']},
            config_key=tempconfigkey,
            version=version
        )

    nodes = rcconfig.get('nodes', {})
    for idx, (nodename, nodevalue) in enumerate(nodes.iteritems()):
        _set_stanza(
            'node%d' % idx,
            {'name': nodename, 'properties': nodevalue},
            config_key=tempconfigkey,
            version=version
        )

    SR.hset(tempconfigkey, 'next_node_id', len(nodes))

    clock = _lock_timeout(REDIS_KEY_CONFIG)
    if clock is None:
        SR.delete(tempconfigkey)
        raise ValueError('Unable to lock config')

    SR.delete(REDIS_KEY_CONFIG)
    SR.rename(tempconfigkey, REDIS_KEY_CONFIG)

    _unlock(REDIS_KEY_CONFIG, clock)

    return version.config


def _commit_config(version):
    ccpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'committed-config.yml'
    )

    clock = _lock_timeout(REDIS_KEY_CONFIG)
    if clock is None:
        raise ValueError('Unable to lock config')

    config_info = _config_info()

    if version != config_info['version']:
        raise VersionMismatchError('Versions mismatch')

    newconfig = {}

    fabric = _get_stanza('fabric')
    if fabric is not None:
        newconfig['fabric'] = json.loads(fabric)['properties']

    mgmtbus = _get_stanza('mgmtbus')
    if mgmtbus is not None:
        newconfig['mgmtbus'] = json.loads(mgmtbus)['properties']

    newconfig['nodes'] = {}
    for n in range(config_info['next_node_id']):
        node = _get_stanza('node%d' % n)
        if node is None:
            continue

        if node['name'] in newconfig:
            raise ValueError('Error in config: duplicate node name - %s' %
                             node['name'])
        if 'properties' not in node:
            raise ValueError('Error in config: no properties for node %s' %
                             node['name'])
        newconfig['nodes'][node['name']] = node['properties']

    _unlock(REDIS_KEY_CONFIG, clock)

    messages = minemeld.run.config.validate_config(newconfig)
    if len(messages) != 0:
        return messages

    with open(ccpath, 'w') as f:
        yaml.safe_dump(
            newconfig,
            f,
            encoding='utf-8',
            default_flow_style=False
        )

    SR.hset(REDIS_KEY_CONFIG, 'changed', 0)

    return 'OK'


@_redlock
def _config_full():
    cinfo = _config_info(lock=False)

    cinfo['nodes'] = []
    nnid = cinfo['next_node_id']
    for n in range(nnid):
        nc = _get_stanza('node%d' % n, lock=False)
        cinfo['nodes'].append(nc)

    return cinfo


@_redlock
def _config_info():
    version = SR.hget(REDIS_KEY_CONFIG, 'version')
    if version is None:
        raise ValueError('candidate config not initialized')

    fabric = SR.hget(REDIS_KEY_CONFIG, 'fabric') is not None
    mgmtbus = SR.hget(REDIS_KEY_CONFIG, 'mgmtbus') is not None
    changed = SR.hget(REDIS_KEY_CONFIG, 'changed') == "1"
    next_node_id = int(SR.hget(REDIS_KEY_CONFIG, 'next_node_id'))

    return {
        'fabric': fabric,
        'mgmtbus': mgmtbus,
        'version': version,
        'next_node_id': next_node_id,
        'changed': changed
    }


@_redlock
def _create_node(nodebody):
    info = _config_info()

    version = nodebody.pop('version', None)
    if version != info['version']:
        raise ValueError('version mismatch')

    cversion = MMConfigVersion(version=info['version']+'+0')

    _set_stanza(
        'node%d' % info['next_node_id'],
        nodebody,
        cversion
    )

    SR.hset(REDIS_KEY_CONFIG, 'changed', 1)
    SR.hset(REDIS_KEY_CONFIG, 'next_node_id', info['next_node_id']+1)

    return {
        'version': str(cversion),
        'id': info['next_node_id']
    }


@_redlock
def _delete_node(nodenum, version):
    node = _get_stanza('node%d' % nodenum)
    if node is None:
        raise ValueError('node %d does not exist' % nodenum)

    if MMConfigVersion(version=version) != MMConfigVersion(node['version']):
        raise VersionMismatchError('version mismatch')

    SR.hdel(REDIS_KEY_CONFIG, 'node%d' % nodenum)
    SR.hdel(REDIS_KEY_CONFIG, 'node%d:version' % nodenum)

    SR.hset(REDIS_KEY_CONFIG, 'changed', 1)

    return 'OK'


@_redlock
def _set_node(nodenum, nodebody):
    if 'version' not in nodebody:
        raise ValueError('version is required')
    version = MMConfigVersion(version=nodebody.pop('version'))

    result = _set_stanza(
        'node%d' % nodenum,
        nodebody,
        version,
    )

    SR.hset(REDIS_KEY_CONFIG, 'changed', 1)

    return str(result)


@app.route('/config/reload', methods=['GET'])
@flask.ext.login.login_required
def reload_running_config():
    cname = request.args.get('c', 'running')

    try:
        if cname == 'running':
            version = _load_running_config()
        elif cname == 'committed':
            version = _load_committed_config()
        else:
            return jsonify(error={'message': 'Unknown config'}), 400

    except Exception as e:
        LOG.exception('Error in loading config')
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=str(version))


@app.route('/config/commit', methods=['POST'])
@flask.ext.login.login_required
def commit():
    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    version = body.get('version', None)
    if body is None:
        return jsonify(error={'message': 'version required'}), 400

    try:
        result = _commit_config(version)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        LOG.exception('exception in commit')
        return jsonify(error={'message': str(e)}), 400

    if result != 'OK':
        return jsonify(error={'message': result}), 402

    return jsonify(result='OK')


@app.route('/config/info', methods=['GET'])
@flask.ext.login.login_required
def get_config_info():
    try:
        result = _config_info(lock=True)
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@app.route('/config/full', methods=['GET'])
@flask.ext.login.login_required
def get_config_full():
    try:
        result = _config_full(lock=True)

    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@app.route('/config/fabric', methods=['GET'])
@flask.ext.login.login_required
def get_fabric():
    try:
        result = _get_stanza('fabric', lock=True)
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    if result is None:
        return jsonify(error={'message': 'Not Found'}), 404

    return jsonify(result=result)


@app.route('/config/mgmtbus', methods=['GET'])
@flask.ext.login.login_required
def get_mgmtbus():
    try:
        result = _get_stanza('mgmtbus', lock=True)
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    if result is None:
        return jsonify(error={'message': 'Not Found'}), 404

    return jsonify(result=result)


@app.route('/config/node', methods=['POST'])
@flask.ext.login.login_required
def create_node():
    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    try:
        result = _create_node(body, lock=True)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@app.route('/config/node/<nodenum>', methods=['GET'])
@flask.ext.login.login_required
def get_node(nodenum):
    try:
        nodenum = int(nodenum)
    except ValueError:
        return jsonify(error='invalid node number'), 400

    try:
        result = _get_stanza('node%d' % nodenum, lock=True)
    except Exception as e:
        LOG.exception('error in get_node')
        return jsonify(error={'message': str(e)}), 500

    if result is None:
        return jsonify(error={'message': 'Not Found'}), 404

    return jsonify(result=result)


@app.route('/config/node/<nodenum>', methods=['PUT'])
@flask.ext.login.login_required
def set_node(nodenum):
    try:
        nodenum = int(nodenum)
    except ValueError:
        return jsonify(error='invalid node number'), 400

    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    try:
        result = _set_node(nodenum, body, lock=True)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        LOG.exception('exception is _set_node')
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@app.route('/config/node/<nodenum>', methods=['DELETE'])
@flask.ext.login.login_required
def delete_node(nodenum):
    try:
        nodenum = int(nodenum)
    except ValueError:
        return jsonify(error='invalid node number'), 400

    version = request.args.get('version', None)
    if version is None:
        return jsonify(error={'message': 'version required'})

    try:
        result = _delete_node(nodenum, version, lock=True)
    except VersionMismatchError:
        return jsonify(error={'message': 'version mismatch'}), 409
    except Exception as e:
        return jsonify(error={'message': str(e)}), 500

    return jsonify(result=result)


@app.route('/config/data/<datafilename>', methods=['GET'])
@flask.ext.login.login_required
def get_config_data(datafilename):
    cpath = os.path.dirname(os.environ.get('MM_CONFIG'))

    fdfname = datafilename+'.yml'

    lockfname = os.path.join(cpath, fdfname+'.lock')
    lock = filelock.FileLock(lockfname)

    os.listdir(cpath)
    if fdfname not in os.listdir(cpath):
        return jsonify(error={
            'message': 'Unknown config data file'
        }), 400

    try:
        with lock.acquire(timeout=10):
            with open(os.path.join(cpath, fdfname), 'r') as f:
                result = yaml.safe_load(f)

    except Exception as e:
        return jsonify(error={
            'message': 'Error loading config data file: %s' % str(e)
        }), 500

    return jsonify(result=result)


@app.route('/config/data/<datafilename>', methods=['PUT'])
@flask.ext.login.login_required
def save_config_data(datafilename):
    cpath = os.path.dirname(os.environ.get('MM_CONFIG'))
    tdir = os.path.dirname(os.path.join(cpath, datafilename))

    if not os.path.samefile(cpath, tdir):
        return jsonify(error={'msg': 'Wrong config data filename'}), 400

    fdfname = os.path.join(cpath, datafilename+'.yml')

    lockfname = fdfname+'.lock'
    lock = filelock.FileLock(lockfname)

    try:
        body = request.get_json()
    except Exception as e:
        return jsonify(error={'message': str(e)}), 400

    try:
        with lock.acquire(timeout=10):
            with open(fdfname, 'w') as f:
                yaml.safe_dump(body, stream=f)
    except Exception as e:
        return jsonify(error={
            'message': str(e)
        }), 500

    hup = request.args.get('h', None)
    if hup is not None:
        MMRpcClient.send_cmd(hup, 'hup', {'source': 'minemeld-web'})

    return jsonify(result='ok'), 200


@app.route('/config/data/<datafilename>/append', methods=['POST'])
@flask.ext.login.login_required
def append_config_data(datafilename):
    cpath = os.path.dirname(os.environ.get('MM_CONFIG'))
    tdir = os.path.dirname(os.path.join(cpath, datafilename))

    if not os.path.samefile(cpath, tdir):
        return jsonify(error={'msg': 'Wrong config data filename'}), 400

    cdfname = os.path.join(cpath, datafilename+'.yml')

    lockfname = cdfname+'.lock'
    lock = filelock.FileLock(lockfname)

    try:
        with lock.acquire(timeout=10):
            if not os.path.isfile(cdfname):
                config_data_file = []
            else:
                with open(cdfname, 'r') as f:
                    config_data_file = yaml.safe_load(f)

            if type(config_data_file) != list:
                raise RuntimeError('Config data file is not a list')

            body = request.get_json()

            config_data_file.append(body)

            with open(cdfname, 'w') as f:
                yaml.safe_dump(config_data_file, stream=f)

    except Exception as e:
        return jsonify(error={
            'message': 'Error append to config data file: %s' % str(e)
        }), 500

    hup = request.args.get('h', None)
    if hup is not None:
        MMRpcClient.send_cmd(hup, 'hup', {'source': 'minemeld-web'})

    return jsonify(result='ok')
