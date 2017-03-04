#  Copyright 2015-present Palo Alto Networks, Inc
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

import os.path
import os
import shutil

from tempfile import NamedTemporaryFile

import yaml
import filelock

from flask import request, jsonify

from .mmrpc import MMRpcClient
from .aaa import MMBlueprint
from .logger import LOG


__all__ = ['BLUEPRINT']


LOCK_TIMEOUT = 3000


BLUEPRINT = MMBlueprint('configdata', __name__, url_prefix='/config/data')


def _safe_remove(path, g=None):
    try:
        os.remove(path)
    except:
        LOG.exception('Exception removing {}'.format(path))


class _CDataYaml(object):
    def __init__(self, cpath, datafilename):
        self.cpath = cpath
        self.datafilename = datafilename

    def read(self):
        fdfname = self.datafilename+'.yml'

        lockfname = os.path.join(self.cpath, fdfname+'.lock')
        lock = filelock.FileLock(lockfname)

        os.listdir(self.cpath)
        if fdfname not in os.listdir(self.cpath):
            return jsonify(error={
                'message': 'Unknown config data file'
            }), 400

        try:
            with lock.acquire(timeout=10):
                with open(os.path.join(self.cpath, fdfname), 'r') as f:
                    result = yaml.safe_load(f)

        except Exception as e:
            return jsonify(error={
                'message': 'Error loading config data file: %s' % str(e)
            }), 500

        return jsonify(result=result)

    def create(self):
        tdir = os.path.dirname(os.path.join(self.cpath, self.datafilename))

        if not os.path.samefile(self.cpath, tdir):
            return jsonify(error={'msg': 'Wrong config data filename'}), 400

        fdfname = os.path.join(self.cpath, self.datafilename+'.yml')

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

    def append(self):
        tdir = os.path.dirname(os.path.join(self.cpath, self.datafilename))

        if not os.path.samefile(self.cpath, tdir):
            return jsonify(error={'msg': 'Wrong config data filename'}), 400

        cdfname = os.path.join(self.cpath, self.datafilename+'.yml')

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
                if body is None:
                    return jsonify(error={
                        'message': 'No record in request'
                    }), 400

                config_data_file.append(body)

                with open(cdfname, 'w') as f:
                    yaml.safe_dump(config_data_file, stream=f)

        except Exception as e:
            return jsonify(error={
                'message': 'Error appending to config data file: %s' % str(e)
            }), 500


class _CDataUploadOnly(object):
    def __init__(self, extension, cpath, datafilename):
        self.extension = extension
        self.cpath = cpath
        self.datafilename = datafilename

    def read(self):
        fdfname = '{}.{}'.format(self.datafilename, self.extension)

        os.listdir(self.cpath)
        if fdfname not in os.listdir(self.cpath):
            return jsonify(error={
                'message': 'Unknown config data file'
            }), 400

        return jsonify(result='ok')

    def create(self):
        tdir = os.path.dirname(os.path.join(self.cpath, self.datafilename))

        if not os.path.samefile(self.cpath, tdir):
            return jsonify(error={'msg': 'Wrong config data filename'}), 400

        fdfname = os.path.join(self.cpath, '{}.{}'.format(self.datafilename, self.extension))

        if 'file' not in request.files:
            return jsonify(error={'messsage': 'No file'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify(error={'message': 'No file'}), 400

        tf = NamedTemporaryFile(prefix='mm-extension-upload', delete=False)
        try:
            file.save(tf)
            tf.close()

            shutil.move(tf.name, fdfname)

        finally:
            _safe_remove(tf.name)


class _CDataCertificate(_CDataUploadOnly):
    def __init__(self, cpath, datafilename):
        super(_CDataCertificate, self).__init__(
            extension='crt',
            cpath=cpath,
            datafilename=datafilename
        )


class _CDataPrivateKey(_CDataUploadOnly):
    def __init__(self, cpath, datafilename):
        super(_CDataPrivateKey, self).__init__(
            extension='pem',
            cpath=cpath,
            datafilename=datafilename
        )


# API for working with side configs and dynamic data files
@BLUEPRINT.route('/<datafilename>', methods=['GET'], read_write=False)
def get_config_data(datafilename):
    cpath = os.path.dirname(os.environ.get('MM_CONFIG'))

    datafiletype = request.values.get('t', 'yaml')

    if datafiletype == 'yaml':
        return _CDataYaml(cpath, datafilename).read()
    elif datafiletype == 'cert':
        return _CDataCertificate(cpath, datafilename).read()
    elif datafiletype == 'pkey':
        return _CDataPrivateKey(cpath, datafilename).read()

    return jsonify(error=dict(message='Unknown data file type')), 400


@BLUEPRINT.route('/<datafilename>', methods=['PUT'], read_write=True)
def save_config_data(datafilename):
    cpath = os.path.dirname(os.environ.get('MM_CONFIG'))

    datafiletype = request.values.get('t', 'yaml')

    if datafiletype == 'yaml':
        result = _CDataYaml(cpath, datafilename).create()
    elif datafiletype == 'cert':
        result = _CDataCertificate(cpath, datafilename).create()
    elif datafiletype == 'pkey':
        result = _CDataPrivateKey(cpath, datafilename).create()
    else:
        return jsonify(error=dict(message='Unknown data file type')), 400

    if result is None:
        hup = request.args.get('h', None)
        if hup is not None:
            MMRpcClient.send_cmd(hup, 'hup', {'source': 'minemeld-web'})

        return jsonify(result='ok'), 200

    return result


@BLUEPRINT.route('/<datafilename>/append', methods=['POST'], read_write=True)
def append_config_data(datafilename):
    cpath = os.path.dirname(os.environ.get('MM_CONFIG'))

    cpath = os.path.dirname(os.environ.get('MM_CONFIG'))

    datafiletype = request.values.get('t', 'yaml')

    if datafiletype == 'yaml':
        result = _CDataYaml(cpath, datafilename).append()
    else:
        return jsonify(error=dict(message='Unknown data file type')), 400

    if result is None:
        hup = request.args.get('h', None)
        if hup is not None:
            MMRpcClient.send_cmd(hup, 'hup', {'source': 'minemeld-web'})

        return jsonify(result='ok'), 200

    return result
