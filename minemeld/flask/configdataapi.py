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
import sqlite3
import time
from tempfile import NamedTemporaryFile

import yaml
import filelock
import ujson as json

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


class _CDataLocalDB(object):
    def __init__(self, cpath, datafilename):
        self.cpath = cpath
        self.datafilename = datafilename
        self.full_path = os.path.join(self.cpath, self.datafilename)

    def read(self):
        tdir = os.path.dirname(self.full_path)
        if not os.path.samefile(self.cpath, tdir):
            return jsonify(error={'msg': 'Wrong config data filename'}), 400

        result = []

        if not os.path.isfile(self.full_path+'.db'):
            return jsonify(result=[])

        try:
            conn = sqlite3.connect(self.full_path+'.db')

            for row in conn.execute('select * from indicators'):
                indicator = json.loads(row[2])
                indicator['indicator'] = row[0]
                indicator['type'] = row[1]
                indicator['_expiration_ts'] = row[3]
                indicator['_update_ts'] = row[4]
                result.append(indicator)

        finally:
            conn.close()

        return jsonify(result=result)

    def create(self):
        jsonify(error=dict(message='Method not allowed on localdb files')), 400

    def _parse_text_data(self, data):
        result = []
        state = 'INIT'
        indicator = {}
        attribute = None

        for line in iter(data.splitlines()):
            if len(line) > 0 and line[0] == '#':
                continue

            if state == 'INIT':
                line = line.strip()
                if len(line) == 0:
                    continue

                indicator['type'] = line
                state = 'TYPE'
                continue

            if state == 'TYPE':
                line = line.strip()
                if len(line) == 0:
                    continue

                indicator['indicator'] = line
                state = 'INDICATOR'
                continue

            if state == 'INDICATOR':
                line = line.strip()
                if len(line) == 0:
                    result.append(indicator)
                    indicator = {}
                    state = 'INIT'
                    continue

                attribute = line
                state = 'ATTRIBUTE'
                continue

            if state == 'ATTRIBUTE':
                line = line.strip()

                indicator[attribute] = line
                if attribute == 'confidence':
                    if not line.isdigit():
                        LOG.error('Invalid confidence value: {!r}'.format(line))
                        return None
                    indicator[attribute] = int(line)

                elif attribute == 'ttl':
                    if line.isdigit():
                        indicator[attribute] = int(line)
                    else:
                        indicator[attribute] = 'disabled'

                state = 'INDICATOR'
                continue

        if state == 'INDICATOR':
            result.append(indicator)
            state = 'INIT'

        if state != 'INIT':
            LOG.error('Error parsing indicators, state: {}'.format(state))
            return None

        if len(result) == 0:
            return None

        return result

    def append(self):
        tdir = os.path.dirname(self.full_path)
        if not os.path.samefile(self.cpath, tdir):
            return jsonify(error={'msg': 'Wrong config data filename'}), 400

        record = request.get_json()
        if record is None:
            record = self._parse_text_data(request.data)

        if record is None:
            return jsonify(error={
                'message': 'No valid record in request'
            }), 400

        indicators = [record]
        if isinstance(record, list):
            indicators = record

        now = int(time.time()*1000)
        updates = []
        for en, entry in enumerate(indicators):
            indicator = entry.pop('indicator', None)
            if indicator is None:
                return jsonify(error={
                    'message': 'entry %d: indicator field is missing'.format(en)
                })
            type_ = entry.pop('type', None)
            if type_ is None:
                return jsonify(error={
                    'message': 'entry %d: type field is missing'.format(en)
                })

            expiration_ts = entry.pop('ttl', None)
            if expiration_ts is not None:
                if isinstance(expiration_ts, int):
                    expiration_ts = (expiration_ts*1000+now)
                else:
                    expiration_ts = 'disabled'

            updates.append((
                indicator, type_, json.dumps(entry), expiration_ts, now
            ))

        try:
            conn = sqlite3.connect(self.full_path+'.db')

            with conn:
                conn.execute('create table if not exists indicators (indicator text, type text, attributes text, expiration_ts integer, update_ts integer, primary key(indicator, type));')
                conn.executemany('''insert or replace into indicators
                    (indicator, type, attributes, expiration_ts, update_ts)
                    values (?, ?, ?, ?, ?);
                ''', updates)

        finally:
            conn.close()


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
    elif datafiletype == 'localdb':
        return _CDataLocalDB(cpath, datafilename).read()

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
    elif datafiletype == 'localdb':
        result = _CDataLocalDB(cpath, datafilename).create()
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
    elif datafiletype == 'localdb':
        result = _CDataLocalDB(cpath, datafilename).append()
    else:
        return jsonify(error=dict(message='Unknown data file type')), 400

    if result is None:
        hup = request.args.get('h', None)
        if hup is not None:
            MMRpcClient.send_cmd(hup, 'hup', {'source': 'minemeld-web'})

        return jsonify(result='ok'), 200

    return result
