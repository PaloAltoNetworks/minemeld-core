#  Copyright 2015-2017 Palo Alto Networks, Inc
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

import sys
import os
import os.path
import shutil
import functools
import subprocess
import uuid
import stat
from tempfile import NamedTemporaryFile

import filelock
from gevent import Timeout
from gevent.subprocess import Popen
from flask import jsonify, request
from werkzeug.utils import secure_filename

import minemeld.extensions
import minemeld.loader

from . import config
from .jobs import JOBS_MANAGER
from .prototypeapi import reset_prototype_paths
from .aaa import MMBlueprint
from .logger import LOG


__all__ = ['BLUEPRINT']


BLUEPRINT = MMBlueprint('extensions', __name__, url_prefix='')

DISABLE_NEW_EXTENSIONS = config.get('DISABLE_NEW_EXTENSIONS', False)


def _get_extensions():
    library_directory = config.get('MINEMELD_LOCAL_LIBRARY_PATH', None)
    if library_directory is None:
        raise RuntimeError('MINEMELD_LOCAL_LIBRARY_PATH not set')

    return minemeld.extensions.extensions(library_directory)


def _build_activate_args(ext_path):
    pip_path = config.get('MINEMELD_PIP_PATH', None)
    if pip_path is None:
        raise RuntimeError('MINEMELD_PIP_PATH not set')

    library_directory = config.get('MINEMELD_LOCAL_LIBRARY_PATH', None)
    if library_directory is None:
        raise RuntimeError('MINEMELD_LOCAL_LIBRARY_PATH not set')

    constraints_file = os.path.join(library_directory, 'constraints.txt')

    args = [
        pip_path,
        'install',
        '-c', constraints_file
    ]
    if ext_path.endswith('.whl'):
        args.append(ext_path)
    else:
        args.append('-e')
        args.append(ext_path)

    return args


def _build_deactivate_args(extension_name):
    pip_path = config.get('MINEMELD_PIP_PATH', None)
    if pip_path is None:
        raise RuntimeError('MINEMELD_PIP_PATH not set')

    args = [
        pip_path,
        'uninstall', '-y',
        extension_name
    ]

    return args


def _find_running_job(extension, jobs):
    for jobid, job in jobs.iteritems():
        if job['status'] != 'RUNNING':
            continue

        if job['name'] == extension.name:
            return jobid

    return None


def _update_freeze_file():
    library_directory = config.get('MINEMELD_LOCAL_LIBRARY_PATH', None)
    if library_directory is None:
        LOG.error('freeze not updated - MINEMELD_LOCAL_LIBRARY_PATH not set')
        return

    freeze_path = os.path.join(library_directory, 'freeze.txt')

    freeze_lock = filelock.FileLock('{}.lock'.format(freeze_path))
    with freeze_lock.acquire(timeout=30):
        with open(freeze_path, 'w+') as ff:
            frozen = minemeld.extensions.freeze(library_directory)
            for frozen_ext in frozen:
                ff.write('{}\n'.format(frozen_ext))


def _extensions_changed(activated_path, deactivated_path, g):
    if g is not None and g.value == 0:
        # process was successful
        if deactivated_path is not None:
            try:
                sys.path.remove(deactivated_path)
            except ValueError:
                LOG.error('extensions_changed: Error removing {}'.format(deactivated_path))

        if activated_path is not None:
            if activated_path not in sys.path:
                sys.path.append(activated_path)

    minemeld.loader.bump_workingset()
    reset_prototype_paths()
    _update_freeze_file()


def _safe_remove(path, g=None):
    try:
        os.remove(path)
    except:
        LOG.exception('Exception removing {}'.format(path))


@BLUEPRINT.route('/extensions', methods=['GET'], read_write=False)
def list_extensions():
    extensions = _get_extensions()

    jobs = JOBS_MANAGER.get_jobs('extensions')

    result = []
    for e in extensions:
        edict = e._asdict()
        rjobid = _find_running_job(e, jobs)
        if rjobid is not None:
            edict['running_job'] = rjobid

        result.append(edict)

    return jsonify(result=result)


@BLUEPRINT.route('/extensions/<extension>/activate', methods=['POST'], read_write=True)
def activate_extension(extension):
    if DISABLE_NEW_EXTENSIONS:
        return 'Disabled', 403

    params = request.get_json(silent=True)
    if params is None:
        return jsonify(error={'message': 'no params'}), 400

    ext_path = params.get('path', None)
    if ext_path is None:
        return jsonify(error={'message': 'path not specified'}), 400

    ext_version = params.get('version', None)
    if ext_version is None:
        return jsonify(error={'message': 'version not specified'}), 400

    extensions = _get_extensions()

    for e in extensions:
        if e.name != extension:
            continue

        if e.version != ext_version:
            continue

        if e.path == ext_path:
            break
    else:
        return jsonify(error={'message': 'extension not found'}), 400

    if not e.installed:
        return jsonify(error={'message': 'extension not installed'}), 400

    if e.activated:
        return jsonify(error={'messsage': 'extension already activated'}), 400

    jobs = JOBS_MANAGER.get_jobs('extensions')
    if _find_running_job(e, jobs) is not None:
        return jsonify(error={'message': 'pending job'}), 400

    jobid = JOBS_MANAGER.exec_job(
        job_group='extensions',
        description='activate {} v{}'.format(e.name, e.version),
        args=_build_activate_args(e.path),
        data={
            'name': extension,
            'version': ext_version,
            'path': ext_path
        },
        callback=functools.partial(_extensions_changed, e.path, None)
    )

    return jsonify(result=jobid)


@BLUEPRINT.route('/extensions/<extension>/deactivate', methods=['GET', 'POST'], read_write=True)
def deactivate_extension(extension):
    if DISABLE_NEW_EXTENSIONS:
        return 'Disabled', 403

    params = request.get_json(silent=True)
    if params is None:
        return jsonify(error={'message': 'no params'}), 400

    ext_path = params.get('path', None)
    if ext_path is None:
        return jsonify(error={'message': 'path not specified'}), 400

    ext_version = params.get('version', None)
    if ext_version is None:
        return jsonify(error={'message': 'version not specified'}), 400

    extensions = _get_extensions()

    for e in extensions:
        if e.name != extension:
            continue

        if e.version != ext_version:
            continue

        if e.path == ext_path:
            break
    else:
        return jsonify(error={'message': 'extension not found'}), 400

    if not e.installed:
        return jsonify(error={'message': 'extension not installed'}), 400

    if not e.activated:
        return jsonify(error={'messsage': 'extension not activated'}), 400

    jobs = JOBS_MANAGER.get_jobs('extensions')
    if _find_running_job(e, jobs) is not None:
        return jsonify(error={'message': 'pending job'}), 400

    jobid = JOBS_MANAGER.exec_job(
        job_group='extensions',
        description='deactivate {} v{}'.format(e.name, e.version),
        args=_build_deactivate_args(extension),
        data={
            'name': extension,
            'version': ext_version,
            'path': ext_path
        },
        callback=functools.partial(_extensions_changed, None, e.path)
    )

    return jsonify(result=jobid)


@BLUEPRINT.route('/extensions/<extension>/uninstall', methods=['GET', 'POST'], read_write=True)
def uninstall_extension(extension):
    if DISABLE_NEW_EXTENSIONS:
        return 'Disabled', 403

    params = request.get_json(silent=True)
    if params is None:
        return jsonify(error={'message': 'no params'}), 400

    ext_path = params.get('path', None)
    if ext_path is None:
        return jsonify(error={'message': 'path not specified'}), 400

    ext_version = params.get('version', None)
    if ext_version is None:
        return jsonify(error={'message': 'version not specified'}), 400

    extensions = _get_extensions()

    for e in extensions:
        if e.name != extension:
            continue

        if e.version != ext_version:
            continue

        if e.path == ext_path:
            break
    else:
        return jsonify(error={'message': 'extension not found'}), 400

    if not e.installed:
        return jsonify(error={'message': 'extension not installed'}), 400

    if e.activated:
        return jsonify(error={'messsage': 'extension activated'}), 400

    jobs = JOBS_MANAGER.get_jobs('extensions')
    if _find_running_job(e, jobs) is not None:
        return jsonify(error={'message': 'pending job'}), 400

    if e.path.endswith('.whl'):
        os.remove(e.path)

    else:
        shutil.rmtree(e.path)

    _extensions_changed(None, None, None)

    return jsonify(result='ok')


@BLUEPRINT.route('/extensions', methods=['POST'], read_write=True)
def upload_extension():
    if DISABLE_NEW_EXTENSIONS:
        return 'Disabled', 403

    library_directory = config.get('MINEMELD_LOCAL_LIBRARY_PATH', None)
    if library_directory is None:
        raise RuntimeError('MINEMELD_LOCAL_LIBRARY_PATH not set')

    if 'file' not in request.files:
        return jsonify(error={'messsage': 'No file'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify(error={'message': 'No file'}), 400

    if not file or not file.filename.endswith('.whl'):
        return jsonify(error={'message': 'Incorrect filename'}), 400

    filename = secure_filename(file.filename)
    if filename != file.filename:
        return jsonify(error={'message': 'Incorrect filename'}), 400
    if os.path.basename(filename) != filename:
        return jsonify(error={'message': 'Incorrect filename'}), 400

    toks = filename.split('-', 5)
    if len(toks) != 4 and len(toks) != 5:
        return jsonify(error={'message': 'Invalid wheel filename'}), 400

    if toks[-1] != 'any.whl' and toks[-1] != 'linux_x86_64.whl':
        return jsonify(error={'message': 'Invalid wheel platform'}), 400

    if not toks[-3].startswith('py2') and not toks[-3].startswith('cp2'):
        return jsonify(error={'message': 'Invalid wheel python version'}), 400

    tf = NamedTemporaryFile(prefix='mm-extension-upload', delete=False)

    try:
        file.save(tf)
        tf.close()

        metadata = minemeld.extensions.get_metadata_from_wheel(tf.name, filename)
        if metadata is None:
            return jsonify(error={'message': 'Invalid MineMeld extension'}), 400

        full_filename = os.path.join(library_directory, filename)
        shutil.move(tf.name, full_filename)

    except (KeyError, ValueError) as e:
        LOG.error('Invalid extension: {}'.format(str(e)))
        return jsonify(error={'message': 'Invalid python wheel'}), 400

    finally:
        _safe_remove(tf.name)

    return jsonify(result='OK')


@BLUEPRINT.route('/extensions/git-refs', methods=['GET'], read_write=False)
def get_git_refs():
    if DISABLE_NEW_EXTENSIONS:
        return 'Disabled', 403

    git_endpoint = request.values.get('ep', None)
    if git_endpoint is None:
        return jsonify(error={'message': 'Missing endpoint'}), 400

    if not git_endpoint.endswith('.git'):
        return jsonify(error={'message': 'Invalid git endpoint'}), 400

    git_path = config.get('MINEMELD_GIT_PATH', None)
    if git_path is None:
        return jsonify(error={'message': 'MINEMELD_GIT_PATH not set'}), 500

    git_args = [git_path, 'ls-remote', '-t', '-h', git_endpoint]

    git_process = Popen(
        args=git_args,
        close_fds=True,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    timeout = Timeout(20.0)
    timeout.start()
    try:
        git_stdout, git_stderr = git_process.communicate()

    except Timeout:
        git_process.kill()
        return jsonify(error={'message': 'Timeout accessing git repo'}), 400

    finally:
        timeout.cancel()

    if git_process.returncode != 0:
        LOG.error('Error running {}: {}'.format(git_args, git_stderr))
        return jsonify(error={'message': 'Error running git: {}'.format(git_stderr)}), 400

    return jsonify(result=[line.rsplit('/', 1)[-1] for line in git_stdout.splitlines()])


@BLUEPRINT.route('/extensions/git-install', methods=['POST'], read_write=True)
def install_from_git():
    if DISABLE_NEW_EXTENSIONS:
        return 'Disabled', 403

    library_directory = config.get('MINEMELD_LOCAL_LIBRARY_PATH', None)
    if library_directory is None:
        raise RuntimeError('MINEMELD_LOCAL_LIBRARY_PATH not set')

    params = request.get_json(silent=True)
    if params is None:
        return jsonify(error={'message': 'no params'}), 400

    git_endpoint = params.get('ep', None)
    if git_endpoint is None:
        return jsonify(error={'message': 'Missing endpoint'}), 400

    if not git_endpoint.endswith('.git'):
        return jsonify(error={'message': 'Invalid git endpoint'}), 400

    git_ref = params.get('ref', None)
    if git_ref is None:
        return jsonify(error={'message': 'Missing git ref'}), 400

    git_path = config.get('MINEMELD_GIT_PATH', None)
    if git_path is None:
        return jsonify(error={'message': 'MINEMELD_GIT_PATH not set'}), 500

    install_directory = os.path.join(
        library_directory,
        str(uuid.uuid4())
    )
    git_args = [
        git_path,
        'clone',
        '-b', git_ref,
        '--depth', '1',
        git_endpoint,
        install_directory
    ]

    tf = NamedTemporaryFile(prefix='mm-extension-upload', delete=False)

    try:
        tf.write('#!/bin/bash\n')
        tf.write('set -e\n')
        tf.write('{}\n'.format(' '.join(git_args)))
        tf.write('if [ ! -f {}/minemeld.json ]; then\n'.format(install_directory))
        tf.write('  >&2 echo "Invalid MineMeld extension - minemeld.json not found"\n')
        tf.write('  /bin/rm -rf {}\n'.format(install_directory))
        tf.write('  exit 1\n')
        tf.write('fi\n')
        tf.close()
        os.chmod(tf.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        jobid = JOBS_MANAGER.exec_job(
            job_group='extensions-git',
            description='install from git {} branch {}'.format(git_endpoint, git_ref),
            args=[tf.name],
            data={
                'endpoint': git_endpoint,
                'ref': git_ref,
                'path': install_directory
            },
            callback=functools.partial(_safe_remove, tf.name)
        )

    except:
        _safe_remove(tf.name)
        raise

    return jsonify(result=jobid)
