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

import yaml
import filelock
from flask import jsonify, request

import minemeld.loader

from . import config
from .utils import running_config, committed_config
from .aaa import MMBlueprint
from .logger import LOG


__all__ = ['BLUEPRINT']


PROTOTYPE_ENV = 'MINEMELD_PROTOTYPE_PATH'
LOCAL_PROTOTYPE_PATH = 'MINEMELD_LOCAL_PROTOTYPE_PATH'

BLUEPRINT = MMBlueprint('prototype', __name__, url_prefix='')

PROTOTYPE_PATHS = None


def _prototype_paths():
    global PROTOTYPE_PATHS
    if PROTOTYPE_PATHS is not None:
        return PROTOTYPE_PATHS

    paths = config.get(PROTOTYPE_ENV, None)
    if paths is None:
        raise RuntimeError('{} environment variable not set'.format(PROTOTYPE_ENV))
    paths = paths.split(':')

    prototype_eps = minemeld.loader.map(minemeld.loader.MM_PROTOTYPES_ENTRYPOINT)
    for pname, mmep in prototype_eps.iteritems():
        if not mmep.loadable:
            LOG.info('Prototype entry point {} not loadable, ignored'.format(pname))
            continue
        try:
            ep = mmep.ep.load()
            paths.append(ep())
        except:
            LOG.exception('Exception loading paths from {}'.format(pname))

    PROTOTYPE_PATHS = paths

    return paths


def _local_library_path(prototypename):
    toks = prototypename.split('.', 1)
    if len(toks) != 2:
        raise ValueError('bad prototype name')
    library, prototype = toks

    if os.path.basename(library) != library:
        raise ValueError('bad library name, nice try')
    if library != 'minemeldlocal':
        raise ValueError('invalid library')
    library_filename = library+'.yml'

    local_path = config.get(LOCAL_PROTOTYPE_PATH)
    if local_path is None:
        paths = os.getenv(PROTOTYPE_ENV, None)
        if paths is None:
            raise RuntimeError(
                '%s environment variable not set' %
                (PROTOTYPE_ENV)
            )

        paths = paths.split(':')
        for p in paths:
            if '/local/' in p:
                local_path = p
                break

        if local_path is None:
            raise RuntimeError(
                'No local path in %s' % PROTOTYPE_ENV
            )

    library_path = os.path.join(local_path, library_filename)

    return library_path, prototype


@BLUEPRINT.route('/prototype', methods=['GET'], read_write=False)
def list_prototypes():
    paths = _prototype_paths()

    prototypes = {}
    for p in paths:
        try:
            for plibrary in os.listdir(p):
                if not plibrary.endswith('.yml'):
                    continue

                plibraryname, _ = plibrary.rsplit('.', 1)

                with open(os.path.join(p, plibrary), 'r') as f:
                    pcontents = yaml.safe_load(f)

                if plibraryname not in prototypes:
                    prototypes[plibraryname] = pcontents
                    continue

                # oldest has precedence
                newprotos = pcontents.get('prototypes', {})
                currprotos = prototypes[plibraryname].get('prototypes', {})
                newprotos.update(currprotos)
                prototypes[plibraryname]['prototypes'] = newprotos

        except:
            LOG.exception('Error loading libraries from %s', p)

    return jsonify(result=prototypes)


@BLUEPRINT.route('/prototype/<prototypename>', methods=['GET'], read_write=False)
def get_prototype(prototypename):
    toks = prototypename.split('.', 1)
    if len(toks) != 2:
        return jsonify(error={'message': 'bad prototype name'}), 400
    library, prototype = toks

    if os.path.basename(library) != library:
        return jsonify(error={'message': 'bad library name, nice try'}), 400
    library_filename = library+'.yml'

    paths = _prototype_paths()

    for path in paths:
        full_library_name = os.path.join(path, library_filename)
        if not os.path.isfile(full_library_name):
            continue

        with open(full_library_name, 'r') as f:
            library_contents = yaml.safe_load(f)

        prototypes = library_contents.get('prototypes', None)
        if prototypes is None:
            continue

        if prototype not in prototypes:
            continue

        curr_prototype = prototypes[prototype]

        result = {
            'class': curr_prototype['class'],
            'developmentStatus': None,
            'config': None,
            'nodeType': None,
            'description': None,
            'indicatorTypes': None,
            'tags': None
        }

        if 'config' in curr_prototype:
            result['config'] = yaml.dump(
                curr_prototype['config'],
                indent=4,
                default_flow_style=False
            )

        if 'development_status' in curr_prototype:
            result['developmentStatus'] = curr_prototype['development_status']

        if 'node_type' in curr_prototype:
            result['nodeType'] = curr_prototype['node_type']

        if 'description' in curr_prototype:
            result['description'] = curr_prototype['description']

        if 'indicator_types' in curr_prototype:
            result['indicatorTypes'] = curr_prototype['indicator_types']

        if 'tags' in curr_prototype:
            result['tags'] = curr_prototype['tags']

        return jsonify(result=result), 200


@BLUEPRINT.route('/prototype/<prototypename>', methods=['POST'], read_write=True)
def add_local_prototype(prototypename):
    AUTHOR_ = 'minemeld-web'
    DESCRIPTION_ = 'Local prototype library managed via MineMeld WebUI'

    try:
        library_path, prototype = _local_library_path(prototypename)

    except ValueError as e:
        return jsonify(error={'message': str(e)}), 400

    lock = filelock.FileLock('{}.lock'.format(library_path))
    with lock.acquire(timeout=10):
        if os.path.isfile(library_path):
            with open(library_path, 'r') as f:
                library_contents = yaml.safe_load(f)
            if not isinstance(library_contents, dict):
                library_contents = {}
            if 'description' not in library_contents:
                library_contents['description'] = DESCRIPTION_
            if 'prototypes' not in library_contents:
                library_contents['prototypes'] = {}
            if 'author' not in library_contents:
                library_contents['author'] = AUTHOR_
        else:
            library_contents = {
                'author': AUTHOR_,
                'description': DESCRIPTION_,
                'prototypes': {}
            }

        try:
            incoming_prototype = request.get_json()
        except Exception as e:
            return jsonify(error={'message': str(e)}), 400

        new_prototype = {
            'class': incoming_prototype['class'],
        }

        if 'config' in incoming_prototype:
            try:
                new_prototype['config'] = yaml.safe_load(
                    incoming_prototype['config']
                )
            except Exception as e:
                return jsonify(error={'message': 'invalid YAML in config'}), 400

        if 'developmentStatus' in incoming_prototype:
            new_prototype['development_status'] = \
                incoming_prototype['developmentStatus']

        if 'nodeType' in incoming_prototype:
            new_prototype['node_type'] = incoming_prototype['nodeType']

        if 'description' in incoming_prototype:
            new_prototype['description'] = incoming_prototype['description']

        if 'indicatorTypes' in incoming_prototype:
            new_prototype['indicator_types'] = incoming_prototype['indicatorTypes']

        if 'tags' in incoming_prototype:
            new_prototype['tags'] = incoming_prototype['tags']

        library_contents['prototypes'][prototype] = new_prototype

        with open(library_path, 'w') as f:
            yaml.safe_dump(library_contents, f, indent=4, default_flow_style=False)

    return jsonify(result='OK'), 200


@BLUEPRINT.route('/prototype/<prototypename>', methods=['DELETE'], read_write=True)
def delete_local_prototype(prototypename):
    try:
        library_path, prototype = _local_library_path(prototypename)

    except ValueError as e:
        return jsonify(error={'message': str(e)}), 400

    if not os.path.isfile(library_path):
        return jsonify(error={'message': 'missing local prototype library'}), 400

    # check if the proto is in use in running or committed config
    rcconfig = running_config()
    for nodename, nodevalue in rcconfig.get('nodes', {}).iteritems():
        if 'prototype' not in nodevalue:
            continue
        if nodevalue['prototype'] == prototypename:
            return jsonify(error={'message': 'prototype in use in running config'}), 400

    ccconfig = committed_config()
    for nodename, nodevalue in ccconfig.get('nodes', {}).iteritems():
        if 'prototype' not in nodevalue:
            continue
        if nodevalue['prototype'] == prototypename:
            return jsonify(error={'message': 'prototype in use in running config'}), 400

    lock = filelock.FileLock('{}.lock'.format(library_path))
    with lock.acquire(timeout=10):
        with open(library_path, 'r') as f:
            library_contents = yaml.safe_load(f)

        if not isinstance(library_contents, dict):
            return jsonify(error={'message': 'invalid local prototype library'}), 400

        library_contents['prototypes'].pop(prototype, None)

        with open(library_path, 'w') as f:
            yaml.safe_dump(library_contents, f, indent=4, default_flow_style=False)

    return jsonify(result='OK'), 200


def reset_prototype_paths():
    global PROTOTYPE_PATHS
    PROTOTYPE_PATHS = None
