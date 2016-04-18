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

import os
import os.path
import yaml

import flask.ext.login

from flask import jsonify
from flask import request

from . import app

LOG = logging.getLogger(__name__)

PROTOTYPE_ENV = 'MINEMELD_PROTOTYPE_PATH'


@app.route('/prototype', methods=['GET'])
@flask.ext.login.login_required
def list_prototypes():
    paths = os.getenv(PROTOTYPE_ENV, None)
    if paths is None:
        raise RuntimeError('%s environment variable not set' %
                           (PROTOTYPE_ENV))
    paths = paths.split(':')

    prototypes = {}
    for p in paths:
        try:
            for plibrary in os.listdir(p):
                if not plibrary.endswith('.yml'):
                    continue

                plibraryname, _ = plibrary.rsplit('.', 1)

                with open(os.path.join(p, plibrary), 'r') as f:
                    pcontents = yaml.safe_load(f)

                prototypes[plibraryname] = pcontents

        except:
            LOG.exception('Error loading libraries from %s', p)

    return jsonify(result=prototypes)


@app.route('/prototype/<prototypename>', methods=['GET'])
def get_prototype(prototypename):
    toks = prototypename.split('.', 1)
    if len(toks) != 2:
        return jsonify(error={'message': 'bad prototype name'}), 400
    library, prototype = toks

    if os.path.basename(library) != library:
        return jsonify(error={'message': 'bad library name, nice try'}), 400
    library_filename = library+'.yml'

    paths = os.getenv(PROTOTYPE_ENV, None)
    if paths is None:
        raise RuntimeError('%s environment variable not set' %
                           (PROTOTYPE_ENV))
    paths = paths.split(':')

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
            'description': None
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

        return jsonify(result=result), 200


@app.route('/prototype/<prototypename>', methods=['POST'])
def add_prototype(prototypename):
    AUTHOR_ = 'minemeld-web'
    DESCRIPTION_ = 'Local prototype library managed via MineMeld WebUI'

    toks = prototypename.split('.', 1)
    if len(toks) != 2:
        return jsonify(error={'message': 'bad prototype name'}), 400
    library, prototype = toks

    if os.path.basename(library) != library:
        return jsonify(error={'message': 'bad library name, nice try'}), 400
    if library != 'minemeldlocal':
        return jsonify(error={'message': 'invalid library'}), 400
    library_filename = library+'.yml'

    paths = os.getenv(PROTOTYPE_ENV, None)
    if paths is None:
        raise RuntimeError('%s environment variable not set' %
                           (PROTOTYPE_ENV))
    paths = paths.split(':')

    library_path = None
    for p in paths:
        library_path = os.path.join(p, library_filename)
        if os.path.isfile(library_path):
            break

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

    library_contents['prototypes'][prototype] = new_prototype

    with open(library_path, 'w') as f:
        yaml.safe_dump(library_contents, f, indent=4, default_flow_style=False)

    return jsonify(result='OK'), 200
