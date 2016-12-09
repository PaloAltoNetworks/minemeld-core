#  Copyright 2015 Palo Alto Networks, Inc
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

from __future__ import print_function

import sys
import time
import yaml
import os
import os.path
import logging
import shutil
import re

LOG = logging.getLogger(__name__)

COMMITTED_CONFIG = 'committed-config.yml'
RUNNING_CONFIG = 'running-config.yml'
PROTOTYPE_ENV = 'MINEMELD_PROTOTYPE_PATH'
MGMTBUS_NUM_CONNS_ENV = 'MGMTBUS_NUM_CONNS'
FABRIC_NUM_CONNS_ENV = 'FABRIC_NUM_CONNS'


def _load_node_prototype(protoname):
    paths = os.getenv(PROTOTYPE_ENV, None)
    if paths is None:
        raise RuntimeError('Unable to load prototype %s: %s '
                           'environment variable not set' %
                           (protoname, PROTOTYPE_ENV))
    paths = paths.split(':')

    proto_module, proto_name = protoname.rsplit('.', 1)

    pmodule = None
    pmprotos = {}
    for p in paths:
        pmpath = os.path.join(p, proto_module+'.yml')

        try:
            with open(pmpath, 'r') as pf:
                pmodule = yaml.safe_load(pf)

                if pmodule is None:
                    pmodule = {}
        except IOError:
            pmodule = None
            continue

        pmprotos = pmodule.get('prototypes', {})

        if proto_name not in pmprotos:
            pmodule = None
            continue

        if 'class' not in pmprotos[proto_name]:
            pmodule = None
            continue

        return pmprotos[proto_name]

    raise RuntimeError('Unable to load prototype %s: '
                       ' not found' % (protoname))


def _load_config_from_file(f):
    valid = True
    config = yaml.safe_load(f)

    if config is None:
        config = {}

    if 'fabric' not in config:
        fabric_num_conns = int(
            os.getenv(FABRIC_NUM_CONNS_ENV, 5)
        )

        config['fabric'] = {
            'class': 'AMQP',
            'config': {
                'num_connections': fabric_num_conns
            }
        }

    if 'mgmtbus' not in config:
        mgmtbus_num_conns = int(
            os.getenv(MGMTBUS_NUM_CONNS_ENV, 1)
        )

        config['mgmtbus'] = {
            'transport': {
                'class': 'AMQP',
                'config': {
                    'num_connections': mgmtbus_num_conns
                }
            },
            'master': {},
            'slave': {}
        }

    if 'nodes' not in config:
        config['nodes'] = {}

    return valid, config


def _load_and_validate_config_form_file(path):
    valid = False
    config = None

    if os.path.isfile(path):
        try:
            with open(path, 'r') as cf:
                valid, config = _load_config_from_file(cf)
            if not valid:
                LOG.error('Invalid config file {}'.format(path))
        except (RuntimeError, IOError):
            LOG.exception(
                'Error loading config {}, config ignored'.format(path)
            )
            valid, config = False, None

    if valid and config is not None:
        valid = resolve_prototypes(config)

    if valid and config is not None:
        vresults = validate_config(config)
        if len(vresults) != 0:
            LOG.error('Invalid config {}: {}'.format(
                path,
                ', '.join(vresults)
            ))
            valid = False

    return valid, config


def _load_config_from_dir(path):
    ccpath = os.path.join(
        path,
        COMMITTED_CONFIG
    )
    rcpath = os.path.join(
        path,
        RUNNING_CONFIG
    )

    ccvalid, cconfig = _load_and_validate_config_form_file(ccpath)
    rcvalid, rcconfig = _load_and_validate_config_form_file(rcpath)

    if not rcvalid and not ccvalid:
        # both running and canidate are not valid
        print(
            "At least one of", RUNNING_CONFIG,
            "or", COMMITTED_CONFIG,
            "should exist in", path,
            file=sys.stderr
        )
        sys.exit(1)

    elif rcvalid and not ccvalid:
        # running is valid but candidate is not
        rcconfig['newconfig'] = False
        return rcconfig

    elif not rcvalid and ccvalid:
        LOG.info('Switching to candidate config')
        # candidate is valid while running is not
        if rcconfig is not None:
            shutil.copyfile(
                rcpath,
                '{}.{}'.format(rcpath, int(time.time()))
            )
        shutil.copyfile(ccpath, rcpath)
        cconfig['newconfig'] = True
        return cconfig

    elif rcvalid and ccvalid:
        # both configs are valid
        if yaml.dump(cconfig) != yaml.dump(rcconfig):
            LOG.info('Switching to candidate config')
            shutil.copyfile(
                rcpath,
                '{}.{}'.format(rcpath, int(time.time()))
            )
            shutil.copyfile(ccpath, rcpath)
            cconfig['newconfig'] = True
            return cconfig

        rcconfig['newconfig'] = False
        return rcconfig


def _detect_cycles(nodes):
    # using Topoligical Sorting to detect cycles in graph, see Wikipedia
    graph = {}
    S = set()
    L = []

    for n in nodes:
        graph[n] = {
            'inputs': [],
            'outputs': []
        }

    for n, v in nodes.iteritems():
        for i in v.get('inputs', []):
            if i in graph:
                graph[i]['outputs'].append(n)
                graph[n]['inputs'].append(i)

    for n, v in graph.iteritems():
        if len(v['inputs']) == 0:
            S.add(n)

    while len(S) != 0:
        n = S.pop()
        L.append(n)

        for m in graph[n]['outputs']:
            graph[m]['inputs'].remove(n)
            if len(graph[m]['inputs']) == 0:
                S.add(m)
        graph[n]['outputs'] = []

    nedges = 0
    for n, v in graph.iteritems():
        nedges += len(v['inputs'])
        nedges += len(v['outputs'])

    return nedges == 0


def resolve_prototypes(config):
    valid = True

    nodes_config = config['nodes']
    for nname, nconfig in nodes_config.iteritems():
        if 'prototype' in nconfig:
            try:
                nproto = _load_node_prototype(nconfig['prototype'])
            except RuntimeError as e:
                LOG.error('Error loading prototype {}: {}'.format(
                    nconfig['prototype'],
                    str(e)
                ))
                valid = False
                continue

            nconfig.pop('prototype')

            nconfig['class'] = nproto['class']
            nproto_config = nproto.get('config', {})
            nproto_config.update(
                nconfig.get('config', {})
            )
            nconfig['config'] = nproto_config

    return valid


def validate_config(config):
    result = []

    nodes = config['nodes']

    for n in nodes.keys():
        if re.match('^[a-zA-Z0-9_\-]+$', n) is None:
            result.append('%s node name is invalid' % n)

    for n, v in nodes.iteritems():
        for i in v.get('inputs', []):
            if i not in nodes:
                result.append('%s -> %s is unknown' % (n, i))
                continue

            if not nodes[i].get('output', False):
                result.append('%s -> %s output disabled' %
                              (n, i))

    if not _detect_cycles(nodes):
        result.append('loop detected')

    return result


def load_config(config_path):
    if os.path.isdir(config_path):
        return _load_config_from_dir(config_path)

    valid, config = _load_and_validate_config_form_file(config_path)
    if not valid:
        raise RuntimeError('Invalid config')

    config['newconfig'] = True

    return config
