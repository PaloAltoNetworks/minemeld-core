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
import os
import os.path
import logging
import shutil
import re
import json
import multiprocessing
import functools

import yaml

import minemeld.loader


__all__ = ['load_config', 'validate_config', 'resolve_prototypes']


LOG = logging.getLogger(__name__)

COMMITTED_CONFIG = 'committed-config.yml'
RUNNING_CONFIG = 'running-config.yml'
PROTOTYPE_ENV = 'MINEMELD_PROTOTYPE_PATH'
MGMTBUS_NUM_CONNS_ENV = 'MGMTBUS_NUM_CONNS'
FABRIC_NUM_CONNS_ENV = 'FABRIC_NUM_CONNS'


def _load_node_prototype(protoname, paths):
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


def _load_and_validate_config_from_file(path):
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


def _destroy_node(desc, nodes=None, installed_nodes=None, installed_nodes_gcs=None):
    LOG.info('Destroying {}'.format(desc))
    destroyed_name, destroyed_class = json.loads(desc)
    if destroyed_class is None:
        LOG.error('Node {} with no class destroyed'.format(destroyed_name))
        return 1

    # load node class GC from entry_point or from "gc" staticmethod of class
    node_gc = None
    mmep = installed_nodes_gcs.get(destroyed_class, None)
    if mmep is None:
        mmep = installed_nodes.get(destroyed_class, None)

        try:
            nodep = mmep.ep.load()

            if hasattr(nodep, 'gc'):
                node_gc = nodep.gc
        except ImportError:
            LOG.exception("Error checking node class {} for gc method".format(destroyed_class))
    else:
        try:
            node_gc = mmep.ep.load()
        except ImportError:
            LOG.exception("Error resolving gc for class {}".format(destroyed_class))    
    if node_gc is None:
        LOG.error('Node {} with class {} with no garbage collector destroyed'.format(
            destroyed_name, destroyed_class
        ))
        return 1

    try:
        node_gc(
            destroyed_name,
            config=nodes[destroyed_name].get('config', None)
        )

    except:
        LOG.exception('Exception destroying old node {} of class {}'.format(
            destroyed_name, destroyed_class
        ))
        return 1

    return 0


def _destroy_old_nodes(oldconfig, newconfig):
    # this destroys resources used by destroyed nodes
    # a nodes has been destroyed if a node with same
    # name & config does not exist in the new config
    # the case of different node config but same and name
    # and class is handled by node itself
    # old config could be invalid, we should be careful here
    old_nodes_raw = oldconfig.get('nodes', None)
    if old_nodes_raw is None:
        return
    if not isinstance(old_nodes_raw, dict):
        return

    old_nodes = set()
    for nname, nvalue in old_nodes_raw.iteritems():
        old_nodes.add(
            json.dumps(
                [nname, nvalue.get('class', None)],
                sort_keys=True
            )
        )

    new_nodes = set()
    for nname, nvalue in newconfig['nodes'].iteritems():
        new_nodes.add(
            json.dumps(
                [nname,nvalue['class']],
                sort_keys=True
            )
        )

    destroyed_nodes = old_nodes - new_nodes
    LOG.info('Destroyed nodes: {!r}'.format(destroyed_nodes))
    if len(destroyed_nodes) == 0:
        return

    installed_nodes = minemeld.loader.map(minemeld.loader.MM_NODES_ENTRYPOINT)
    installed_nodes_gcs = minemeld.loader.map(minemeld.loader.MM_NODES_GCS_ENTRYPOINT)

    dpool = multiprocessing.Pool()
    _bound_destroy_node = functools.partial(
        _destroy_node,
        nodes=old_nodes_raw,
        installed_nodes=installed_nodes,
        installed_nodes_gcs=installed_nodes_gcs
    )
    dpool.imap_unordered(
        _bound_destroy_node,
        destroyed_nodes
    )
    dpool.close()
    dpool.join()
    dpool = None


def _load_config_from_dir(path):
    ccpath = os.path.join(
        path,
        COMMITTED_CONFIG
    )
    rcpath = os.path.join(
        path,
        RUNNING_CONFIG
    )

    ccvalid, cconfig = _load_and_validate_config_from_file(ccpath)
    rcvalid, rcconfig = _load_and_validate_config_from_file(rcpath)

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
        # candidate is valid while running is not
        LOG.info('Switching to candidate config')
        if rcconfig is not None:
            _destroy_old_nodes(rcconfig, cconfig)
            shutil.copyfile(
                rcpath,
                '{}.{}'.format(rcpath, int(time.time()))
            )
        shutil.copyfile(ccpath, rcpath)
        cconfig['newconfig'] = True
        return cconfig

    elif rcvalid and ccvalid:
        # both configs are valid
        if json.dumps(cconfig, sort_keys=True) == json.dumps(rcconfig, sort_keys=True):
            # same old config, nothing to do here
            rcconfig['newconfig'] = False
            return rcconfig

        LOG.info('Switching to candidate config')
        _destroy_old_nodes(rcconfig, cconfig)
        shutil.copyfile(
            rcpath,
            '{}.{}'.format(rcpath, int(time.time()))
        )
        shutil.copyfile(ccpath, rcpath)
        cconfig['newconfig'] = True
        return cconfig


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
    # retrieve prototype dir from environment
    # used for main library and local library
    paths = os.getenv(PROTOTYPE_ENV, None)
    if paths is None:
        raise RuntimeError('Unable to load prototype %s: %s '
                           'environment variable not set' %
                           (protoname, PROTOTYPE_ENV))
    paths = paths.split(':')

    # add prototype dirs from extension to paths
    prototypes_entrypoints = minemeld.loader.map(minemeld.loader.MM_PROTOTYPES_ENTRYPOINT)
    for epname, mmep in prototypes_entrypoints.iteritems():
        if not mmep.loadable:
            LOG.info('Prototypes entrypoint {} not loadable'.format(epname))
            continue

        try:
            ep = mmep.ep.load()
            paths.append(ep())

        except:
            LOG.exception(
                'Exception retrieving path from prototype entrypoint {}'.format(epname)
            )

    # resolve all prototypes
    valid = True

    nodes_config = config['nodes']
    for nname, nconfig in nodes_config.iteritems():
        if 'prototype' in nconfig:
            try:
                nproto = _load_node_prototype(nconfig['prototype'], paths)
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

    installed_nodes = minemeld.loader.map(minemeld.loader.MM_NODES_ENTRYPOINT)
    for n, v in nodes.iteritems():
        nclass = v.get('class', None)
        if nclass is None:
            result.append('No class in {}'.format(n))
            continue

        mmep = installed_nodes.get(nclass, None)
        if mmep is None:
            result.append(
                'Unknown node class {} in {}'.format(nclass, n)
            )
            continue

        if not mmep.loadable:
            result.append(
                'Class {} in {} not safe to load'.format(nclass, n)
            )

    if not _detect_cycles(nodes):
        result.append('loop detected')

    return result


def load_config(config_path):
    if os.path.isdir(config_path):
        return _load_config_from_dir(config_path)

    valid, config = _load_and_validate_config_from_file(config_path)
    if not valid:
        raise RuntimeError('Invalid config')

    config['newconfig'] = True

    return config
