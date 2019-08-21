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
from collections import namedtuple

import yaml
import gevent.core

import minemeld.loader

__all__ = ['load_config', 'validate_config', 'resolve_prototypes']


# disables construction of timestamp objects
yaml.SafeLoader.add_constructor(
    u'tag:yaml.org,2002:timestamp',
    yaml.SafeLoader.construct_yaml_str
)


LOG = logging.getLogger(__name__)

COMMITTED_CONFIG = 'committed-config.yml'
RUNNING_CONFIG = 'running-config.yml'
PROTOTYPE_ENV = 'MINEMELD_PROTOTYPE_PATH'
MGMTBUS_NUM_CONNS_ENV = 'MGMTBUS_NUM_CONNS'
FABRIC_NUM_CONNS_ENV = 'FABRIC_NUM_CONNS'

CHANGE_ADDED = 0
CHANGE_DELETED = 1
CHANGE_INPUT_ADDED = 2
CHANGE_INPUT_DELETED = 3
CHANGE_OUTPUT_ENABLED = 4
CHANGE_OUTPUT_DISABLED = 5

_ConfigChange = namedtuple(
    '_ConfigChange',
    ['nodename', 'nodeclass', 'change', 'detail']
)

_Config = namedtuple(
    '_Config',
    ['nodes', 'fabric', 'mgmtbus', 'changes']
)


class MineMeldConfigChange(_ConfigChange):
    def __new__(_cls, nodename, nodeclass, change, detail=None):
        return _ConfigChange.__new__(
            _cls,
            nodename=nodename,
            nodeclass=nodeclass,
            change=change,
            detail=detail
        )


class MineMeldConfig(_Config):
    def as_nset(self):
        result = set()
        for nname, nvalue in self.nodes.iteritems():
            result.add(
                json.dumps(
                    [nname, nvalue.get('class', None)],
                    sort_keys=True
                )
            )
        return result

    def compute_changes(self, oconfig):
        if oconfig is None:
            # oconfig is None, mark everything as added
            for nodename, nodeattrs in self.nodes.iteritems():
                self.changes.append(
                    MineMeldConfigChange(nodename=nodename, nodeclass=nodeattrs['class'], change=CHANGE_ADDED)
                )
            return

        my_nset = self.as_nset()
        other_nset = oconfig.as_nset()

        deleted = other_nset - my_nset
        added = my_nset - other_nset
        untouched = my_nset & other_nset

        # mark delted as deleted
        for snode in deleted:
            nodename, nodeclass = json.loads(snode)
            change = MineMeldConfigChange(
                nodename=nodename,
                nodeclass=nodeclass,
                change=CHANGE_DELETED,
                detail=oconfig.nodes[nodename]
            )
            self.changes.append(change)

        # mark added as added
        for snode in added:
            nodename, nodeclass = json.loads(snode)
            change = MineMeldConfigChange(
                nodename=nodename,
                nodeclass=nodeclass,
                change=CHANGE_ADDED
            )
            self.changes.append(change)

        # check inputs/output for untouched
        for snode in untouched:
            nodename, nodeclass = json.loads(snode)

            my_inputs = set(self.nodes[nodename].get('inputs', []))
            other_inputs = set(oconfig.nodes[nodename].get('inputs', []))

            iadded = my_inputs - other_inputs
            ideleted = other_inputs - my_inputs

            for i in iadded:
                change = MineMeldConfigChange(
                    nodename=nodename,
                    nodeclass=nodeclass,
                    change=CHANGE_INPUT_ADDED,
                    detail=i
                )
                self.changes.append(change)

            for i in ideleted:
                change = MineMeldConfigChange(
                    nodename=nodename,
                    nodeclass=nodeclass,
                    change=CHANGE_INPUT_DELETED,
                    detail=i
                )
                self.changes.append(change)

            my_output = self.nodes[nodename].get('output', False)
            other_output = oconfig.nodes[nodename].get('output', False)

            if my_output == other_output:
                continue

            change_type = CHANGE_OUTPUT_DISABLED
            if my_output:
                change_type = CHANGE_OUTPUT_ENABLED

            change = MineMeldConfigChange(
                nodename=nodename,
                nodeclass=nodeclass,
                change=change_type
            )
            self.changes.append(change)

    @classmethod
    def from_dict(cls, dconfig=None):
        if dconfig is None:
            dconfig = {}

        fabric = dconfig.get('fabric', None)
        if fabric is None:
            fabric_num_conns = int(
                os.getenv(FABRIC_NUM_CONNS_ENV, 50)
            )

            fabric = {
                'class': 'ZMQRedis',
                'config': {
                    'num_connections': fabric_num_conns,
                    'priority': gevent.core.MINPRI  # pylint:disable=E1101
                }
            }

        mgmtbus = dconfig.get('mgmtbus', None)
        if mgmtbus is None:
            mgmtbus_num_conns = int(
                os.getenv(MGMTBUS_NUM_CONNS_ENV, 10)
            )

            mgmtbus = {
                'transport': {
                    'class': 'ZMQRedis',
                    'config': {
                        'num_connections': mgmtbus_num_conns,
                        'priority': gevent.core.MAXPRI  # pylint:disable=E1101
                    }
                },
                'master': {},
                'slave': {}
            }

        nodes = dconfig.get('nodes', None)
        if nodes is None:
            nodes = {}

        return cls(nodes=nodes, fabric=fabric, mgmtbus=mgmtbus, changes=[])


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

    if not isinstance(config, dict) and config is not None:
        raise ValueError('Invalid config YAML type')

    return valid, MineMeldConfig.from_dict(config)


def _load_and_validate_config_from_file(sys_config, path):
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
        valid = resolve_prototypes(sys_config, config)

    if valid and config is not None:
        vresults = validate_config(config)
        if len(vresults) != 0:
            LOG.error('Invalid config {}: {}'.format(
                path,
                ', '.join(vresults)
            ))
            valid = False

    return valid, config


def _destroy_node(change, installed_nodes=None, installed_nodes_gcs=None):
    LOG.info('Destroying {!r}'.format(change))

    destroyed_name = change.nodename
    destroyed_class = change.nodeclass
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
            config=change.detail.get('config', None)
        )

    except:
        LOG.exception('Exception destroying old node {} of class {}'.format(
            destroyed_name, destroyed_class
        ))
        return 1

    return 0


def _destroy_old_nodes(config):
    # this destroys resources used by destroyed nodes
    # a nodes has been destroyed if a node with same
    # name & config does not exist in the new config
    # the case of different node config but same and name
    # and class is handled by node itself
    destroyed_nodes = [c for c in config.changes if c.change == CHANGE_DELETED]
    LOG.info('Destroyed nodes: {!r}'.format(destroyed_nodes))
    if len(destroyed_nodes) == 0:
        return

    installed_nodes = minemeld.loader.map(minemeld.loader.MM_NODES_ENTRYPOINT)
    installed_nodes_gcs = minemeld.loader.map(minemeld.loader.MM_NODES_GCS_ENTRYPOINT)

    dpool = multiprocessing.Pool()
    _bound_destroy_node = functools.partial(
        _destroy_node,
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


def _load_config_from_dir(sys_config, path):
    ccpath = os.path.join(
        path,
        COMMITTED_CONFIG
    )
    rcpath = os.path.join(
        path,
        RUNNING_CONFIG
    )

    ccvalid, cconfig = _load_and_validate_config_from_file(sys_config, ccpath)
    rcvalid, rcconfig = _load_and_validate_config_from_file(sys_config, rcpath)

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
        return rcconfig

    elif not rcvalid and ccvalid:
        # candidate is valid while running is not
        LOG.info('Switching to candidate config')
        cconfig.compute_changes(rcconfig)
        LOG.info('Changes in config: {!r}'.format(cconfig.changes))
        _destroy_old_nodes(cconfig)
        if rcconfig is not None:
            shutil.copyfile(
                rcpath,
                '{}.{}'.format(rcpath, int(time.time()))
            )
        shutil.copyfile(ccpath, rcpath)
        return cconfig

    elif rcvalid and ccvalid:
        LOG.info('Switching to candidate config')
        cconfig.compute_changes(rcconfig)
        LOG.info('Changes in config: {!r}'.format(cconfig.changes))
        _destroy_old_nodes(cconfig)
        shutil.copyfile(
            rcpath,
            '{}.{}'.format(rcpath, int(time.time()))
        )
        shutil.copyfile(ccpath, rcpath)
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


def resolve_prototypes(sys_config, config):
    # retrieve prototype dir from environment
    # used for main library and local library
    paths = sys_config.get(PROTOTYPE_ENV, os.environ.get(PROTOTYPE_ENV, None))
    if paths is None:
        raise RuntimeError('Unable to load prototypes: %s '
                           'environment variable not set' %
                           (PROTOTYPE_ENV))
    paths = paths.split(':')

    # add prototype dirs from extension to paths
    prototypes_entrypoints = minemeld.loader.map(minemeld.loader.MM_PROTOTYPES_ENTRYPOINT)
    for epname, mmep in prototypes_entrypoints.iteritems():
        if not mmep.loadable:
            LOG.info('Prototypes entrypoint {} not loadable'.format(epname))
            continue

        try:
            ep = mmep.ep.load()
            # we add prototype paths in front, to let extensions override default protos
            paths.insert(0, ep())

        except:
            LOG.exception(
                'Exception retrieving path from prototype entrypoint {}'.format(epname)
            )

    # resolve all prototypes
    valid = True

    nodes_config = config.nodes
    for _, nconfig in nodes_config.iteritems():
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

    nodes = config.nodes

    for n in nodes.keys():
        if re.match('^[a-zA-Z0-9_\-]+$', n) is None:  # pylint:disable=W1401
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


def load_config(sys_config, config_path):
    if os.path.isdir(config_path):
        return _load_config_from_dir(sys_config, config_path)

    # this is just a file, as we can't do a delta
    # we just load it and mark all the nodes as added
    valid, config = _load_and_validate_config_from_file(sys_config, config_path)
    if not valid:
        raise RuntimeError('Invalid config')
    config.compute_changes(None)

    return config
