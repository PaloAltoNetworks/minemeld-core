from __future__ import print_function

import sys
import time
import yaml
import os
import os.path
import logging
import shutil

LOG = logging.getLogger(__name__)

COMMITTED_CONFIG = 'committed-config.yml'
RUNNING_CONFIG = 'running-config.yml'
PROTOTYPE_ENV = 'MINEMELD_PROTOTYPE_PATH'


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
    config = yaml.safe_load(f)

    if config is None:
        config = {}

    if 'fabric' not in config:
        config['fabric'] = {
            'class': 'AMQP',
            'config': {
                'num_connections': 5
            }
        }

    if 'mgmtbus' not in config:
        config['mgmtbus'] = {
            'transport': {
                'class': 'AMQP',
                'config': {}
            },
            'master': {},
            'slave': {}
        }

    nodes_config = config.get('nodes', {})
    for nname, nconfig in nodes_config.iteritems():
        if 'prototype' in nconfig:
            nproto = _load_node_prototype(nconfig['prototype'])

            nconfig.pop('prototype')

            nconfig['class'] = nproto['class']
            nproto_config = nproto.get('config', {})
            nproto_config.update(
                nconfig.get('config', {})
            )
            nconfig['config'] = nproto_config

    return config


def _load_config_from_dir(path):
    ccpath = os.path.join(
        path,
        COMMITTED_CONFIG
    )
    rcpath = os.path.join(
        path,
        RUNNING_CONFIG
    )

    cconfig = None
    if os.path.exists(ccpath):
        with open(ccpath, 'r') as cf:
            cconfig = _load_config_from_file(cf)

    rcconfig = None
    if os.path.exists(rcpath):
        with open(rcpath, 'r') as cf:
            rcconfig = _load_config_from_file(cf)

    if rcconfig is None and cconfig is None:
        print(
            "At least one of", RUNNING_CONFIG,
            "or", COMMITTED_CONFIG,
            "should exist in", path,
            file=sys.stderr
        )
        sys.exit(1)
    elif rcconfig is not None and cconfig is None:
        rcconfig['newconfig'] = False
        return rcconfig
    elif rcconfig is None and cconfig is not None:
        shutil.copyfile(ccpath, rcpath)
        cconfig['newconfig'] = True
        return cconfig
    elif rcconfig is not None and cconfig is not None:
        # ugly
        if yaml.dump(cconfig) != yaml.dump(rcconfig):
            shutil.copyfile(rcpath, rcpath+'.%d' % int(time.time()))
            shutil.copyfile(ccpath, rcpath)
            cconfig['newconfig'] = True
            return cconfig

        rcconfig['newconfig'] = False
        return rcconfig


def load_config(config_path):
    if os.path.isdir(config_path):
        return _load_config_from_dir(config_path)

    with open(config_path, 'r') as cf:
        config = _load_config_from_file(cf)

    config['newconfig'] = True

    return config
