import json
import os
import sys

import pkg_resources


def get_config_value(config, key, default_value):
    if '.' in key:
        key_path = key.split('.')
        for i in key_path[:-1]:
            config = config.get(i, {})
        key = key_path[-1]
        env_key = '_'.join([i.upper() for i in key_path])
    else:
        env_key = key
    return config.get(key.lower(), os.environ.get(env_key.upper(), default_value))


def initialize_default_nodes_distribution(sys_config):
    try:
        ws = getattr(sys.modules['minemeld.loader'], '_WS')
        if ws is None:
            ws = pkg_resources.WorkingSet()
        if len([ep for ep in ws.iter_entry_points('minemeld_nodes')]) == 0:
            path = sys_config.get('MINEMELD_NODES_PATH', os.environ.get('MINEMELD_NODES_PATH', None))
            with open(path, 'r') as f:
                node_definitions = json.load(f)
            node_endpoints = [
                '{} = {}'.format(xk, xv['class'])
                for xk, xv in node_definitions.items()
                if 'class' in xv
            ]
            project_name = 'minemeld_synthetic_core'
            project_version = '1.0'
            python_version = '2.7'
            dist = pkg_resources.Distribution(
                location='/tmp/{}-{}-py{}.egg'.format(project_name, project_version, python_version),
                project_name=project_name,
                version=project_version,
                py_version=python_version
            )
            node_map = {'minemeld_nodes': node_endpoints}
            dist._ep_map = pkg_resources.EntryPoint.parse_map(node_map, dist)
            ws.add(dist)
            setattr(sys.modules['minemeld.loader'], '_WS', ws)
    except (KeyError, OSError):
        pass
