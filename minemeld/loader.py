import logging

import pip

from pkg_resources import iter_entry_points
from collections import namedtuple


LOG = logging.getLogger(__name__)

MM_NODES_ENTRYPOINT = 'minemeld_nodes'
MM_NODES_GCS_ENTRYPOINT = 'minemeld_nodes_gcs'
MM_NODES_VALIDATORS_ENTRYPOINT = 'minemeld_nodes_validators'
MM_PROTOTYPES_ENTRYPOINT = 'minemeld_prototypes'
MM_API_ENTRYPOINT = 'minemeld_api'

MMEntryPoint = namedtuple(
    'MMEntryPoint',
    ['ep', 'name', 'loadable', 'conflicts']
)

_ENTRYPOINT_GROUPS = {}


def _installed_versions():
    installed_dists = pip.get_installed_distributions()
    return {d.project_name: d for d in installed_dists}


def _conflicts(requirements, installed):
    result = []

    for r in requirements:
        installed_dist = installed.get(r.project_name, None)
        if installed_dist is None:
            result.append('{} not installed'.format(r.project_name))
            continue

        if installed_dist.version not in r:
            result.append('{}=={} not compatible with {}'.format(
                installed_dist.project_name,
                installed_dist.version,
                str(r)
            ))

    return result


def _initialize_entry_point_group(entrypoint_group):
    installed = _installed_versions()

    cache = {}
    result = {}
    for ep in iter_entry_points(entrypoint_group):
        egg_name = ep.dist.egg_name()
        conflicts = cache.get(egg_name, None)
        if conflicts is None:
            conflicts = _conflicts(
                ep.dist.requires(),
                installed
            )
            cache[egg_name] = conflicts

        if len(conflicts) != 0:
            LOG.error('{} not loadable: {}'.format(
                ep.name,
                ', '.join(conflicts)
            ))
        result[ep.name] = MMEntryPoint(
            ep=ep,
            name=ep.name,
            conflicts=conflicts,
            loadable=(len(conflicts) == 0)
        )

    _ENTRYPOINT_GROUPS[entrypoint_group] = result


def list(entrypoint_group):
    if entrypoint_group not in _ENTRYPOINT_GROUPS:
        _initialize_entry_point_group(entrypoint_group)
    eg = _ENTRYPOINT_GROUPS[entrypoint_group]

    return eg.keys()


def map(entrypoint_group):
    if entrypoint_group not in _ENTRYPOINT_GROUPS:
        _initialize_entry_point_group(entrypoint_group)
    eg = _ENTRYPOINT_GROUPS[entrypoint_group]

    return eg


def load(entrypoint_group, entrypoint_name):
    LOG.info('Loading %s:%s', entrypoint_group, entrypoint_name)
    if entrypoint_group not in _ENTRYPOINT_GROUPS:
        _initialize_entry_point_group(entrypoint_group)
    eg = _ENTRYPOINT_GROUPS[entrypoint_group]

    mmep = eg.get(entrypoint_name, None)
    if mmep is None:
        raise RuntimeError('Unknown entry point: {}:{}'.format(entrypoint_group, entrypoint_name))

    if not mmep.loadable:
        raise RuntimeError('Entry point {}:{} not loadable: {}'.format(
            entrypoint_group,
            entrypoint_name,
            ', '.join(mmep.conflicts)
        ))

    return mmep.ep.load()
