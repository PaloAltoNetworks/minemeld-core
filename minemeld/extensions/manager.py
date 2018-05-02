import sys
import os
import os.path
import json
import logging
from email.parser import Parser
from collections import namedtuple
from zipfile import ZipFile

from pkg_resources import EntryPoint, parse_version

import minemeld.loader

LOG = logging.getLogger(__name__)


__all__ = [
    'get_metadata_from_wheel',
    'activated_extensions',
    'installed_extensions',
    'extensions',
    'freeze',
    'load_frozen_paths'
]


METADATA_MAP = {
    'name': 'Name',
    'version': 'Version',
    'author': 'Author',
    'author_email': 'Author-email',
    'description': 'Summary',
    'url': 'Home-page'
}


InstalledExtension = namedtuple(
    'InstalledExtension',
    [
        'name', 'version', 'author', 'author_email',
        'description', 'url', 'path', 'entry_points'
    ]
)


ActivatedExtension = namedtuple(
    'ActivatedExtension',
    [
        'name', 'version', 'author', 'author_email',
        'description', 'url', 'location', 'entry_points'
    ]
)


ExternalExtension = namedtuple(
    'ExternalExtension',
    [
        'name', 'version', 'author', 'author_email',
        'description', 'url', 'path', 'activated',
        'installed', 'entry_points'
    ]
)


def _egg_link_path(dist):
    for path_item in sys.path:
        egg_link = os.path.join(path_item, dist.project_name + '.egg-link')
        LOG.debug('{}'.format(egg_link))
        if os.path.isfile(egg_link):
            return egg_link
    return None


def _read_metadata(metadata_str):
    return Parser().parsestr(metadata_str)


def _read_entry_points(ep_contents):
    ep_map = EntryPoint.parse_map(ep_contents)

    for _, epgroup in ep_map.iteritems():
        for epname, ep in epgroup.iteritems():
            epgroup[epname] = str(ep)

    return ep_map


def _activated_extensions():
    epgroups = (
        minemeld.loader.MM_NODES_ENTRYPOINT,
        minemeld.loader.MM_NODES_GCS_ENTRYPOINT,
        minemeld.loader.MM_NODES_VALIDATORS_ENTRYPOINT,
        minemeld.loader.MM_PROTOTYPES_ENTRYPOINT,
        minemeld.loader.MM_API_ENTRYPOINT,
        minemeld.loader.MM_WEBUI_ENTRYPOINT
    )

    activated_extensions = {}

    for epgroup in epgroups:
        for _, epvalue in minemeld.loader.map(epgroup).iteritems():
            if epvalue.ep.dist.project_name == 'minemeld-core':
                continue

            location = 'site-packages'
            egg_link = _egg_link_path(epvalue.ep.dist)
            if egg_link is not None:
                with open(egg_link, 'r') as f:
                    location = f.readline().strip()

            metadata = {
                'name': epvalue.ep.dist.project_name,
                'version': epvalue.ep.dist.version,
                'author': None,
                'author_email': None,
                'description': None,
                'url': None,
                'entry_points': None
            }
            if egg_link:
                try:
                    with open(os.path.join(location, 'minemeld.json'), 'r') as f:
                        dist_metadata = json.load(f)
                    for k in metadata.keys():
                        metadata[k] = dist_metadata.get(k, None)

                except (IOError, OSError) as excpt:
                    LOG.error('Error loading metatdata from {}: {}'.format(location, str(excpt)))

            elif epvalue.ep.dist.has_metadata('METADATA'):
                dist_metadata = _read_metadata(
                    epvalue.ep.dist.get_metadata('METADATA')
                )
                for k in metadata.keys():
                    if k in METADATA_MAP and METADATA_MAP[k] in dist_metadata:
                        metadata[k] = dist_metadata[METADATA_MAP[k]]

                if epvalue.ep.dist.has_metadata('entry_points.txt'):
                    metadata['entry_points'] = _read_entry_points(
                        epvalue.ep.dist.get_metadata('entry_points.txt')
                    )

            activated_extensions[epvalue.ep.dist.project_name] = ActivatedExtension(
                location=location,
                **metadata
            )

    return activated_extensions


def _load_metadata_from_wheel(extpath, extname=None):
    wheel_name = extname
    if extname is None:
        wheel_name = os.path.basename(extpath)

    project_name, version, _ = wheel_name.split('-', 2)
    metadata_path = '{}-{}.dist-info/METADATA'.format(project_name, version)

    with ZipFile(extpath, 'r') as wheel_file:
        metadata_file = wheel_file.open(metadata_path, 'r')
        metadata_lines = metadata_file.read()

    metadata = _read_metadata(metadata_lines)

    # classifier framework :: minemeld should be in METADATA
    # for this to be an extension
    classifiers = metadata.get_all('Classifier')
    if classifiers is None:
        return None

    for c in classifiers:
        if c.lower() == 'framework :: minemeld':
            break
    else:
        return None

    ie_metadata = {}
    for field in InstalledExtension._fields:
        if field == 'path' or field == 'entry_points':
            continue
        ie_metadata[field] = metadata.get(METADATA_MAP[field], None)

    entry_points = None

    try:
        ep_path = '{}-{}.dist-info/entry_points.txt'.format(project_name, version)
        with ZipFile(extpath, 'r') as wheel_file:
            ep_file = wheel_file.open(ep_path, 'r')
            ep_contents = ep_file.read()

        entry_points = _read_entry_points(ep_contents)

    except (IOError, OSError):
        pass

    ie_metadata['entry_points'] = entry_points

    return InstalledExtension(
        path=extpath,
        **ie_metadata
    )


def _load_metadata_from_dir(extpath):
    with open(os.path.join(extpath, 'minemeld.json'), 'r') as f:
        metadata = json.load(f)

    return InstalledExtension(
        name=metadata['name'],
        version=metadata['version'],
        author=metadata['author'],
        author_email=metadata.get('author_email', None),
        description=metadata.get('description', None),
        url=metadata.get('url', None),
        entry_points=metadata.get('entry_points', None),
        path=extpath
    )


def _is_activated(installed_extension, activated):
    activated_extension = activated.get(installed_extension.name, None)
    if activated_extension is None:
        return False

    if activated_extension.version != installed_extension.version:
        return False

    if installed_extension.path == activated_extension.location:
        return True

    if activated_extension.location == 'site-packages' and \
       installed_extension.path.endswith('.whl'):
        return True

    return False


def get_metadata_from_wheel(wheelpath, wheelname=None):
    return _load_metadata_from_wheel(wheelpath, wheelname)


def installed_extensions(installation_dir):
    _installed_extensions = []

    entries = os.listdir(installation_dir)

    for e in entries:
        epath = os.path.join(installation_dir, e)

        # check if this is a wheel
        if e.endswith('.whl'):
            try:
                installed_extension = _load_metadata_from_wheel(epath)
                if installed_extension is None:
                    continue

                _installed_extensions.append(installed_extension)

            except (ValueError, IOError, KeyError, OSError) as excpt:
                LOG.error(u'Error extracting metadata from {}: {}'.format(e, str(excpt)))

        # check if it is a directory
        elif os.path.isdir(epath):
            try:
                installed_extension = _load_metadata_from_dir(epath)
                if installed_extension is None:
                    continue

                _installed_extensions.append(installed_extension)

            except (IOError, OSError, KeyError) as excpt:
                LOG.error(u'Error extracting metadata from {}: {}'.format(e, str(excpt)))

    return _installed_extensions


def activated_extensions():
    return _activated_extensions()


def extensions(installation_dir):
    _extensions = []

    _installed = installed_extensions(installation_dir)
    _activated = activated_extensions()

    for installed_extension in _installed:
        _extension_activated = _is_activated(installed_extension, _activated)
        _extensions.append(ExternalExtension(
            installed=True,
            activated=_extension_activated,
            **installed_extension._asdict()
        ))
        if _extension_activated:
            _activated.pop(installed_extension.name)

    for _activated_extension in _activated.values():
        _adict = _activated_extension._asdict()
        _adict.pop('location')
        _extensions.append(ExternalExtension(
            installed=False,
            activated=True,
            path=None,
            **_adict
        ))

    return _extensions


def freeze(installation_dir):
    _freeze = []

    _extensions = extensions(installation_dir)

    for e in _extensions:
        if not e.activated:
            continue

        if not e.installed:
            continue

        if e.path.endswith('.whl'):
            _freeze.append(e.path)
        else:
            _freeze.append('-e {}'.format(e.path))

    return _freeze


def load_frozen_paths(freeze_file):
    for l in freeze_file:
        l = l.strip()
        if not l.startswith('-e '):
            continue

        _, epath = l.split(' ', 1)
        if epath not in sys.path:
            LOG.info('Extension path {!r} not in sys.path, adding'.format(epath))
            sys.path.append(epath)
