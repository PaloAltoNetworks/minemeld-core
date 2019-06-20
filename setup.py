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

import json
from setuptools import Extension, setup, find_packages

try:
    from Cython.Build import cythonize
except ImportError:
    # this is for platter
    cythonize = lambda x: x

import sys
import os.path
sys.path.insert(0, os.path.abspath('.'))
from minemeld import __version__

with open('nodes.json') as f:
    _entry_points = {
        'minemeld_nodes': [],
        'minemeld_nodes_gcs': [],
        'minemeld_nodes_validators': []
    }
    _nodes = json.load(f)
    for node, v in _nodes.iteritems():
        _entry_points['minemeld_nodes'].append(
            '{} = {}'.format(node, v['class'])
        )
        if 'gc' in v:
            _entry_points['minemeld_nodes_gcs'].append(
                '{} = {}'.format(node, v['gc'])
            )
        if 'validator' in v:
            _entry_points['minemeld_nodes_validators'].append(
                '{} = {}'.format(node, v['validator'])
            )


with open('requirements.txt') as f:
    _requirements = f.read().splitlines()

with open('README.md') as f:
    _long_description = f.read()

_packages = find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"])

GDNS = Extension(
    name='minemeld.packages.gdns._ares',
    sources=['minemeld/packages/gdns/_ares.pyx'],
    include_dirs=[],
    libraries=['cares'],
    define_macros=[('HAVE_NETDB_H', '')],
    depends=['minemeld/packages/gdns/dnshelper.c']
)

setup(
    name='minemeld-core',
    version=__version__,
    url='https://github.com/PaloAltoNetworks-BD/minemeld-core',
    author='Palo Alto Networks',
    author_email='techbizdev@paloaltonetworks.com',
    description='An extensible indicator processing framework',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: Internet'
    ],
    long_description=_long_description,
    packages=_packages,
    provides=['minemeld'],
    install_requires=_requirements,
    ext_modules=cythonize([GDNS]),
    entry_points={
        'console_scripts': [
            'mm-run = minemeld.run.launcher:main',
            'mm-console = minemeld.run.console:main',
            'mm-traced = minemeld.traced.main:main',
            'mm-traced-purge = minemeld.traced.purge:main',
            'mm-supervisord-listener = minemeld.supervisord.listener:main',
            'mm-extensions-freeze = minemeld.run.freeze:main',
            'mm-cacert-merge = minemeld.run.cacert_merge:main',
            'mm-restore = minemeld.run.restore:main',
            'mm-extension-from-git = minemeld.run.extgit:main'
        ],
        'minemeld_nodes': _entry_points['minemeld_nodes'],
        'minemeld_nodes_gcs': _entry_points['minemeld_nodes_gcs'],
        'minemeld_nodes_validators': _entry_points['minemeld_nodes_validators']
    }
)
