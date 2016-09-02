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

with open('requirements.txt') as f:
    _requirements = f.read().splitlines()

with open('dependency-links.txt') as f:
    _dependency_links = f.read().splitlines()

with open('README.md') as f:
    _long_description = f.read()

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
    packages=find_packages(),
    install_requires=_requirements,
    dependency_links=_dependency_links,
    ext_modules=cythonize([GDNS]),
    entry_points={
        'console_scripts': [
            'mm-run = minemeld.run.launcher:main',
            'mm-console = minemeld.run.console:main',
            'mm-traced = minemeld.traced.main:main',
            'mm-traced-purge = minemeld.traced.purge:main'
        ]
    }
)
