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

from setuptools import setup, find_packages

import sys
import os.path
sys.path.insert(0, os.path.abspath('.'))
from minemeld import __version__

with open('requirements.txt') as f:
    _requirements = f.read().splitlines()

with open('README.md') as f:
    _long_description = f.read()

setup(
    name='minemeld-core',
    version=__version__,
    url='https://github.com/PaloAltoNetworks-BD/minemeld-core',
    author='Palo Alto Networks',
    author_email='techbizdev@paloaltonetworks.com',
    description='Low-latency threat indicators processor',
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
    entry_points={
        'console_scripts': [
            'mm-run = minemeld.run.launcher:main',
            'mm-console = minemeld.run.console:main',
            'mm-traced = minemeld.traced.main:main'
        ]
    }
)
