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
    license='Apache',
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
            'mm-console = minemeld.run.console:main'
        ]
    }
)
