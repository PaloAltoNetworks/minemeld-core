#  Copyright 2019 Palo Alto Networks, Inc
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

import sys
import logging
import argparse
import subprocess
import os.path
import shutil

from minemeld import __version__


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Install MineMeld extension from git repo"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=__version__
    )
    parser.add_argument(
        'git_path',
        action='store',
        metavar='GIT_PATH',
        help='path of git executable'
    )
    parser.add_argument(
        'git_ref',
        action='store',
        metavar='GIT_REF',
        help='git reference'
    )
    parser.add_argument(
        'git_endpoint',
        action='store',
        metavar='GIT_ENDPOINT',
        help='git endpoint'
    )
    parser.add_argument(
        'install_directory',
        action='store',
        metavar='INSTALL_DIRECTORY',
        help='directory to install the extension into'
    )
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG)

    args = _parse_args()

    git_args = [
        args.git_path,
        'clone',
        '-b', args.git_ref,
        '--depth', '1',
        args.git_endpoint,
        args.install_directory
    ]
    logging.info('Calling git: {!r}'.format(git_args))
    subprocess.check_call(git_args)

    if not os.path.exists(os.path.join(args.install_directory, 'minemeld.json')):
        logging.error('minemeld.json does not exists in install directory - invalid extension')
        try:
            shutil.rmtree(args.install_directory)
        except Exception as _:
            logging.exception('Error removing install directory')

        sys.exit(1)

    sys.exit(0)
