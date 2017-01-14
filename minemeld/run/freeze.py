#  Copyright 2017 Palo Alto Networks, Inc
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

import minemeld.extensions
from minemeld import __version__


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Freeze MineMeld extensions"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=__version__
    )
    parser.add_argument(
        'library',
        action='store',
        metavar='LIBRARY',
        help='path of the MineMeld library directory'
    )
    parser.add_argument(
        'outfile',
        action='store',
        metavar='OUTFILE',
        default='-',
        nargs='?',
        help='path of the file to write the output to. (default: stdout)'
    )
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG)

    args = _parse_args()

    if args.outfile == '-':
        of = sys.stdout
    else:
        of = open(args.outfile, 'w+')

    frozenext = minemeld.extensions.freeze(args.library)
    for e in frozenext:
        of.write('{}\n'.format(e))

    of.close()
