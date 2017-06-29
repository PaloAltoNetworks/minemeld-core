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

import logging
import argparse
import sys
import os
import os.path

import yaml

try:
    from ssl import create_default_context
except ImportError:
    def create_default_context(cafile, cadata):
        print('WARNING: old python version (< 2.7.9) - certificate verification not performed')

try:
    import certifi
    CERTIFI_WHERE = certifi.where()
except ImportError:
    # XXX Error?
    CERTIFI_WHERE = None


LOG = logging.getLogger(__name__)


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s (%(process)d)%(module)s.%(funcName)s"
               " %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )

    parser = argparse.ArgumentParser(usage='%(prog)s [options] [cafile ...]')
    parser.add_argument('--no-merge-certifi',
                        action='store_const',
                        const=True,
                        help='do not merge certifi CA bundle '
                        '(default: merge "%s")' % CERTIFI_WHERE)
    parser.add_argument('--config',
                        help='configuration file path (default: no config)')
    parser.add_argument('--dst',
                        required=True,
                        help='destination CA bundle path')
    parser.add_argument('cafile',
                        nargs='*',
                        help='local CA bundle file(s) '
                        '(default: stdin)')
    args = parser.parse_args()

    try:
        certs = open(args.dst, 'w')
    except IOError as e:
        LOG.error('open: %s: %s' % (args.dst, e))
        return 1

    config = {
        'no_merge_certifi': False
    }

    if args.config:
        with open(args.config, 'r') as f:
            loaded_config = yaml.safe_load(f)
            if loaded_config is not None:
                config.update(loaded_config)

    config.update({k: v for k, v in vars(args).iteritems() if v is not None})
    LOG.info('config: {}'.format(config))

    if not config['no_merge_certifi'] and CERTIFI_WHERE:
        try:
            with open(CERTIFI_WHERE) as f:
                buf = f.read()
        except IOError as e:
            LOG.error('%s: %s' % (CERTIFI_WHERE, e))
            return 1
        try:
            certs.write(buf)
        except IOError as e:
            LOG.error('%s: %s' % (args.dst, e))
            return 1

    if args.cafile:
        for x in args.cafile:
            files = [x]
            if os.path.isdir(x):
                files = [os.path.join(x, e) for e in os.listdir(x)]

            for fname in files:
                verify_cafile(cafile=fname)
                try:
                    with open(fname) as f:
                        buf = f.read()
                except IOError as e:
                    LOG.error('%s: %s' % (fname, e))
                    return 1
                try:
                    certs.write(buf)
                except IOError as e:
                    LOG.error('%s: %s' % (args.dst, e))
                    return 1
    else:
        x = sys.stdin.read()
        try:
            x = unicode(x)
        except NameError:
            # 3.x
            pass
        verify_cafile(cadata=x)
        try:
            certs.write(x)
        except IOError as e:
            LOG.error('%s: %s' % (args.dst, e))
            return 1

    certs.close()
    verify_cafile(cafile=args.dst)

    return 0


def verify_cafile(cafile=None, cadata=None):
    try:
        create_default_context(cafile=cafile, cadata=cadata)
    except IOError as e:
        if cafile:
            LOG.error('Invalid cafile %s: %s' % (cafile, e))
        else:
            LOG.error('Invalid cadata: %s' % e)
        sys.exit(1)
