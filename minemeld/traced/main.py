#  Copyright 2016 Palo Alto Networks, Inc
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

"""
This module implements the main entry point to the mm-traced daemon
"""

from __future__ import print_function

import gevent
import gevent.event
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import argparse
import logging
import yaml
import functools
import signal

from minemeld import __version__

import minemeld.comm
import minemeld.traced.storage
import minemeld.traced.writer
import minemeld.traced.queryprocessor

LOG = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Tracing daemon for MineMeld engine"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=__version__
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='verbose'
    )
    parser.add_argument(
        'config',
        action='store',
        metavar='CONFIG',
        help='path of the config file or of the config directory'
    )
    return parser.parse_args()


def _ioloop_failure(event):
    LOG.debug("loop failure")
    event.set()


def main():
    def _sigint_handler():
        raise KeyboardInterrupt('Ctrl-C from _sigint_handler')

    def _sigterm_handler():
        raise KeyboardInterrupt('Ctrl-C from _sigterm_handler')

    def _cleanup():
        trace_writer.stop()
        query_processor.stop()
        store.stop()
        comm.stop()

    args = _parse_args()

    loglevel = logging.INFO
    if args.verbose:
        loglevel = logging.DEBUG

    logging.basicConfig(
        level=loglevel,
        format="%(asctime)s (%(process)d)%(module)s.%(funcName)s"
               " %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    LOG.info('Starting mm-traced version %s', __version__)
    LOG.info('mm-traced arguments: %s', args)

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
    if config is None:
        config = {}

    LOG.info('mm-traced config: %s', config)

    store = minemeld.traced.storage.Store(config.get('store', None))

    transport_config = config.get('transport', {
        'class': 'AMQP',
        'config': {
            'num_connections': 1
        }
    })
    comm = minemeld.comm.factory(
        transport_config['class'],
        transport_config['config']
    )

    trace_writer = minemeld.traced.writer.Writer(
        comm,
        store,
        topic=config.get('topic', 'mbus:log'),
        config=config.get('writer', {})
    )

    query_processor = minemeld.traced.queryprocessor.QueryProcessor(
        comm,
        store,
        config=config.get('queryprocessor', {})
    )

    shutdown_event = gevent.event.Event()
    comm.add_failure_listener(
        functools.partial(_ioloop_failure, shutdown_event)
    )

    comm.start()

    gevent.signal(signal.SIGINT, _sigint_handler)
    gevent.signal(signal.SIGTERM, _sigterm_handler)

    try:
        shutdown_event.wait()

    except KeyboardInterrupt:
        pass

    except:
        LOG.exception('Exception')

    finally:
        _cleanup()
