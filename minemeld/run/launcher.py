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

from __future__ import print_function

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import os.path
import logging
import signal
import multiprocessing
import argparse
import os
import sys

import minemeld.chassis
import minemeld.mgmtbus
import minemeld.run.config

from minemeld import __version__

LOG = logging.getLogger(__name__)


def _run_chassis(fabricconfig, mgmtbusconfig, fts):
    try:
        # lower priority to make master and web
        # more "responsive"
        os.nice(5)

        c = minemeld.chassis.Chassis(
            fabricconfig['class'],
            fabricconfig['config'],
            mgmtbusconfig
        )
        c.configure(fts)

        while not c.fts_init():
            gevent.sleep(1)

        gevent.signal(signal.SIGUSR1, c.stop)

        try:
            c.start()
            c.poweroff.wait()
        except KeyboardInterrupt:
            LOG.error("We should not be here !")
            c.stop()

    except:
        LOG.exception('Exception in chassis main procedure')
        raise


def _start_mgmtbus_master(config, ftlist):
    mbusmaster = minemeld.mgmtbus.master_factory(
        config['master'],
        config['transport']['class'],
        config['transport']['config'],
        ftlist
    )
    mbusmaster.start()

    return mbusmaster


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Low-latency threat indicators processor"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=__version__
    )
    parser.add_argument(
        '--multiprocessing',
        default=0,
        type=int,
        action='store',
        metavar='NP',
        help='enable multiprocessing. NP is the number of processes, '
             '0 to use a process per machine core'
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


def main():
    def _sigint_handler():
        mbusmaster.checkpoint_graph()
        for p in processes:
            os.kill(p.pid, signal.SIGUSR1)
        raise KeyboardInterrupt('Ctrl-C from _sigint_handler')

    def _sigterm_handler():
        mbusmaster.checkpoint_graph()
        for p in processes:
            os.kill(p.pid, signal.SIGUSR1)

    args = _parse_args()

    # logging
    loglevel = logging.INFO
    if args.verbose:
        loglevel = logging.DEBUG

    logging.basicConfig(
        level=loglevel,
        format="%(asctime)s (%(process)d)%(module)s.%(funcName)s"
               " %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    LOG.info("Starting mm-run.py version %s", __version__)
    LOG.info("mm-run.py arguments: %s", args)

    # load and validate config
    config = minemeld.run.config.load_config(args.config)
    vresults = minemeld.run.config.validate_config(config)
    if len(vresults) != 0:
        LOG.critical('Invalid config: %s', ', '.join(vresults))
        sys.exit(1)

    LOG.info("mm-run.py config: %s", config)

    # make config dir available to nodes
    cdir = args.config
    if not os.path.isdir(cdir):
        cdir = os.path.dirname(args.config)
    os.environ['MM_CONFIG_DIR'] = cdir

    np = args.multiprocessing
    if np == 0:
        np = multiprocessing.cpu_count()
    LOG.info("multiprocessing active, #cpu: %d", np)

    np = min(len(config['nodes']), np)
    LOG.info("Number of chassis: %d", np)

    ftlists = [{} for j in range(np)]
    j = 0
    for ft in config['nodes']:
        pn = j % len(ftlists)
        ftlists[pn][ft] = config['nodes'][ft]
        j += 1

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    processes = []
    for g in ftlists:
        if len(g) == 0:
            continue

        p = multiprocessing.Process(
            target=_run_chassis,
            args=(
                config['fabric'],
                config['mgmtbus'],
                g
            )
        )
        processes.append(p)
        p.start()

    LOG.info('Waiting for chassis getting ready')
    gevent.sleep(5)

    gevent.signal(signal.SIGINT, _sigint_handler)
    gevent.signal(signal.SIGTERM, _sigterm_handler)

    mbusmaster = _start_mgmtbus_master(
        config['mgmtbus'],
        config['nodes'].keys()
    )
    mbusmaster.init_graph(config['newconfig'])

    mbusmaster.start_status_monitor()

    try:
        while True:
            r = [int(t.is_alive()) for t in processes]
            if sum(r) != len(processes):
                LOG.info("One of the chassis has stopped, exit")
                break

            gevent.sleep(1)

    except KeyboardInterrupt:
        LOG.info("Ctrl-C received, exiting")
    except:
        LOG.exception("Exception in main loop")
