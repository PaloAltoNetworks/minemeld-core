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
import math

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
            LOG.info('power off')

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
        help='enable multiprocessing. NP is the number of chassis, '
             '0 to use two chassis per machine core (default)'
    )
    parser.add_argument(
        '--nodes-per-chassis',
        default=5.0,
        type=float,
        action='store',
        metavar='NPC',
        help='number of nodes per chassis (default 4)'
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
    mbusmaster = None

    def _sigint_handler():
        LOG.info('SIGINT received')

        if mbusmaster is not None:
            mbusmaster.checkpoint_graph()

        with processes_lock:
            for p in processes:
                os.kill(p.pid, signal.SIGUSR1)
            while sum([int(t.is_alive()) for t in processes]) != 0:
                gevent.sleep(1)

        signal_received.set()

    def _sigterm_handler():
        LOG.info('SIGTERM received')

        if mbusmaster is not None:
            mbusmaster.checkpoint_graph()

        with processes_lock:
            for p in processes:
                os.kill(p.pid, signal.SIGUSR1)
            while sum([int(t.is_alive()) for t in processes]) != 0:
                gevent.sleep(1)

        signal_received.set()

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

    # make config dir available to nodes
    cdir = args.config
    if not os.path.isdir(cdir):
        cdir = os.path.dirname(args.config)
    os.environ['MM_CONFIG_DIR'] = cdir

    # load and validate config
    config = minemeld.run.config.load_config(args.config)

    LOG.info("mm-run.py config: %s", config)

    np = args.multiprocessing
    if np == 0:
        np = multiprocessing.cpu_count()*2
    LOG.info('multiprocessing: #cores: %d', multiprocessing.cpu_count())
    LOG.info("multiprocessing: max #chassis: %d", np)

    npc = args.nodes_per_chassis
    if npc <= 0:
        LOG.critical('nodes-per-chassis should be a positive integer')
        return 1

    np = min(
        int(math.ceil(len(config.nodes)/npc)),
        np
    )
    LOG.info("Number of chassis: %d", np)

    ftlists = [{} for j in range(np)]
    j = 0
    for ft in config.nodes:
        pn = j % len(ftlists)
        ftlists[pn][ft] = config.nodes[ft]
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
                config.fabric,
                config.mgmtbus,
                g
            )
        )
        processes.append(p)
        p.start()

    processes_lock = gevent.lock.BoundedSemaphore()
    signal_received = gevent.event.Event()

    gevent.signal(signal.SIGINT, _sigint_handler)
    gevent.signal(signal.SIGTERM, _sigterm_handler)

    LOG.info('Waiting 5s for chassis to get ready')
    gevent.sleep(5)

    mbusmaster = _start_mgmtbus_master(
        config.mgmtbus,
        config.nodes.keys()
    )
    mbusmaster.init_graph(config)
    mbusmaster.start_status_monitor()

    try:
        while not signal_received.wait(timeout=1.0):
            with processes_lock:
                r = [int(t.is_alive()) for t in processes]
                if sum(r) != len(processes):
                    LOG.info("One of the chassis has stopped, exit")
                    break

    except KeyboardInterrupt:
        LOG.info("Ctrl-C received, exiting")
    except:
        LOG.exception("Exception in main loop")
