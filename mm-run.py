#!/usr/bin/env python

from __future__ import print_function

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import sys
import os.path
import logging
import time
import signal
import multiprocessing
import argparse
import yaml
import shutil
import os

import minemeld.chassis
import minemeld.mgmtbus

from minemeld import __version__

LOG = logging.getLogger(__name__)

COMMITTED_CONFIG = 'committed-config.yml'

RUNNING_CONFIG = 'running-config.yml'


def _run_chassis(fabricconfig, mgmtbusconfig, fts):
    try:
        c = minemeld.chassis.Chassis(
            fabricconfig['class'],
            fabricconfig['args'],
            mgmtbusconfig['class'],
            mgmtbusconfig['args']
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
        config['class'],
        config['args'],
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


def _load_config(path):
    if os.path.isdir(path):
        ccpath = os.path.join(
            path,
            COMMITTED_CONFIG
        )
        rcpath = os.path.join(
            path,
            RUNNING_CONFIG
        )

        cconfig = None
        if os.path.exists(ccpath):
            with open(ccpath, 'r') as cf:
                cconfig = yaml.safe_load(cf)

        rcconfig = None
        if os.path.exists(rcpath):
            with open(rcpath, 'r') as cf:
                rcconfig = yaml.safe_load(cf)

        if rcconfig is None and cconfig is None:
            print(
                "At least one of", RUNNING_CONFIG,
                "or", COMMITTED_CONFIG,
                "should exist in", path,
                file=sys.stderr
            )
            sys.exit(1)
        elif rcconfig is not None and cconfig is None:
            rcconfig['newconfig'] = False
            return rcconfig
        elif rcconfig is None and cconfig is not None:
            shutil.copyfile(ccpath, rcpath)
            cconfig['newconfig'] = True
            return cconfig
        elif rcconfig is not None and cconfig is not None:
            # ugly
            if yaml.dump(cconfig) != yaml.dump(rcconfig):
                shutil.copyfile(rcpath, rcpath+'.%d' % int(time.time()))
                shutil.copyfile(ccpath, rcpath)
                cconfig['newconfig'] = True
                return cconfig

            rcconfig['newconfig'] = False
            return rcconfig

    with open(path, 'r') as cf:
        config = yaml.safe_load(cf)

    config['newconfig'] = True

    return config


def main():
    def _sigint_handler():
        mbusmaster.checkpoint_graph()
        for p in processes:
            os.kill(p.pid, signal.SIGUSR1)
        raise KeyboardInterrupt('Ctrl-C from _sigint_handler')

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

    config = _load_config(args.config)
    LOG.info("mm-run.py config: %s", config)

    if 'fabric' not in config:
        config['fabric'] = {
            'class': 'minemeld.fabric.AMQP',
            'args': {}
        }

    if 'mgmtbus' not in config:
        config['mgmtbus'] = {
            'class': 'AMQP',
            'args': {}
        }

    np = args.multiprocessing
    if np == 0:
        np = multiprocessing.cpu_count()
    LOG.info("multiprocessing active, #cpu: %d", np)

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

    mbusmaster = _start_mgmtbus_master(
        config['mgmtbus'],
        config['nodes'].keys()
    )
    mbusmaster.init_graph(config['newconfig'])

    gevent.signal(signal.SIGINT, _sigint_handler)
    gevent.signal(signal.SIGTERM, _sigint_handler)

    mbusmaster.start_status_monitor()

    try:
        while True:
            r = [int(t.is_alive()) for t in processes]
            if sum(r) != len(processes):
                LOG.info("One of the chassis has stopped, exit")
                break

            try:
                mbusmaster.get(block=False, timeout=None)
            except gevent.Timeout:
                pass
            else:
                LOG.error("We should not be here !")
                break

            gevent.sleep(1)

    except KeyboardInterrupt:
        LOG.info("Ctrl-C received, exiting")
    except:
        LOG.exception("Exception in main loop")


if __name__ == "__main__":
    main()
