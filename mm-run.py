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

import minemeld.chassis
from minemeld import __version__

LOG = logging.getLogger(__name__)


def _run_chassis(fabricconfig, fts, reinit):
    c = minemeld.chassis.Chassis(
        fabricconfig['class'],
        fabricconfig['args'],
        reinit=reinit
    )
    c.configure(fts)

    gevent.signal(signal.SIGTERM, c.stop)
    gevent.signal(signal.SIGQUIT, c.stop)
    gevent.signal(signal.SIGINT, c.stop)

    try:
        c.start()
        c.poweroff.wait()
    except KeyboardInterrupt:
        LOG.debug("KeyboardInterrupt")
        c.stop()


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
        help='enable multiprocessing. np is the number of processes, '
             '-1 to use a process per machine core, 0 to disable'
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
        help='path of the config file'
    )
    return parser.parse_args()

def _load_config(path):
    if os.path.isdir(path):
        ccpath = os.path.join(
            path,
            'candidate-config.yml'
        )
        rcpath = os.path.join(
            path,
            'running-config.yml'
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
                "At least on of running-config.yml or candidate-config.yml "
                "should exist in", path,
                file=sys.stderr
            )
            sys.exit(1)
        elif rcconfig is not None and cconfig is None:
            rcconfig['reinit'] = False
            return rcconfig
        elif rcconfig is None and cconfig is not None:
            shutil.copyfile(ccpath, rcpath)
            cconfig['reinit'] = True
            return cconfig
        elif rcconfig is not None and cconfig is not None:
            # ugly
            if yaml.dump(cconfig) != yaml.dump(rcconfig):
                shutil.copyfile(rcpath, rcpath+'.%d' % int(time.time()))
                shutil.copyfile(ccpath, rcpath)
                cconfig['reinit'] = True
                return cconfig

            rcconfig['reinit'] = False
            return rcconfig

    with open(path, 'r') as cf:
        config = yaml.safe_load(cf)

    config['reinit'] = True

    return config

def main():
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

    if args.multiprocessing == 0:
        # no multiprocessing
        try:
            _run_chassis(config['fabric'], config['FTs'], config['reinit'])
        except KeyboardInterrupt:
            LOG.info('Ctrl-C received, exiting')
        except:
            LOG.exception("Exception in main loop")

    else:
        np = args.multiprocessing
        if np < 0:
            np = multiprocessing.cpu_count()
        LOG.info("multiprocessing active, #cpu: %d", np)

        ftlists = [{} for j in range(np)]
        j = 0
        for ft in config['FTs']:
            pn = j % len(ftlists)
            ftlists[pn][ft] = config['FTs'][ft]
            j += 1

        processes = []
        for g in ftlists:
            if len(g) == 0:
                continue

            p = multiprocessing.Process(
                target=_run_chassis,
                args=(config['fabric'], g, config['reinit'])
            )
            processes.append(p)
            p.start()

        try:
            while True:
                r = [int(t.is_alive()) for t in processes]
                if sum(r) != len(processes):
                    LOG.info("One of the chassis has stopped, exit")
                    break
                time.sleep(1)

        except KeyboardInterrupt:
            LOG.info("Ctrl-C received, exiting")
        except:
            LOG.exception("Exception in main loop")


if __name__ == "__main__":
    main()
