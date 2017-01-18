#!/usr/bin/env python

import logging
import os
import time
import sys
import argparse
import shutil
import json
import xmlrpclib
import supervisor.xmlrpc

LOG = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Purge utility for old MineMeld traces"
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Dry run'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Delete all traces'
    )
    parser.add_argument(
        'config',
        action='store',
        metavar='CONFIG',
        nargs='?',
        help='path of the config file or of the config directory'
    )
    return parser.parse_args()


def stop_minemeld_traced(supervisor_url):
    sserver = xmlrpclib.ServerProxy(
        'http://127.0.0.1',
        transport=supervisor.xmlrpc.SupervisorTransport(
            None,
            None,
            supervisor_url
        )
    )

    sstate = sserver.supervisor.getState()
    if sstate['statecode'] == 2:  # FATAL
        return False
    if sstate['statecode'] != 1:
        LOG.critical(
            "Supervisor transitioning to a new state, we will purge next time"
        )
        sys.exit(1)

    pstate = sserver.supervisor.getProcessInfo('minemeld-traced')['statename']
    if pstate in ['STOPPED', 'EXITED', 'FATAL']:
        return False
    if pstate != 'RUNNING':
        LOG.critical(
            ("minemeld-traced transitioning to a new state, " +
             "we will purge next time")
        )
        sys.exit(1)

    result = sserver.supervisor.stopProcess('minemeld-traced', False)
    if not result:
        LOG.critical('Stop minemeld-traced returned False')
        sys.exit(1)

    LOG.info('Stopping minemeld-traced')

    now = time.time()
    info = None
    while (time.time()-now) < 60*15*1000:
        info = sserver.supervisor.getProcessInfo('minemeld-traced')
        if info['statename'] == 'STOPPED':
            break
        time.sleep(5)

    if info is not None and info['statename'] != 'STOPPED':
        LOG.critical('Timeout during minemeld-traced stop')
        sys.exit(1)

    return True


def start_minemeld_traced(supervisor_url):
    sserver = xmlrpclib.ServerProxy(
        'http://127.0.0.1',
        transport=supervisor.xmlrpc.SupervisorTransport(
            None,
            None,
            supervisor_url
        )
    )

    sserver.supervisor.startProcess('minemeld-traced', False)
    LOG.info('Started minemeld-traced')


def main():
    trace_directory = '/opt/minemeld/local/trace'
    supervisor_url = 'unix:///var/run/minemeld/minemeld.sock'
    num_days = 30

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    args = _parse_args()

    if args.config is not None:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)

        except (IOError, ValueError) as e:
            LOG.critical(
                'Error loading config file %s: %s' % (args.config, str(e))
            )
            sys.exit(1)

        trace_directory = config.get('trace_directory', trace_directory)
        supervisor_url = config.get('supervisor_url', supervisor_url)
        num_days = config.get('num_days', num_days)

    trace_directory = os.environ.get(
        'MINEMELD_TRACE_DIRECTORY',
        trace_directory
    )
    if not os.path.isdir(trace_directory):
        LOG.critical("%s is not a directory", trace_directory)
        sys.exit(1)

    num_days = int(os.environ.get('MINEMELD_TRACE_NUM_DAYS', num_days))
    if num_days < 1:
        LOG.critical(
            'MINEMELD_TRACE_NUM_DAYS should be greater than 1: %d',
            num_days
        )
        sys.exit(1)

    supervisor_url = os.environ.get(
        'SUPERVISOR_URL',
        supervisor_url
    )

    LOG.info(
        "mm-traced-purge started, #days: %d directory: %s",
        num_days,
        trace_directory
    )

    now = time.time()
    today = now - (now % 86400)
    oldest = today - (num_days-1)*86400

    tables = os.listdir(trace_directory)
    tobe_removed = []
    for t in tables:
        try:
            d = int(t, 16)
        except ValueError:
            LOG.debug("Invalid table name: %s", t)
            continue

        if d < oldest or args.all:
            LOG.info('Marking table %s for removal', t)
            tobe_removed.append(t)

    if len(tobe_removed) > 0 and not args.dry_run:
        trunning = stop_minemeld_traced(supervisor_url)

        for tr in tobe_removed:
            LOG.info("Removing %s", tr)
            try:
                shutil.rmtree(os.path.join(trace_directory, tr))
            except:
                LOG.exception("Error removing table %s", tr)

        if trunning:
            start_minemeld_traced(supervisor_url)
