#!/usr/bin/env python

import os
import signal
import time
import logging
import argparse
import xmlrpclib
from zipfile import ZipFile
from collections import deque
from contextlib import contextmanager

import yaml
import redis
import supervisor.xmlrpc


REDIS_KEY_PREFIX = 'mm:config:'


LOG = logging.getLogger(__name__)


class BFile(object):
    def __init__(self, zip_path, type_, extracted_path=None, target_path=None):
        self.zip_path = zip_path
        self.type_ = type_
        self.extracted_path = extracted_path
        self.target_path = target_path

    def __repr__(self):
        return '{}({}) => {}({})'.format(
            self.zip_path,
            self.type_,
            self.target_path,
            self.extracted_path
        )


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Restore full MineMeld backup"
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Dry run'
    )
    parser.add_argument(
        '--configuration-path',
        action='store',
        help='Path to restore configuration files to'
    )
    parser.add_argument(
        '--prototypes-path',
        action='store',
        help='Path to restore prototypes to'
    )
    parser.add_argument(
        '--feeds-aaa-path',
        action='store',
        help='Path to restore feeds AAA configuration to'
    )
    parser.add_argument(
        '--feeds-aaa',
        action='append',
        help='Restore feeds AAA configuration'
    )
    parser.add_argument(
        '--certificates-path',
        action='store',
        help='Path to restore certificates to'
    )
    parser.add_argument(
        '--password',
        action='store',
        help='Password for the backup file'
    )
    parser.add_argument(
        'backup',
        action='store',
        help='path of the backup file'
    )
    return parser.parse_args()


class ContextManagerStack(object):
    def __init__(self):
        self._stack = deque()

    def enter(self, cm):
        result = cm.__enter__()
        self._stack.append(cm.__exit__)

        return result

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        while self._stack:
            cb = self._stack.pop()
            cb(*exc_info)


@contextmanager
def handle_minemeld_engine(supervisor_url):
    sserver = xmlrpclib.ServerProxy(
        'http://127.0.0.1',
        transport=supervisor.xmlrpc.SupervisorTransport(
            None,
            None,
            supervisor_url
        )
    )

    # check supervisor state
    sstate = sserver.supervisor.getState()
    if sstate['statecode'] == 2:  # FATAL
        raise RuntimeError('Supervisor state: 2')

    if sstate['statecode'] != 1:
        raise RuntimeError(
            "Supervisor transitioning to a new state, restore not performed"
        )

    # check minemeld-engine state
    pstate = sserver.supervisor.getProcessInfo('minemeld-engine')['statename']
    if pstate not in ['STOPPED', 'EXITED', 'FATAL', 'RUNNING']:
        raise RuntimeError(
            ("minemeld-engine transitioning to a new state, " +
             "restore not performed")
        )

    # if minemeld-engine state is running, stop it
    if pstate == 'RUNNING':
        result = sserver.supervisor.stopProcess('minemeld-engine', False)
        if not result:
            raise RuntimeError('Stop minemeld-engine returned False')

        LOG.info('Stopping minemeld-engine')

        now = time.time()
        info = None
        while (time.time()-now) < 60*15*1000:
            info = sserver.supervisor.getProcessInfo('minemeld-engine')
            if info['statename'] == 'STOPPED':
                break
            time.sleep(5)

        if info is not None and info['statename'] != 'STOPPED':
            raise RuntimeError('Timeout during minemeld-engine stop')
    else:
        LOG.info('minemeld-engine not running: {}'.format(pstate))

    yield

    # we restart only if no Exception have been raised by other tasks
    sserver.supervisor.startProcess('minemeld-engine', False)
    started_at = time.time()

    # check minemeld-engine state
    pstate = sserver.supervisor.getProcessInfo('minemeld-engine')['statename']
    while pstate != 'RUNNING':
        LOG.info('minemeld-engine state: {}'.format(pstate))

        if pstate == 'FATAL':
            raise RuntimeError('minemeld-engine failed to start')

        if (time.time() - started_at) > 40:
            raise RuntimeError('minemeld-engine didn\'t start in 40 seconds')

        time.sleep(1)

        pstate = sserver.supervisor.getProcessInfo('minemeld-engine')['statename']

    LOG.info('Started minemeld-engine')


@contextmanager
def extract_file(backup_id, bfile, efile, configuration_path, prototypes_path, feeds_aaa_path, certificates_path):
    if efile.type_ == 'configuration':
        new_path = configuration_path
    elif efile.type_ == 'prototypes':
        new_path = prototypes_path
    elif efile.type_ == 'feeds_aaa':
        new_path = feeds_aaa_path
    elif efile.type_ == 'certificates':
        new_path = certificates_path
        if efile.zip_path.startswith('certs/site'):
            new_path = os.path.join(certificates_path, '/site')
    else:
        raise RuntimeError('Unknown file type: {!r}'.format(efile))
    new_path = os.path.join(
        new_path,
        '{}'.format(os.path.basename(efile.zip_path))
    )
    extracted_path = '{}.{}'.format(new_path, backup_id)
    LOG.info('Extracting {} to {}'.format(efile.zip_path, extracted_path))
    efile.extracted_path = extracted_path
    efile.target_path = new_path

    fin = bfile.open(efile.zip_path, 'r')
    with open(extracted_path, 'w') as fout:
        while True:
            b = fin.read(1024 * 1024)
            if not b:
                break
            fout.write(b)

    try:
        yield

    except:
        try:
            os.remove(extracted_path)
            LOG.info('Removed temporary file {}'.format(extracted_path))
        except:
            pass


@contextmanager
def backup_file(old_file_path):
    new_path = '{}.bak'.format(old_file_path)
    os.rename(old_file_path, new_path)

    try:
        yield

    except:
        try:
            os.rename(new_path, old_file_path)

        except:
            LOG.error('Error restoring {} to {}'.format(new_path, old_file_path))

    else:
        try:
            os.remove(new_path)
        except:
            LOG.error('Error removing backup {}'.format(new_path))


@contextmanager
def restore_file(f):
    LOG.info('Moving {} to {}'.format(f.extracted_path, f.target_path))
    os.rename(f.extracted_path, f.target_path)

    try:
        yield

    except:
        try:
            os.remove(f.target_path)
        except:
            LOG.error('Error removing extracted file during recovery: {}'.format(f.target_path))


def _list_of_configuration_files(bfile, flist):
    dir_prefix = 'config/'

    committed_config_path = os.path.join(dir_prefix, 'committed-config.yml')
    if committed_config_path not in flist:
        raise RuntimeError('No committed-config in backup')

    committed_config = yaml.safe_load(bfile.open(committed_config_path, 'r'))
    result = [BFile(zip_path=committed_config_path, type_='configuration')]
    prefixes = [os.path.join(dir_prefix, nname) for nname in committed_config['nodes']]
    for c in flist:
        if not c.startswith(dir_prefix):
            continue
        for p in prefixes:
            if c.startswith(p):
                result.append(BFile(zip_path=c, type_='configuration'))
                break

    return result


def _list_of_prototypes_files(bfile, flist):
    dir_prefix = 'prototypes/'

    result = []
    for c in flist:
        if c == dir_prefix:
            continue
        if not c.startswith(dir_prefix):
            continue

        result.append(BFile(zip_path=c, type_='prototypes'))

    return result


def _list_of_certificates_files(bfile, flist):
    # from the backup file we restore certs/config.yml
    # and all the files in certs/site/

    result = []
    for c in flist:
        if c == 'certs/site/':
            continue
        if not c == 'certs/config.yml' and not c.startswith('certs/site/'):
            continue

        result.append(BFile(zip_path=c, type_='certificates'))

    return result


def _list_of_feeds_aaa_files(faaf, bfile, flist):
    faaf_path = os.path.join('config/api/', faaf)
    if faaf_path in flist:
        return [BFile(zip_path=faaf_path, type_='feeds_aaa')]

    return []


def _reload_candidate_config(supervisor_url):
    SR = redis.StrictRedis()
    ckeys = SR.keys('{}*'.format(REDIS_KEY_PREFIX))
    if ckeys:
        for ck in ckeys:
            LOG.info('Deleting {}'.format(ck))
            SR.delete(ck)

    LOG.info('Candidate config keys deleted')

    sserver = xmlrpclib.ServerProxy(
        'http://127.0.0.1',
        transport=supervisor.xmlrpc.SupervisorTransport(
            None,
            None,
            supervisor_url
        )
    )

    # check supervisor state
    sstate = sserver.supervisor.getState()
    if sstate['statecode'] == 2:  # FATAL
        raise RuntimeError('Supervisor state: 2')

    if sstate['statecode'] != 1:
        raise RuntimeError(
            "Supervisor transitioning to a new state, restore not performed"
        )

    # check minemeld-engine state
    pinfo = sserver.supervisor.getProcessInfo('minemeld-web')
    if pinfo['statename'] != 'RUNNING':
        raise RuntimeError('minemeld-web not running, reload not sent')

    os.kill(pinfo['pid'], signal.SIGHUP)

    LOG.info('API process reloaded')


def main():
    supervisor_url = 'unix:///var/run/minemeld/minemeld.sock'

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    args = _parse_args()

    supervisor_url = os.environ.get(
        'SUPERVISOR_URL',
        supervisor_url
    )

    LOG.info('restore started: {!r}'.format(args))

    with ContextManagerStack() as cmstack:
        backup_id = os.path.basename(args.backup)
        bfile = cmstack.enter(ZipFile(args.backup, 'r'))

        if args.password:
            bfile.setpassword(args.password)

        contents = bfile.namelist()

        files = []
        if args.configuration_path:
            files.extend(_list_of_configuration_files(bfile, contents))
        if args.prototypes_path:
            files.extend(_list_of_prototypes_files(bfile, contents))
        if args.certificates_path:
            files.extend(_list_of_certificates_files(bfile, contents))
        if args.feeds_aaa_path:
            if not args.feeds_aaa:
                LOG.warning('No feeds AAA config file specified')
            else:
                for faaf in args.feeds_aaa:
                    files.extend(_list_of_feeds_aaa_files(faaf, bfile, contents))
        LOG.info('List of files to be restored: {}'.format(files))

        # stop/start minemeld-engine
        cmstack.enter(handle_minemeld_engine(supervisor_url))

        # extract files
        for f in files:
            cmstack.enter(extract_file(
                backup_id=backup_id,
                bfile=bfile,
                efile=f,
                configuration_path=args.configuration_path,
                prototypes_path=args.prototypes_path,
                feeds_aaa_path=args.feeds_aaa_path,
                certificates_path=args.certificates_path
            ))
        LOG.info('Extracted files: {}'.format(files))

        # check if I can move old files
        for f in files:
            LOG.info('Checking {} for write permissions'.format(f.target_path))
            if not os.path.exists(f.target_path):
                continue
            if not os.path.isfile(f.target_path):
                raise RuntimeError('{} is not a file !'.format(f.target_path))
            if not os.access(f.target_path, os.W_OK):
                raise RuntimeError('No permission to write to {}'.format(f.target_path))
            if not os.access(os.path.dirname(f.target_path), os.W_OK):
                raise RuntimeError('No permission to write to {}'.format(os.path.dirname(f.target_path)))

        # backup old files
        for f in files:
            if os.path.exists(f.target_path):
                cmstack.enter(backup_file(
                    f.target_path
                ))

        # move new files
        for f in files:
            cmstack.enter(restore_file(f))

    try:
        _reload_candidate_config(supervisor_url)

    except:
        LOG.exception('Error reverting candidate config')
