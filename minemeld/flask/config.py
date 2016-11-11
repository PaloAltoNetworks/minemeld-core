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

import os

import gevent
import logging

import yaml
import filelock
import passlib.apache

from . import utils

CONFIG = {}
API_CONFIG_PATH = None
API_CONFIG_LOCK = None

LOG = logging.getLogger(__name__)
CONFIG_FILES_RE = '^(?:(?:[0-9]+.*\.yml)|(?:.*\.htpasswd))$'

_AUTH_DBS = {
    'USERS_DB': 'wsgi.htpasswd',
    'FEEDS_USERS_DB': 'feeds.htpasswd'
}

def get(key, default=None):
    try:
        result = CONFIG[key]
    except KeyError:
        pass
    else:
        return result

    try:
        result = os.environ[key]
    except KeyError:
        pass
    else:
        if result == 'False':
            result = False
        if result == 'True':
            result = True

        return result

    return default


def store(file, value):
    with API_CONFIG_LOCK.acquire():
        with open(os.path.join(API_CONFIG_PATH, file), 'w+') as f:
            yaml.safe_dump(value, stream=f)


def lock():
    return API_CONFIG_LOCK.acquire()


class APIConfigDict(object):
    def __init__(self, attribute, level=50):
        self.attribute = attribute
        self.filename = '%d-%s.yml' % (level, attribute.lower().replace('_', '-'))

    def set(self, key, value):
        curvalues = get(self.attribute, {})
        curvalues[key] = value
        store(self.filename, { self.attribute: curvalues })

    def delete(self, key):
        curvalues = get(self.attribute, {})
        curvalues.pop(key, None)
        store(self.filename, { self.attribute: curvalues })

    def value(self):
        return get(self.attribute, {})


def _load_config(config_path):
    global CONFIG

    new_config = {}

    # comptaibilty early releases where all the config
    # was store in a single file
    old_config_file = os.path.join(config_path, 'wsgi.yml')
    if os.path.exists(old_config_file):
        try:
            with open(old_config_file, 'r') as f:
                add_config = yaml.safe_load(f)

            if add_config is not None:
                new_config.update(add_config)
        except OSError:
            pass

    with API_CONFIG_LOCK.acquire():
        api_config_path = os.path.join(config_path, 'api')
        if os.path.exists(api_config_path):
            config_files = sorted(os.listdir(api_config_path))

            for cf in config_files:
                if not cf.endswith('.yml'):
                    continue

                try:
                    with open(os.path.join(api_config_path, cf), 'r') as f:
                        add_config = yaml.safe_load(f)

                    if add_config is not None:
                        new_config.update(add_config)

                except (OSError, IOError, ValueError):
                    LOG.exception('Error loading config file %s' % cf)

    CONFIG = new_config
    LOG.info('Config loaded: %r', new_config)


def _load_auth_dbs(config_path):
    with API_CONFIG_LOCK.acquire():
        api_config_path = os.path.join(config_path, 'api')
        for env, default in _AUTH_DBS.iteritems():
            dbname = get(env, default)
            new_db = False

            dbpath = os.path.join(
                api_config_path,
                dbname
            )

            # for compatibility with old releases
            if not os.path.exists(dbpath):
                old_dbpath = os.path.join(
                    config_path,
                    dbname
                )
                if os.path.exists(old_dbpath):
                    dbpath = old_dbpath
                else:
                    new_db = True

            CONFIG[env] = passlib.apache.HtpasswdFile(
                path=dbpath,
                new=new_db
            )

            LOG.info('%s loaded from %s', env, dbpath)


def _config_monitor(config_path):
    api_config_path = os.path.join(config_path, 'api')
    dirsnapshot = utils.DirSnapshot(api_config_path, CONFIG_FILES_RE)
    while True:
        new_snapshot = utils.DirSnapshot(api_config_path, CONFIG_FILES_RE)

        if new_snapshot != dirsnapshot:
            try:
                _load_config(config_path)
                _load_auth_dbs(config_path)

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('Error loading config')

            dirsnapshot = new_snapshot

        gevent.sleep(1)


# initialization
def init():
    global API_CONFIG_PATH
    global API_CONFIG_LOCK

    logging.basicConfig(level=logging.DEBUG)

    config_path = os.environ.get('MM_CONFIG', None)
    if config_path is None:
        LOG.critical('MM_CONFIG environment variable not set')
        raise RuntimeError('MM_CONFIG environment variable not set')

    if not os.path.isdir(config_path):
        config_path = os.path.dirname(config_path)

    # init global vars
    API_CONFIG_PATH = os.path.join(config_path, 'api')
    API_CONFIG_LOCK = filelock.FileLock(
        os.path.join(API_CONFIG_PATH, 'config.lock')
    )

    _load_config(config_path)
    _load_auth_dbs(config_path)
    if config_path is not None:
        gevent.spawn(_config_monitor, config_path)
