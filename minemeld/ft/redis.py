#  Copyright 2015 Palo Alto Networks, Inc
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

from __future__ import absolute_import

import logging
import redis
import os
import ujson as json

from . import base
from . import actorbase

LOG = logging.getLogger(__name__)


class RedisSet(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.redis_skey = name
        self.redis_skey_value = name+'.value'
        self.redis_skey_chkp = name+'.chkp'

        self.SR = None

        super(RedisSet, self).__init__(name, chassis, config)

    def configure(self):
        super(RedisSet, self).configure()

        self.redis_url = self.config.get('redis_url',
            os.environ.get('REDIS_URL', 'unix:///var/run/redis/redis.sock')
        )
        self.scoring_attribute = self.config.get(
            'scoring_attribute',
            'last_seen'
        )
        self.store_value = self.config.get('store_value', False)
        self.max_entries = self.config.get('max_entries', 1000 * 1000)

    def connect(self, inputs, output):
        output = False
        super(RedisSet, self).connect(inputs, output)

    def read_checkpoint(self):
        self._connect_redis()

        self.last_checkpoint = None

        config = {
            'class': (self.__class__.__module__+'.'+self.__class__.__name__),
            'config': self._original_config
        }
        config = json.dumps(config, sort_keys=True)

        try:
            contents = self.SR.get(self.redis_skey_chkp)
            if contents is None:
                raise ValueError('{} - last checkpoint not found'.format(self.name))

            if contents[0] == '{':
                # new format
                contents = json.loads(contents)
                self.last_checkpoint = contents['checkpoint']
                saved_config = contents['config']
                saved_state = contents['state']

            else:
                self.last_checkpoint = contents
                saved_config = ''
                saved_state = None

            LOG.debug('%s - restored checkpoint: %s', self.name, self.last_checkpoint)

            # old_status is missing in old releases
            # stick to the old behavior
            if saved_config and saved_config != config:
                LOG.info(
                    '%s - saved config does not match new config',
                    self.name
                )
                self.last_checkpoint = None
                return

            LOG.info(
                '%s - saved config matches new config',
                self.name
            )

            if saved_state is not None:
                self._saved_state_restore(saved_state)

        except (ValueError, IOError):
            LOG.exception('{} - Error reading last checkpoint'.format(self.name))
            self.last_checkpoint = None

    def create_checkpoint(self, value):
        self._connect_redis()

        config = {
            'class': (self.__class__.__module__+'.'+self.__class__.__name__),
            'config': self._original_config
        }

        contents = {
            'checkpoint': value,
            'config': json.dumps(config, sort_keys=True),
            'state': self._saved_state_create()
        }

        self.SR.set(self.redis_skey_chkp, json.dumps(contents))

    def remove_checkpoint(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey_chkp)

    def _connect_redis(self):
        if self.SR is not None:
            return

        self.SR = redis.StrictRedis.from_url(
            self.redis_url
        )

    def initialize(self):
        self._connect_redis()

    def rebuild(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey)
        self.SR.delete(self.redis_skey_value)

    def reset(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey)
        self.SR.delete(self.redis_skey_value)

    def _add_indicator(self, score, indicator, value):
        if self.length() >= self.max_entries:
            self.statistics['drop.overflow'] += 1
            return

        with self.SR.pipeline() as p:
            p.multi()

            p.zadd(self.redis_skey, score, indicator)
            if self.store_value:
                p.hset(self.redis_skey_value, indicator, json.dumps(value))

            result = p.execute()[0]

        self.statistics['added'] += result

    def _delete_indicator(self, indicator):
        with self.SR.pipeline() as p:
            p.multi()

            p.zrem(self.redis_skey, indicator)
            p.hdel(self.redis_skey_value, indicator)

            result = p.execute()[0]

        self.statistics['removed'] += result

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        score = 0
        if self.scoring_attribute is not None:
            av = value.get(self.scoring_attribute, None)
            if type(av) == int or type(av) == long:
                score = av
            else:
                LOG.error("scoring_attribute is not int: %s", type(av))
                score = 0

        self._add_indicator(score, indicator, value)

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        self._delete_indicator(indicator)

    def length(self, source=None):
        return self.SR.zcard(self.redis_skey)

    @staticmethod
    def gc(name, config=None):
        actorbase.ActorBaseFT.gc(name, config=config)

        if config is None:
            config = {}

        redis_skey = name
        redis_skey_value = '{}.value'.format(name)
        redis_skey_chkp = '{}.chkp'.format(name)
        redis_url = config.get('redis_url',
            os.environ.get('REDIS_URL', 'unix:///var/run/redis/redis.sock')
        )

        cp = None
        try:
            cp = redis.ConnectionPool.from_url(
                url=redis_url
            )

            SR = redis.StrictRedis(connection_pool=cp)

            SR.delete(redis_skey)
            SR.delete(redis_skey_value)
            SR.delete(redis_skey_chkp)

        except Exception as e:
            raise RuntimeError(str(e))

        finally:
            if cp is not None:
                cp.disconnect()
