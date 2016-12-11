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
import ujson

from . import base

LOG = logging.getLogger(__name__)


class RedisSet(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.redis_skey = name
        self.redis_skey_value = name+'.value'
        self.redis_skey_chkp = name+'.chkp'

        self.SR = None

        super(RedisSet, self).__init__(name, chassis, config)

    def configure(self):
        super(RedisSet, self).configure()

        self.redis_host = self.config.get('redis_host', '127.0.0.1')
        self.redis_port = self.config.get('redis_port', 6379)
        self.redis_password = self.config.get('redis_password', None)
        self.redis_db = self.config.get('redis_db', 0)
        self.scoring_attribute = self.config.get(
            'scoring_attribute',
            'last_seen'
        )
        self.store_value = self.config.get('store_value', False)

    def connect(self, inputs, output):
        output = False
        super(RedisSet, self).connect(inputs, output)

    def read_checkpoint(self):
        self._connect_redis()
        self.last_checkpoint = self.SR.get(self.redis_skey_chkp)
        self.SR.delete(self.redis_skey_chkp)

    def create_checkpoint(self, value):
        self._connect_redis()
        self.SR.set(self.redis_skey_chkp, value)

    def _connect_redis(self):
        if self.SR is not None:
            return

        self.SR = redis.StrictRedis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password,
            db=self.redis_db
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
        with self.SR.pipeline() as p:
            p.multi()

            p.zadd(self.redis_skey, score, indicator)
            if self.store_value:
                p.hset(self.redis_skey_value, indicator, ujson.dumps(value))

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
        base.BaseFT.gc(name, config=config)

        if config is None:
            config = {}

        redis_skey = name
        redis_skey_value = '{}.value'.format(name)
        redis_skey_chkp = '{}.chkp'.format(name)
        redis_host = config.get('redis_host', '127.0.0.1')
        redis_port = config.get('redis_port', 6379)
        redis_password = config.get('redis_password', None)
        redis_db = config.get('redis_db', 0)

        cp = None
        try:
            cp = redis.ConnectionPool(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                db=redis_db,
                socket_timeout=10
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
