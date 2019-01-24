from __future__ import absolute_import

from .zmqredis import ZMQRedis


def factory(commclass, config):
    if commclass == 'ZMQRedis':
        return ZMQRedis(config)

    return ZMQRedis(config)
