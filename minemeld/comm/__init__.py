from __future__ import absolute_import

from .amqp import AMQP


def factory(commclass, config):
    if commclass != 'AMQP':
        raise RuntimeError('Unknown comm class %s', commclass)

    return AMQP(config)
