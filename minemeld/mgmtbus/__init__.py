from __future__ import absolute_import

from .amqp import AMQPMaster
from .amqp import AMQPSlave


def master_factory(mgmtbusclass, mgmtbusargs, fts):
    return AMQPMaster(fts, mgmtbusargs)


def slave_factory(mgmtbusclass, mgmtbusargs):
    return AMQPSlave(mgmtbusargs)
