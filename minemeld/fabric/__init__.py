from __future__ import absolute_import

from .amqp import AMQP

def _dynamic_load(classname):
    if '.' not in classname:
        raise ValueError('invalid absolute classname %s' % classname)

    modname, classname = classname.rsplit('.', 1)
    t = __import__(modname, globals(), locals(), [classname])
    cls = getattr(t, classname)
    return cls

def factory(classname, chassis, config):
    if classname == 'AMQP':
        return AMQP(chassis=chassis, config=config)

    return _dynamic_load(classname)(
        chassis=chassis,
        config=config
    )
