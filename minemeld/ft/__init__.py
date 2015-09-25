_KNOWN_CLASSES = {
    'HTTP': 'minemeld.ft.http.HttpFT',
    'AggregatorIPv4': 'minemeld.ft.ipop.AggregateIPv4FT',
    'Aggregator': 'minemeld.ft.op.AggregateFT',
    'RedisSet': 'minemeld.ft.redis.RedisSet'
}


def _dynamic_load(classname):
    if '.' not in classname:
        raise ValueError('invalid absolute classname %s' % classname)

    modname, classname = classname.rsplit('.', 1)
    t = __import__(modname, globals(), locals(), [classname])
    cls = getattr(t, classname)
    return cls


def factory(classname, name, chassis, config):
    classname = _KNOWN_CLASSES.get(classname, classname)

    return _dynamic_load(classname)(
        name=name,
        chassis=chassis,
        config=config
    )


class ft_states(object):
    READY = 0
    CONNECTED = 1
    REBUILDING = 2
    RESET = 3
    INIT = 4
    STARTED = 5
    CHECKPOINT = 6
    IDLE = 7
    STOPPED = 8
