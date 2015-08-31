import time
import calendar
import operator
import functools


def utc_millisec():
    return int(calendar.timegm(time.gmtime())*1000)


def _merge_atomic_values(op, v1, v2):
    if op(v1, v2):
        return v2
    return v1


def _merge_array(v1, v2):
    for e in v2:
        if e not in v1:
            v1.append(e)
    return v1


RESERVED_ATTRIBUTES = {
    'sources': _merge_array,
    'first_seen': functools.partial(_merge_atomic_values, operator.gt),
    'last_seen': functools.partial(_merge_atomic_values, operator.lt),
    'type': functools.partial(_merge_atomic_values, operator.eq),
    'direction': functools.partial(_merge_atomic_values, operator.eq),
    'confidence': functools.partial(_merge_atomic_values, operator.lt),
    'country': functools.partial(_merge_atomic_values, operator.eq),
    'AS': functools.partial(_merge_atomic_values, operator.eq)
}
