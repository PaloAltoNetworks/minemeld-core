import uuid

from .. import config
from ..mmrpc import MMMaster

def get_taxii2_feeds():
    # check if feed exists
    status = MMMaster.status()
    status = status.get('result', None)
    if status is None:
        raise RuntimeError('Error retrieving engine status')

    result = []
    for node, node_status in status.iteritems():
        class_ = node_status.get('class', None)
        if class_ != 'minemeld.ft.redis.RedisSet':
            continue

        _, _, feedname = node.split(':', 2)
        result.append(dict(name=feedname, taxii2_id=get_feed_id(feedname)))

    return result


def get_feed_id(feedname):
    return str(uuid.uuid3(uuid.NAMESPACE_URL, ('minemeld/'+feedname).encode('ascii', 'ignore')))


def get_ioc_property(feedname):
    if not config.get('FEEDS_AUTH_ENABLED', False):
        return None

    fattributes = config.get('FEEDS_ATTRS', None)
    if fattributes is None or feedname not in fattributes:
        return None

    return fattributes[feedname].get('ioc_tags_property', None)
