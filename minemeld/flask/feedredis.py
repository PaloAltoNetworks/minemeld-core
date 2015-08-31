import logging

from flask import request
from flask import jsonify
from flask import Response
from flask import stream_with_context

from . import app
from . import SR
from . import config

LOG = logging.getLogger(__name__)
FEED_INTERVAL = 100


def generate_feed(feed, start, num, desc):
    zrange = SR.zrange
    if desc:
        zrange = SR.zrevrange

    if num is None:
        num = (1 << 32)-1

    cstart = start
    while cstart < (start+num):
        LOG.debug("cstart: %s start+num: %s", cstart, start+num)
        LOG.debug("interval: %s desc: %s",
                  min(start+num - cstart, FEED_INTERVAL), desc)
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))
        yield '\n'.join(ilist)+'\n'

        if len(ilist) < 100:
            break

        cstart += 100


@app.route('/feeds/<feed>', methods=['GET'])
def get_feed_content(feed):
    if feed not in config.get('FEEDS', []):
        LOG.error("Invalid request, unknown feed: %s", feed)
        return jsonify(error="Unknown feed %s" % feed), 400

    start = request.values.get('s')
    if start is None:
        start = 0
    try:
        start = int(start)
        if start < 0:
            raise ValueError()
    except ValueError:
        LOG.error("Invalid request, s not a non-negative integer: %s", start)
        return jsonify(error="s should be a positive integer"), 400

    num = request.values.get('n')
    if num is not None:
        try:
            num = int(num)
            if num <= 0:
                raise ValueError()
        except ValueError:
            LOG.error("Invalid request, n not a positive integer: %s", num)
            return jsonify(error="n should be a positive integer"), 400
    else:
        num = None

    desc = request.values.get('d')
    desc = (False if desc is None else True)

    return Response(stream_with_context(generate_feed(feed, start, num, desc)),
                    mimetype="text/plain")
