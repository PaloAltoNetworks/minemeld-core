import logging
import cStringIO

from flask import request
from flask import jsonify
from flask import Response
from flask import stream_with_context

from . import app
from . import SR
from . import MMMaster

LOG = logging.getLogger(__name__)
FEED_INTERVAL = 100


def generate_feed(feed, start, num, desc, value):
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

        if not value:
            yield '\n'.join(ilist)+'\n'
        else:
            result = cStringIO.StringIO()

            for i in ilist:
                v = SR.hget(feed+'.value', i)
                if v is None:
                    v = 'null'

                result.write('\x1E{"indicator":"')
                result.write(i)
                result.write('","value":')
                result.write(v)
                result.write('}\n')

            yield result.getvalue()

            result.close()

        if len(ilist) < 100:
            break

        cstart += 100


@app.route('/feeds/<feed>', methods=['GET'])
def get_feed_content(feed):
    # check if feed exists
    status = MMMaster.status()
    tr = status.get('result', None)
    if tr is None:
        return jsonify(error={'message': status.get('error', 'error')})

    nname = 'mbus:slave:'+feed
    if nname not in tr:
        return jsonify(error={'message': 'Unknown feed'}), 404
    nclass = tr[nname].get('class', None)
    if nclass != 'RedisSet':
        return jsonify(error={'message': 'Unknown feed'}), 404

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

    value = request.values.get('v')
    value = (False if value is None else True)

    return Response(
        stream_with_context(
            generate_feed(feed, start, num, desc, value)
        ),
        mimetype=("text/plain" if value is False else "application/json-seq")
    )
