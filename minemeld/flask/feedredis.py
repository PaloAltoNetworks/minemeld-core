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

    if value == 'json':
        yield '[\n'

    cstart = start
    firstelement = True

    while cstart < (start+num):
        LOG.debug("cstart: %s start+num: %s", cstart, start+num)
        LOG.debug("interval: %s desc: %s",
                  min(start+num - cstart, FEED_INTERVAL), desc)
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))

        if value is None:
            yield '\n'.join(ilist)+'\n'
        else:
            result = cStringIO.StringIO()

            for i in ilist:
                v = SR.hget(feed+'.value', i)
                if v is None:
                    v = 'null'

                if value == 'json' and not firstelement:
                    result.write(',\n')

                if value == 'json-seq':
                    result.write('\x1E')

                result.write('{"indicator":"')
                result.write(i)
                result.write('","value":')
                result.write(v)
                result.write('}')

                if value == 'json-seq':
                    result.write('\n')

                firstelement = False

            yield result.getvalue()

            result.close()

        if len(ilist) < 100:
            break

        cstart += 100

    if value == 'json':
        yield ']\n'


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
    if nclass != 'minemeld.ft.redis.RedisSet':
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
    if value is not None and value not in ['json', 'json-seq']:
        return jsonify(error="unknown format %s" % value), 400

    mimetype = 'text/plain'
    if value == 'json':
        mimetype = 'application/json'
    elif value == 'json-seq':
        mimetype = 'application/json-seq'

    return Response(
        stream_with_context(
            generate_feed(feed, start, num, desc, value)
        ),
        mimetype=mimetype
    )
