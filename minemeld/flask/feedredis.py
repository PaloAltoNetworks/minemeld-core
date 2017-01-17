#  Copyright 2015-2016 Palo Alto Networks, Inc
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

import re
import cStringIO

from flask import request, jsonify, Response, stream_with_context
from flask.ext.login import current_user

from .redisclient import SR
from .mmrpc import MMMaster
from .aaa import MMBlueprint
from .logger import LOG


__all__ = ['BLUEPRINT']


FEED_INTERVAL = 100
_PROTOCOL_RE = re.compile('^(?:[a-z]+:)*//')
_INVALID_TOKEN_RE = re.compile('(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')


BLUEPRINT = MMBlueprint('feeds', __name__, url_prefix='/feeds')


def generate_panosurl_feed(feed, start, num, desc, value):
    zrange = SR.zrange
    if desc:
        zrange = SR.zrevrange

    if num is None:
        num = (1 << 32)-1

    cstart = start

    while cstart < (start+num):
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))

        for i in ilist:
            i = i.lower()

            i = _PROTOCOL_RE.sub('', i)
            i = _INVALID_TOKEN_RE.sub('*', i)

            yield i+'\n'

        if len(ilist) < 100:
            break

        cstart += 100


def generate_plain_feed(feed, start, num, desc, value):
    zrange = SR.zrange
    if desc:
        zrange = SR.zrevrange

    if num is None:
        num = (1 << 32)-1

    cstart = start

    while cstart < (start+num):
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))

        yield '\n'.join(ilist)+'\n'

        if len(ilist) < 100:
            break

        cstart += 100


def generate_json_feed(feed, start, num, desc, value):
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
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))

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


_FEED_FORMATS = {
    'json': {
        'formatter': generate_json_feed,
        'mimetype': 'application/json'
    },
    'json-seq': {
        'formatter': generate_json_feed,
        'mimetype': 'application/json-seq'
    },
    'panosurl': {
        'formatter': generate_panosurl_feed,
        'mimetype': 'text/plain'
    }
}


@BLUEPRINT.route('/<feed>', methods=['GET'], feeds=True, read_write=False)
def get_feed_content(feed):
    if not current_user.check_feed(feed):
        return 'Unauthorized', 401

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
    if value is not None and value not in _FEED_FORMATS:
        return jsonify(error="unknown format %s" % value), 400

    mimetype = 'text/plain'
    formatter = generate_plain_feed
    if value in _FEED_FORMATS:
        formatter = _FEED_FORMATS[value]['formatter']
        mimetype = _FEED_FORMATS[value]['mimetype']

    return Response(
        stream_with_context(
            formatter(feed, start, num, desc, value)
        ),
        mimetype=mimetype
    )
