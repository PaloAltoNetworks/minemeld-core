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
import json
from contextlib import contextmanager

import unicodecsv
from netaddr import IPRange, AddrFormatError
from flask import request, jsonify, Response, stream_with_context
from flask.ext.login import current_user
from collections import defaultdict

from .redisclient import SR
from .mmrpc import MMMaster
from .aaa import MMBlueprint
from .logger import LOG


__all__ = ['BLUEPRINT']


FEED_INTERVAL = 100
_PROTOCOL_RE = re.compile('^(?:[a-z]+:)*//')
_INVALID_TOKEN_RE = re.compile('(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')


BLUEPRINT = MMBlueprint('feeds', __name__, url_prefix='/feeds')


def _translate_ip_ranges(indicator, value=None):
    if value is not None and value['type'] != 'IPv4':
        return [indicator]

    try:
        ip_range = IPRange(*indicator.split('-', 1))

    except (AddrFormatError, ValueError, TypeError):
        return [indicator]

    return [str(x) if x.size != 1 else str(x.network) for x in ip_range.cidrs()]


@contextmanager
def _buffer():
    result = cStringIO.StringIO()

    try:
        yield result
    finally:
        result.close()


def generate_panosurl_feed(feed, start, num, desc, value, **kwargs):
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


def generate_plain_feed(feed, start, num, desc, value, **kwargs):
    zrange = SR.zrange
    if desc:
        zrange = SR.zrevrange

    if num is None:
        num = (1 << 32)-1

    translate_ip_ranges = kwargs.pop('translate_ip_ranges', False)

    cstart = start

    while cstart < (start+num):
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))

        if translate_ip_ranges:
            ilist = [xi for i in ilist for xi in _translate_ip_ranges(i)]

        yield '\n'.join(ilist)+'\n'

        if len(ilist) < 100:
            break

        cstart += 100


def generate_json_feed(feed, start, num, desc, value, **kwargs):
    zrange = SR.zrange
    if desc:
        zrange = SR.zrevrange

    if num is None:
        num = (1 << 32)-1

    translate_ip_ranges = kwargs.pop('translate_ip_ranges', False)

    if value == 'json':
        yield '[\n'

    cstart = start
    firstelement = True

    while cstart < (start+num):
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))

        result = cStringIO.StringIO()

        for indicator in ilist:
            v = SR.hget(feed+'.value', indicator)

            xindicators = [indicator]
            if translate_ip_ranges and '-' in indicator:
                xindicators = _translate_ip_ranges(indicator, None if v is None else json.loads(v))

            if v is None:
                v = 'null'

            for i in xindicators:
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


def generate_csv_feed(feed, start, num, desc, value, **kwargs):
    def _is_atomic_type(fv):
        return (isinstance(fv, unicode) or isinstance(fv, str) or isinstance(fv, int) or isinstance(fv, bool))

    def _format_field_value(fv):
        if _is_atomic_type(fv):
            return fv

        if isinstance(fv, list):
            ok = True
            for fve in fv:
                ok &= _is_atomic_type(fve)

            if ok:
                return ','.join(fv)

        return json.dumps(fv)

    zrange = SR.zrange
    if desc:
        zrange = SR.zrevrange

    if num is None:
        num = (1 << 32)-1

    translate_ip_ranges = kwargs.pop('translate_ip_ranges', False)

    # extract name of fields and column names
    columns = []
    fields = []
    for addf in kwargs.pop('f', []):
        if '|' in addf:
            fname, cname = addf.rsplit('|', 1)
        else:
            fname = addf
            cname = addf
        columns.append(cname)
        fields.append(fname)

    # if no fields are specified, only indicator is generated
    if len(fields) == 0:
        fields = ['indicator']
        columns = ['indicator']

    # check if header should be generated
    header = kwargs.pop('h', None)
    if header is None:
        header = True
    else:
        header = int(header[0])

    # check if bom should be generated
    ubom = kwargs.pop('ubom', None)
    if ubom is None:
        ubom = False
    else:
        ubom = int(ubom[0])

    cstart = start

    if ubom:
        LOG.debug('BOM')
        yield '\xef\xbb\xbf'

    with _buffer() as current_line:
        w = unicodecsv.DictWriter(
            current_line,
            fieldnames=columns,
            encoding='utf-8'
        )

        if header:
            w.writeheader()
            yield current_line.getvalue()

        while cstart < (start+num):
            ilist = zrange(feed, cstart,
                           cstart-1+min(start+num - cstart, FEED_INTERVAL))

            for indicator in ilist:
                v = SR.hget(feed+'.value', indicator)
                v = None if v is None else json.loads(v)

                xindicators = [indicator]
                if translate_ip_ranges and '-' in indicator:
                    xindicators = _translate_ip_ranges(indicator, v)

                for i in xindicators:
                    fieldvalues = {}

                    for f, c in zip(fields, columns):
                        if f == 'indicator':
                            fieldvalues[c] = i
                            continue

                        if v is not None and f in v:
                            fieldvalues[c] = _format_field_value(v[f])

                    current_line.truncate(0)
                    w.writerow(fieldvalues)
                    yield current_line.getvalue()

            if len(ilist) < FEED_INTERVAL:
                break

            cstart += FEED_INTERVAL


def generate_mwg_feed(feed, start, num, desc, value, **kwargs):
    zrange = SR.zrange
    if desc:
        zrange = SR.zrevrange

    if num is None:
        num = (1 << 32)-1

    translate_ip_ranges = kwargs.pop('translate_ip_ranges', False)
    type_ = kwargs.get('t', None)
    if type_ is None:
        type_ = 'string'
    else:
        type_ = type_[0]
    translate_ip_ranges |= type_ == 'ip'

    yield 'type={}\n'.format(type_)

    cstart = start
    while cstart < (start+num):
        ilist = zrange(feed, cstart,
                       cstart-1+min(start+num - cstart, FEED_INTERVAL))

        for indicator in ilist:
            v = SR.hget(feed+'.value', indicator)
            v = None if v is None else json.loads(v)

            xindicators = [indicator]
            if translate_ip_ranges and '-' in indicator:
                xindicators = _translate_ip_ranges(indicator, v)

            sources = 'from minemeld'
            if v is not None:
                sources = v.get('sources', 'from minemeld')
                if isinstance(sources, list):
                    sources = ','.join(sources)

            for i in xindicators:
                yield '"{}" "{}"\n'.format(
                    i.replace('"', '\\"'),
                    sources.replace('"', '\\"')
                )

        if len(ilist) < 100:
            break

        cstart += 100


# This formatter implements BlueCoat custom URL format as described at
# https://www.bluecoat.com/documents/download/a366dc73-d455-4859-b92a-c96bd034cb4c/f849f1e3-a906-4ee8-924e-a2061dfe3cdf
# It expects the value 'bc_category' in the indicator. The value can be either a single string or a list of strings.
# Optional feed arguments:
#     ca : Indicator's attribute that hosts the BlueCoat category. Defaults to 'bc_category'
#     cd : Default BlueCoat category for indicators that do not have 'catattr'. This argument can appear multiple
#          times and it will be handled as a list of categories the indicator belongs to. If not present then
#          indicators without 'catattr' will be discarded.
def generate_bluecoat_feed(feed, start, num, desc, value, **kwargs):
    zrange = SR.zrange
    ilist = zrange(feed, 0, (1 << 32)-1)
    bc_dict = defaultdict(list)
    flag_category_default = kwargs.get('cd', None)
    flag_category_attr = kwargs.get('ca', ['bc_category'])[0]

    for i in ilist:
        v = SR.hget(feed+'.value', i)
        v = None if v is None else json.loads(v)
        i = i.lower()
        i = _PROTOCOL_RE.sub('', i)
        i = _INVALID_TOKEN_RE.sub('*', i)

        if v is None:
            if flag_category_default is None:
                continue
            else:
                bc_cat_list = flag_category_default
        else:
            bc_cat_attr = v.get(flag_category_attr, None)
            if isinstance(bc_cat_attr, list):
                bc_cat_list = bc_cat_attr
            elif isinstance(bc_cat_attr, basestring):
                bc_cat_list = [bc_cat_attr]
            elif flag_category_default is not None:
                bc_cat_list = flag_category_default
            else:
                continue

        for bc_cat in bc_cat_list:
            bc_dict[bc_cat].append(i)

    for key, value in bc_dict.iteritems():
        yield 'define category {}\n'.format(key)
        for ind in value:
            yield ind+'\n'
        yield 'end\n'


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
    },
    'mwg': {
        'formatter': generate_mwg_feed,
        'mimetype': 'text/plain'
    },
    'bluecoat': {
        'formatter': generate_bluecoat_feed,
        'mimetype': 'text/plain'
    },
    'csv': {
        'formatter': generate_csv_feed,
        'mimetype': 'text/csv'
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

    kwargs = {}
    kwargs['translate_ip_ranges'] = int(request.values.get('tr', 0))  # generate IP ranges

    # move to kwargs all the additional parameters, pop the predefined
    kwargs.update(request.values.to_dict(flat=False))
    kwargs.pop('s', None)
    kwargs.pop('n', None)
    kwargs.pop('d', None)
    kwargs.pop('v', None)
    kwargs.pop('tr', None)

    mimetype = 'text/plain'
    formatter = generate_plain_feed
    if value in _FEED_FORMATS:
        formatter = _FEED_FORMATS[value]['formatter']
        mimetype = _FEED_FORMATS[value]['mimetype']

    return Response(
        stream_with_context(
            formatter(feed, start, num, desc, value, **kwargs)
        ),
        mimetype=mimetype
    )
