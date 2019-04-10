#  Copyright 2019 Palo Alto Networks, Inc
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

import uuid
import cStringIO
from collections import defaultdict

import ujson as json
from flask import request, jsonify, stream_with_context, Response
from flask_login import current_user
from netaddr import IPRange, AddrFormatError

from ..redisclient import SR
from ..logger import LOG

from .stix2 import stix2_converter
from .utils import get_ioc_property


FEED_INTERVAL = 100


def translate_ip_ranges(indicator):
    try:
        ip_range = IPRange(*indicator.split('-', 1))

    except (AddrFormatError, ValueError, TypeError):
        return [indicator]

    return [str(x) if x.size != 1 else str(x.network) for x in ip_range.cidrs()]


def stix2_bundle_formatter(feedname):
    authz_property = get_ioc_property(feedname)

    bundle_id = str(uuid.uuid3(
        uuid.NAMESPACE_URL,
        ('minemeld/{}/{}'.format(feedname, 0)).encode('ascii', 'ignore')
    ))

    last_entry = SR.zrange(feedname, -1, -1, withscores=True)
    LOG.debug(last_entry)
    if len(last_entry) != 0:
        _, score = last_entry[0]
        bundle_id = str(uuid.uuid3(
            uuid.NAMESPACE_URL,
            ('minemeld/{}/{}'.format(feedname, score)).encode('ascii', 'ignore')
        ))

    yield '{{\n"type": "bundle",\n"spec_version": "2.0",\n"id": "bundle--{}",\n"indicators": [\n'.format(bundle_id)

    start = 0
    num = (1 << 32) - 1

    identities = defaultdict(uuid.uuid4)
    cstart = 0
    firstelement = True
    while cstart < (start + num):
        ilist = SR.zrange(
                    feedname, cstart,
                    cstart - 1 + min(start + num - cstart, FEED_INTERVAL)
                )

        result = cStringIO.StringIO()

        for indicator in ilist:
            v = SR.hget(feedname + '.value', indicator)

            if v is None:
                continue
            v = json.loads(v)

            if authz_property is not None:
                # authz_property is defined in config
                ioc_tags = v.get(authz_property, None)
                if ioc_tags is not None:
                    # authz_property is defined inside the ioc value
                    ioc_tags = set(ioc_tags)
                    if not current_user.can_access(ioc_tags):
                        # user has no access to this ioc
                        continue

            xindicators = [indicator]
            if '-' in indicator and v.get('type', None) in ['IPv4', 'IPv6']:
                xindicators = translate_ip_ranges(indicator)

            for i in xindicators:
                try:
                    converted = stix2_converter(i, v, feedname)
                except RuntimeError:
                    LOG.error('Error converting {!r} to STIX2'.format(i))
                    continue

                created_by_ref = converted.pop('_created_by_ref', None)
                if created_by_ref is not None:
                    converted['created_by_ref'] = 'identity--'+str(identities[created_by_ref])

                if not firstelement:
                    result.write(',')
                firstelement = False

                result.write(json.dumps(converted, escape_forward_slashes=False))

        yield result.getvalue()

        result.close()

        if len(ilist) < 100:
            break

        cstart += 100

    # dump identities
    result = cStringIO.StringIO()
    for identity, uuid_ in identities.iteritems():
        identity_class, name = identity.split(':', 1)
        result.write(',')
        result.write(json.dumps({
            'type': 'identty',
            'id': 'identity--'+str(uuid_),
            'name': name,
            'identity_class': identity_class
        }))
    yield result.getvalue()
    result.close()

    yield ']\n}'


def generate_stix2_bundle(feedname):
    return Response(
        stream_with_context(stix2_bundle_formatter(feedname)),
        mimetype='application/vnd.oasis.stix+json; version=2.0'
    )
