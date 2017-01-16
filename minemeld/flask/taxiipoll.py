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

import datetime

import pytz
import lz4

import libtaxii
import libtaxii.constants
import stix.core

from flask import request, Response, stream_with_context
from flask.ext.login import current_user

from .redisclient import SR
from .taxiiutils import taxii_check, get_taxii_feeds
from .aaa import MMBlueprint
from .logger import LOG
from minemeld.ft.utils import dt_to_millisec


__all__ = ['BLUEPRINT']


BLUEPRINT = MMBlueprint('taxiipoll', __name__, url_prefix='')


_TAXII_POLL_RESPONSE_HEADER = """
<taxii_11:Poll_Response xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" message_id="%(message_id)s" in_response_to="%(in_response_to)s" collection_name="%(collection_name)s" more="false" result_part_number="1">
<taxii_11:Inclusive_End_Timestamp>%(inclusive_end_timestamp_label)s</taxii_11:Inclusive_End_Timestamp>
"""


def _oldest_indicator_timestamp(feed):
    olist = SR.zrevrange(
        feed, 0, 0,
        withscores=True
    )
    if len(olist) == 0:
        return None

    ots = int(olist[0][1])/1000

    return datetime.datetime.fromtimestamp(ots, pytz.utc)


def _indicators_feed(feed, excbegtime, incendtime):
    if excbegtime is None:
        excbegtime = 0
    else:
        excbegtime = dt_to_millisec(excbegtime) + 1
    incendtime = dt_to_millisec(incendtime)

    cstart = 0
    while True:
        indicators = SR.zrangebyscore(
            feed, excbegtime, incendtime,
            start=cstart, num=100
        )
        if indicators is None:
            break

        for i in indicators:
            value = SR.hget(feed + '.value', i)

            if value.startswith('lz4'):
                try:
                    value = lz4.decompress(value[3:])
                    value = stix.core.STIXPackage.from_json(value)
                    value = value.to_xml(
                        ns_dict={'https://go.paloaltonetworks.com/minemeld': 'minemeld'}
                    )

                except ValueError:
                    continue

            yield value

        if len(indicators) < 100:
            break

        cstart += 100


def data_feed_11(rmsgid, cname, excbegtime, incendtime):
    tfeeds = get_taxii_feeds()
    if cname not in tfeeds:
        return 'Invalid message, unknown feed', 400

    if not incendtime:
        incendtime = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)

    def _resp_generator():
        # yield the opening tag of the Poll Response
        resp_header = _TAXII_POLL_RESPONSE_HEADER % {
            'collection_name': cname,
            'message_id': libtaxii.messages_11.generate_message_id(),
            'in_response_to': rmsgid,
            'inclusive_end_timestamp_label': incendtime.isoformat()
        }
        if excbegtime is not None:
            resp_header += (
                '<taxii_11:Exclusive_Begin_Timestamp>' +
                excbegtime.isoformat() +
                '</taxii_11:Exclusive_Begin_Timestamp>'
            )

        yield resp_header

        # yield the content blocks
        for i in _indicators_feed(cname, excbegtime, incendtime):
            cb1 = libtaxii.messages_11.ContentBlock(
                content_binding=libtaxii.constants.CB_STIX_XML_11,
                content=i
            )
            yield cb1.to_xml()+'\n'

        # yield the closing tag
        yield '</taxii_11:Poll_Response>'

    return Response(
        response=stream_with_context(_resp_generator()),
        status=200,
        headers={
            'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
            'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
        },
        mimetype='application/xml'
    )


@BLUEPRINT.route('/taxii-poll-service', methods=['POST'], feeds=True, read_write=False)
@taxii_check
def taxii_poll_service():
    taxiict = request.headers['X-TAXII-Content-Type']
    if taxiict == 'urn:taxii.mitre.org:message:xml:1.1':
        tm = libtaxii.messages_11.get_message_from_xml(request.data)
        if tm.message_type != libtaxii.constants.MSG_POLL_REQUEST:
            return 'Invalid message', 400

        cname = tm.collection_name
        excbegtime = tm.exclusive_begin_timestamp_label
        incendtime = tm.inclusive_end_timestamp_label

        if not current_user.check_feed(cname):
            return 'Unauthorized', 401

        return data_feed_11(tm.message_id, cname, excbegtime, incendtime)

    elif taxiict == 'urn:taxii.mitre.org:message:xml:1.0':
        # old TAXII 1.0 not supported yet
        return 'Invalid message', 400

    else:
        return 'Invalid message', 400
