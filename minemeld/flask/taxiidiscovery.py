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

import logging
import re

import libtaxii
import libtaxii.messages_11
import libtaxii.constants

from flask import request

import flask.ext.login

from . import app
from . import config
from .taxiiutils import taxii_check, taxii_make_response

LOG = logging.getLogger(__name__)

HOST_RE = re.compile('^[a-zA-Z\d-]{1,63}(?:\.[a-zA-Z\d-]{1,63})*(?::[0-9]{1,5})*$')

_SERVICE_INSTANCES = [
    {
        'type': libtaxii.constants.SVC_DISCOVERY,
        'path': 'taxii-discovery-service'
    },
    {
        'type': libtaxii.constants.SVC_COLLECTION_MANAGEMENT,
        'path': 'taxii-collection-management-service'
    },
    {
        'type': libtaxii.constants.SVC_POLL,
        'path': 'taxii-poll-service'
    }
]


@app.route('/taxii-discovery-service', methods=['POST'])
@flask.ext.login.login_required
@taxii_check
def taxii_discovery_service():
    server_host = config.get('TAXII_HOST', None)
    if server_host is None:
        server_host = request.headers.get('Host', None)
        if server_host is None:
            return 'Missing Host header', 400

        if HOST_RE.match(server_host) is None:
            return 'Invalid Host header', 400

    tm = libtaxii.messages_11.get_message_from_xml(request.data)
    if tm.message_type != libtaxii.constants.MSG_DISCOVERY_REQUEST:
        return 'Invalid message, invalid Message Type', 400

    dresp = libtaxii.messages_11.DiscoveryResponse(
        libtaxii.messages_11.generate_message_id(),
        tm.message_id
    )

    for si in _SERVICE_INSTANCES:
        sii = libtaxii.messages_11.ServiceInstance(
            si['type'],
            'urn:taxii.mitre.org:services:1.1',
            'urn:taxii.mitre.org:protocol:http:1.0',
            "https://{}/{}".format(server_host, si['path']),
            ['urn:taxii.mitre.org:message:xml:1.1'],
            available=True
        )
        dresp.service_instances.append(sii)

    return taxii_make_response(dresp)
