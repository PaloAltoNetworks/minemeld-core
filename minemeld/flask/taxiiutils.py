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

import functools

from flask import request
from flask import make_response

from .mmrpc import MMMaster
from .logger import LOG


def taxii_make_response(m11):
    h = {
        'Content-Type': "application/xml",
        'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
        'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
    }
    r = make_response((m11.to_xml(pretty_print=True), 200, h))
    return r


def taxii_make_response_10(m10):
    h = {
        'Content-Type': "application/xml",
        'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.0',
        'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
    }
    r = make_response((m10.to_xml(pretty_print=True), 200, h))
    return r


def taxii_check(f):
    @functools.wraps(f)
    def check(*args, **kwargs):
        tct = request.headers.get('X-TAXII-Content-Type', None)
        if tct not in [
            'urn:taxii.mitre.org:message:xml:1.1',
            'urn:taxii.mitre.org:message:xml:1.0'
        ]:
            return 'Invalid TAXII Headers', 400
        tct = request.headers.get('X-TAXII-Protocol', None)
        if tct not in [
            'urn:taxii.mitre.org:protocol:http:1.0',
            'urn:taxii.mitre.org:protocol:https:1.0'
        ]:
            return 'Invalid TAXII Headers', 400
        tct = request.headers.get('X-TAXII-Services', None)
        if tct not in [
            'urn:taxii.mitre.org:services:1.1',
            'urn:taxii.mitre.org:services:1.0'
        ]:
            return 'Invalid TAXII Headers', 400
        return f(*args, **kwargs)
    return check


def get_taxii_feeds():
    # check if feed exists
    status = MMMaster.status()
    status = status.get('result', None)
    if status is None:
        raise RuntimeError('Error retrieving engine status')

    result = []
    for node, node_status in status.iteritems():
        class_ = node_status.get('class', None)
        if class_ != 'minemeld.ft.taxii.DataFeed':
            continue

        _, _, feedname = node.split(':', 2)
        result.append(feedname)

    return result
