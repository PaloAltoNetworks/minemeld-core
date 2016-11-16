#
# Copyright (c) 2016 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

'''Interface to the Cisco ISE ERS (External RESTful Services) API

The interface is specific to requirements for creating SGT mappings
on PAN-OS.

See ERS SDK page at: https://ise:9060/ers/sdk
'''

from collections import defaultdict
import inspect
import logging
import pprint
import xml.etree.ElementTree as etree

from . import DEBUG1, DEBUG2, DEBUG3

try:
    import requests
except ImportError:
    raise ValueError('Install requests library: '
                     'http://docs.python-requests.org/')

# https://github.com/shazow/urllib3/issues/655
# Requests treats None as forever
_None = object()


class IseErsRequest:
    def __init__(self, name=None):
        self.name = name
        # python-requests
        self.response = None
        self.status_code = None
        self.reason = None
        self.headers = None
        self.encoding = None
        self.content = None
        self.text = None
        #
        self.xml_root = None
        self.obj = None

    def raise_for_status(self):
        if self.response is not None:
            try:
                self.response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                raise IseErsError(e)


class IseErsError(Exception):
    pass


class IseErs:
    def __init__(self,
                 hostname=None,
                 username=None,
                 password=None,
                 verify=None,
                 timeout=_None):
        if hostname is None:
            raise IseErsError('no hostname')
        if username is None:
            raise IseErsError('no username')
        if password is None:
            raise IseErsError('no password')

        self._log = logging.getLogger(__name__).log
        self.verify = verify
        if self.verify is False:
            requests.packages.urllib3.disable_warnings()
        self.timeout = timeout
        self._log(DEBUG2, 'timeout: %s', repr(timeout))
        self.uri = 'https://' + hostname + ':9060'
        self.auth = requests.auth.HTTPBasicAuth(username, password)

    def _request(self,
                 uri,
                 headers):

        kwargs = {}
        if self.verify is not None:
            kwargs['verify'] = self.verify
        if self.timeout is not _None:
            kwargs['timeout'] = self.timeout

        try:
            r = requests.get(url=uri,
                             headers=headers,
                             auth=self.auth,
                             **kwargs)
        except (requests.exceptions.RequestException, ValueError) as e:
            raise IseErsError(e)

        return r

    def _set_attributes(self, r):
        x = IseErsRequest(inspect.stack()[1][3])
        # http://docs.python-requests.org/en/master/api/#requests.Response
        x.response = r
        x.status_code = r.status_code
        x.reason = r.reason
        x.headers = r.headers
        x.encoding = r.encoding
        self._log(DEBUG2, r.encoding)
        self._log(DEBUG2, r.request.headers)  # XXX authorization header
        self._log(DEBUG2, r.headers)
        x.content = r.content  # bytes
        x.text = r.text  # Unicode
        self._log(DEBUG3, r.text)
        try:
            x.xml_root = etree.fromstring(r.content)
        except etree.ParseError as e:
            self._log(DEBUG1, 'ElementTree.fromstring ParseError: %s', e)

        if x.xml_root is not None:
            self._log(DEBUG1, 'root tag: %s', x.xml_root.tag)
            if x.xml_root.tag == '{ers.ise.cisco.com}ersResponse':
                message = x.xml_root.find('messages/message')
                if message is not None:
                    x.obj = {}
                    x.obj['error'] = {}
                    for k in ['type', 'code']:
                        if k in message.attrib:
                            x.obj['error'][k] = message.attrib[k]
                    title = message.findall('title')
                    if title is not None:
                        x.obj['error']['title'] = []
                        for elem in title:
                            x.obj['error']['title'].append(elem.text)

                    self._log(DEBUG2, x.obj)

        return x

    def sgts_ips_map(self):
        r = self.sgt()
        r.raise_for_status()
        if 'sgt' not in r.obj:
            raise IseErsError('no response data for sgt()')
        _sgt = r.obj['sgt']

        r = self.sgmapping()
        r.raise_for_status()
        if 'sgmapping' not in r.obj:
            raise IseErsError('no response data for sgmapping()')
        _sgmapping = r.obj['sgmapping']

        _sgt_name_desc_map = {}
        _sgt_id_name_map = {}
        _sgts_ips_map = {}
        for x in _sgt:
            _sgt_name_desc_map[x['name']] = x['description']
            _sgt_id_name_map[x['id']] = x['name']
            _sgts_ips_map[x['name']] = []

        self._log(DEBUG2, pprint.pformat(_sgt_name_desc_map))
        self._log(DEBUG2, pprint.pformat(_sgt_id_name_map))

        for x in _sgmapping:
            r = self.sgmapping(id=x['id'])
            r.raise_for_status()
            if 'sgmapping_id' not in r.obj:
                raise IseErsError('no response data for sgmapping(%s)' %
                                  x['id'])
            _sgmapping_id = r.obj['sgmapping_id']
            if 'hostIp' in _sgmapping_id:
                if _sgmapping_id['sgt'] not in _sgt_id_name_map:
                    pass  # XXX refresh _sgt_id_name_map
                else:
                    _sgts_ips_map[_sgt_id_name_map[_sgmapping_id['sgt']]].\
                        append(_sgmapping_id['hostIp'])

        self._log(DEBUG2, pprint.pformat(_sgts_ips_map))

        d = defaultdict(list)
        [d[v].append(k) for k in _sgts_ips_map for v in _sgts_ips_map[k]]

        self.sgt_name_desc_map = _sgt_name_desc_map
        self.sgts_ips_map = _sgts_ips_map
        self.ips_sgts_map = dict(d)

        return self.sgt_name_desc_map, self.sgts_ips_map, self.ips_sgts_map

    def sgt(self,
            id=None):
        '''Security Groups:
        Get-By-Id
        Get-All
        '''

        headers = {
            'accept':
            'application/vnd.com.cisco.ise.trustsec.sgt.1.0+xml'
        }
        path = '/ers/config/sgt'
        if id is not None:
            path += '/' + str(id)
        uri = self.uri + path

        r = self._request(uri=uri, headers=headers)
        x = self._set_attributes(r)

        if x.xml_root is not None:
            rk = 'sgt'  # root key
            if x.xml_root.tag == '{ers.ise.cisco.com}searchResult':
                x.obj = {}
                x.obj[rk] = []
                for elem in x.xml_root.findall('resources/resource'):
                    for k in ['name', 'id', 'description']:
                        if k not in elem.attrib:
                            raise IseErsError('missing attribute \"%s\": %s' %
                                              (k, elem.attrib))
                    x.obj[rk].append(elem.attrib)

            elif x.xml_root.tag == '{trustsec.ers.ise.cisco.com}sgt':
                rk = 'sgt_id'
                x.obj = {}
                x.obj[rk] = {}
                for k in ['id', 'name', 'description']:
                    if k not in x.xml_root.attrib:
                        raise IseErsError('missing attribute \"%s\": %s' %
                                          (k, elem.attrib))
                    else:
                        x.obj[rk][k] = x.xml_root.attrib[k]
                    for elem in x.xml_root.findall('*'):
                        x.obj[rk][elem.tag] = elem.text

            self._log(DEBUG2, pprint.pformat(x.obj))

        return x

    def sgmapping(self,
                  id=None):
        '''IP To SGT Mapping:
        Get-All
        Get-By-Id
        '''

        headers = {
            'accept':
            'application/vnd.com.cisco.ise.trustsec.sgmapping.1.0+xml'
        }
        path = '/ers/config/sgmapping'
        if id is not None:
            path += '/' + str(id)
        uri = self.uri + path

        r = self._request(uri=uri, headers=headers)
        x = self._set_attributes(r)

        if x.xml_root is not None:
            if x.xml_root.tag == '{ers.ise.cisco.com}searchResult':
                rk = 'sgmapping'
                x.obj = {}
                x.obj[rk] = []
                for elem in x.xml_root.findall('resources/resource'):
                    for k in ['name', 'id']:
                        if k not in elem.attrib:
                            raise IseErsError('missing attribute \"%s\": %s' %
                                              (k, elem.attrib))
                    x.obj[rk].append(elem.attrib)

            elif x.xml_root.tag == '{trustsec.ers.ise.cisco.com}sgMapping':
                rk = 'sgmapping_id'
                x.obj = {}
                x.obj[rk] = {}
                for elem in x.xml_root.findall('*'):
                    x.obj[rk][elem.tag] = elem.text

            self._log(DEBUG2, pprint.pformat(x.obj))

        return x
