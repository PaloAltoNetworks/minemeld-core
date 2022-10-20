#  Copyright 2015-present Palo Alto Networks, Inc
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

from __future__ import absolute_import

import logging
import os
import yaml
from datetime import datetime, timedelta
from uuid import UUID

import pytz
import requests
import requests.structures
import ujson

from stix2patterns.pattern import Pattern, ParseException

from . import basepoller

from .utils import dt_to_millisec, interval_in_sec

LOG = logging.getLogger(__name__)

_STIX2_TYPES_TO_MM_TYPES = {
    'ipv4-addr': 'IPv4',
    'ipv6-addr': 'IPv6',
    'domain': 'domain',
    'domain-name': 'domain',
    'url': 'URL',
    'file': None,
    'md5': 'md5',
    'sha-1': 'sha1',
    'sha-256': 'sha256'
}


class Taxii2Client(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        self.poll_service = None
        self.last_taxii2_run = None
        self.last_stix2_package_ts = None
        self.taxii_date_added_last = None

        super(Taxii2Client, self).__init__(name, chassis, config)

    def configure(self):
        super(Taxii2Client, self).configure()

        self.initial_interval = self.config.get('initial_interval', '1d')
        self.initial_interval = interval_in_sec(self.initial_interval)
        if self.initial_interval is None:
            LOG.error('%s - wrong initial_interval format: %s', self.name, self.initial_interval)
            self.initial_interval = 86400
        self.max_poll_dt = self.config.get('max_poll_dt', 86400)

        # options for processing
        self.lower_timestamp_precision = self.config.get('lower_timestamp_precision', False)

        self.auth_type = self.config.get('auth_type', 'none')

        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)

        self.api_key = self.config.get('api_key', None)

        self.discovery_service = self.config.get('discovery_service', None)
        self.api_root = self.config.get('api_root', None)
        self.collection = self.config.get('collection', None)
        self.verify_cert = self.config.get('verify_cert', True)

        self.enabled = self.config.get('enabled', 'no')

        self.client = None
        self.taxii_collection = None
        self.taxii_version = None

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        # self.prefix = self.config.get('prefix', self.name)

        # self.confidence_map = self.config.get('confidence_map', {'low': 40, 'medium': 60, 'high': 80})

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        auth_type = sconfig.get('auth_type', None)
        username = sconfig.get('username', None)
        password = sconfig.get('password', None)
        api_key = sconfig.get('api_key', None)

        if api_key is not None:
            self.api_key = api_key
            LOG.info('{} - Loaded credentials from side config'.format(self.name))
        elif username is not None and password is not None:
            self.username = username
            self.password = password
            LOG.info('{} - Loaded credentials from side config'.format(self.name))

        discovery_service = sconfig.get('discovery_service', None)
        api_root = sconfig.get('api_root', None)
        collection = sconfig.get('collection', None)
        verify_cert = sconfig.get('verify_cert', None)

        enabled = sconfig.get('enabled', None)

        if discovery_service is not None:
            self.discovery_service = discovery_service
            LOG.info('{} - Loaded discovery service from side config'.format(self.name))

        if api_root is not None:
            self.api_root = api_root
            LOG.info('{} - Loaded api root from side config'.format(self.name))

        if collection is not None:
            self.collection = collection
            LOG.info('{} - Loaded collection from side config'.format(self.name))

        if verify_cert is not None:
            self.verify_cert = verify_cert
            LOG.info('{} - Loaded collection from side config'.format(self.name))

        if auth_type is not None:
            self.auth_type = auth_type
            LOG.info('{} - Loaded collection from side config'.format(self.name))

        if enabled is not None:
            self.enabled = enabled
            LOG.info('{} - Loaded collection from side config'.format(self.name))

    def _saved_state_restore(self, saved_state):
        super(Taxii2Client, self)._saved_state_restore(saved_state)
        self.last_taxii2_run = saved_state.get('last_taxii2_run', None)
        LOG.info('last_taxii2_run from sstate: %s', self.last_taxii2_run)

    def _saved_state_create(self):
        sstate = super(Taxii2Client, self)._saved_state_create()
        sstate['last_taxii2_run'] = self.last_taxii2_run

        return sstate

    def _saved_state_reset(self):
        super(Taxii2Client, self)._saved_state_reset()
        self.last_taxii2_run = None

    def _set_accept_header(self, session):
        content_types = {
            'stix20': 'application/vnd.oasis.stix+json; version=2.0',
            'taxii20': 'application/vnd.oasis.taxii+json; version=2.0',
            'stix21': 'application/taxii+json; version=2.1',
            'taxii21': 'application/taxii+json; version=2.1'
        }

        try:
            # Assume the server is TAXII 2.0
            self.taxii_version = '2.0'
            session.headers.update({'Accept': content_types['taxii20']})

            r1 = session.get(self.discovery_service)
            if r1.status_code == 406:
                # If the server is not TAXII 2.0, assume it is TAXII 2.1
                self.taxii_version = '2.1'
                session.headers.update({'Accept': content_types['taxii21']})

                r2 = session.get(self.discovery_service)
                if r2.status_code == 406:
                    # The server supports neither
                    raise RuntimeError('server does not support TAXII 2.0 nor TAXII 2.1')
        except Exception as e:
            raise RuntimeError('error contacting server. {}'.format(e))

    def _build_taxii2_client(self):
        session = requests.Session()
        session.verify = True if self.verify_cert == 'yes' else False

        if self.api_key:
            session.headers.update({'Authorization': 'Token {}'.format(self.api_key)})
        elif self.username and self.password:
            session.auth = (self.username, self.password)
            # session.auth = requests.auth.HTTPBasicAuth(self.username, self.password)
        else:
            pass

        # Check the TAXII server to ensure the correct Accept header is set
        self._set_accept_header(session)

        self.client = session

    def _get_api_root(self):
        if self.client:
            r = self.client.get(self.discovery_service)
            if r.status_code == requests.codes.ok:
                try:
                    discovery = r.json()
                    if 'api_roots' in discovery:
                        api_roots = discovery['api_roots']
                        for url in api_roots:
                            # strip the trailing slash
                            if url[:-1].endswith(self.api_root):
                                self.api_root = url
                                break
                    else:
                        raise RuntimeError('error getting api_root.'.format(r.status_code))
                except Exception as e:
                    raise RuntimeError('error getting api_root. {}'.format(e))
            else:
                raise RuntimeError('error getting api_root. received code {}'.format(r.status_code))
        else:
            raise RuntimeError('client does not exist {}'.format(self.collection))

    def _is_uuid(self, val, ver):
        n = len(val)
        if n == 32 or n == 36:
            try:
                uuid_val = UUID(val, version=ver)
            except Exception:
                return False

            return str(uuid_val) == val
        else:
            return False

    def _get_collection(self):
        try:
            if self.client:
                collection_url = '{}collections/'.format(self.api_root)
                r = self.client.get(collection_url)
                if r.status_code == requests.codes.ok:
                    collections = r.json()['collections']
                    if self._is_uuid(self.collection, 3) or self._is_uuid(self.collection, 4):
                        for c in collections:
                            if c['id'] == self.collection:
                                self.taxii_collection = c
                                break
                    else:
                        self.taxii_collection = collections[0]
                else:
                    msg = 'error getting collection {}. received code {}'.format(self.collection, r.status_code)
                    raise RuntimeError(msg)
            else:
                raise RuntimeError('client does not exist {}'.format(self.collection))
        except RuntimeError as e:
            LOG.exception(e)
        except Exception as e:
            LOG.exception('collection {} was not found - {}'.format(self.collection, e))


    # noinspection PyMethodMayBeStatic
    def _clean_indicator(self, sub_pattern_value):
        indicator = str(sub_pattern_value)

        if indicator[0] == "'" and indicator[-1] == "'":
            return indicator[1:-1]
        else:
            return indicator

    # noinspection PyMethodMayBeStatic
    def _detect_and_map_type(self, i_type, sub_pattern_type):
        if i_type == 'file':
            sub_pattern_type = sub_pattern_type[-1].lower()

            return _STIX2_TYPES_TO_MM_TYPES.get(sub_pattern_type, None)
        else:
            return _STIX2_TYPES_TO_MM_TYPES.get(i_type, None)

    def _convert_stix2_obj_to_mm_obj(self, obj, rels, ttps):
        # Inspect the STIX2 Pattern
        # result
        #   comparisons
        #       type_dict
        #           foo
        #               0
        #                   0 (type)
        #                   1 (op)
        #                   2 (value)
        #           bar
        #               0
        #                   0 (type)
        #                   1 (op)
        #                   2 (value)
        #   ...

        # noinspection PyBroadException
        try:
            pattern = obj['pattern']
            inspected_pattern = Pattern(pattern).inspect()
            comparisons = inspected_pattern.comparisons

            indicators = []

            # noinspection PyCompatibility
            for i_type, i_patterns in comparisons.iteritems():
                # The Pattern Inspector buckets each comparison expression in the observable expression based on type
                if i_type in _STIX2_TYPES_TO_MM_TYPES:
                    # The Pattern Inspector reduces the observable expression into a flat list of comparison expressions
                    for sub_pattern in i_patterns:
                        (sub_pattern_type, sub_pattern_op, sub_pattern_value) = sub_pattern

                        mm_type = self._detect_and_map_type(i_type, sub_pattern_type)

                        if mm_type:
                            indicator = self._clean_indicator(sub_pattern_value)
                            value = {
                                "type": mm_type
                            }
                            if 'confidence' in obj:
                                value['confidence'] = obj['confidence']

                            descriptions = [r["description"].strip() for r in rels if "description" in r]
                            if len(descriptions):
                                value["description"] = ", ".join(descriptions)

                            techniques = [t["name"].strip() for t in ttps]
                            if len(techniques):
                                value["techniques"] = ", ".join(techniques)

                            i = [indicator, value]
                            indicators.append(i)

            return indicators
        except ParseException as e:
            LOG.warning('error parsing indicator pattern {}'.format(e))
        except Exception as e:
            LOG.error('exception parsing indicator pattern {}'.format(e))

    def _explore(self, root, types):
        objs = [root]
        while objs:
            obj = objs.pop()
            if isinstance(obj, dict):
                if 'type' in obj and obj['type'] in types:
                    yield obj
                else:
                    objs.extend(obj.values())
            elif isinstance(obj, list):
                objs.extend(obj)

    def _poll_taxii21_server(self):
        """
        TAXII 2.1 uses a limit url query parameter and a 'more' true/false key in the returned data
        as well as a next key for pagination, and the X-TAXII-Date-Added-Last to show the added
        datetime of the newest object in the response.
        https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988055
        :return: list of objects
        """

        data = []
        params = {'limit': '100'}
        if self.taxii_date_added_last:
            params['added_after'] = self.taxii_date_added_last
        fetch_more = True

        while fetch_more:
            # Poll the server
            # Check the 'more' field in the response json to see if there is more data
            # Poll until there is no data
            url = '{}collections/{}/objects/'.format(self.api_root, self.taxii_collection['id'])

            r = self.client.get(url, params=params)

            if r.status_code in [200, 201, 206]:
                try:
                    r_json = ujson.loads(r.text)
                    # Filter objects by type in the data returned by the TAXII 2.x server
                    types = ['indicator', 'attack-pattern', 'relationship']
                    objs = self._explore(r_json, types)
                    data.extend(objs)

                    # Sort the objs in data by timestamp to find the most recent timestamp
                    data.sort(key=lambda x: datetime.strptime(x['modified'], '%Y-%m-%dT%H:%M:%S.%fZ'))
                    if len(data):
                        if 'next' in r_json:
                            next_uuid = r_json['next']
                            params['next'] = next_uuid
                            ts = self.taxii_date_added_last
                            LOG.info('{} - Paginating via next uuid - {}'.format(self.name, next_uuid))
                        elif 'X-TAXII-Date-Added-Last' in r.headers:
                            params.pop('next', None)
                            ts = r.headers['X-TAXII-Date-Added-Last']
                            LOG.info('{} - Paginating via X-TAXII-Date-Added-Last header - {}'.format(self.name, ts))
                        else:
                            raise RuntimeError('Server does not appear to use X-TAXII-Date-Added-Last header \
                                    or "next" key in response, cannot paginate.  Is this really a TAXII 2.1 server?')

                        params['added_after'] = ts
                        self.taxii_date_added_last = ts

                    if 'more' in r_json and r_json['more'] is True:
                        pass
                    else:
                        break
                except Exception as e:
                    LOG.exception(e)
                    break
            else:
                break

        return data

    def _poll_taxii20_server(self):
        """
        TAXII 2.0 uses Range and Content-Range headers for pagination
        http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542715
        :return: list of objects
        """

        data = []
        size = 100
        params = {}
        if self.last_stix2_package_ts:
            params['added_after'] = self.last_stix2_package_ts
        fetch_more = True

        while fetch_more:
            # Poll the server
            # Check the response headers to see if there is paginated data
            # Poll until there is no data

            url = '{}collections/{}/objects/'.format(self.api_root, self.taxii_collection['id'])

            r = self.client.get(url, params=params)

            if r.status_code in [200, 201, 206]:
                try:
                    r_json = ujson.loads(r.text)
                    # Filter objects by type in the data returned by the TAXII 2.x server
                    types = ['indicator', 'attack-pattern', 'relationship']
                    objs = self._explore(r_json, types)
                    data.extend(objs)

                    # Sort the objs in data by timestamp to find the most recent timestamp
                    data.sort(key=lambda x: datetime.strptime(x['modified'], '%Y-%m-%dT%H:%M:%S.%fZ'))

                    if len(data):
                        self.last_stix2_package_ts = data[-1]['modified']

                    content_range = r.headers.get('Content-Range', None)
                    if content_range and content_range.startswith('items '):
                        content_range_start_end_size = content_range[6:]
                        content_range_start_end, content_range_size = content_range_start_end_size.split('/')
                        content_range_start, content_range_end = content_range_start_end.split('-')

                        next_start = int(content_range_end) + 1
                        # next_end = next_start + size
                        next_end = next_start + (int(content_range_end) - int(content_range_start)) + 1

                        if next_start < int(content_range_size):
                            updated_content_range = 'items {}-{}'.format(next_start, next_end)
                            self.client.headers.update({'Range': updated_content_range})
                        else:
                            break
                    else:
                        break
                except Exception as e:
                    LOG.exception(e)
                    break
            else:
                break

        return data

    def _poll_and_filter_collection(self, begin=None, end=None):
        if self.client:
            if self.taxii_collection:
                if self.taxii_version == '2.0':
                    data = self._poll_taxii20_server()
                elif self.taxii_version == '2.1':
                    data = self._poll_taxii21_server()
                else:
                    # Unsupported
                    data = []

                raw_objs = data

                # Sort objects by type in the data returned by the TAXII 2.x server
                objs = {}
                types = ['indicator', 'attack-pattern', 'relationship']
                for k in types:
                    objs[k] = []

                for obj in raw_objs:
                    if obj['type'] == 'indicator' and 'pattern' in obj:
                        objs[obj['type']].append(obj)
                    else:
                        objs[obj['type']].append(obj)

                ids_to_ttps = {}
                for t in objs['attack-pattern']:
                    ids_to_ttps[t['id']] = t

                indicators = []
                for i in objs['indicator']:
                    i_rels = [x for x in objs['relationship'] if i['id'] == x['source_ref']]
                    i_ttp_rels = [x for x in i_rels if x['target_ref'].startswith('attack-pattern')]
                    i_ttps = [ids_to_ttps[x['target_ref']] for x in i_ttp_rels]

                    mm_is = self._convert_stix2_obj_to_mm_obj(i, i_rels, i_ttps)
                    if mm_is:
                        # The indicator pattern is valid and was parsed
                        indicators.extend(mm_is)

                return indicators
            else:
                raise RuntimeError('no collection {}'.format(self.collection))
        else:
            raise RuntimeError('client does not exist {}'.format(self.collection))

    def _incremental_poll_collection(self, begin, end):
        cbegin = begin
        dt = timedelta(seconds=self.max_poll_dt)

        # self.last_stix2_package_ts = None

        while cbegin < end:
            cend = min(end, cbegin + dt)

            LOG.info('{} - polling {!r} to {!r}'.format(self.name, cbegin, cend))
            result = self._poll_and_filter_collection(begin=cbegin, end=cend)

            for i in result:
                yield i

            if self.last_stix2_package_ts is not None:
                self.last_taxii2_run = self.last_stix2_package_ts

            cbegin = cend

    def _process_item(self, item):
        return [item]

    def _manage_time(self, now):
        last_run = self.last_taxii2_run
        if last_run:
            last_run = dt_to_millisec(datetime.strptime(self.last_taxii2_run, '%Y-%m-%dT%H:%M:%S.%fZ'))
        max_back = now - (self.initial_interval * 1000)
        if last_run is None or last_run < max_back:
            last_run = max_back

        begin = datetime.utcfromtimestamp(last_run / 1000)
        begin = begin.replace(tzinfo=pytz.UTC)

        end = datetime.utcfromtimestamp(now / 1000)
        end = end.replace(tzinfo=pytz.UTC)

        if self.lower_timestamp_precision:
            end = end.replace(second=0, microsecond=0)
            begin = begin.replace(second=0, microsecond=0)

        return begin, end

    def _check_args(self):
        if (self.username or self.password) and self.api_key:
            raise RuntimeError(
                '%s - username, password, and api_key cannot all be set, poll not performed' % self.name
            )

        if not self.discovery_service:
            raise RuntimeError(
                '%s - discovery_service required and not set, poll not performed' % self.name
            )

        if not self.api_root:
            raise RuntimeError(
                '%s - api_root required and not set, poll not performed' % self.name
            )

        if not self.collection:
            raise RuntimeError(
                '%s - collection required and not set, poll not performed' % self.name
            )

        if not self.enabled:
            raise RuntimeError(
                '%s - node is disabled, poll not performed' % self.name
            )

    def _build_iterator(self, now):
        self._check_args()

        self._build_taxii2_client()
        self._get_api_root()
        self._get_collection()

        self._check_args()

        (begin, end) = self._manage_time(now)

        return self._incremental_poll_collection(begin=begin, end=end)

    def _flush(self):
        self.last_taxii2_run = None
        super(Taxii2Client, self)._flush()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Taxii2Client, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except Exception:
            pass
