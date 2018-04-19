import logging
import hmac
import hashlib
import base64
import time
import requests
import pytz
import os
import yaml
import re

from netaddr import IPNetwork, AddrFormatError
from urllib import quote
from basepoller import BasePollerFT
from utils import utc_millisec, dt_to_millisec
from datetime import datetime

LOG = logging.getLogger(__name__)
GENERIC_INDICATOR_MAP = [
    {"apiBranch": "emailAddresses", "apiEntity": "emailAddress", "indicator": {"address": "email-addr"}},
    {"apiBranch": "hosts", "apiEntity": "host", "indicator": {"hostName": "domain"}},
    {"apiBranch": "urls", "apiEntity": "url", "indicator": {"text": "URL"}},
    {"apiBranch": "files", "apiEntity": "file", "indicator": {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}},
    {"apiBranch": "registryKeys", "apiEntity": "registryKey", "indicator": None},
    {"apiBranch": "userAgents", "apiEntity": "userAgent", "indicator": None}
]

IP_INDICATOR_MAP = [
    {"apiBranch": "addresses", "apiEntity": "address", "indicator": ["ip"]},
    {"apiBranch": "ipPorts", "apiEntity": "ipPort", "indicator": None}
]

GROUP_TYPES = ["adversaries", "campaigns", "documents", "emails", "incidents", "signatures", "threats"]

SHA256_PATTERN = "[A-Fa-f0-9]{64}"
SHA1_PATTERN = "[A-Fa-f0-9]{40}"
MD5_PATTERN = "[A-Fa-f0-9]{32}"


class ThreatConnect(object):
    api_secret = None
    api_key = None
    api_url = None
    api_base_uri = None
    signature = None
    api_timestamp = None
    owner = None
    hash_patterns = {"sha256": re.compile(SHA256_PATTERN), "sha1": re.compile(SHA1_PATTERN),
                     "md5": re.compile(MD5_PATTERN)}

    def __init__(self, api_secret, api_key, api_url, api_base_uri, owner):
        self.api_secret = api_secret
        self.api_key = api_key
        self.api_url = api_url
        self.api_base_uri = api_base_uri
        self.owner = None if owner is None else quote(owner)

    def prepare_get(self, uri):
        self.api_timestamp = str(int(time.time()))
        message = '{}:GET:{}'.format(uri, self.api_timestamp)
        digest = hmac.new(self.api_secret, msg=message, digestmod=hashlib.sha256).digest()
        self.signature = 'TC {}:{}'.format(self.api_key, base64.b64encode(digest).decode())

    def __call__(self, r):
        r.headers['Authorization'] = self.signature
        r.headers['Timestamp'] = self.api_timestamp
        return r

    def _detect_ip_version(self, ip_addr):
        try:
            parsed = IPNetwork(ip_addr)
        except (AddrFormatError, ValueError):
            LOG.error('{} - Unknown IP version: {}'.format(self.name, ip_addr))
            return None

        if parsed.version == 4:
            return 'IPv4'

        if parsed.version == 6:
            return 'IPv6'

        return None

    def _detect_sha_version(self, hash):
        for hash_type, re_obj in self.hash_patterns.iteritems():
            if re_obj.match(hash) is not None:
                return hash_type
        return None

    def group_indicator_processing(self, item, group_type, group_id, f_seen, l_seen):
        attributes = {'tc_group_type': group_type, 'tc_group_id': group_id, 'first_seen': f_seen, 'last_seen': l_seen}
        indicator = item.get("summary", None)
        confidence = item.get('threatAssessConfidence', None)
        if confidence is not None:
            attributes['confidence'] = int(confidence)
        tc_indicator_type = item.get("type", None)
        if tc_indicator_type == "Address":
            attributes['type'] = self._detect_ip_version(indicator)
        elif tc_indicator_type == "File":
            attributes['type'] = self._detect_sha_version(indicator)
        elif tc_indicator_type == "EmailAddress":
            attributes['type'] = "email-addr"
        elif tc_indicator_type == "URL":
            attributes['type'] = "URL"
        elif tc_indicator_type == "Host":
            attributes['type'] = "domain"
        if tc_indicator_type is None or indicator is None:
            return []
        return [indicator, attributes]

    def general_processing(self, item, indicator_map, f_seen, l_seen):
        result = []
        for tc_indicator, mm_indicator in indicator_map.iteritems():
            indicator = item.get(tc_indicator, None)
            if indicator is None:
                continue
            attributes = {'type': mm_indicator, 'first_seen': f_seen, 'last_seen': l_seen}
            confidence = item.get('threatAssessConfidence', None)
            if confidence is not None:
                attributes['confidence'] = int(confidence)
            add_attributes = dict(indicator_map)
            add_attributes.pop(tc_indicator)
            for tc_attribute, mm_attribute in add_attributes.iteritems():
                value = item.get(tc_attribute, None)
                if value is None:
                    continue
                attributes[mm_attribute] = value
            result.append([indicator, attributes])
        return result

    def ip_processing(self, item, indicator_list, f_seen, l_seen):
        result = []
        for tc_indicator in indicator_list:
            indicator = item.get(tc_indicator, None)
            if indicator is None:
                continue
            ip_type = self._detect_ip_version(indicator)
            if ip_type is None:
                continue
            attributes = {'type': ip_type, 'first_seen': f_seen, 'last_seen': l_seen}
            confidence = item.get('threatAssessConfidence', None)
            if confidence is not None:
                attributes['confidence'] = int(confidence)
            result.append([indicator, attributes])
        return result

    def _paginate_request(self, entry_point, entity, from_timestamp=None):
        if from_timestamp is not None:
            isotime = datetime.fromtimestamp(from_timestamp / 1000).replace(tzinfo=pytz.utc).isoformat()

        def do_call(start):
            api_request = entry_point + '?resultStart={}&resultLimit=100'.format(start)
            if from_timestamp is not None:
                api_request += "&modifiedSince={}".format(isotime)
            if self.owner is not None:
                api_request += '&owner={}'.format(self.owner)
            self.prepare_get(api_request)
            final_url = self.api_url + api_request
            response = requests.get(final_url, auth=self)
            doc = response.json()
            if doc["status"] != "Success":
                raise RuntimeError("ThreatConnectAPI - {}".format(doc.get("message", "unknown error")))
            return doc

        r_data = do_call(0)
        pointer = 0
        if "data" not in r_data:
            return
        if "resultCount" not in r_data["data"]:
            return
        result_count = r_data["data"]["resultCount"]
        while True:
            items = r_data["data"][entity]
            for item in items:
                yield item
            pointer += len(items)
            if result_count <= pointer:
                break
            r_data = do_call(pointer)

    def indicator_iterator(self, last_tc_run):
        from_timestamp = last_tc_run
        for a in IP_INDICATOR_MAP:
            indicator_list = a.get("indicator", None)
            if indicator_list is None:
                continue
            for item in self._paginate_request(self.api_base_uri + "/v2/indicators/" + a["apiBranch"], a["apiEntity"],
                                               from_timestamp):
                yield ("IP", item, indicator_list)

        for a in GENERIC_INDICATOR_MAP:
            indicator_map = a.get("indicator", None)
            if indicator_map is None:
                continue
            for item in self._paginate_request(self.api_base_uri + "/v2/indicators/" + a["apiBranch"], a["apiEntity"],
                                               from_timestamp):
                yield ("GENERAL", item, indicator_map)

    def groups_iterator(self, groups):
        for group_type, group_ids in groups.iteritems():
            for group_id in group_ids:
                for item in self._paginate_request(
                        self.api_base_uri + "/v2/groups/{}/{}/indicators".format(group_type, group_id), "indicator"):
                    yield (item, group_type, group_id)


class TCMiner(BasePollerFT):
    tc = None
    api_secret = None
    api_key = None
    api_url = None
    api_base_uri = None
    owner = None
    side_config_path = None
    last_tc_run = None

    def configure(self):
        super(TCMiner, self).configure()
        self.api_key = self.config.get('apikey', None)
        self.api_secret = self.config.get('apisecret', None)
        sandbox = self.config.get('sandbox', False)
        if sandbox:
            self.api_url = 'https://sandbox.threatconnect.com'
            self.api_base_uri = '/api'
        else:
            self.api_url = 'https://api.threatconnect.com'
            self.api_base_uri = ''
        self.owner = self.config.get('owner', None)
        if not (None in [self.api_key, self.api_secret]):
            self.tc = ThreatConnect(self.api_secret, self.api_key, self.api_url, self.api_base_uri, self.owner)
        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )
        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        self.tc = None
        data_owner = sconfig.get('owner', self.owner)
        side_api_key = sconfig.get('apikey', self.api_key)
        side_api_secret = sconfig.get('apisecret', self.api_secret)
        if not (None in [side_api_key, side_api_secret]):
            self.tc = ThreatConnect(side_api_secret, side_api_key, self.api_url, self.api_base_uri, data_owner)

    def _saved_state_restore(self, saved_state):
        super(TCMiner, self)._saved_state_restore(saved_state)
        self.last_tc_run = saved_state.get('last_tc_run', None)
        LOG.info('last_tc_run from sstate: %s', self.last_tc_run)

    def _saved_state_create(self):
        sstate = super(TCMiner, self)._saved_state_create()
        sstate['last_tc_run'] = self.last_tc_run
        return sstate

    def _saved_state_reset(self):
        super(TCMiner, self)._saved_state_reset()
        self.last_tc_run = None

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(TCMiner, self).hup(source=source)

    @staticmethod
    def gc(name, config=None):
        BasePollerFT.gc(name, config=config)

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
        finally:
            pass


class IndicatorsMiner(TCMiner):
    initial_interval = None

    def configure(self):
        super(IndicatorsMiner, self).configure()
        self.initial_interval = self.config.get('initial_interval', 30)

    def _build_iterator(self, now):
        if self.tc is None:
            raise RuntimeError(
                '{} - API Key or API Secret not set, '
                'poll not performed'.format(self.name)
            )
        if self.last_successful_run is None:
            self.last_successful_run = utc_millisec() - self.initial_interval * 86400000.0
        if self.last_tc_run is None:
            self.last_tc_run = self.last_successful_run

        return self.tc.indicator_iterator(self.last_tc_run)

    def _process_item(self, item):
        tc_date_added = item[1].get('dateAdded', None)
        tc_last_modified = item[1].get('lastModified', None)
        f_seen = utc_millisec() if tc_date_added is None else dt_to_millisec(
            datetime.strptime(tc_date_added, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc))
        l_seen = utc_millisec() if tc_last_modified is None else dt_to_millisec(
            datetime.strptime(tc_last_modified, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc))
        if l_seen > self.last_tc_run:
            self.last_tc_run = l_seen
        if item[0] == "IP":
            return self.tc.ip_processing(item[1], item[2], f_seen, l_seen)
        if item[0] == "GENERAL":
            return self.tc.general_processing(item[1], item[2], f_seen, l_seen)
        return []


class GroupsMiner(TCMiner):
    groups = {}

    def configure(self):
        super(GroupsMiner, self).configure()
        groups = self.config.get('groups', None)
        if groups is not None and isinstance(groups, dict):
            for group_type in GROUP_TYPES:
                group_ids = groups.get(group_type, None)
                if group_ids is not None and isinstance(group_ids, list):
                    self.groups[group_type] = group_ids

    def _build_iterator(self, now):
        if self.tc is None:
            raise RuntimeError(
                '{} - API Key or API Secret not set, '
                'poll not performed'.format(self.name)
            )

        return self.tc.groups_iterator(self.groups)

    def _process_item(self, item):
        tc_date_added = item[0].get('dateAdded', None)
        tc_last_modified = item[0].get('lastModified', None)
        f_seen = utc_millisec() if tc_date_added is None else dt_to_millisec(
            datetime.strptime(tc_date_added, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc))
        l_seen = utc_millisec() if tc_last_modified is None else dt_to_millisec(
            datetime.strptime(tc_last_modified, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.utc))

        return [self.tc.group_indicator_processing(item[0], item[1], item[2], f_seen, l_seen)]
