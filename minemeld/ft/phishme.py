#  Copyright 2016 Palo Alto Networks, Inc
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

"""
This module implements minemeld.ft.phishme.Intelligence, the Miner node for
PhishMe Intelligence API.
"""

import os
import yaml
import requests
import itertools
import logging

from . import basepoller
from .utils import interval_in_sec

LOG = logging.getLogger(__name__)


_API_BASE = 'https://www.threathq.com/apiv1'
_API_THREAT_SEARCH = '/threat/search'
_API_THREAT_UPDATE = '/threat/updates'

_RESULTS_PER_PAGE = 10


class Intelligence(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        self.position = None

        super(Intelligence, self).__init__(name, chassis, config)

    def configure(self):
        super(Intelligence, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.prefix = self.config.get('prefix', 'phishme')
        initial_interval = self.config.get('initial_interval', '30d')
        self.initial_interval = interval_in_sec(initial_interval)
        if initial_interval is None:
            LOG.error(
                '%s - wrong initial_interval format: %s',
                self.name, initial_interval
            )
            self.initial_interval = 3600

        self.fields = self.config.get('fields', [
            'threatDetailURL',
            'label',
            'threatType'
        ])
        self.confidence_map = self.config.get('confidence_map', {
            'Major': 100,
            'Moderate': 70,
            'Minor': 34,
            'None': 0
        })
        self.product = self.config.get('product', 'malware')
        self.source_name = self.config.get('source_name', 'phishme.intelligence')

        self.api_key = None
        self.username = None
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

        self.api_key = sconfig.get('api_key', None)
        if self.api_key is not None:
            LOG.info('%s - API Key set', self.name)

        self.username = sconfig.get('username', None)
        if self.username is not None:
            LOG.info('%s - username set', self.name)

    def _saved_state_restore(self, saved_state):
        super(Intelligence, self)._saved_state_restore(saved_state)
        self.position = saved_state.get('position', None)
        LOG.info('position from sstate: %s', self.position)

    def _saved_state_create(self):
        sstate = super(Intelligence, self)._saved_state_create()
        sstate['position'] = self.position

        return sstate

    def _saved_state_reset(self):
        super(Intelligence, self)._saved_state_reset()
        self.position = None

    def _update_attributes(self, current, _new):
        LOG.debug('current: %r', current)
        LOG.debug('_new: %r', _new)

        # create temp store for phishme spec values
        phishme_values = {}

        # loop over the phishme fields
        for f in self.fields:
            field_name = self.prefix+'_'+f

            newv = _new.get(field_name, None)
            if newv is None:
                continue

            phishme_values[field_name] = current.get(field_name, [])
            if newv[0] not in phishme_values[field_name]:
                phishme_values[field_name].append(newv[0])

        # add role
        field_name = self.prefix+'_role'
        newrole = _new.get(field_name, None)
        if newrole is not None:
            phishme_values[field_name] = current.get(field_name, [])
            if newrole[0] not in phishme_values[field_name]:
                phishme_values[field_name].append(newrole[0])

        # impact and confidence
        if _new['confidence'] < current['confidence']:
            phishme_values['confidence'] = current['confidence']
            phishme_values[self.prefix+'_impact'] = current[self.prefix+'_impact']

        LOG.debug(phishme_values)

        current.update(_new)
        current.update(phishme_values)

        return current

    def _convert_block(self, block):
        v = {}

        impact = block.get('impact', None)
        if impact is not None:
            v[self.prefix+'_impact'] = impact

            if impact in self.confidence_map:
                v['confidence'] = self.confidence_map[impact]

        role = block.get('role', None)
        if role is not None:
            v[self.prefix+'_role'] = [role]

        type_ = block.get('blockType', None)
        if type_ is None:
            LOG.error(
                '%s - no "blockType" attribute in block',
                self.name
            )
            return None, None

        if type_ == 'IPv4 Address':
            v['type'] = 'IPv4'
        elif type_ == 'Domain Name':
            v['type'] = 'domain'
        elif type_ == 'URL':
            v['type'] = 'URL'
        else:
            LOG.error('%s - unknown blockType: %s', self.name, type_)
            return None, None

        indicator = block.get('data', None)
        if indicator is None:
            LOG.error('%s - no "data" attribute in block', self.name)
            return None, None

        return indicator, v

    def _process_item(self, item):
        result = []

        block_set = item.get('blockSet', None)

        value = {}
        for f in self.fields:
            fv = item.get(f, None)
            if fv is None:
                continue
            value[self.prefix+'_'+f] = [fv]

        if block_set is not None:
            for block in block_set:
                indicator, v = self._convert_block(block)

                if indicator is not None:
                    v.update(value)
                    result.append([indicator, v])

        else:
            LOG.error('%s - no "blockSet" in item', self.name)
            result = [[None, None]]

        return result

    def _build_iterator(self, now):
        LOG.info('position: %s', self.position)

        if self.api_key is None or self.username is None:
            raise RuntimeError('%s - credentials not set' % self.name)

        if self.position is None:
            # backfill
            return itertools.chain(
                self._threathq_backfill(now),
                self._threathq_update(now)
            )

        # update
        return self._threathq_update(now)

    def _threathq_backfill(self, now):
        payload = {
            'beginTimestamp': int(now/1000.0 - self.initial_interval),
            'endTimestamp': int(now/1000.0),
            'threatType': self.product,
            'resultsPerPage': _RESULTS_PER_PAGE
        }

        cur_page = 0
        total_pages = 1

        while cur_page < total_pages:
            LOG.debug('%s - polling backfill %d/%d', self.name, cur_page, total_pages)

            payload['page'] = cur_page

            rkwargs = dict(
                verify=self.verify_cert,
                timeout=self.polling_timeout,
                params=payload,
                auth=(self.username, self.api_key)
            )

            r = requests.post(
                _API_BASE+_API_THREAT_SEARCH,
                **rkwargs
            )

            try:
                r.raise_for_status()
            except:
                LOG.error(
                    '%s - exception in request: %s %s',
                    self.name, r.status_code, r.content
                )
                raise

            cjson = r.json()

            data = cjson.get('data', None)
            if 'data' is None:
                LOG.error('%s - no "data" in response', self.name)
                return

            page = data.get('page', None)
            if page is None:
                LOG.error('%s - no "page" in response', self.name)
                return
            total_pages = page.get('totalPages', None)
            if total_pages is None:
                LOG.error('%s - no "totalPages" in response', self.name)
                return
            LOG.debug('%s - total_pages set to %d', self.name, total_pages)

            threats = data.get('threats', [])
            for t in threats:
                yield t

            cur_page += 1

    def _threathq_update(self, now):
        changelog_size = 1000
        while changelog_size == 1000:
            if self.position is not None:
                payload = dict(position=self.position)
            else:
                payload = dict(timestamp=int(now/1000.0))

            rkwargs = dict(
                stream=True,
                verify=self.verify_cert,
                timeout=self.polling_timeout,
                params=payload,
                auth=(self.username, self.api_key)
            )

            r = requests.post(
                _API_BASE+_API_THREAT_UPDATE,
                **rkwargs
            )

            try:
                r.raise_for_status()
            except:
                LOG.error(
                    '%s - exception in request: %s %s',
                    self.name, r.status_code, r.content
                )
                raise

            cjson = r.json()

            data = cjson.get('data', None)
            if data is None:
                LOG.error('%s - no "data" in update request', self.name)
                return

            changelog = data.get('changelog', None)
            if changelog is not None:
                changelog_size = len(changelog)

            else:
                LOG.info('%s - no "changelog" in update request', self.name)
                changelog_size = 0
                changelog = []

            thgen = self._retrieve_threats(
                self._group_changes_in_pages(
                    itertools.ifilter(self._filter_changes, changelog)
                )
            )
            for t in thgen:
                yield t

            next_position = data.get('nextPosition', None)
            if next_position is None:
                LOG.error('%s - no nextPosition in update request', self.name)
            else:
                self.position = next_position

    def _group_changes_in_pages(self, ichanges):
        # I know I could use izip with *n, but really ?
        threatids = []
        for c in ichanges:
            id_ = str(c.get('threatId', None))
            if id_ is None:
                LOG.error('%s - change with no threatId', self.name)
                continue

            type_ = c.get('threatType', None)
            if type_ is None:
                LOG.error('%s - change with no threatType', self.name)
                continue

            if type_ == 'malware':
                id_ = 'm_' + id_
            elif type_ == 'phish':
                id_ = 'p_' + id_
            else:
                LOG.error('%s - unknown threatType: %s', self.name, type_)
                continue

            threatids.append(id_)
            if len(threatids) == _RESULTS_PER_PAGE:
                yield threatids
                threatids = []

        if len(threatids) != 0:
            yield threatids

    def _retrieve_threats(self, pages):
        for p in pages:
            payload = {
                'resultsPerPage': _RESULTS_PER_PAGE,
                'threatId': p
            }

            rkwargs = dict(
                verify=self.verify_cert,
                timeout=self.polling_timeout,
                params=payload,
                auth=(self.username, self.api_key)
            )

            r = requests.post(
                _API_BASE+_API_THREAT_SEARCH,
                **rkwargs
            )

            try:
                r.raise_for_status()
            except:
                LOG.error(
                    '%s - exception in request: %s %s',
                    self.name, r.status_code, r.content
                )
                raise

            cjson = r.json()

            data = cjson.get('data', None)
            if data is None:
                LOG.error('%s - no "data" in search request', self.name)
                continue

            threats = data.get('threats', None)
            if threats is None:
                LOG.error('%s - no "threats" in search request', self.name)
                continue

            for t in threats:
                yield t

    def _filter_changes(self, change):
        if change.get('deleted', None):
            LOG.debug('%s - deleted change', self.name)
            return False

        if self.product == 'all':
            return True

        threat_type = change.get('threatType', None)
        if threat_type is None:
            LOG.error('%s - change with no threatType', self.name)
            return False

        if threat_type == 'malware' and self.product == 'malware':
            return True

        if threat_type == 'phish' and self.product == 'phish':
            return True

        return False

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Intelligence, self).hup(source)
