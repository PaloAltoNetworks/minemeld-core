#  Copyright 2017-present Palo Alto Networks, Inc
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

import os
import os.path
import logging
import sqlite3
from contextlib import contextmanager

import ujson as json

from . import basepoller
from . import ft_states
from .utils import interval_in_sec, dt_to_millisec, utc_millisec

LOG = logging.getLogger(__name__)

_MAX_AGE_OUT = ((1 << 32)-1)*1000  # 2106-02-07 6:28:15


@contextmanager
def dbconnection(path):
    conn = sqlite3.connect(path)

    yield conn

    conn.close()


class Miner(basepoller.BasePollerFT):
    def __init__(self, name, chassis, config):
        super(Miner, self).__init__(name, chassis, config)

        self.last_run = None

    def configure(self):
        if not 'age_out' in self.config:
            self.config['age_out'] = {
                'interval': 1800,
                'sudden_death': False,
                'default': None
            }

        super(Miner, self).configure()

        self.default_ttl = self.config.get('default_ttl', 86400)

        self.path = self.config.get('path', None)
        if self.path is None:
            self.path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_indicators.db' % self.name
            )

    def _collect_garbage(self):
        if not os.path.isfile(self.path):
            return

        now = utc_millisec()

        with self.state_lock, dbconnection(self.path) as conn:
            if self.state != ft_states.STARTED:
                return

            with conn:
                for i, v in self.table.query(index='_withdrawn',
                                             to_key=now,
                                             include_value=True):
                    # if v.get('_last_run', 0) >= (self.last_successful_run-1):
                    #     continue

                    itype = v.get('type', None)

                    conn.execute('delete from indicators where indicator=? and type=?;', (i, itype))

                    self.table.delete(i, itype=itype)
                    self.statistics['garbage_collected'] += 1

    def _calc_age_out(self, indicator, attributes):
        if isinstance(attributes['_expiration_ts'], int):
            return attributes['_expiration_ts']

        return _MAX_AGE_OUT

    def _process_item(self, item):
        indicator = item[0]
        value = json.loads(item[2])
        value['type'] = item[1]
        value['_expiration_ts'] = item[3]

        if value['_expiration_ts'] is None:
            # if none, expiration is set to update_ts+default_ttl
            value['_expiration_ts'] = item[4]+self.default_ttl*1000

        return [[indicator, value]]

    def _updates_iterator(self, last_successful_run):
        with dbconnection(self.path) as conn:
            for row in conn.execute('select * from indicators where update_ts >= ?', (last_successful_run,)):
                yield row

    def _build_iterator(self, now):
        if not os.path.isfile(self.path):
            return []

        last_successful_run = 0
        if self.last_successful_run is not None:
            last_successful_run = self.last_successful_run

        return self._updates_iterator(last_successful_run)

    def hup(self, source=None):
        super(Miner, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        basepoller.BasePollerFT.gc(name, config=config)

        path = None
        if config is not None:
            path = config.get('path', None)
        if path is None:
            path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_indicators.db'.format(name)
            )

        try:
            os.remove(path)
        except:
            pass
