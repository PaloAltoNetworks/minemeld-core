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

import logging
import os
import yaml
import minemeld.packages.ise.ers
from . import basepoller

LOG = logging.getLogger(__name__)


class ErsSgt(basepoller.BasePollerFT):
    def configure(self):
        super(ErsSgt, self).configure()

        self.kwargs = {}
        for x in ['hostname', 'username', 'password',
                  'verify_cert', 'timeout']:
            if x == 'verify_cert':
                self.kwargs['verify'] = self.config.get(x, None)
            else:
                self.kwargs[x] = self.config.get(x, None)

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self._load_side_config()

        self.prefix = self.config.get('prefix', 'ise_sgt')

        d = self.kwargs.copy()
        if d['password']:
            d['password'] = '*' * 6
        LOG.debug('%s prefix: %s', d, self.prefix)

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except IOError as e:
            LOG.info('%s - No side config: %s', self.name, e)
            return

        if sconfig is None:
            LOG.info('%s - Empty side config: %s', self.name,
                     self.side_config_path)
            return

        for x in ['hostname', 'username', 'password',
                  'verify_cert', 'timeout']:
            v = sconfig.get(x, None)
            if v is not None and x == 'verify_cert':
                self.kwargs['verify'] = v
            elif v is not None:
                self.kwargs[x] = v

    def _process_item(self, item):
        return [[item['ip'], {'type': 'IPv4', self.prefix: item['sgt']}]]

    def _build_iterator(self, now):
        def indicators(ips_sgts_map):
            LOG.debug('SGT indicators #%d %s', len(api.ips_sgts_map),
                      api.ips_sgts_map)
            for item in ips_sgts_map:
                yield {'ip': item, 'sgt': ips_sgts_map[item]}

        try:
            api = minemeld.packages.ise.ers.IseErs(**self.kwargs)
        except minemeld.packages.ise.ers.IseErsError as e:
            # missing arguments
            x = '%s: poll not performed: %s' % (self.name, e)
            LOG.info('%s', x)
            raise RuntimeError(x)

        api.sgts_ips_map()

        return indicators(api.ips_sgts_map)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(ErsSgt, self).hup(source=source)

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
        except:
            pass
