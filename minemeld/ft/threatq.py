#  Copyright 2015 Palo Alto Networks, Inc
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
This module implements minemeld.ft.threatq.Export, the Miner node for ThreatQ
export API.
"""

import requests
import logging
import os
import yaml
import netaddr

from . import basepoller

LOG = logging.getLogger(__name__)


class Export(basepoller.BasePollerFT):
    """Implements class for Miners of ThreatQ Export API.

    **Config parameters**
        :side_config (str): path to the side config file, defaults
            to CONFIGDIR/<node name>_side_config.yml
        :polling_timeout: timeout of the polling request in seconds.
            Default: 20

    **Side Config parameters**
        :url: URL of the feed.
        :polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*

    Example:
        Example side config in YAML::

            url: https://10.5.172.225/api/export/6e472a434efe34ceb5a99ff6c9a8124e/?token=xoZjB4ypoNQdnbQhVi0B
            verify_cert: false

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """
    def configure(self):
        super(Export, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)

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

        self.url = sconfig.get('url', None)
        if self.url is not None:
            LOG.info('%s - url set', self.name)

        self.verify_cert = sconfig.get('verify_cert', True)

    def _process_item(self, line):
        line = line.strip()
        if not line:
            return [[None, None]]

        itype, indicator = line.split(',', 1)

        attributes = {}
        if itype == 'IP Address':
            ipaddr = netaddr.IPAddress(indicator)

            if ipaddr.version == 4:
                attributes['type'] = 'IPv4'

            elif ipaddr.version == 6:
                attributes['type'] = 'IPv6'

            else:
                LOG.error(
                    '%s - %s: unknown IP version %s',
                    line,
                    self.name,
                    ipaddr.version
                )
                return [[None, None]]

        elif itype == 'CIDR Block':
            ipaddr = netaddr.IPNetwork(indicator)

            if ipaddr.version == 4:
                attributes['type'] = 'IPv4'

            elif ipaddr.version == 6:
                attributes['type'] = 'IPv6'

            else:
                LOG.error(
                    '%s - %s: unknown IP version %s',
                    line,
                    self.name,
                    ipaddr.version
                )
                return [[None, None]]

        elif itype == 'FQDN':
            attributes['type'] = 'domain'

        elif itype == 'URL':
            attributes['type'] = 'URL'

        else:
            LOG.error(
                '%s - unknown indicator type %s - ignored',
                self.name,
                itype
            )
            return [[None, None]]

        return [[indicator, attributes]]

    def _build_iterator(self, now):
        if self.url is None:
            raise RuntimeError(
                '%s - url not set, poll not performed' % self.name
            )

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            self.url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        result = r.iter_lines()

        return result

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Export, self).hup(source=source)

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
