from __future__ import absolute_import

import logging
import requests
import os
import ujson
import netaddr
import netaddr.core

from . import csv

LOG = logging.getLogger(__name__)


class ThreatFeed(csv.CSVFT):
    def configure(self):
        super(ThreatFeed, self).configure()

        self.token = self.config.get('token',
                                     '@RECORDED_FUTURE_TOKEN')
        if self.token.startswith('@'):
            self.token = os.getenv(self.public_key[1:])

    def _process_item(self, row):
        row.pop(None, None)  # I love this

        result = {}

        indicator = row.get('Name', '')
        if indicator == '':
            return []

        try:
            ip = netaddr.IPAddress(indicator)
        except netaddr.core.AddrFormatError:
            LOG.exception("%s - failed parsing indicator", self.name)
            return []

        if ip.version == 4:
            result['type'] = 'IPv4'
        elif ip.version == 6:
            result['type'] = 'IPv6'
        else:
            LOG.debug("%s - unknon IP version %d", self.name, ip.version)
            return []

        risk = row.get('Risk', '')
        if risk != '':
            try:
                result['recordedfuture_risk'] = int(risk)
            except:
                LOG.debug("%s - invalid risk string: %s",
                          self.name, risk)

        riskstring = row.get('RiskString', '')
        if riskstring != '':
            result['recordedfuture_riskstring'] = riskstring

        edetails = row.get('EvidenceDetails', '')
        if edetails != '':
            try:
                edetails = ujson.loads(edetails)
            except:
                LOG.debug("%s - invalid JSON string in EvidenceDetails: %s",
                          self.name, edetails)
            else:
                edetails = edetails.get('EvidenceDetails', [])
                result['recordedfuture_evidencedetails'] = \
                    [ed['Rule'] for ed in edetails]

        result['recordedfuture_entityurl'] = \
            'https://www.recordedfuture.com/live/sc/entity/ip:'+indicator

        return [[indicator, result]]

    def _build_request(self, now):
        params = {
            'version': '1.0',
            'output_format': 'csv/splunk',
            'token': self.token
        }

        r = requests.Request(
            'GET',
            'https://api.recordedfuture.com/query/list/HighRisk/IpAddress',
            params=params
        )

        return r.prepare()
