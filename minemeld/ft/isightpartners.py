from __future__ import absolute_import

import logging
import urllib
import hmac
import hashlib
import email.Utils
import requests
import os

from . import csv

LOG = logging.getLogger(__name__)


class Indicators(csv.CSVFT):
    def configure(self):
        super(Indicators, self).configure()

        self.public_key = self.config.get('public_key',
                                          '@ISIGHT_PRIVATE_KEY')
        if self.public_key.startswith('@'):
            self.public_key = os.getenv(self.public_key[1:])

        self.private_key = self.config.get('private_key',
                                           '@ISIGHT_PRIVATE_KEY')
        if self.private_key.startswith('@'):
            self.private_key = os.getenv(self.private_key[1:])

        self.starting_interval = self.config.get(
            'starting_interval',
            604800
        )

    def _process_item(self, row):
        row.pop(None, None)  # I love this

        LOG.debug('row: %s', row)

        result = []

        if row.get('ip', '') != '':
            value = {'isightpartners_'+k: v for k, v in row.iteritems()}
            value['type'] = 'IPv4'
            result.append([row['ip'], value])

        if row.get('domain', '') != '':
            value = {'isightpartners_'+k: v for k, v in row.iteritems()}
            value['type'] = 'domain'
            result.append([row['domain'], value])

        if row.get('url', '') != '':
            value = {'isightpartners_'+k: v for k, v in row.iteritems()}
            value['type'] = 'URL'
            result.append([row['url'], value])

        return result

    def _build_request(self, now):
        sdate = now/1000.0 - self.starting_interval
        if self.last_run is not None:
            sdate = self.last_run/1000.0

        query = {
            'startDate': int(sdate),
            'endDate': int(now/1000.0)
        }
        timestamp = email.Utils.formatdate(localtime=True)
        uri = '/view/indicators?'+urllib.urlencode(query)
        data = uri+'2.0'+'text/csv'+timestamp
        data = hmac.new(self.private_key, data, hashlib.sha256)

        headers = {
            'Accept': 'text/csv',
            'Accept-Version': '2.0',
            'X-Auth': self.public_key,
            'X-Auth-Hash': data.hexdigest(),
            'X-App-Name': 'mysight-api',
            'Date': timestamp
        }

        r = requests.Request(
            'GET',
            'https://api.isightpartners.com'+uri,
            headers=headers
        )

        return r.prepare()
