import requests
import logging
import re
import itertools

from . import basepoller

LOG = logging.getLogger(__name__)


class HttpFT(basepoller.BasePollerFT):
    def configure(self):
        super(HttpFT, self).configure()

        self.url = self.config.get('url', None)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.ignore_regex = self.config.get('ignore_regex', None)
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)

        self.indicator = self.config.get('indicator', None)

        if self.indicator is not None:
            if 'regex' in self.indicator:
                self.indicator['regex'] = re.compile(self.indicator['regex'])
            else:
                raise ValueError('%s - indicator stanza should have a regex',
                                 self.name)
            if 'transform' not in self.indicator:
                if self.indicator['regex'].groups > 0:
                    LOG.warning('%s - no transform string for indicator'
                                ' but pattern contains groups',
                                self.name)
                self.indicator['transform'] = '\g<0>'

        self.fields = self.config.get('fields', {})
        for f, fattrs in self.fields.iteritems():
            if 'regex' in fattrs:
                fattrs['regex'] = re.compile(fattrs['regex'])
            else:
                raise ValueError('%s - %s field does not have a regex',
                                 self.name, f)
            if 'transform' not in fattrs:
                if fattrs['regex'].groups > 0:
                    LOG.warning('%s - no transform string for field %s'
                                ' but pattern contains groups',
                                self.name, f)
                fattrs['transform'] = '\g<0>'

    def _process_item(self, line):
        line = line.strip()
        if not line:
            return [[None, None]]

        if self.indicator is None:
            indicator = line.split()[0]

        else:
            indicator = self.indicator['regex'].search(line)
            if indicator is None:
                return [[None, None]]

            indicator = indicator.expand(self.indicator['transform'])

        attributes = {}
        for f, fattrs in self.fields.iteritems():
            m = fattrs['regex'].search(line)

            if m is None:
                continue

            attributes[f] = m.expand(fattrs['transform'])

            try:
                i = int(attributes[f])
            except:
                pass
            else:
                attributes[f] = i

        return [[indicator, attributes]]

    def _build_iterator(self, now):
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
        if self.ignore_regex is not None:
            result = itertools.ifilter(
                lambda x: self.ignore_regex.match(x) is None,
                result
            )

        return result
