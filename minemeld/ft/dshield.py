import logging
import copy

from . import http

LOG = logging.getLogger(__name__)


class DshieldBlockList(http.HttpFT):
    _ftclass = 'DshieldBlockList'

    def __init__(self, name, chassis, config):
        config['cchar'] = '#'
        config['url'] = 'https://www.dshield.org/block.txt'
        config['source_name'] = 'https://www.dshield.org/block.txt'

        super(DshieldBlockList, self).__init__(
            name,
            chassis,
            config
        )

    def _process_line(self, line):
        toks = line.split('\t')
        if toks[0] == 'Start':
            return None, None

        indicator = '-'.join(toks[:2])

        attributes = copy.deepcopy(self.attributes)

        attributes['direction'] = 'inbound'
        attributes['type'] = 'IPv4'

        attributes['dshield_nattacks'] = int(toks[3])
        if len(toks) > 4:
            attributes['dshield_name'] = toks[4]
        if len(toks) > 5:
            attributes['dshield_country'] = toks[5]
        if len(toks) > 6:
            attributes['dshield_email'] = toks[6]

        return indicator, attributes
