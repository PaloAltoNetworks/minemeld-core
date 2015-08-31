from . import base


class InspectFT(base.BaseFT):
    _ftclass = 'InspectFT'

    def update(self, source=None, indicator=None, value=None):
        print '%s - %s: %s' % (source, indicator, value)

    def call_length(self, target):
        print self.do_rpc(target, 'length')

    def call_get(self, target, indicator):
        print self.do_rpc(target, 'get', indicator=indicator)

    def call_get_all(self, target):
        print self.do_rpc(target, 'get_all')

    def call_get_range(self, target, index=None, from_key=None, to_key=None):
        print self.do_rpc(target, 'get_range', index=index,
                          from_key=from_key, to_key=to_key)
