import logging
import copy

from . import condition


LOG = logging.getLogger(__name__)


class _Filters(object):
    def __init__(self, filters):
        self.filters = []

        for f in filters:
            cf = {
                'name': f.get('name', 'filter_%d' % len(self.filters)),
                'conditions': [],
                'actions': []
            }

            for c in f.get('conditions', []):
                cf['conditions'].append(condition.Condition(c))

            for a in f.get('actions'):
                cf['actions'].append(a)

            self.filters.append(cf)

    def apply(self, indicator, value):
        if value is None:
            d = {}
        else:
            d = copy.deepcopy(value)
        d['_indicator'] = indicator

        for f in self.filters:
            LOG.debug("evaluating filter %s", f['name'])

            r = True
            for c in f['conditions']:
                r &= c.eval(d)

            if not r:
                continue

            for a in f['actions']:
                if a == 'accept':
                    if value is None:
                        return indicator, None

                    d.pop('_indicator')
                    return indicator, d

                elif a == 'drop':
                    return None, None

        LOG.debug("no matching filter, default accept")

        if value is None:
            return indicator, None

        d.pop('_indicator')
        return indicator, d


class BaseFT(object):
    _ftclass = 'BaseFT'

    def __init__(self, name, chassis, config, reinit=True):
        self.name = name

        self.chassis = chassis

        self.config = config
        self.configure()

        self.inputs = []
        self.output = None

        self._state = {
            'class': self.ftclass,
            'name': self.name,
            'updates_emitted': 0,
            'withdraws_emitted': 0,
            'inputs': self.inputs,
            'output': self.output,
            'num_indicators': 0
        }

        self.reinit_flag = reinit

    @property
    def ftclass(self):
        return self._ftclass

    @ftclass.setter
    def ftclass(self, newv):
        self._ftclass = newv
        self._state['class'] = newv

    def configure(self):
        self.infilters = _Filters(self.config.get('infilters', []))
        self.outfilters = _Filters(self.config.get('outfilters', []))

    def connect(self, inputs, output):
        for i in inputs:
            LOG.info("%s - requesting fabric sub channel for %s", self.name, i)
            self.chassis.request_sub_channel(
                self.name,
                self,
                i,
                allowed_methods=['update', 'withdraw']
            )
        self.inputs = inputs
        self._state['inputs'] = inputs

        if output:
            self.output = self.chassis.request_pub_channel(self.name)
            self._state['output'] = output

        self.chassis.request_rpc_channel(
            self.name,
            self,
            allowed_methods=[
                'update',
                'withdraw',
                'get',
                'get_all',
                'get_range',
                'length'
            ]
        )

    def apply_infilters(self, indicator, value):
        return self.infilters.apply(indicator, value)

    def apply_outfilters(self, indicator, value):
        return self.outfilters.apply(indicator, value)

    def do_rpc(self, dftname, method,  block=True, timeout=30, **kwargs):
        return self.chassis.send_rpc(self.name, dftname, method, kwargs,
                                     block=block, timeout=timeout)

    def emit_update(self, indicator, value):
        if self.output is None:
            return

        indicator, value = self.apply_outfilters(indicator, value)
        if indicator is None:
            return

        self.output.publish("update", {
            'indicator': indicator,
            'value': value
        })
        self._state['updates_emitted'] += 1

    def emit_withdraw(self, indicator, value=None):
        if self.output is None:
            return

        indicator, value = self.apply_outfilters(indicator, value)
        if indicator is None:
            return

        self.output.publish("withdraw", {
            'indicator': indicator,
            'value': value
        })
        self._state['withdraws_emitted'] += 1

    def state(self):
        self._state['num_indicators'] = self.length()

        return self._state

    def update(self, source=None, indicator=None, value=None):
        if value is not None:
            for k in value.keys():
                if k.startswith("_"):
                    value.pop(k)

        fltindicator, fltvalue = self.apply_infilters(indicator, value)
        if fltindicator is None:
            self._withdraw(source=source, indicator=indicator, value=value)
            return

        self._update(source=source, indicator=fltindicator, value=fltvalue)

    def _update(self, source=None, indicator=None, value=None):
        raise NotImplementedError('%s: update' % self.name)

    def withdraw(self, source=None, indicator=None, value=None):
        if value is not None:
            for k in value.keys():
                if k.startswith("_"):
                    value.pop(k)

        fltindicator, fltvalue = self.apply_infilters(indicator, value)
        if fltindicator is None:
            return

        self._withdraw(source=source, indicator=fltindicator, value=fltvalue)

    def _withdraw(self, source=None, indicator=None, value=None):
        raise NotImplementedError('%s: withdraw' % self.name)

    def get(self, source=None, indicator=None):
        raise NotImplementedError('%s: get - not implemented' % self.name)

    def get_all(self, source=None):
        raise NotImplementedError('%s: get_all - not implemented' % self.name)

    def get_range(self, source=None, index=None, from_key=None, to_key=None):
        raise NotImplementedError('%s: get_range - not implemented' %
                                  self.name)

    def length(self, source=None):
        raise NotImplementedError('%s: length - not implemented' % self.name)

    def start(self):
        pass

    def stop(self):
        pass

    def destroy(self):
        pass
