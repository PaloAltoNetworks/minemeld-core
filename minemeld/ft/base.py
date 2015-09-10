import logging
import copy
import os
import collections

from . import condition
from . import ft_states


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


def _counting(statsname):
    def _counter_out(f):
        def _counter(self, *args, **kwargs):
            LOG.debug('updating %s', statsname)
            self.statistics[statsname] += 1
            f(self, *args, **kwargs)
        return _counter
    return _counter_out


class BaseFT(object):
    def __init__(self, name, chassis, config):
        self.name = name

        self.chassis = chassis

        self.config = config
        self.configure()

        self.inputs = []
        self.output = None

        self.statistics = collections.defaultdict(lambda: 0)

        self.read_checkpoint()

        self.chassis.request_mgmtbus_channel(self)

        self.state = ft_states.READY

    def read_checkpoint(self):
        self.last_checkpoint = None

        try:
            with open(self.name+'.chkp', 'r') as f:
                self.last_checkpoint = f.read().strip()
            os.remove(self.name+'.chkp')
        except IOError:
            pass

    def create_checkpoint(self, value):
        with open(self.name+'.chkp', 'w') as f:
            f.write(value)

    def configure(self):
        self.infilters = _Filters(self.config.get('infilters', []))
        self.outfilters = _Filters(self.config.get('outfilters', []))

    def connect(self, inputs, output):
        if self.state != ft_states.READY:
            LOG.error('connect called in non ready FT')
            raise AssertionError('connect called in non ready FT')

        for i in inputs:
            LOG.info("%s - requesting fabric sub channel for %s", self.name, i)
            self.chassis.request_sub_channel(
                self.name,
                self,
                i,
                allowed_methods=['update', 'withdraw', 'checkpoint']
            )
        self.inputs = inputs
        self.inputs_checkpoint = {}

        if output:
            self.output = self.chassis.request_pub_channel(self.name)

        self.chassis.request_rpc_channel(
            self.name,
            self,
            allowed_methods=[
                'update',
                'withdraw',
                'checkpoint',
                'get',
                'get_all',
                'get_range',
                'length'
            ]
        )

        self.state = ft_states.CONNECTED

    def apply_infilters(self, indicator, value):
        return self.infilters.apply(indicator, value)

    def apply_outfilters(self, indicator, value):
        return self.outfilters.apply(indicator, value)

    def do_rpc(self, dftname, method,  block=True, timeout=30, **kwargs):
        return self.chassis.send_rpc(self.name, dftname, method, kwargs,
                                     block=block, timeout=timeout)

    @_counting('update.tx')
    def emit_update(self, indicator, value):
        if self.output is None:
            return

        indicator, value = self.apply_outfilters(indicator, value)
        if indicator is None:
            return

        self.output.publish("update", {
            'source': self.name,
            'indicator': indicator,
            'value': value
        })

    @_counting('withdraw.tx')
    def emit_withdraw(self, indicator, value=None):
        if self.output is None:
            return

        indicator, value = self.apply_outfilters(indicator, value)
        if indicator is None:
            return

        self.output.publish("withdraw", {
            'source': self.name,
            'indicator': indicator,
            'value': value
        })

    @_counting('checkpoint.tx')
    def emit_checkpoint(self, value):
        if self.output is None:
            return

        self.output.publish('checkpoint', {
            'source': self.name,
            'value': value
        })

    @_counting('update.rx')
    def update(self, source=None, indicator=None, value=None):
        LOG.debug('%s {%s} - update from %s value %s',
                  self.name, self.state, source, value)

        if self.state not in [ft_states.STARTED, ft_states.CHECKPOINT]:
            return

        if source in self.inputs_checkpoint:
            LOG.error("update recevied from checkpointed source")
            raise AssertionError("update recevied from checkpointed source")

        if value is not None:
            for k in value.keys():
                if k.startswith("_"):
                    value.pop(k)

        fltindicator, fltvalue = self.apply_infilters(indicator, value)
        if fltindicator is None:
            self.filtered_withdraw(
                source=source,
                indicator=indicator,
                value=value
            )
            return

        self.filtered_update(
            source=source,
            indicator=fltindicator,
            value=fltvalue
        )

    @_counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        raise NotImplementedError('%s: update' % self.name)

    @_counting('withdraw.rx')
    def withdraw(self, source=None, indicator=None, value=None):
        LOG.debug('%s {%s} - withdraw from %s value %s',
                  self.name, self.state, source, value)

        if self.state not in [ft_states.STARTED, ft_states.CHECKPOINT]:
            return

        if source in self.inputs_checkpoint:
            LOG.error("withdraw recevied from checkpointed source")
            raise AssertionError("withdraw recevied from checkpointed source")

        if value is not None:
            for k in value.keys():
                if k.startswith("_"):
                    value.pop(k)

        self.filtered_withdraw(
            source=source,
            indicator=indicator,
            value=value
        )

    @_counting('update.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        raise NotImplementedError('%s: withdraw' % self.name)

    @_counting('checkpoint.rx')
    def checkpoint(self, source=None, value=None):
        LOG.debug('%s {%s} - checkpoint from %s value %s',
                  self.name, self.state, source, value)

        if self.state not in [ft_states.STARTED, ft_states.CHECKPOINT]:
            LOG.error("%s {%s} - checkpoint received with state not STARTED "
                      "or CHECKPOINT",
                      self.name, self.state)
            raise AssertionError("checkpoint received with state not STARTED "
                                 "or CHECKPOINT")

        for v in self.inputs_checkpoint.values():
            if v != value:
                LOG.error("different checkpoint value received")
                raise AssertionError("different checkpoint value received")

        self.inputs_checkpoint[source] = value

        if len(self.inputs_checkpoint) != len(self.inputs):
            self.state = ft_states.CHECKPOINT
            return

        self.state = ft_states.IDLE
        self.create_checkpoint(value)
        self.last_checkpoint = value
        self.emit_checkpoint(value)

    def mgmtbus_state_info(self):
        return {
            'checkpoint': self.last_checkpoint,
            'state': self.state,
            'is_source': len(self.inputs) == 0
        }

    def mgmtbus_initialize(self):
        self.state = ft_states.INIT
        return 'OK'

    def mgmtbus_rebuild(self):
        self.state = ft_states.REBUILDING
        self.rebuild()
        self.state = ft_states.INIT
        return 'OK'

    def mgmtbus_reset(self):
        self.state = ft_states.RESET
        self.reset()
        self.state = ft_states.INIT
        return 'OK'

    def mgmtbus_status(self):
        result = {
            'state': self.state,
            'statistics': self.statistics,
            'length': self.length(),
            'inputs': self.inputs,
            'output': (self.output is not None)
        }
        return result

    def mgmtbus_checkpoint(self, value=None):
        if len(self.inputs) != 0:
            return 'ignored'

        self.state = ft_states.IDLE
        self.create_checkpoint(value)
        self.last_checkpoint = value
        self.emit_checkpoint(value)

        return 'OK'

    def rebuild(self):
        pass

    def reset(self):
        pass

    def get_state(self):
        return self.state

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
        LOG.debug("%s - start called", self.name)

        if self.state != ft_states.INIT:
            LOG.error("start on not INIT FT")
            raise AssertionError("start on not INIT FT")

        self.state = ft_states.STARTED

    def stop(self):
        if self.state not in [ft_states.IDLE, ft_states.STARTED]:
            LOG.error("stop on not IDLE or STARTED FT")
            raise AssertionError("stop on not IDLE or STARTED FT")

        self.state = ft_states.STOPPED
