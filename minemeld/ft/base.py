#  Copyright 2015-2016 Palo Alto Networks, Inc
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
This module implements minemeld.ft.base.BaseFT, the base class for nodes.
"""

from __future__ import absolute_import

import logging
import copy
import os
import collections
import json

from . import condition
from . import ft_states
from . import utils


LOG = logging.getLogger(__name__)


class _Filters(object):
    """Implements a set of filters to be applied to indicators.
    Used by mineneld.ft.base.BaseFT for ingress and egress filters.

    Args:
        filters (list): list of filters.
    """
    def __init__(self, filters):
        self.filters = []

        for f in filters:
            cf = {
                'name': f.get('name', 'filter_%d' % len(self.filters)),
                'conditions': [],
                'actions': []
            }

            fconditions = f.get('conditions', None)
            if fconditions is None:
                fconditions = []
            for c in fconditions:
                cf['conditions'].append(condition.Condition(c))

            for a in f.get('actions'):
                cf['actions'].append(a)

            self.filters.append(cf)

    def apply(self, origin=None, method=None, indicator=None, value=None):
        if value is None:
            d = {}
        else:
            d = copy.copy(value)

        if indicator is not None:
            d['__indicator'] = indicator

        if method is not None:
            d['__method'] = method

        if origin is not None:
            d['__origin'] = origin

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

                    d.pop('__indicator')
                    d.pop('__origin', None)
                    d.pop('__method', None)

                    return indicator, d

                elif a == 'drop':
                    return None, None

        LOG.debug("no matching filter, default accept")

        if value is None:
            return indicator, None

        d.pop('__indicator')
        d.pop('__origin', None)
        d.pop('__method', None)

        return indicator, d


def _counting(statsname):
    """Decorator for counting calls to decorated instance methods.
    Counters are stored in statistics attribute of the instance.

    Args:
        statsname (str): name of the counter to increment
    """
    def _counter_out(f):
        def _counter(self, *args, **kwargs):
            self.statistics[statsname] += 1
            f(self, *args, **kwargs)
            self.publish_status()
        return _counter
    return _counter_out


class BaseFT(object):
    """Implements base class of MineMeld engine nodes.

    **Config parameters**

        :infilters: inbound filter set. Filters to be applied to
            received indicators.
        :outfilters: outbound filter set. Filters to be applied to
            transmitted indicators.

    **Filter set**
        Each filter set is a list of filters. Filters are verified from top
        to bottom, and the first matching filter is applied. Default action
        is **accept**.
        Each filter is a dictionary with 3 keys:

        :name: name of the filter.
        :conditions: list of boolean expressions to match on the
            indicator.
        :actions: list of actions to be applied to the indicator.
            Currently the only supported actions are **accept** and **drop**

        In addition to the atttributes in the indicator value, filters can
        match on 3 special attributes:

        :__indicator: the indicator itself.
        :__method: the method of the message, **update** or **withdraw**.
        :__origin: the name of the node who sent the indicator.

    **Condition**
        A condition in the filter, is boolean expression composed by a JMESPath
        expression, an operator (<, <=, ==, >=, >, !=) and a value.

    Example:
        Example config in YAML::

            infilters:
                - name: accept withdraws
                  conditions:
                    - __method == 'withdraw'
                  actions:
                    - accept
                - name: accept URL
                  conditions:
                    - type == 'URL'
                  actions:
                    - accept
                - name: drop all
                  actions:
                    - drop
            outfilters:
                - name: accept all (default)
                  actions:
                    - accept

    Args:
        name (str): node name, should be unique inside the graph
        chassis (object): parent chassis instance
        config (dict): node config.
    """
    def __init__(self, name, chassis, config):
        self.name = name

        self.chassis = chassis

        self._original_config = copy.deepcopy(config)
        self.config = config
        self.configure()

        self.inputs = []
        self.output = None

        self.statistics = collections.defaultdict(int)

        self.read_checkpoint()

        self.chassis.request_mgmtbus_channel(self)

        self._state = ft_states.READY

        self._last_status_publish = None
        self._throttled_publish_status = utils.GThrottled(self._internal_publish_status, 3000)
        self._clock = 0

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        LOG.info("%s - transitioning to state %d", self.name, value)
        self._state = value

        if value >= ft_states.INIT and value <= ft_states.STOPPED:
            self.publish_status(force=True)

    def read_checkpoint(self):
        """Reads checkpoint file from disk.

        First line of the checkpoint file is a UUID, the *checkpoint* received
        before stopping. The second line is a dictionary in JSON with the class
        of the node and the config. The third line is a dictionary in JSON
        with the persistent state of the node.

        Checkpoint files are used to check if the saved state on disk is
        consistent with the current running config. If the state is not
        consistent `last_checkpoint` is set to None, to indicate that the state
        stored on disk is not valid or inexistent.

        Called by `__init__`.
        """
        self.last_checkpoint = None

        config = {
            'class': (self.__class__.__module__+'.'+self.__class__.__name__),
            'config': self._original_config
        }
        config = json.dumps(config, sort_keys=True)

        try:
            with open(self.name+'.chkp', 'r') as f:
                contents = f.read()
                if contents[0] == '{':
                    # new format
                    contents = json.loads(contents)
                    self.last_checkpoint = contents['checkpoint']
                    saved_config = contents['config']
                    saved_state = contents['state']

                else:
                    # old format
                    lines = contents.splitlines()
                    self.last_checkpoint = lines[0]

                    saved_config = ''
                    if len(lines) > 1:
                        # this to support a really old format
                        # where only checkpoint value was saved
                        saved_config = lines[1]

                    saved_state = None

                LOG.debug('%s - restored checkpoint: %s', self.name, self.last_checkpoint)

            # old_status is missing in old releases
            # stick to the old behavior
            if saved_config and saved_config != config:
                LOG.info(
                    '%s - saved config does not match new config',
                    self.name
                )
                self.last_checkpoint = None
                return

            LOG.info(
                '%s - saved config matches new config',
                self.name
            )

            if saved_state is not None:
                self._saved_state_restore(saved_state)

        except (ValueError, IOError):
            LOG.exception('%s - Error reading last checkpoint', self.name)
            self.last_checkpoint = None

    def create_checkpoint(self, value):
        """Saves checkpoint file to disk.

        Called by `checkpoint`.

        Args:
            value (str): received *checkpoint*
        """
        config = {
            'class': (self.__class__.__module__+'.'+self.__class__.__name__),
            'config': self._original_config
        }

        contents = {
            'checkpoint': value,
            'config': json.dumps(config, sort_keys=True),
            'state': self._saved_state_create()
        }

        with open(self.name+'.chkp', 'w') as f:
            f.write(json.dumps(contents))
            f.write('\n')

    def remove_checkpoint(self):
        try:
            os.remove('{}.chkp'.format(self.name))

        except (IOError, OSError):
            pass

    def _saved_state_restore(self, saved_state):
        pass

    def _saved_state_create(self):
        return {}

    def configure(self):
        """Applies the config settings stored in `self.config`.

        Called by `__init__`.

        When this method is changed to add/remove new parameters, the class
        docstring should be updated.
        """
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

    def apply_infilters(self, origin, method, indicator, value):
        return self.infilters.apply(
            origin=origin,
            method=method,
            indicator=indicator,
            value=value
        )

    def apply_outfilters(self, origin, method, indicator, value):
        return self.outfilters.apply(
            origin=origin,
            method=method,
            indicator=indicator,
            value=value
        )

    def do_rpc(self, dftname, method, block=True, timeout=30, **kwargs):
        return self.chassis.send_rpc(self.name, dftname, method, kwargs,
                                     block=block, timeout=timeout)

    @_counting('update.tx')
    def emit_update(self, indicator, value):
        if self.output is None:
            return

        self.trace('EMIT_UPDATE', indicator, value=value)

        indicator, value = self.apply_outfilters(
            origin=self.name,
            method='update',
            indicator=indicator,
            value=value
        )

        if indicator is None:
            return

        if value is not None:
            for k in value.keys():
                if k[0] in ['_', '$']:
                    value.pop(k)

        self.output.publish("update", {
            'source': self.name,
            'indicator': indicator,
            'value': value
        })

    @_counting('withdraw.tx')
    def emit_withdraw(self, indicator, value=None):
        if self.output is None:
            return

        self.trace('EMIT_WITHDRAW', indicator, value=value)

        indicator, value = self.apply_outfilters(
            origin=self.name,
            method='withdraw',
            indicator=indicator,
            value=value
        )

        if indicator is None:
            return

        if value is not None:
            for k in value.keys():
                if k[0] in ['_', '$']:
                    value.pop(k)

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

        self.trace('RECVD_UPDATE', indicator, source_node=source, value=value)

        if self.state not in [ft_states.STARTED, ft_states.CHECKPOINT]:
            self.statistics['error.wrong_state'] += 1
            return

        if source in self.inputs_checkpoint:
            LOG.error("update received from checkpointed source")
            raise AssertionError("update received from checkpointed source")

        if value is not None:
            for k in value.keys():
                if k.startswith("_"):
                    value.pop(k)

        fltindicator, fltvalue = self.apply_infilters(
            origin=source,
            method='update',
            indicator=indicator,
            value=value
        )

        if fltindicator is None:
            self.trace('DROP_UPDATE', indicator, source_node=source, value=value)
            self.filtered_withdraw(
                source=source,
                indicator=indicator,
                value=value
            )
            return

        self.trace('ACCEPT_UPDATE', indicator, source_node=source, value=value)
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

        self.trace('RECVD_WITHDRAW', indicator, source_node=source, value=value)

        if self.state not in [ft_states.STARTED, ft_states.CHECKPOINT]:
            self.statistics['error.wrong_state'] += 1
            return

        if source in self.inputs_checkpoint:
            LOG.error("withdraw received from checkpointed source")
            raise AssertionError("withdraw received from checkpointed source")

        fltindicator, fltvalue = self.apply_infilters(
            origin=source,
            method='withdraw',
            indicator=indicator,
            value=value
        )

        if fltindicator is None:
            self.trace('DROP_WITHDRAW', indicator, source_node=source, value=value)
            return

        if fltvalue is not None:
            for k in fltvalue.keys():
                if k.startswith("_"):
                    fltvalue.pop(k)

        self.trace('ACCEPT_WITHDRAW', indicator, source_node=source, value=value)
        self.filtered_withdraw(
            source=source,
            indicator=indicator,
            value=value
        )

    @_counting('withdraw.processed')
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

    def publish_status(self, force=False):
        if force:
            self._internal_publish_status()

        self._throttled_publish_status()

    def _internal_publish_status(self):
        self._last_status_publish = utils.utc_millisec()
        status = self.mgmtbus_status()
        self.chassis.publish_status(
            timestamp=utils.utc_millisec(),
            nodename=self.name,
            status=status
        )

    def mgmtbus_state_info(self):
        return {
            'checkpoint': self.last_checkpoint,
            'state': self.state,
            'is_source': len(self.inputs) == 0
        }

    def mgmtbus_initialize(self):
        self.state = ft_states.INIT
        self.remove_checkpoint()
        self.initialize()
        return 'OK'

    def mgmtbus_rebuild(self):
        self.state = ft_states.REBUILDING
        self.remove_checkpoint()
        self.rebuild()
        self.state = ft_states.INIT
        return 'OK'

    def mgmtbus_reset(self):
        self.state = ft_states.RESET
        self.remove_checkpoint()
        self.reset()
        self.state = ft_states.INIT
        return 'OK'

    def mgmtbus_status(self):
        try:
            # if node is not ready yet to publish the length
            length = self.length()
        except:
            length = None

        result = {
            'clock': self._clock,
            'class': (self.__class__.__module__+'.'+self.__class__.__name__),
            'state': self.state,
            'statistics': self.statistics,
            'length': length,
            'inputs': self.inputs,
            'output': (self.output is not None)
        }
        self._clock += 1
        return result

    def mgmtbus_checkpoint(self, value=None):
        if len(self.inputs) != 0:
            return 'ignored'

        self.state = ft_states.IDLE
        self.create_checkpoint(value)
        self.last_checkpoint = value
        self.emit_checkpoint(value)

        return 'OK'

    def mgmtbus_hup(self, source=None):
        self.hup(source=source)

    def mgmtbus_signal(self, source=None, signal=None, **kwargs):
        raise NotImplementedError('{}: signal - not implemented'.format(self.name))

    def initialize(self):
        pass

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

    def hup(self, source=None):
        raise NotImplementedError('%s: hup - not implemented' % self.name)

    def trace(self, action, indicator, **kwargs):
        if self.state not in [ft_states.STARTED, ft_states.CHECKPOINT]:
            LOG.debug(
                "%s - trace called in wrong state %s",
                self.name,
                self.state
            )
            return

        trace = {
            'indicator': indicator,
            'op': action,
        }
        trace.update(kwargs)
        self.chassis.log(
            timestamp=utils.utc_millisec(),
            nodename=self.name,
            log_type='TRACE',
            value=trace
        )

    def start(self):
        LOG.debug("%s - start called", self.name)

        if self.state != ft_states.INIT:
            LOG.error("start on not INIT FT")
            raise AssertionError("start on not INIT FT")

        self.state = ft_states.STARTED

    def stop(self):
        LOG.debug("%s - stop called", self.name)
        if self.state not in [ft_states.IDLE, ft_states.STARTED]:
            LOG.error("stop on not IDLE or STARTED FT")
            raise AssertionError("stop on not IDLE or STARTED FT")

        self._throttled_publish_status.cancel()

        self.state = ft_states.STOPPED

    @staticmethod
    def gc(name, config=None):
        try:
            os.remove('{}.chkp'.format(name))
        except:
            pass
