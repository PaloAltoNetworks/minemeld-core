from __future__ import absolute_import

import logging
import gevent
import gevent.queue

from . import base
from . import table
from .utils import utc_millisec

LOG = logging.getLogger(__name__)


class SyslogMatcher(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.amqp_glet = None

        super(SyslogMatcher, self).__init__(name, chassis, config)

    def configure(self):
        super(SyslogMatcher, self).configure()

        self.exchange = self.config.get('exchange', 'mmeld-syslog')
        self.rabbitmq_username = self.config.get('rabbitmq_username', 'guest')
        self.rabbitmq_password = self.config.get('rabbitmq_password', 'guest')

        self.input_types = self.config.get('input_types', {})

    def _initialize_tables(self, truncate=False):
        self.table_ipv4 = table.Table(self.name+'_ipv4', truncate=truncate)
        self.table_ipv6 = table.Table(self.name+'_ipv6', truncate=truncate)
        self.table_indicators = table.Table(
            self.name+'_indicators',
            truncate=truncate
        )

    def initialize(self):
        self._initialize_tables()

    def rebuild(self):
        self._initialize_tables(truncate=(self.last_checkpoint is None))

    def reset(self):
        self._initialize_tables(truncate=True)

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        type_ = value.get('type', None)
        if type_ is None:
            LOG.error("%s - received update with no type, ignored", self.name)
            return

        itype = self.input_types.get(source, None)
        if itype is None:
            LOG.debug('%s - no type associated to %s, added %s',
                      self.name, source, type_)
            self.input_types[source] = type_
            itype = type_

        if itype != type_:
            LOG.error("%s - indicator of type %s recevied from "
                      "source %s with type %s, ignored",
                      self.name, type_, source, itype)
            return

        if type_ == 'IPv4':
            self.table_ipv4.put(indicator, value)
        elif type_ == 'IPv6':
            self.table_ipv6.put(indicator, value)
        else:
            self.table_indicators.put(type_+indicator, value)

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        itype = self.input_types.get(source, None)
        if itype is None:
            LOG.error('%s - withdraw from unknown source', self.name)

        if itype == 'IPv4':
            v = self.table_ipv4.get(indicator)
            if v is not None:
                self.table_ipv4.delete(indicator)
                if v.get('syslog_matched', None) is not None:
                    self.emit_withdraw(indicator)
        elif itype == 'IPv6':
            v = self.table_ipv6.get(indicator)
            if v is not None:
                self.table_ipv6.delete(indicator)
                if v.get('syslog_matched', None) is not None:
                    self.emit_withdraw(indicator)
        else:
            v = self.table_ipv6.get(itype+'\x00'+indicator)
            if v is not None:
                self.table_indicators.delete(itype+'\x00'+indicator)
                if v.get('syslog_matched', None) is not None:
                    self.emit_withdraw(indicator)

    def _amqp_consumer(self):
        while True:
            pass

    def mgmtbus_status(self):
        result = super(SyslogMatcher, self).mgmtbus_status()

        return result

    def length(self, source=None):
        return (self.table_ipv4.num_indicators +
                self.table_ipv6.num_indicators +
                self.table_indicators.num_indicators)

    def start(self):
        super(SyslogMatcher, self).start()

        self.amqp_glet = gevent.spawn_later(
            2,
            self._amqp_consumer
        )

    def stop(self):
        super(SyslogMatcher, self).stop()

        if self.amqp_glet is None:
            return
