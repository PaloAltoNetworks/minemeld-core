from __future__ import absolute_import

import logging
import gevent
import gevent.queue

import amqp
import ujson
import netaddr

from . import base
from . import table

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
        self.table_ipv4.create_index('_start')

        self.table_indicators = table.Table(
            self.name+'_indicators',
            truncate=truncate
        )

        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('syslog_original_indicator')

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
            LOG.error("%s - indicator of type %s received from "
                      "source %s with type %s, ignored",
                      self.name, type_, source, itype)
            return

        if type_ == 'IPv4':
            start, end = map(netaddr.IPAddress, indicator.split('-', 1))

            LOG.debug('start: %d', start.value)

            value['_start'] = start.value
            value['_end'] = end.value

            self.table_ipv4.put(indicator, value)

        else:
            self.table_indicators.put(type_+indicator, value)

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        itype = self.input_types.get(source, None)
        if itype is None:
            LOG.error('%s - withdraw from unknown source', self.name)
            return

        if itype == 'IPv4':
            v = self.table_ipv4.get(indicator)
            if v is not None:
                self.table_ipv4.delete(indicator)

        else:
            v = self.table_indicators.get(itype+indicator)
            if v is not None:
                self.table_indicators.delete(itype+indicator)

        if v is not None:
            for i in self.table.query(index='syslog_original_indicator',
                                      from_key=itype+indicator,
                                      to_key=itype+indicator,
                                      include_value=False):
                self.emit_withdraw(i)
                self.table.delete(i)

    def _handle_ip(self, ip, source=True):
        try:
            ipv = netaddr.IPAddress(ip)
        except:
            return

        if ipv.version != 4:
            return

        ipv = ipv.value

        iv = next(
            (self.table_ipv4.query(index='_start',
                                   to_key=ipv,
                                   include_value=True,
                                   include_start=True,
                                   reverse=True)),
            None
        )
        if iv is None:
            return

        i, v = iv

        if v['_end'] < ipv:
            return

        for s in v.get('sources', []):
            self.statistics[s] += 1
        self.statistics['total_matches'] += 1

        v['syslog_original_indicator'] = 'IPv4'+i

        self.table.put(ip, v)
        self.emit_update(ip, v)

    def _handle_url(self, url):
        domain = url.split('/', 1)[0]

        v = self.table_indicators.get('domain'+domain)
        if v is None:
            return

        v['syslog_original_indicator'] = 'domain'+domain

        for s in v.get('sources', []):
            self.statistics[s] += 1
        self.statistics['total_matches'] += 1

        self.table.put(domain, v)
        self.emit_update(domain, v)

    @base._counting('syslog.processed')
    def _handle_syslog_message(self, message):
        src_ip = message.get('src_ip', None)
        if src_ip is not None:
            self._handle_ip(src_ip)

        dst_ip = message.get('dest_ip', None)
        if dst_ip is not None:
            self._handle_ip(dst_ip, source=False)

        url = message.get('url', None)
        if url is not None:
            self._handle_url(url)

    def _amqp_callback(self, msg):
        try:
            message = ujson.loads(msg.body)
            self._handle_syslog_message(message)

        except gevent.GreenletExit:
            raise

        except:
            LOG.exception("%s - exception handling syslog message")

    def _amqp_consumer(self):
        while True:
            try:
                conn = amqp.connection.Connection(
                    userid=self.rabbitmq_username,
                    password=self.rabbitmq_password
                )
                channel = conn.channel()
                channel.exchange_declare(
                    self.exchange,
                    'fanout',
                    durable=False,
                    auto_delete=True
                )
                q = channel.queue_declare(
                    exclusive=False
                )

                channel.queue_bind(
                    queue=q.queue,
                    exchange=self.exchange,
                )
                channel.basic_consume(
                    callback=self._amqp_callback,
                    no_ack=True,
                    exclusive=True
                )

                while True:
                    conn.drain_events()

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('%s - Exception in consumer glet', self.name)

            gevent.sleep(30)

    def mgmtbus_status(self):
        result = super(SyslogMatcher, self).mgmtbus_status()

        return result

    def length(self, source=None):
        return (self.table_ipv4.num_indicators +
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
