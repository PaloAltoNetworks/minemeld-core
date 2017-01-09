#  Copyright 2015 Palo Alto Networks, Inc
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

from __future__ import absolute_import

import logging
import shutil

import gevent
import gevent.queue
import gevent.event

import amqp
import ujson
import netaddr
import datetime
import socket
import random
import os
import yaml
import copy
import re

from . import base
from . import actorbase
from . import table
from . import ft_states
from . import condition
from .utils import utc_millisec
from .utils import RWLock
from .utils import parse_age_out

LOG = logging.getLogger(__name__)

_MAX_AGE_OUT = ((1 << 32)-1)*1000


class SyslogMatcher(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.amqp_glet = None

        super(SyslogMatcher, self).__init__(name, chassis, config)

        self._ls_socket = None

    def configure(self):
        super(SyslogMatcher, self).configure()

        self.exchange = self.config.get('exchange', 'mmeld-syslog')
        self.rabbitmq_username = self.config.get('rabbitmq_username', 'guest')
        self.rabbitmq_password = self.config.get('rabbitmq_password', 'guest')

        self.input_types = self.config.get('input_types', {})

        self.logstash_host = self.config.get('logstash_host', None)
        self.logstash_port = self.config.get('logstash_port', 5514)

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
        self._initialize_tables(truncate=True)

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
            for i, v in self.table.query(index='syslog_original_indicator',
                                         from_key=itype+indicator,
                                         to_key=itype+indicator,
                                         include_value=True):
                self.emit_withdraw(i, value=v)
                self.table.delete(i)

    def _handle_ip(self, ip, source=True, message=None):
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
            self.statistics['source.'+s] += 1
        self.statistics['total_matches'] += 1

        v['syslog_original_indicator'] = 'IPv4'+i

        self.table.put(ip, v)
        self.emit_update(ip, v)

        if message is not None:
            self._send_logstash(
                message='matched IPv4',
                indicator=i,
                value=v,
                session=message
            )

    def _handle_url(self, url, message=None):
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

        if message is not None:
            self._send_logstash(
                message='matched domain',
                indicator=domain,
                value=v,
                session=message
            )

    @base._counting('syslog.processed')
    def _handle_syslog_message(self, message):
        src_ip = message.get('src_ip', None)
        if src_ip is not None:
            self._handle_ip(src_ip, message=message)

        dst_ip = message.get('dest_ip', None)
        if dst_ip is not None:
            self._handle_ip(dst_ip, source=False, message=message)

        url = message.get('url', None)
        if url is not None:
            self._handle_url(url, message=message)

    def _amqp_callback(self, msg):
        try:
            message = ujson.loads(msg.body)
            self._handle_syslog_message(message)

        except gevent.GreenletExit:
            raise

        except:
            LOG.exception(
                "%s - exception handling syslog message",
                self.name
            )

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
                    auto_delete=False
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

    def _connect_logstash(self):
        if self._ls_socket is not None:
            return

        if self.logstash_host is None:
            return

        _ls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _ls_socket.connect((self.logstash_host, self.logstash_port))

        self._ls_socket = _ls_socket

    def _send_logstash(self, message=None, indicator=None,
                       value=None, session=None):
        now = datetime.datetime.now()

        fields = {
            '@timestamp': now.isoformat()+'Z',
            '@version': 1,
            'syslog_node': self.name,
            'message': message
        }

        if indicator is not None:
            fields['indicator'] = indicator

        if value is not None:
            if 'last_seen' in value:
                last_seen = datetime.datetime.fromtimestamp(
                    float(value['last_seen'])/1000.0
                )
                value['last_seen'] = last_seen.isoformat()+'Z'

            if 'first_seen' in fields:
                first_seen = datetime.datetime.fromtimestamp(
                    float(value['first_seen'])/1000.0
                )
                value['first_seen'] = first_seen.isoformat()+'Z'

            fields['indicator_value'] = value

        if session is not None:
            session.pop('event.tags', None)
            fields['session'] = session

        try:
            self._connect_logstash()

            if self._ls_socket is not None:
                self._ls_socket.sendall(ujson.dumps(fields)+'\n')

        except:
            self._ls_socket = None
            raise

        self.statistics['logstash.sent'] += 1

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

        self.table.close()
        self.table_indicators.close()
        self.table_ipv4.close()

    @staticmethod
    def gc(name, config=None):
        actorbase.ActorBaseFT.gc(name, config=config)
        shutil.rmtree(name, ignore_errors=True)
        shutil.rmtree('{}_indicators'.format(name), ignore_errors=True)
        shutil.rmtree('{}_ipv4'.format(name), ignore_errors=True)


class SyslogMiner(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.amqp_glet = None
        self.ageout_glet = None
        self._actor_glet = None
        self._actor_queue = gevent.queue.Queue(maxsize=128)
        self._msg_queue = gevent.queue.Queue(maxsize=1)
        self._do_process = gevent.event.Event()

        self.active_requests = []
        self.rebuild_flag = False
        self.last_ageout_run = None

        self.state_lock = RWLock()

        super(SyslogMiner, self).__init__(name, chassis, config)

    def configure(self):
        super(SyslogMiner, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.attributes = self.config.get('attributes', {})

        _age_out = self.config.get('age_out', {})

        self.age_out = {
            'interval': _age_out.get('interval', 3600),
            'default': parse_age_out(_age_out.get('default', 'last_seen+1h'))
        }
        for k, v in _age_out.iteritems():
            if k in self.age_out:
                continue
            self.age_out[k] = parse_age_out(v)

        self.exchange = self.config.get('exchange', 'mmeld-syslog')
        self.rabbitmq_username = self.config.get('rabbitmq_username', 'guest')
        self.rabbitmq_password = self.config.get('rabbitmq_password', 'guest')

        self.indicator_mapping = self.config.get('indicator_mapping', {
            'src_ip': 'IP',
            'dest_ip': 'IP',
            'misc': 'URL'
        })

        self.prefix = self.config.get('prefix', 'panossyslog')

        self.rules = []
        self.side_config_path = self.config.get('rules', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_rules.yml' % self.name
            )

        self._load_side_config()

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('_age_out')
        self.table.create_index('_withdrawn')

    def initialize(self):
        self._initialize_table()

    def rebuild(self):
        self._actor_queue.put(
            (utc_millisec(), 'rebuild')
        )
        self._initialize_table(truncate=(self.last_checkpoint is None))

    def reset(self):
        self._initialize_table(truncate=True)

    def _compile_rule(self, name, f):
        LOG.debug('%s - compiling rule %s: %s', self.name, name, f)
        result = {
            'name': name,
            'metric': 'rule.%s' % re.sub('[^a-zA-Z0-9]', '_', name),
            'conditions': [],
            'indicators': [],
            'fields': []
        }

        conditions = f.get('conditions', None)
        if conditions is None or len(conditions) == 0:
            LOG.error('%s - no conditions in rule %s, ignored',
                      self.name, name)
            return None
        for c in conditions:
            result['conditions'].append(condition.Condition(c))

        indicators = f.get('indicators', None)
        if type(indicators) != list:
            LOG.error('%s - no indicators list in rule %s, ignored',
                      self.name, name)
            return None
        for i in indicators:
            if i not in self.indicator_mapping:
                LOG.error('%s - rule %s unknown type indicator %s, ignored',
                          self.name, name, i)
                continue
            result['indicators'].append(i)
        if len(result['indicators']) == 0:
            LOG.error('%s - no valid indicators in rule %s, ignored',
                      self.name, name)
            return None

        fields = f.get('fields', None)
        if fields is not None:
            if type(fields) != list:
                LOG.error('%s - wrong fields format in rule %s, ignored',
                          self.name, name)
                return None

            result['fields'] = [fld for fld in fields if type(fld) == str]

        return result

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                rules = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading rules: %s', self.name, str(e))
            return

        if type(rules) != list:
            LOG.error('%s - Error loading rules: not a list', self.name)
            return

        newrules = []
        for idx, f in enumerate(rules):
            fname = f.get('name', None)
            if fname is None:
                LOG.error('%s - rule %d does not have a name, ignored',
                          self.name, idx)
                continue

            cf = self._compile_rule(fname, f)
            if cf is not None:
                newrules.append(cf)

        self.rules = newrules

    @base.BaseFT.state.setter
    def state(self, value):
        self.state_lock.lock()
        #  this is weird ! from stackoverflow 10810369
        super(SyslogMiner, self.__class__).state.fset(self, value)
        self.state_lock.unlock()

    def _command_rebuild(self):
        with self.state_lock:
            if self.state != ft_states.STARTED:
                return

            for i, v in self.table.query(include_value=True):
                indicator, _ = i.split('\0', 1)
                self.emit_update(indicator=indicator, value=v)

    def _command_age_out(self):
        with self.state_lock:
            if self.state != ft_states.STARTED:
                return

            try:
                now = utc_millisec()

                for i, v in self.table.query(index='_age_out',
                                             to_key=now-1,
                                             include_value=True):
                    indicator, _ = i.split('\0', 1)

                    self.emit_withdraw(indicator=indicator, value=v)
                    self.table.delete(i)

                    self.statistics['aged_out'] += 1

                self.last_ageout_run = now

            except gevent.GreenletExit:
                raise

            except:
                LOG.exception('Exception in _age_out_loop')

    def _calc_age_out(self, indicator, attributes):
        t = attributes.get('type', None)
        if t is None or t not in self.age_out:
            sel = self.age_out['default']
        else:
            sel = self.age_out[t]

        if sel is None:
            return _MAX_AGE_OUT

        b = attributes[sel['base']]

        return b + sel['offset']

    def _apply_rule(self, f, message):
        r = True
        for c in f['conditions']:
            r &= c.eval(message)

        if not r:
            return

        for i in f['indicators']:
            indicator = message.get(i, None)
            if indicator is None:
                continue

            value = {}

            for fld in f['fields']:
                fv = message.get(fld, None)
                if fv is not None:
                    value['%s_%s' % (self.prefix, fld)] = fv

            type_ = self.indicator_mapping[i]

            if type_ == 'IP':
                pi = netaddr.IPAddress(indicator)
                if pi.version == 6:
                    type_ = 'IPv6'
                elif pi.version == 4:
                    type_ = 'IPv4'
                else:
                    continue

            value['type'] = type_

            device = message.get('serial_number', 'unknown')

            yield [indicator, value, device]

    @base._counting('syslog.processed')
    def _handle_syslog_message(self, message):
        devices_attribute = '%s_devices' % self.prefix

        now = utc_millisec()

        for f in self.rules:
            for indicator, value, device in self._apply_rule(f, message):
                if indicator is None:
                    continue

                self.statistics[f['metric']] += 1

                type_ = value.get('type', None)
                if type_ is None:
                    LOG.error('%s - no type for indicator %s, ignored',
                              self.name, indicator)
                    continue

                ikey = indicator+'\0'+type_
                cv = self.table.get(ikey)

                if cv is None:
                    cv = copy.copy(self.attributes)
                    cv['sources'] = [self.source_name]
                    cv['last_seen'] = now
                    cv['first_seen'] = now
                    cv[devices_attribute] = [device]
                    cv.update(value)
                    cv['_age_out'] = self._calc_age_out(indicator, cv)

                    self.statistics['added'] += 1
                    self.table.put(ikey, cv)
                    self.emit_update(indicator, cv)

                else:
                    cv['last_seen'] = now
                    cv.update(value)
                    cv['_age_out'] = self._calc_age_out(indicator, cv)
                    if device not in cv[devices_attribute]:
                        cv[devices_attribute].append(device)

                    self.table.put(ikey, cv)
                    self.emit_update(indicator, cv)

    def _actor_loop(self):
        while True:
            msg = None

            try:
                msg = self._actor_queue.get(block=False)
            except gevent.queue.Empty:
                msg = None

            if msg is not None:
                _, command = msg
                if command == 'age_out':
                    self._command_age_out()
                elif command == 'rebuild':
                    self._command_rebuild()
                else:
                    LOG.error('{} - unknown command {} - ignored'.format(
                        self.name,
                        command
                    ))

            msg = None
            try:
                while self._msg_queue.qsize() != 0:
                    msg = self._msg_queue.get(block=False)

                    try:
                        self._handle_syslog_message(msg)
                    except gevent.GreenletExit:
                        raise
                    except:
                        LOG.exception('{} - exception handling message'.format(self.name))

            except gevent.queue.Empty:
                pass

            self._do_process.wait()
            self._do_process.clear()

    def _age_out_loop(self):
        while True:
            self._actor_queue.put(
                (utc_millisec(), 'age_out')
            )
            self._do_process.set()

            try:
                gevent.sleep(self.age_out['interval'])

            except gevent.GreenletExit:
                break

    def _amqp_callback(self, msg):
        try:
            LOG.info(u'{}'.format(msg.body))
            message = ujson.loads(msg.body)
            self._msg_queue.put(message)
            self._do_process.set()

        except gevent.GreenletExit:
            raise

        except:
            LOG.exception(
                "%s - exception handling syslog message",
                self.name
            )

    def _amqp_consumer(self):
        while self.last_ageout_run is None:
            gevent.sleep(1)

        with self.state_lock:
            if self.state != ft_states.STARTED:
                LOG.error('{} - wrong state in amqp_consumer'.format(self.name))
                return

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
                    auto_delete=False
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

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(SyslogMiner, self).start()

        if self.amqp_glet is not None:
            return

        self.amqp_glet = gevent.spawn_later(
            random.randint(0, 2),
            self._amqp_consumer
        )
        self.ageout_glet = gevent.spawn(self._age_out_loop)
        self._actor_glet = gevent.spawn(self._actor_loop)

    def stop(self):
        super(SyslogMiner, self).stop()

        if self.amqp_glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.amqp_glet.kill()
        self.ageout_glet.kill()
        self._actor_glet.kill()

        self.table.close()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)

    def hup(self, source=None):
        LOG.info('%s - hup received, reload filters', self.name)
        self._load_side_config()

    @staticmethod
    def gc(name, config=None):
        base.BaseFT.gc(name, config=config)

        shutil.rmtree(name, ignore_errors=True)
        side_config_path = None
        if config is not None:
            side_config_path = config.get('rules', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_rules.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except:
            pass
