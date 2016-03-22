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
import ujson
import random
import gevent
import gevent.event
import gevent.queue
import yaml
import os
import sleekxmpp
import sleekxmpp.xmlstream

from . import base
from . import op

LOG = logging.getLogger(__name__)


class XMPPOutput(base.BaseFT):
    def __init__(self, name, chassis, config):
        super(XMPPOutput, self).__init__(name, chassis, config)

        self._xmpp_client = None
        self._xmpp_glet = None
        self._publisher_glet = None

        self.q = gevent.queue.Queue()

        self._read_sequence_number()

        self._load_event = gevent.event.Event()
        self._xmpp_client_ready = gevent.event.Event()

    def configure(self):
        super(XMPPOutput, self).configure()

        self.server = self.config.get('server', None)
        self.port = self.config.get('port', 5222)
        self.pubsub_service = self.config.get('pubsub_service', None)
        self.node = self.config.get('node', None)

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )
        self._load_side_config()

    def _load_side_config(self):
        self.jid = None
        self.password = None

        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        self.jid = sconfig.get('jid', None)
        if self.jid is not None:
            LOG.info('%s - jid set', self.name)

        self.password = sconfig.get('password', None)
        if self.password is not None:
            LOG.info('%s - password set', self.name)

    def connect(self, inputs, output):
        output = False
        super(XMPPOutput, self).connect(inputs, output)

    def initialize(self):
        pass

    def rebuild(self):
        self.sequence_number = None

    def reset(self):
        self.sequence_number = None

    def _read_sequence_number(self):
        self.sequence_number = None

        try:
            with open(self.name+'.seqn', 'r') as f:
                self.sequence_number = int(f.read().strip())
            os.remove(self.name+'.seqn')
        except IOError:
            pass

    def _write_sequence_number(self):
        if self.sequence_number is None:
            return

        with open(self.name+'.seqn', 'w') as f:
            f.write('%s' % self.sequence_number)

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        self.q.put(['UPDATE', indicator, value])

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        self.q.put(['WITHDRAW', indicator, value])

    def _xmpp_publish(self, cmd, data=None):
        if data is None:
            data = ''

        payload_xml = sleekxmpp.xmlstream.ET.Element('mm-command')
        command_xml = sleekxmpp.xmlstream.ET.SubElement(payload_xml, 'command')
        command_xml.text = cmd
        seqno_xml = sleekxmpp.xmlstream.ET.SubElement(payload_xml, 'seqno')
        seqno_xml.text = '%s' % self.sequence_number
        data_xml = sleekxmpp.xmlstream.ET.SubElement(payload_xml, 'data')
        data_xml.text = ujson.dumps(data)

        result = self._xmpp_client['xep_0060'].publish(
            self.pubsub_service,
            self.node,
            payload=payload_xml
        )
        LOG.debug('%s - xmpp publish: %s', self.name, result)

        self.sequence_number += 1

        self.statistics['xmpp.published'] += 1

    def _xmpp_session_start(self, event):
        LOG.debug('%s - _xmpp_session_start', self.name)
        self._xmpp_client.get_roster()
        self._xmpp_client.send_presence()

        if self.sequence_number is None:
            self.sequence_number = random.getrandbits(64)
            self._xmpp_publish('INIT')

        self._xmpp_client_ready.set()

    def _xmpp_disconnected(self, event):
        LOG.debug('%s - _xmpp_disconnected', self.name)
        self._xmpp_client_ready.clear()

    def _start_xmpp_client(self):
        if self._xmpp_client is not None:
            return

        if self.jid is None or self.password is None:
            raise RuntimeError('%s - jid or password not set', self.name)

        if self.server is None or self.port is None:
            raise RuntimeError('%s - server or port not set', self.name)

        if self.node is None or self.pubsub_service is None:
            raise RuntimeError(
                '%s - node or pubsub_service not set',
                self.name
            )

        self._xmpp_client = sleekxmpp.ClientXMPP(
            jid=self.jid,
            password=self.password
        )
        self._xmpp_client.register_plugin('xep_0030')
        self._xmpp_client.register_plugin('xep_0059')
        self._xmpp_client.register_plugin('xep_0060')
        self._xmpp_client.add_event_handler(
            'session_start',
            self._xmpp_session_start
        )
        self._xmpp_client.add_event_handler(
            'disconnected',
            self._xmpp_disconnected
        )

        if not self._xmpp_client.connect((self.server, self.port)):
            raise RuntimeError(
                '%s - error connecting to XMPP server',
                self.name
            )

        self._xmpp_client.process(block=True)

    def _publisher(self):
        while True:
            self._xmpp_client_ready.wait()

            try:
                while True:
                    cmd, indicator, value = self.q.peek()
                    if value is None:
                        value = {}
                    value['origins'] = [self.jid]
                    self._xmpp_publish(cmd, {
                        'indicator': indicator,
                        'value': value
                    })
                    _ = self.q.get()

            except gevent.GreenletExit:
                break

            except Exception as e:
                LOG.exception('%s - Exception in publishing message', self.name)
                gevent.sleep(30)
                self.statistics['xmpp.publish_error'] += 1

    def _run(self):
        while True:
            try:
                self._start_xmpp_client()

            except RuntimeError() as e:
                LOG.error('%s - %s', self.name, str(e))
                self.statistics['xmpp.error'] += 1

            except gevent.GreenletExit:
                if self._xmpp_client is not None:
                    self._xmpp_client.disconnect()
                break

            except Exception as e:
                LOG.exception('%s - error in starting XMPP client', self.name)

            try:
                if self._xmpp_client is not None:
                    self._xmpp_client.disconnect()
                self._xmpp_client = None

                hup_called = self._load_event.wait(timeout=60)
                if hup_called:
                    LOG.debug('%s - clearing load event', self.name)
                    self._load_event.clear()

            except gevent.GreenletExit:
                break

    def length(self, source=None):
        return 0

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        self._load_event.set()

    def mgmtbus_checkpoint(self, value=None):
        self._write_sequence_number()
        return super(XMPPOutput, self).mgmtbus_checkpoint(value=value)

    def start(self):
        super(XMPPOutput, self).start()

        if self._xmpp_glet is not None:
            return
        self._xmpp_glet = gevent.spawn_later(random.randint(0, 2), self._run)
        self._publisher_glet = gevent.spawn_later(random.randint(0, 3), self._publisher)

    def stop(self):
        super(XMPPOutput, self).stop()

        if self._xmpp_client is None:
            return

        self._xmpp_glet.kill()
        self._publisher_glet.kill()


class XMPPMiner(op.AggregateFT):
    def __init__(self, name, chassis, config):
        super(XMPPMiner, self).__init__(name, chassis, config)

        self._xmpp_client = None
        self._xmpp_glet = None

        self._load_event = gevent.event.Event()

    def configure(self):
        super(XMPPMiner, self).configure()

        self.server = self.config.get('server', None)
        self.port = self.config.get('port', 5222)
        self.pubsub_service = self.config.get('pubsub_service', None)
        self.node = self.config.get('node', None)

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )
        self._load_side_config()

    def _load_side_config(self):
        self.jid = None
        self.password = None

        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        self.jid = sconfig.get('jid', None)
        if self.jid is not None:
            LOG.info('%s - jid set', self.name)

        self.password = sconfig.get('password', None)
        if self.password is not None:
            LOG.info('%s - password set', self.name)

    def _xmpp_session_start(self, event):
        LOG.debug('%s - _xmpp_session_start', self.name)
        self._xmpp_client.get_roster()
        self._xmpp_client.send_presence()

        result = self._xmpp_client['xep_0060'].subscribe(
            self.pubsub_service,
            self.node
        )
        LOG.debug('%s - subscribe result: %s', self.name, result)

    def _xmpp_publish(self, msg):
        LOG.debug('%s - _publish %s', self.name, msg)
        payload = msg['pubsub_event']['items']['item']['payload']
        if payload is None:
            return

        command = payload.find('{http://jabber.org/protocol/pubsub#event}command')
        if command is None:
            LOG.error(
                '%s - pubsub event received with no commands',
                self.name
            )
            return

        command = command.text
        if command == 'INIT':
            return

        data = payload.find('{http://jabber.org/protocol/pubsub#event}data')
        if data is None:
            LOG.error(
                '%s - pubsub event received with no data',
                self.name
            )
            return

        data = data.text
        data = ujson.loads(data)

        indicator = data.get('indicator', None)
        if indicator is None:
            LOG.error('%s - received command with no indicator', self.name)
            return

        value = data.get('value', None)
        if value is None:
            LOG.error('%s - received command with no value', self.name)
            return

        origins = value.get('origins', None)
        if origins is None:
            LOG.error('%s - received indicator with no origin', self.name)
            return

        if self.jid in origins:
            LOG.debug('%s - indicator already known, ignored', self.name)
            return

        if command == 'UPDATE':
            for o in origins:
                self.update(
                    source=o,
                    indicator=indicator,
                    value=value
                )

        elif command == 'WITHDRAW':
            for o in origins:
                self.withdraw(
                    source=o,
                    indicator=indicator,
                    value=value
                )

        else:
            LOG.error('%s - unknown command %s', self.name, command)

    def _start_xmpp_client(self):
        if self._xmpp_client is not None:
            return

        if self.jid is None or self.password is None:
            raise RuntimeError('%s - jid or password not set', self.name)

        if self.server is None or self.port is None:
            raise RuntimeError('%s - server or port not set', self.name)

        if self.node is None or self.pubsub_service is None:
            raise RuntimeError(
                '%s - node or pubsub_service not set',
                self.name
            )

        self._xmpp_client = sleekxmpp.ClientXMPP(
            jid=self.jid,
            password=self.password
        )
        self._xmpp_client.register_plugin('xep_0030')
        self._xmpp_client.register_plugin('xep_0059')
        self._xmpp_client.register_plugin('xep_0060')
        self._xmpp_client.add_event_handler(
            'session_start',
            self._xmpp_session_start
        )
        self._xmpp_client.add_event_handler(
            'pubsub_publish',
            self._xmpp_publish
        )

        if not self._xmpp_client.connect((self.server, self.port)):
            raise RuntimeError(
                '%s - error connecting to XMPP server',
                self.name
            )

        self._xmpp_client.process(block=True)

    def _run(self):
        while True:
            try:
                self._start_xmpp_client()

            except RuntimeError() as e:
                LOG.error('%s - %s', self.name, str(e))
                self.statistics['xmpp.error'] += 1

            except gevent.GreenletExit:
                if self._xmpp_client is not None:
                    self._xmpp_client.disconnect()
                break

            except Exception as e:
                LOG.exception('%s - error in starting XMPP client', self.name)

            try:
                if self._xmpp_client is not None:
                    self._xmpp_client.disconnect()
                self._xmpp_client = None

                hup_called = self._load_event.wait(timeout=60)
                if hup_called:
                    LOG.debug('%s - clearing load event', self.name)
                    self._load_event.clear()

            except gevent.GreenletExit:
                break        

    def start(self):
        super(XMPPMiner, self).start()

        if self._xmpp_glet is not None:
            return
        self._xmpp_glet = gevent.spawn_later(random.randint(0, 2), self._run)

    def stop(self):
        super(XMPPMiner, self).stop()

        if self._xmpp_client is None:
            return

        self._xmpp_glet.kill()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        self._load_event.set()
