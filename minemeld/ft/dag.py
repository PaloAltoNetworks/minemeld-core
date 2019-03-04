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
import yaml
import netaddr
import os
import re
import collections
import itertools
import shutil

import gevent
import gevent.queue
import gevent.event

import pan.xapi

from . import base
from . import actorbase
from . import table
from .utils import utc_millisec

LOG = logging.getLogger(__name__)

SUBRE = re.compile("[^A-Za-z0-9_]")


class DevicePusher(gevent.Greenlet):
    def __init__(self, device, prefix, watermark, attributes, persistent):
        super(DevicePusher, self).__init__()

        self.device = device
        self.xapi = pan.xapi.PanXapi(
            tag=self.device.get('tag', None),
            api_username=self.device.get('api_username', None),
            api_password=self.device.get('api_password', None),
            api_key=self.device.get('api_key', None),
            port=self.device.get('port', None),
            hostname=self.device.get('hostname', None),
            serial=self.device.get('serial', None)
        )

        self.prefix = prefix
        self.attributes = attributes
        self.watermark = watermark
        self.persistent = persistent

        self.q = gevent.queue.Queue()

    def put(self, op, address, value):
        LOG.debug('adding %s:%s to device queue', op, address)
        self.q.put([op, address, value])

    def _get_registered_ip_tags(self, ip):
        self.xapi.op(
            cmd='<show><object><registered-ip><ip>%s</ip></registered-ip></object></show>' % ip,
            vsys=self.device.get('vsys', None),
            cmd_xml=False
        )

        entries = self.xapi.element_root.findall('./result/entry')
        if entries is None or len(entries) == 0:
            LOG.warning('%s: ip %s has no tags', self.device.get('hostname', None), ip)
            return None

        tags = [member.text for member in entries[0].findall('./tag/member')
                if member.text and member.text.startswith(self.prefix)]

        return tags

    def _get_all_registered_ips(self):
        cmd = (
            '<show><object><registered-ip><tag><entry name="%s%s"/></tag></registered-ip></object></show>' %
            (self.prefix, self.watermark)
        )
        self.xapi.op(
            cmd=cmd,
            vsys=self.device.get('vsys', None),
            cmd_xml=False
        )

        entries = self.xapi.element_root.findall('./result/entry')
        if not entries:
            return

        for entry in entries:
            ip = entry.get("ip")

            yield ip, self._get_registered_ip_tags(ip)

    def _dag_message(self, type_, addresses):
        message = [
            "<uid-message>",
            "<version>1.0</version>",
            "<type>update</type>",
            "<payload>"
        ]
        persistent = ''
        if type_ == 'register':
            persistent = ' persistent="%d"' % (1 if self.persistent else 0)
        message.append('<%s>' % type_)

        if addresses is not None and len(addresses) != 0:
            akeys = sorted(addresses.keys())
            for a in akeys:
                message.append(
                    '<entry ip="%s"%s>' % (a, persistent)
                )

                tags = sorted(addresses[a])
                if tags is not None:
                    message.append('<tag>')
                    for t in tags:
                        message.append('<member>%s</member>' % t)
                    message.append('</tag>')

                message.append('</entry>')

        message.append('</%s>' % type_)
        message.append('</payload></uid-message>')

        return ''.join(message)

    def _user_id(self, cmd=None):
        try:
            self.xapi.user_id(cmd=cmd,
                              vsys=self.device.get('vsys', None))

        except gevent.GreenletExit:
            raise

        except pan.xapi.PanXapiError as e:
            LOG.debug('%s', e)
            if 'already exists, ignore' in str(e):
                pass
            elif 'does not exist, ignore unreg' in str(e):
                pass
            elif 'Failed to register' in str(e):
                pass
            else:
                LOG.exception('XAPI exception in pusher for device %s: %s',
                              self.device.get('hostname', None), str(e))
                raise

    def _tags_from_value(self, value):
        result = []

        def _tag(t, v):
            if type(v) == unicode:
                v = v.encode('ascii', 'replace')
            else:
                v = str(v)

            v = SUBRE.sub('_', v)
            tag = '%s%s_%s' % (self.prefix, t, v)

            return tag

        for t in self.attributes:
            if t in value:
                if t == 'confidence':
                    confidence = value[t]
                    if confidence < 50:
                        tag = '%s%s_low' % (self.prefix, t)
                    elif confidence < 75:
                        tag = '%s%s_medium' % (self.prefix, t)
                    else:
                        tag = '%s%s_high' % (self.prefix, t)

                    result.append(tag)

                else:
                    LOG.debug('%s %s %s', t, value[t], type(value[t]))
                    if isinstance(value[t], list):
                        for v in value[t]:
                            LOG.debug('%s', v)
                            result.append(_tag(t, v))
                    else:
                        result.append(_tag(t, value[t]))

            else:
                # XXX noop for this case?
                result.append('%s%s_unknown' % (self.prefix, t))

        LOG.debug('%s', result)

        return set(result)  # XXX eliminate duplicates

    def _push(self, op, address, value):
        tags = []

        tags.append('%s%s' % (self.prefix, self.watermark))

        tags += self._tags_from_value(value)

        if len(tags) == 0:
            tags = None

        msg = self._dag_message(op, {address: tags})

        self._user_id(cmd=msg)

    def _init_resync(self):
        ctags = collections.defaultdict(set)
        while True:
            op, address, value = self.q.get()
            if op == 'EOI':
                break

            if op != 'init':
                raise RuntimeError(
                    'DevicePusher %s - wrong op %s received in init phase' %
                    (self.device.get('hostname', None), op)
                )

            ctags[address].add('%s%s' % (self.prefix, self.watermark))
            for t in self._tags_from_value(value):
                ctags[address].add(t)

        LOG.debug('%s', ctags)

        register = collections.defaultdict(list)
        unregister = collections.defaultdict(list)
        for a, atags in self._get_all_registered_ips():
            regtags = set()
            if atags is not None:
                for t in atags:
                    regtags.add(t)

            added = ctags[a] - regtags
            removed = regtags - ctags[a]

            for t in added:
                register[a].append(t)

            for t in removed:
                unregister[a].append(t)

            ctags.pop(a)

        # ips not in firewall
        for a, atags in ctags.iteritems():
            register[a] = atags

        LOG.debug('register %s', register)
        LOG.debug('unregister %s', unregister)

        # XXX use constant for chunk size
        if len(register) != 0:
            addrs = iter(register)
            for i in xrange(0, len(register), 1000):
                rmsg = self._dag_message(
                    'register',
                    {k: register[k] for k in itertools.islice(addrs, 1000)}
                )
                self._user_id(cmd=rmsg)

        if len(unregister) != 0:
            addrs = iter(unregister)
            for i in xrange(0, len(unregister), 1000):
                urmsg = self._dag_message(
                    'unregister',
                    {k: unregister[k] for k in itertools.islice(addrs, 1000)}
                )
                self._user_id(cmd=urmsg)

    def _run(self):
        self._init_resync()

        while True:
            try:
                op, address, value = self.q.peek()
                self._push(op, address, value)
                self.q.get()  # discard processed message

            except gevent.GreenletExit:
                break

            except pan.xapi.PanXapiError as e:
                LOG.exception('XAPI exception in pusher for device %s: %s',
                              self.device.get('hostname', None), str(e))
                raise


class DagPusher(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.devices = []
        self.device_pushers = []

        self.device_list_glet = None
        self.device_list_mtime = None

        self.ageout_glet = None
        self.last_ageout_run = None

        self.hup_event = gevent.event.Event()

        super(DagPusher, self).__init__(name, chassis, config)

    def configure(self):
        super(DagPusher, self).configure()

        self.device_list_path = self.config.get('device_list', None)
        if self.device_list_path is None:
            self.device_list_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_device_list.yml' % self.name
            )
        self.age_out = self.config.get('age_out', 3600)
        self.age_out_interval = self.config.get('age_out_interval', None)
        self.tag_prefix = self.config.get('tag_prefix', 'mmld_')
        self.tag_watermark = self.config.get('tag_watermark', 'pushed')
        self.tag_attributes = self.config.get(
            'tag_attributes',
            ['confidence', 'direction']
        )
        self.persistent_registered_ips = self.config.get(
            'persistent_registered_ips',
            True
        )

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('_age_out')

    def initialize(self):
        self._initialize_table()

    def rebuild(self):
        self.rebuild_flag = True
        self._initialize_table(truncate=True)

    def reset(self):
        self._initialize_table(truncate=True)

    def _validate_ip(self, indicator, value):
        type_ = value.get('type', None)
        if type_ not in ['IPv4', 'IPv6']:
            LOG.error('%s - invalid indicator type, ignored: %s',
                      self.name, type_)
            self.statistics['ignored'] += 1
            return

        if '-' in indicator:
            i1, i2 = indicator.split('-', 1)
            if i1 != i2:
                LOG.error('%s - indicator range must be equal, ignored: %s',
                          self.name, indicator)
                self.statistics['ignored'] += 1
                return
            indicator = i1

        try:
            address = netaddr.IPNetwork(indicator)
        except netaddr.core.AddrFormatError as e:
            LOG.error('%s - invalid IP address received, ignored: %s',
                      self.name, e)
            self.statistics['ignored'] += 1
            return

        if address.size != 1:
            LOG.error('%s - IP network received, ignored: %s',
                      self.name, address)
            self.statistics['ignored'] += 1
            return

        if type_ == 'IPv4' and address.version != 4 or \
           type_ == 'IPv6' and address.version != 6:
            LOG.error('%s - IP version mismatch, ignored',
                      self.name)
            self.statistics['ignored'] += 1
            return

        return address

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        address = self._validate_ip(indicator, value)
        if address is None:
            return

        current_value = self.table.get(str(address))

        now = utc_millisec()
        age_out = now+self.age_out*1000

        value['_age_out'] = age_out

        self.statistics['added'] += 1
        self.table.put(str(address), value)
        LOG.debug('%s - #indicators: %d', self.name, self.length())

        value.pop('_age_out')

        uflag = False
        if current_value is not None:
            for t in self.tag_attributes:
                cv = current_value.get(t, None)
                nv = value.get(t, None)
                if isinstance(cv, list) or isinstance(nv, list):
                    uflag |= set(cv) != set(nv)
                else:
                    uflag |= cv != nv

        LOG.debug('uflag %s current %s new %s', uflag, current_value, value)

        for p in self.device_pushers:
            if uflag:
                p.put('unregister', str(address), current_value)
            p.put('register', str(address), value)

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        address = self._validate_ip(indicator, value)
        if address is None:
            return

        current_value = self.table.get(str(address))
        if current_value is None:
            LOG.warning('%s - unknown indicator received, ignored: %s',
                        self.name, address)
            self.statistics['ignored'] += 1
            return

        current_value.pop('_age_out', None)

        self.statistics['removed'] += 1
        self.table.delete(str(address))
        LOG.debug('%s - #indicators: %d', self.name, self.length())

        for p in self.device_pushers:
            p.put('unregister', str(address), current_value)

    def _age_out_run(self):
        while True:
            try:
                now = utc_millisec()

                LOG.debug('now: %s', now)

                for i, v in self.table.query(index='_age_out',
                                             to_key=now-1,
                                             include_value=True):
                    LOG.debug('%s - %s %s aged out', self.name, i, v)

                    for dp in self.device_pushers:
                        dp.put(
                            op='unregister',
                            address=i,
                            value=v
                        )

                    self.statistics['aged_out'] += 1
                    self.table.delete(i)

                self.last_ageout_run = now
                LOG.debug('%s - #indicators: %d', self.name, self.length())

            except gevent.GreenletExit:
                break

            except Exception:
                LOG.exception('Exception in _age_out_loop')

            try:
                gevent.sleep(self.age_out_interval)
            except gevent.GreenletExit:
                break

    def _spawn_device_pusher(self, device):
        dp = DevicePusher(
            device,
            self.tag_prefix,
            self.tag_watermark,
            self.tag_attributes,
            self.persistent_registered_ips
        )
        dp.link_exception(self._device_pusher_died)

        for i, v in self.table.query(include_value=True):
            LOG.debug('%s - addding %s to init', self.name, i)
            dp.put('init', i, v)
        dp.put('EOI', None, None)

        return dp

    def _device_pusher_died(self, g):
        try:
            g.get()

        except gevent.GreenletExit:
            pass

        except Exception:
            LOG.exception('%s - exception in greenlet for %s, '
                          'respawning in 60 seconds',
                          self.name, g.device['hostname'])

            for idx in range(len(self.device_pushers)):
                if self.device_pushers[idx].device == g.device:
                    break
            else:
                LOG.info('%s - device pusher for %s removed,' +
                         ' respawning aborted',
                         self.name, g.device['hostname'])
                g = None
                return

            dp = self._spawn_device_pusher(g.device)
            self.device_pushers[idx] = dp
            dp.start_later(60)

    def _load_device_list(self):
        with open(self.device_list_path, 'r') as dlf:
            dlist = yaml.safe_load(dlf)

        added = [d for i, d in enumerate(dlist) if d not in self.devices]
        removed = [i for i, d in enumerate(self.devices) if d not in dlist]

        dpushers = []
        for d in dlist:
            if d in added:
                dp = self._spawn_device_pusher(d)
                dpushers.append(dp)
            else:
                idx = self.devices.index(d)
                dpushers.append(self.device_pushers[idx])

        for idx in removed:
            self.device_pushers[idx].kill()

        self.device_pushers = dpushers
        self.devices = dlist

        for g in self.device_pushers:
            if g.value is None and not g.started:
                g.start()

    def _huppable_wait(self, wait_time):
        hup_called = self.hup_event.wait(timeout=wait_time)
        if hup_called:
            LOG.debug('%s - clearing poll event', self.name)
            self.hup_event.clear()

    def _device_list_monitor(self):
        if self.device_list_path is None:
            LOG.warning('%s - no device_list path configured', self.name)
            return

        while True:
            try:
                mtime = os.stat(self.device_list_path).st_mtime
            except OSError:
                LOG.debug('%s - error checking mtime of %s',
                          self.name, self.device_list_path)
                self._huppable_wait(5)
                continue

            if mtime != self.device_list_mtime:
                self.device_list_mtime = mtime

                try:
                    self._load_device_list()
                    LOG.info('%s - device list loaded', self.name)
                except Exception:
                    LOG.exception('%s - exception loading device list',
                                  self.name)

            self._huppable_wait(5)

    def mgmtbus_status(self):
        result = super(DagPusher, self).mgmtbus_status()

        result['devices'] = len(self.devices)

        return result

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(DagPusher, self).start()

        if self.device_list_glet is not None:
            return

        self.device_list_glet = gevent.spawn_later(
            2,
            self._device_list_monitor
        )

        if self.age_out_interval is not None:
            self.ageout_glet = gevent.spawn(self._age_out_run)

    def stop(self):
        super(DagPusher, self).stop()

        if self.device_list_glet is None:
            return

        for g in self.device_pushers:
            g.kill()

        self.device_list_glet.kill()

        if self.ageout_glet is not None:
            self.ageout_glet.kill()

        self.table.close()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload device list', self.name)
        self.hup_event.set()

    @staticmethod
    def gc(name, config=None):
        actorbase.ActorBaseFT.gc(name, config=config)

        shutil.rmtree(name, ignore_errors=True)
        device_list_path = None
        if config is not None:
            device_list_path = config.get('device_list', None)
        if device_list_path is None:
            device_list_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_device_list.yml'.format(name)
            )

        try:
            os.remove(device_list_path)
        except OSError:
            pass
