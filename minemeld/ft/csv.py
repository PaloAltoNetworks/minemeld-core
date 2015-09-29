from __future__ import absolute_import

import logging
import copy
import gevent
import gevent.event
import random
import re
import itertools
import csv
import requests

from . import base
from . import table
from . import ft_states
from .utils import utc_millisec
from .utils import age_out_in_millisec
from .utils import RWLock

LOG = logging.getLogger(__name__)


class FtStateChanged(Exception):
    pass


class CSVFT(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None
        self.ageout_glet = None

        self.active_requests = []
        self.rebuild_flag = False
        self.last_run = None
        self.last_ageout_run = None

        self.poll_service = None
        self.collection_mgmt_service = None

        self.state_lock = RWLock()

        super(CSVFT, self).__init__(name, chassis, config)

    def configure(self):
        super(CSVFT, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.url = self.config.get('url', None)
        self.attributes = self.config.get('attributes', {})
        self.interval = self.config.get('interval', 3600)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.num_retries = self.config.get('num_retries', 2)
        self.verify_cert = self.config.get('verify_cert', True)

        self.age_out_interval = int(self.config.get(
            'age_out_interval',
            '3600'
        ))
        self.age_out = self.config.get(
            'age_out',
            '%d' % self.interval*2
        )

        self.ignore_regex = self.config.get('ignore_regex', None)
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)
        self.attributes = self.config.get('attributes', {})

        self.fieldnames = self.config.get('fieldnames', {})

        self.dialect = {
            'delimiter': self.config.get('delimiter', ','),
            'doublequote': self.config.get('doublequote', True),
            'escapechar': self.config.get('escapechar', None),
            'quotechar': self.config.get('quotechar', '"'),
            'skipinitialspace': self.config.get('skipinitialspace', False)
        }

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('_age_out')

    def initialize(self):
        self._initialize_table()

    def rebuild(self):
        self.rebuild_flag = True
        self._initialize_table(truncate=(self.last_checkpoint is None))

    def reset(self):
        self._initialize_table(truncate=True)

    @base.BaseFT.state.setter
    def state(self, value):
        LOG.debug("%s - acquiring state write lock", self.name)
        self.state_lock.lock()
        #  this is weird ! from stackoverflow 10810369
        super(CSVFT, self.__class__).state.fset(self, value)
        self.state_lock.unlock()
        LOG.debug("%s - releasing state write lock", self.name)

    def _age_out_run(self):
        while True:
            self.state_lock.rlock()
            if self.state != ft_states.STARTED:
                self.state_lock.runlock()
                return

            try:
                now = utc_millisec()

                for i, v in self.table.query(index='_age_out',
                                             to_key=now-1000,
                                             include_value=True):
                    LOG.debug('%s - %s %s aged out', self.name, i, v)
                    self.emit_withdraw(indicator=i)
                    self.table.delete(i)

                self.last_ageout_run = now

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('Exception in _age_out_loop')

            finally:
                self.state_lock.runlock()

            gevent.sleep(self.age_out_interval)

    def _process_row(self, row):
        row.pop(None, None)  # I love this

        indicator = row.pop('indicator', None)
        return [[indicator, row]]

    def _build_url(self, now):
        return self.url

    def _polling_loop(self):
        age_out = age_out_in_millisec(self.age_out)

        LOG.info("Polling %s", self.name)

        now = utc_millisec()

        rkwargs = dict(
            stream=True,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            self._build_url(now),
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            self.state_lock.unlock()
            raise

        response = r.raw
        if self.ignore_regex is not None:
            response = itertools.ifilter(
                lambda x: self.ignore_regex.match(x) is None,
                r.raw
            )

        csvreader = csv.DictReader(
            response,
            fieldnames=self.fieldnames,
            **self.dialect
        )

        for row in csvreader:
            ipairs = self._process_row(row)

            for indicator, attributes in ipairs:
                if indicator is None:
                    LOG.debug('%s - indicator is None for row %s',
                              self.name, row)

                value = copy.copy(self.attributes)

                attributes['sources'] = [self.source_name]
                attributes['last_seen'] = now
                attributes['_age_out'] = now+age_out

                ev = self.table.get(indicator)
                if ev is not None:
                    attributes['first_seen'] = ev['first_seen']
                else:
                    self.statistics['added'] += 1
                    attributes['first_seen'] = now

                value.update(attributes)

                LOG.debug("%s - Updating %s %s",
                          self.name, indicator, value)
                self.table.put(indicator, value)

                LOG.debug("%s - Emitting update for %s", self.name, indicator)
                self.emit_update(indicator, value)

        LOG.debug("%s - End of polling #indicators: %d",
                  self.name, self.table.num_indicators)

    def _run(self):
        while self.last_ageout_run is None:
            gevent.sleep(1)

        self.state_lock.rlock()
        if self.state != ft_states.STARTED:
            self.state_lock.runlock()
            return

        try:
            if self.rebuild_flag:
                LOG.debug("rebuild flag set, resending current indicators")
                # reinit flag is set, emit update for all the known indicators
                for i, v in self.table.query(include_value=True):
                    self.emit_update(i, v)
        finally:
            self.state_lock.unlock()

        tryn = 0

        while True:
            lastrun = utc_millisec()

            self.state_lock.rlock()
            if self.state != ft_states.STARTED:
                self.state_lock.runlock()
                break

            try:
                self._polling_loop()
            except gevent.GreenletExit:
                break

            except FtStateChanged:
                break

            except:
                LOG.exception("Exception in polling loop for %s", self.name)
                tryn += 1
                if tryn < self.num_retries:
                    gevent.sleep(random.randint(1, 5))
                    continue

            finally:
                self.state_lock.runlock()

            self.last_run = lastrun

            tryn = 0

            now = utc_millisec()
            deltat = (lastrun+self.interval*1000)-now

            while deltat < 0:
                LOG.warning("Time for processing exceeded interval for %s",
                            self.name)
                deltat += self.interval*1000

            try:
                gevent.sleep(deltat/1000.0)

            except gevent.GreenletExit:
                break

    def mgmtbus_status(self):
        result = super(CSVFT, self).mgmtbus_status()
        result['last_run'] = self.last_run

        return result

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(CSVFT, self).start()

        if self.glet is not None:
            return

        self.glet = gevent.spawn_later(random.randint(0, 2), self._run)
        self.ageout_glet = gevent.spawn(self._age_out_run)

    def stop(self):
        super(CSVFT, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()
        self.ageout_glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
