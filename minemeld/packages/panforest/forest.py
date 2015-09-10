#
# Copyright (c) 2015 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

from __future__ import print_function
import pprint
import random
import sys
import time

import pan.config

_NLOGS = 100


class PanForestError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        if self.msg is None:
            return ''
        return self.msg


class PanForest:
    def __init__(self,
                 xapi=None,
                 log_type=None,
                 filter=None,
                 nlogs=None,
                 format=None,
                 debug=0):
        self.xapi = xapi
        self.log_type = log_type
        self.filter = filter
        self.nlogs = _NLOGS if nlogs is None else nlogs
        if format not in ['xml', 'python', None]:
            raise PanForestError('Invalid format: %s' % format)
        self.format = 'python' if format is None else format
        self.debug = debug

    def __iter__(self):
        return self.follow()

    def follow(self):
        """\
        generator function to return log entries matching optional
        filter
        """

        # filter time < now so we start at logs in current second
        now = int(time.time()) - 1
        filter = '(receive_time leq %d)' % now
        if self.debug > 0:
            print('filter:', filter, file=sys.stderr)
        _, obj = self._log_get(nlogs=1,
                               filter=filter)
        if not obj:
            raise PanForestError("Can't get last log")

        count = self._log_count(obj)

        if count != 1:
            seqno = 0
        else:
            seqno = self._log_seqno(obj)

        if self.debug > 0:
            print('starting seqno:', seqno, file=sys.stderr)

        filter = self._filter(seqno)
        nlogs = self.nlogs

        skip = 0
        sleeper = self._sleeper()

        while True:
            if self.debug > 0:
                print('skip: %d nlogs: %d filter: "%s"' %
                      (skip, nlogs, filter), file=sys.stderr)
            elem, obj = self._log_get(nlogs=nlogs,
                                      filter=filter,
                                      skip=skip)

            if not obj:
                raise PanForestError("Can't get log chunk")

            count = self._log_count(obj)

            if count == 0:
                skip = 0
                filter = self._filter(seqno)

                try:
                    wait = next(sleeper)
                except StopIteration:
                    pass
                x = random.uniform(0, 0.5)
                if self.debug > 0:
                    print('sleep:', wait, x, file=sys.stderr)

                time.sleep(wait+x)
                continue

            elif count == nlogs:
                sleeper = self._sleeper()
                skip += nlogs
                t = self._log_seqno(obj)
                if t > seqno:
                    seqno = t
                # don't update filter

            elif count < nlogs:
                sleeper = self._sleeper()
                t = self._log_seqno(obj)
                if t > seqno:
                    seqno = t
                filter = self._filter(seqno)

            else:
                assert False, 'NOTREACHED'

            if self.format == 'python':
                for entry in self._log_entry(obj['logs'], 'entry'):
                    yield entry
            elif self.format == 'xml':
                nodes = elem.findall('.')
                for node in nodes:
                    yield node

    def tail(self, lines):
        elem, obj = self._log_get(nlogs=lines,
                                  filter=self.filter)
        if not obj:
            raise PanForestError("Can't get log")

        count = self._log_count(obj)
        if count == 0:
            return None

        if self.format == 'python':
            return obj
        elif self.format == 'xml':
            return elem

    def _log_get(self, nlogs=None, skip=None, filter=None):
        try:
            self.xapi.log(log_type=self.log_type,
                          skip=skip,
                          nlogs=nlogs,
                          filter=filter)
        except pan.xapi.PanXapiError as e:
            raise PanForestError('pan.xapi.PanXapi: %s' % e)

        path = './result/log/logs'
        elem = self.xapi.element_root.find(path)
        if elem is None:
            raise PanForestError('No %s in element_root' % path)

        obj = self._xml_python(elem)

        if self.debug > 2:
            print(pprint.pformat(obj), file=sys.stderr)

        return elem, obj

    def _sleeper(self):
        """return iterator of seconds to sleep until log match"""

        try:
            xrange(1)
        except NameError:
            _range = range
        else:
            _range = xrange

        x = _range(1, 60, 3)

        return iter(x)

    @staticmethod
    def _xml_python(elem, path=None):
        try:
            conf = pan.config.PanConfig(config=elem)
        except pan.config.PanConfigError as e:
            raise PanForestError('pan.config.PanConfigError: %s' % e)

        obj = conf.python(path)
        return obj

    def _log_count(self, obj):
        if not ('logs' in obj and 'count' in obj['logs']):
            raise PanForestError('logs count not found')

        try:
            count = int(obj['logs']['count'])
        except ValueError:
            raise PanForestError('count not numeric: %s' %
                                 obj['logs']['count'])

        if self.debug > 0:
            print('count: %d' % count, file=sys.stderr)

        return count

    def _log_seqno(self, obj):
        x = self._log_entry(obj['logs']['entry'][0], 'seqno')
        try:
            n = int(x)
        except ValueError:
            raise PanForestError('seqno not numeric: %s' % x)

        return n

    @staticmethod
    def _log_entry(obj, key):
        if key not in obj:
            raise PanForestError('key not in entry: %s' % key)

        return obj[key]

    def _filter(self, seqno):
        s = 'not (seqno leq %d)' % seqno

        if self.filter:
            s = self.filter + ' and ' + s

        return s
