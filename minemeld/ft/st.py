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

"""
Simple segment tree implementation based on LevelDB.

**KEYS**

Numbers are 8-bit unsigned.

- Segment key: (1, <start>, <end>, <level>, <uuid>)
- Endpoint key: (1, <endpoint>, <type>, <level>, <uuid>)

**ENDPOINT**

- Type: 0: START, 1: END
"""

import plyvel
import struct
import logging
import shutil
import array

LOG = logging.getLogger(__name__)

MAX_LEVEL = 0xFE
TYPE_START = 0x00
TYPE_END = 0x1


class ST(object):
    def __init__(self, name, epsize, truncate=False,
                 bloom_filter_bits=10, write_buffer_size=(4 << 20)):
        if truncate:
            try:
                shutil.rmtree(name)
            except:
                pass

        self.db = plyvel.DB(
            name,
            create_if_missing=True,
            write_buffer_size=write_buffer_size,
            bloom_filter_bits=bloom_filter_bits
        )
        self.epsize = epsize
        self.max_endpoint = (1 << epsize)-1

        self.num_endpoints = 0
        self.num_segments = 0

    def _split_interval(self, start, end, lower, upper):
        if start <= lower and upper <= end:
            return [(lower, upper)]

        mid = (lower+upper)/2

        result = []
        if start <= mid:
            result += self._split_interval(start, end, lower, mid)
        if end > mid:
            result += self._split_interval(start, end, mid+1, upper)

        return result

    def _segment_key(self, start, end, uuid_=None, level=None):
        res = array.array('B', [
            1,
            (start >> 56) & 0xFF, (start >> 48) & 0xFF,
            (start >> 40) & 0xFF, (start >> 32) & 0xFF,
            (start >> 24) & 0xFF, (start >> 16) & 0xFF,
            (start >> 8) & 0xFF, start & 0xFF,
            (end >> 56) & 0xFF, (end >> 48) & 0xFF,
            (end >> 40) & 0xFF, (end >> 32) & 0xFF,
            (end >> 24) & 0xFF, (end >> 16) & 0xFF,
            (end >> 8) & 0xFF, end & 0xFF,
        ])

        if level is not None:
            res.append(level)
            if uuid_ is not None:
                for c in uuid_:
                    res.append(ord(c))

        return res.tostring()

    def _split_segment_key(self, key):
        _, start, end, level = struct.unpack(">BQQB", key[:18])
        return start, end, level, key[18:]

    def _endpoint_key(self, endpoint, level=None, type_=None, uuid_=None):
        res = array.array('B', [
            2,
            (endpoint >> 56) & 0xFF, (endpoint >> 48) & 0xFF,
            (endpoint >> 40) & 0xFF, (endpoint >> 32) & 0xFF,
            (endpoint >> 24) & 0xFF, (endpoint >> 16) & 0xFF,
            (endpoint >> 8) & 0xFF, endpoint & 0xFF
        ])

        if level is not None:
            res.append(level)
            if type_ is not None:
                res.append(type_)
                if uuid_ is not None:
                    for c in uuid_:
                        res.append(ord(c))

        return res.tostring()

    def _split_endpoint_key(self, k):
        _, endpoint, level, type_ = struct.unpack(">BQBB", k[:11])
        type_ = (True if type_ == TYPE_START else False)
        return endpoint, level, type_, k[11:]

    def close(self):
        self.db.close()

    def put(self, uuid_, start, end, level=0):
        si = self._split_interval(start, end, 0, self.max_endpoint)

        value = struct.pack(">QQ", start, end)

        batch = self.db.write_batch()

        for i in si:
            k = self._segment_key(i[0], i[1], uuid_=uuid_, level=level)
            batch.put(k, value)

        ks = self._endpoint_key(
            start,
            level=level,
            type_=TYPE_START,
            uuid_=uuid_
        )
        batch.put(ks, "\x00")
        ke = self._endpoint_key(
            end,
            level=level,
            type_=TYPE_END,
            uuid_=uuid_
        )
        batch.put(ke, "\x00")

        batch.write()

        self.num_endpoints += 2
        self.num_segments += len(si)

    def delete(self, uuid_, start, end, level=0):
        batch = self.db.write_batch()

        si = self._split_interval(start, end, 0, self.max_endpoint)
        for i in si:
            k = self._segment_key(i[0], i[1], uuid_=uuid_, level=level)
            batch.delete(k)

        ks = self._endpoint_key(
            start,
            level=level,
            type_=TYPE_START,
            uuid_=uuid_
        )
        batch.delete(ks)
        ke = self._endpoint_key(
            end,
            level=level,
            type_=TYPE_END,
            uuid_=uuid_
        )
        batch.delete(ke)

        batch.write()

        self.num_endpoints -= 2
        self.num_segments -= len(si)

    def cover(self, value):
        """Iterate over segments covering value. Segment format:
        (uuid, level, start, end).
        
        Args:
            value (int): Address
        """

        lower = 0
        upper = self.max_endpoint*2

        while True:
            mid = (lower+upper)/2
            if value <= mid:
                upper = mid
            else:
                lower = mid+1

            ks = self._segment_key(lower, upper)
            ke = self._segment_key(lower, upper, level=MAX_LEVEL+1)

            for k, v in self.db.iterator(start=ks, stop=ke, include_value=True,
                                         reverse=True, include_start=False,
                                         include_stop=False):
                _, _, level, uuid_ = self._split_segment_key(k)
                start, end = struct.unpack(">QQ", v)

                yield uuid_, level, start, end

            if lower == upper:
                break

    def query_endpoints(self, start=None, stop=None, reverse=False,
                        include_start=True, include_stop=True):
        """Iterate over endpoints between start and end. endpoints have the
        format (endpoint, level, type, uuid). Type: 0 - start, 1 - end

            start (int, optional): Defaults to None.
            stop (int, optional): Defaults to None.
            reverse (bool, optional): Defaults to False.
            include_start (bool, optional): Defaults to True.
            include_stop (bool, optional): Defaults to True.
        """

        if start is None:
            start = self._endpoint_key(0)
        else:
            start = self._endpoint_key(start)
        if stop is None:
            stop = self._endpoint_key(self.max_endpoint, level=MAX_LEVEL+1)
        else:
            stop = self._endpoint_key(stop, level=MAX_LEVEL+1)

        di = self.db.iterator(
            start=start,
            stop=stop,
            reverse=reverse,
            include_value=False,
            include_start=include_start,
            include_stop=include_stop
        )
        for k in di:
            yield self._split_endpoint_key(k)
