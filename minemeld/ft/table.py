"""
Table implementation based on LevelDB (https://github.com/google/leveldb).
This is a sort of poor, lazy man implementation of IndexedDB schema.

**KEYS**

Numbers are 8-bit unsigned.

- Schema Version: (0)
- Index Last Global Id: (0,1, <indexnum>)
- Last Update Key: (0,2)
- Number of Indicators: (0,3)
- Indicator Version: (1,0,<indicator>)
- Indicator: (1,1,<indicator>)

**INDICATORS**

Each indicators has 2 entries associated in the DB: a version and a value.

The version number is used to track indicator existance and versioning.
When an indicator value is updated, its version number is incremented.
The version number is a 64-bit LSB unsigned int.

The value of an indicator is a 64-bit unsigned int LSB followed by a dump of
a dictionary of attributes in JSON format.

To iterate over all the indicators versions iterate from key (1,0) to key
(1,1) excluded.

NULL indicators are not allowed.

**INDEXES**

Indicators are stored in alphabetical order. Indexes are secondary indexes
on indicators attributes.

Each index has an associated id in the range 0 - 255. The attribute associated
to the index is stored at (0,1,<index id>), if the key does not exist the
index does not exist.

There is also a Last Global Id per index, used to index indicators with the
same attribute value. Each time a new indicator is added to the index, the
Last Global Id is incremented. The Last Global Id of an index is stored at
(2,<index id>,0) as a 64-bit LSB unsigned int.

Each entry in the index is stored with a key
(2,<index id>,0xF0,<encoded value>,<last global id>) and value
(<version>,<indicator>). <encoded value> depends on the type of attribute.

When iterating over an index, the value of an index entry is loaded and if
the version does not match with current indicator version the index entry is
deleted. This permits a sort of lazy garbage collection.

To retrieve all the indicators with a specific attribute value just iterate
over the keys (2,<index id>,0xF0,<encoded value>) and
(2,<index id>,0xF0,<encoded value>,0xFF..FF)
"""

import plyvel
import struct
import ujson
import time
import logging
import shutil


SCHEMAVERSION_KEY = struct.pack("B", 0)
START_INDEX_KEY = struct.pack("BBB", 0, 1, 0)
END_INDEX_KEY = struct.pack("BBB", 0, 1, 0xFF)
LAST_UPDATE_KEY = struct.pack("BB", 0, 2)
NUM_INDICATORS_KEY = struct.pack("BB", 0, 3)

LOG = logging.getLogger(__name__)


class InvalidTableException(Exception):
    pass


class Table(object):
    def __init__(self, name, truncate=False, bloom_filter_bits=0):
        if truncate:
            try:
                shutil.rmtree(name)
            except:
                pass

        self.db = plyvel.DB(
            name,
            create_if_missing=True,
            bloom_filter_bits=bloom_filter_bits
        )
        self._read_metadata()

    def _init_db(self):
        self.last_update = 0
        self.indexes = {}
        self.num_indicators = 0

        batch = self.db.write_batch()
        batch.put(SCHEMAVERSION_KEY, struct.pack("B", 0))
        batch.put(LAST_UPDATE_KEY, struct.pack(">Q", self.last_update))
        batch.put(NUM_INDICATORS_KEY, struct.pack(">Q", self.num_indicators))
        batch.write()

    def _read_metadata(self):
        sv = self._get(SCHEMAVERSION_KEY)
        if sv is None:
            return self._init_db()
        sv = struct.unpack("B", sv)[0]
        if sv != 0:
            raise InvalidTableException("Schema version not supported")

        self.indexes = {}
        ri = self.db.iterator(
            start=START_INDEX_KEY,
            stop=END_INDEX_KEY
        )
        for k, v in ri:
            _, _, indexid = struct.unpack("BBB", k)
            if v in self.indexes:
                raise InvalidTableException("2 indexes with the same name")
            self.indexes[v] = {
                'id': indexid,
                'last_global_id': 0
            }
        for i in self.indexes:
            lgi = self._get(self._last_global_id_key(self.indexes[i]['id']))
            if lgi is not None:
                self.indexes[i]['last_global_id'] = struct.unpack(">Q", lgi)[0]
            else:
                self.indexes[i]['last_global_id'] = -1

        t = self._get(LAST_UPDATE_KEY)
        if t is None:
            raise InvalidTableException("LAST_UPDATE_KEY not found")
        self.last_update = struct.unpack(">Q", t)[0]

        t = self._get(NUM_INDICATORS_KEY)
        if t is None:
            raise InvalidTableException("NUM_INDICATORS_KEY not found")
        self.num_indicators = struct.unpack(">Q", t)[0]

    def _get(self, key):
        try:
            result = self.db.get(key)
        except KeyError:
            return None

        return result

    def close(self):
        self.db.close()

    def exists(self, key):
        if type(key) == unicode:
            key = key.encode('utf8')

        ikeyv = self._indicator_key_version(key)
        return (self._get(ikeyv) is not None)

    def get(self, key):
        if type(key) == unicode:
            key = key.encode('utf8')

        ikey = self._indicator_key(key)
        value = self._get(ikey)
        if value is None:
            return None

        # skip version
        return ujson.loads(value[8:])

    def delete(self, key):
        if type(key) == unicode:
            key = key.encode('utf8')

        ikey = self._indicator_key(key)
        ikeyv = self._indicator_key_version(key)

        if self._get(ikeyv) is None:
            return

        batch = self.db.write_batch()
        batch.delete(ikey)
        batch.delete(ikeyv)
        self.num_indicators -= 1
        batch.put(NUM_INDICATORS_KEY, struct.pack(">Q", self.num_indicators))
        batch.write()

    def _indicator_key(self, key):
        return struct.pack("BB", 1, 1)+key

    def _indicator_key_version(self, key):
        return struct.pack("BB", 1, 0)+key

    def _index_key(self, idxid, value, lastidxid=None):
        key = struct.pack("BBB", 2, idxid, 0xF0)

        if type(value) == unicode:
            value = value.encode('utf8')

        if type(value) == str:
            key += struct.pack(">BL", 0x0, len(value))+value
        elif type(value) == int or type(value) == long:
            key += struct.pack(">BQ", 0x1, value)
        else:
            raise ValueError("Unhandled value type: %s" % type(value))

        if lastidxid is not None:
            key += struct.pack(">Q", lastidxid)

        return key

    def _last_global_id_key(self, idxid):
        return struct.pack("BBB", 2, idxid, 0)

    def create_index(self, attribute):
        if attribute in self.indexes:
            return

        if len(self.indexes) == 0:
            idxid = 0
        else:
            idxid = max([i['id'] for i in self.indexes.values()])+1

        self.indexes[attribute] = {
            'id': idxid,
            'last_global_id': -1
        }

        batch = self.db.write_batch()
        batch.put(struct.pack("BBB", 0, 1, idxid), attribute)
        batch.write()

    def put(self, key, value):
        if type(key) == unicode:
            key = key.encode('utf8')

        if type(value) != dict:
            raise ValueError()

        ikey = self._indicator_key(key)
        ikeyv = self._indicator_key_version(key)

        exists = self._get(ikeyv)
        if exists is not None:
            cversion = struct.unpack(">Q", exists)[0]
        else:
            cversion = -1

        now = time.time()
        self.last_update = now
        cversion = cversion+1

        batch = self.db.write_batch()
        batch.put(ikey, struct.pack(">Q", cversion)+ujson.dumps(value))
        batch.put(ikeyv, struct.pack(">Q", cversion))
        batch.put(LAST_UPDATE_KEY, struct.pack(">Q", self.last_update))

        if exists is None:
            self.num_indicators += 1
            batch.put(
                NUM_INDICATORS_KEY,
                struct.pack(">Q", self.num_indicators)
            )

        for iattr, index in self.indexes.iteritems():
            v = value.get(iattr, None)
            if v is None:
                continue

            index['last_global_id'] += 1

            idxkey = self._index_key(index['id'], v, index['last_global_id'])
            batch.put(idxkey, struct.pack(">Q", cversion)+key)

            batch.put(
                self._last_global_id_key(index['id']),
                struct.pack(">Q", index['last_global_id'])
            )

        batch.write()

    def query(self, index=None, from_key=None, to_key=None,
              include_value=False, include_stop=True, include_start=True,
              reverse=False):
        if type(from_key) is unicode:
            from_key = from_key.encode('ascii', 'replace')
        if type(to_key) is unicode:
            to_key = to_key.encode('ascii', 'replace')

        if index is None:
            return self._query_by_indicator(
                from_key=from_key,
                to_key=to_key,
                include_value=include_value,
                include_stop=include_stop,
                include_start=include_start,
                reverse=reverse
            )
        return self._query_by_index(
            index,
            from_key=from_key,
            to_key=to_key,
            include_value=include_value,
            include_stop=include_stop,
            include_start=include_start,
            reverse=reverse
        )

    def _query_by_indicator(self, from_key=None, to_key=None,
                            include_value=False, include_stop=True,
                            include_start=True, reverse=False):
        if from_key is None:
            from_key = struct.pack("BB", 1, 1)
            include_stop = False
        else:
            from_key = self._indicator_key(from_key)

        if to_key is None:
            to_key = struct.pack("BB", 1, 2)
            include_start = False
        else:
            to_key = self._indicator_key(to_key)

        ri = self.db.iterator(
            start=from_key,
            stop=to_key,
            include_stop=include_stop,
            include_start=include_start,
            reverse=reverse,
            include_value=False
        )
        for ekey in ri:
            ekey = ekey[2:]
            if include_value:
                yield ekey, self.get(ekey)
            else:
                yield ekey

    def _query_by_index(self, index, from_key=None, to_key=None,
                        include_value=False, include_stop=True,
                        include_start=True, reverse=False):
        if index not in self.indexes:
            raise ValueError()

        idxid = self.indexes[index]['id']

        if from_key is None:
            from_key = struct.pack("BBB", 2, idxid, 0xF0)
            include_start = False
        else:
            from_key = self._index_key(idxid, from_key)

        if to_key is None:
            to_key = struct.pack("BBB", 2, idxid, 0xF1)
            include_stop = False
        else:
            to_key = self._index_key(
                idxid,
                to_key,
                lastidxid=0xFFFFFFFFFFFFFFFF
            )

        ri = self.db.iterator(
            start=from_key,
            stop=to_key,
            include_value=True,
            include_start=include_start,
            include_stop=include_stop,
            reverse=reverse
        )
        for ikey, ekey in ri:
            iversion = struct.unpack(">Q", ekey[:8])[0]
            ekey = ekey[8:]

            evalue = self._get(self._indicator_key_version(ekey))
            if evalue is None:
                # LOG.debug("Key does not exist")
                # key does not exist
                self.db.delete(ikey)
                continue

            cversion = struct.unpack(">Q", evalue)[0]
            if iversion != cversion:
                # index value is old
                # LOG.debug("Version mismatch")
                self.db.delete(ikey)
                continue

            if include_value:
                yield ekey, self.get(ekey)
            else:
                yield ekey
