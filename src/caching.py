"""
存 cache
查 cache
检查 TTL 是否过期
返回剩余 TTL
线程安全 lock

"""


import time
import threading
from dataclasses import replace

import  dataStructures.dns_dataTypes as DDT 

class cacheEntry_C:

    def __init__(self, records: list[DDT.resourceRecord_S]):
        self.items = []

        now = time.time()

        for record in records:
            if record.ttl > 0:
                expiry = now + record.ttl
                self.items.append((record, expiry))

    def get_valid_records(self):
        result = []
        now = time.time()

        for record, expiry in self.items:
            remain_ttl = int(expiry - now)

            if remain_ttl > 0:
                new_record = replace(record, ttl=remain_ttl)
                result.append(new_record)

        return result


class dnsCache_C:

    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()

    def _norm_name(self, name):
        return name.lower()

    def _make_key(self, name, rr_type, rr_class):
        return (
            self._norm_name(name),
            rr_type,
            rr_class
        )

    def get(self, name, rr_type, rr_class):
        key = self._make_key(name, rr_type, rr_class)

        with self.lock:
            if key not in self.cache:
                return None

            entry = self.cache[key]
            records = entry.get_valid_records()

            if len(records) == 0:
                del self.cache[key]
                return None

            return records

    def put(self, name, rr_type, rr_class, records):
        if len(records) == 0:
            return

        entry = cacheEntry_C(records)

        if len(entry.items) == 0:
            return

        key = self._make_key(name, rr_type, rr_class)

        with self.lock:
            self.cache[key] = entry

    def put_answer_records(self, records: list[DDT.resourceRecord_S]):
        """
        Simple positive answer cache.
        Later we can improve this for CNAME chain cache.
        """

        groups = {}

        for record in records:
            key = self._make_key(record.name, record.rr_type, record.rr_class)

            if key not in groups:
                groups[key] = []

            groups[key].append(record)

        for key in groups:
            name, rr_type, rr_class = key
            self.put(name, rr_type, rr_class, groups[key])
