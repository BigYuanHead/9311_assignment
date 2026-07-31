"""
    positive answer cache
    one entry stores one complete logical answer
"""


import math
import time
import threading
from dataclasses import replace

import dataStructures.dns_dataTypes as DDT



class cacheBlock_C:

    def __init__(self, records: list[DDT.a_rr_S]):
        self.items: list[ tuple[DDT.a_rr_S, float] ] = []
        self.is_cacheable: bool = True
        now = time.time()

        for record in records:
            # TTL=0
            if record.ttl <= 0:
                self.items = []
                self.is_cacheable = False
                return

            saved_record = replace(record)
            expiry = now + record.ttl
            self.items.append((saved_record, expiry))

    def get_valid_records(self) -> list[DDT.a_rr_S] | None:
        result: list[DDT.a_rr_S] = []

        # timer
        now = time.time()
        for record, expiry in self.items:
            remain_ttl = math.floor(expiry - now)

            # one expired link, drop all logical answers
            if remain_ttl <= 0:
                return None

            new_record = replace(record, ttl=remain_ttl)
            result.append(new_record)

        return result



class dnsCache_C:

    def __init__(self):
        self.cache: dict[ tuple[str, int, int], cacheBlock_C ] = {}
        self.lock = threading.Lock()

    def _norm_name(self, name: str) -> str:
        return name.rstrip('.').lower() + '.'

    def _make_key(self,
                  name: str,
                  rr_type: int,
                  rr_class: int
                  ) -> tuple[str, int, int]:
        return (
            self._norm_name(name),
            rr_type,
            rr_class
        )

    def get(self,
            name: str,
            rr_type: int,
            rr_class: int
            ) -> list[DDT.a_rr_S] | None:
        """
            @return
                a resource recored list - if exist
                OR
                None - if not
        """
        key = self._make_key(name, rr_type, rr_class)

        with self.lock: # lock for multi threading
            if key not in self.cache:
                return None

            entry = self.cache[key]
            records = entry.get_valid_records()

            if records is None: # destory expired
                del self.cache[key]
                return None

            return records


    def put(self,
            name: str,
            rr_type: int,
            rr_class: int,
            records: list[DDT.a_rr_S]
            ):
        if len(records) == 0:
            return

        entry = cacheBlock_C(records)

        if entry.is_cacheable is False: # TTL=0
            return
        key = self._make_key(name, rr_type, rr_class)

        with self.lock: # lock
            self.cache[key] = entry

    
    def put_chain(self,
                  question: DDT.a_question_S,
                  records: list[DDT.a_rr_S]
                  ) -> None:
        """
            save full answer chain

            e.g.
                client question: 
                    www.a.com A
                I records:
                    www.a.com CNAME real.b.com
                    real.b.com A 1.2.3.4

                cache key using:
                    (www.a.com, A, IN)
        """
        self.put(
            question.qname,
            question.qtype,
            question.qclass,
            records
        )

    def get_chain(self,
                  question: DDT.a_question_S
                  ) -> list[DDT.a_rr_S] | None:
        """ get answer in chain """
        return self.get(
            question.qname,
            question.qtype,
            question.qclass
        )
