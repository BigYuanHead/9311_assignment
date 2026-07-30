import unittest
from unittest.mock import patch

from dns_test_utils import make_question, make_record

import dataStructures.dns_dataTypes as DDT
from src.caching import dnsCache_C



class dnsCacheTest_C(unittest.TestCase):

    def test_key_is_case_insensitive_and_fully_qualified(self):
        cache = dnsCache_C()
        question = make_question('Example.COM.')
        record = make_record(
            'Example.COM.',
            DDT.dnsType_ENUM.A,
            '192.0.2.1',
            ttl=60
        )

        with patch(
            'src.caching.time.time',
            side_effect=[100.0, 101.0]
        ):
            cache.put_chain(question, [record])
            result = cache.get_chain(make_question('example.com'))

        self.assertIsNotNone(result)
        self.assertEqual(result[0].rdata, '192.0.2.1')

    def test_returned_ttl_is_floored(self):
        cache = dnsCache_C()
        question = make_question()
        record = make_record(
            question.qname,
            question.qtype,
            '192.0.2.1',
            ttl=10
        )

        with patch(
            'src.caching.time.time',
            side_effect=[100.0, 102.2]
        ):
            cache.put_chain(question, [record])
            result = cache.get_chain(question)

        self.assertEqual(result[0].ttl, 7)

    def test_expired_entry_is_removed(self):
        cache = dnsCache_C()
        question = make_question()
        record = make_record(
            question.qname,
            question.qtype,
            '192.0.2.1',
            ttl=2
        )

        with patch(
            'src.caching.time.time',
            side_effect=[100.0, 102.0]
        ):
            cache.put_chain(question, [record])
            result = cache.get_chain(question)

        self.assertIsNone(result)
        self.assertEqual(cache.cache, {})

    def test_ttl_zero_chain_is_not_cached(self):
        cache = dnsCache_C()
        question = make_question()
        record = make_record(
            question.qname,
            question.qtype,
            '192.0.2.1',
            ttl=0
        )

        with patch('src.caching.time.time', return_value=100.0):
            cache.put_chain(question, [record])

        self.assertIsNone(cache.get_chain(question))

    def test_one_expired_CNAME_link_invalidates_full_chain(self):
        cache = dnsCache_C()
        question = make_question('alias.example.')
        cname = make_record(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME,
            'target.example.',
            ttl=1
        )
        final_A = make_record(
            'target.example.',
            DDT.dnsType_ENUM.A,
            '192.0.2.1',
            ttl=60
        )

        with patch(
            'src.caching.time.time',
            side_effect=[100.0, 102.0]
        ):
            cache.put_chain(question, [cname, final_A])
            result = cache.get_chain(question)

        self.assertIsNone(result)

    def test_cache_stores_and_returns_record_copies(self):
        cache = dnsCache_C()
        question = make_question()
        record = make_record(
            question.qname,
            question.qtype,
            '192.0.2.1',
            ttl=60
        )

        with patch(
            'src.caching.time.time',
            side_effect=[100.0, 101.0, 102.0]
        ):
            cache.put_chain(question, [record])
            record.rdata = '203.0.113.1'
            first = cache.get_chain(question)
            first[0].rdata = '203.0.113.2'
            second = cache.get_chain(question)

        self.assertEqual(second[0].rdata, '192.0.2.1')


if __name__ == '__main__':
    unittest.main()

