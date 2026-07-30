import unittest
from unittest.mock import patch

from dns_test_utils import (
    RESOURCE_DIR,
    make_query,
    make_record
)

import dataStructures.dns_dataTypes as DDT
from src import caching
from src.dns_resolver import resolver_C
from src.helpers.flagOpt import dnsFlag_C as FO
from src.request_parser import dnsParser_C
from src.respond_builder import dnsResponseBuilder_C
from src.rootHints_parser import rootHints_C



class failIfCalled_C:

    def __getattr__(self, name):
        raise AssertionError('{} should not be called'.format(name))


class iterativeStub_C:

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def resolve(self, question):
        self.calls.append(question)
        return self.results.pop(0)


class noLocalRoot_C:

    def find_local_result(self, question):
        return None


class fakeServerSocket_C:

    def __init__(self, query_data):
        self.query_data = query_data
        self.received = False
        self.sent = []

    def recvfrom(self, size):
        if self.received:
            raise StopIteration()

        self.received = True
        return self.query_data, ('127.0.0.1', 50000)

    def sendto(self, data, address):
        self.sent.append((data, address))


class bindSocket_C:

    def __init__(self):
        self.bound_address = None

    def bind(self, address):
        self.bound_address = address



class resolverDispatchTest_C(unittest.TestCase):

    def _resolver_without_socket(self):
        resolver = resolver_C.__new__(resolver_C)
        resolver.response_builder = dnsResponseBuilder_C()
        return resolver

    def _parse(self, data):
        return dnsParser_C(data=data).parse()

    def test_resolver_binds_to_loopback_address(self):
        fake_socket = bindSocket_C()

        with patch(
            'src.dns_resolver.socket.socket',
            return_value=fake_socket
        ):
            resolver = resolver_C(
                str(RESOURCE_DIR / 'named.root'),
                1,
                55000
            )

        self.assertEqual(
            fake_socket.bound_address,
            ('127.0.0.1', 55000)
        )
        self.assertEqual(resolver.timeout, 1)

    def test_root_local_answer_bypasses_cache_and_iterative(self):
        resolver = self._resolver_without_socket()
        resolver.root_hints = rootHints_C(
            str(RESOURCE_DIR / 'named.root')
        )
        resolver.root_hints.parse()
        resolver.cache = failIfCalled_C()
        resolver.iterative_resolver = failIfCalled_C()

        response = self._parse(resolver._handle_query(make_query(
            '.',
            DDT.dnsType_ENUM.NS
        )))

        self.assertEqual(response.header.anCount, 13)
        self.assertEqual(response.header.arCount, 13)
        self.assertEqual(FO.decode(response.header.flags).AA, 0)

    def test_unsupported_query_type_returns_SERVFAIL(self):
        resolver = self._resolver_without_socket()
        resolver.root_hints = failIfCalled_C()
        resolver.cache = failIfCalled_C()
        resolver.iterative_resolver = failIfCalled_C()

        response = self._parse(resolver._handle_query(make_query(
            'example.com.',
            28
        )))

        self.assertEqual(
            FO.get_rcode(response.header.flags),
            DDT.flag_respondCode_ENUM.SERVFAIL
        )
        self.assertEqual(response.questions[0].qtype, 28)

    def test_malformed_query_returns_SERVFAIL(self):
        resolver = self._resolver_without_socket()

        response = self._parse(resolver._handle_query(b'\x00'))

        self.assertEqual(
            FO.get_rcode(response.header.flags),
            DDT.flag_respondCode_ENUM.SERVFAIL
        )

    def test_cache_miss_then_repeated_query_uses_cache(self):
        resolver = self._resolver_without_socket()
        resolver.root_hints = noLocalRoot_C()
        resolver.cache = caching.dnsCache_C()
        answer = make_record(
            'cached.example.',
            DDT.dnsType_ENUM.A,
            '192.0.2.80',
            ttl=60
        )
        resolver.iterative_resolver = iterativeStub_C([
            DDT.resolutionResult_S(
                [answer],
                [],
                [],
                DDT.flag_respondCode_ENUM.NOERROR,
                aa=1
            )
        ])

        with patch(
            'src.caching.time.time',
            side_effect=[100.0, 101.0]
        ):
            first = self._parse(resolver._handle_query(make_query(
                'cached.example.',
                DDT.dnsType_ENUM.A,
                txid=100
            )))
            second = self._parse(resolver._handle_query(make_query(
                'CACHED.EXAMPLE.',
                DDT.dnsType_ENUM.A,
                txid=101
            )))

        self.assertEqual(len(resolver.iterative_resolver.calls), 1)
        self.assertEqual(first.header.id, 100)
        self.assertEqual(second.header.id, 101)
        self.assertEqual(FO.decode(first.header.flags).AA, 1)
        self.assertEqual(FO.decode(second.header.flags).AA, 0)
        self.assertEqual(second.answers[0].rdata, '192.0.2.80')

    def test_TTL_zero_positive_result_is_not_reused(self):
        resolver = self._resolver_without_socket()
        resolver.root_hints = noLocalRoot_C()
        resolver.cache = caching.dnsCache_C()
        answer = make_record(
            'zero.example.',
            DDT.dnsType_ENUM.A,
            '192.0.2.80',
            ttl=0
        )
        result = DDT.resolutionResult_S(
            [answer],
            [],
            [],
            DDT.flag_respondCode_ENUM.NOERROR,
            aa=1
        )
        resolver.iterative_resolver = iterativeStub_C([
            result,
            result
        ])

        resolver._handle_query(make_query(
            'zero.example.',
            DDT.dnsType_ENUM.A,
            txid=200
        ))
        resolver._handle_query(make_query(
            'zero.example.',
            DDT.dnsType_ENUM.A,
            txid=201
        ))

        self.assertEqual(len(resolver.iterative_resolver.calls), 2)

    def test_iterative_AA_reaches_client_response(self):
        resolver = self._resolver_without_socket()
        resolver.root_hints = noLocalRoot_C()
        resolver.cache = caching.dnsCache_C()
        answer = make_record(
            'direct.example.',
            DDT.dnsType_ENUM.A,
            '192.0.2.80'
        )
        resolver.iterative_resolver = iterativeStub_C([
            DDT.resolutionResult_S(
                [answer],
                [],
                [],
                DDT.flag_respondCode_ENUM.NOERROR,
                aa=1
            )
        ])

        response = self._parse(resolver._handle_query(make_query(
            'direct.example.',
            DDT.dnsType_ENUM.A
        )))

        self.assertEqual(FO.decode(response.header.flags).AA, 1)

    def test_request_exception_isolated_as_SERVFAIL(self):
        query_data = make_query(
            'example.com.',
            DDT.dnsType_ENUM.A
        )
        resolver = self._resolver_without_socket()
        resolver.sock = fakeServerSocket_C(query_data)

        def fail_query(data):
            raise RuntimeError('test failure')

        resolver._handle_query = fail_query

        with self.assertRaises(StopIteration):
            resolver.start()

        self.assertEqual(len(resolver.sock.sent), 1)
        response = self._parse(resolver.sock.sent[0][0])
        self.assertEqual(
            FO.get_rcode(response.header.flags),
            DDT.flag_respondCode_ENUM.SERVFAIL
        )
        self.assertEqual(response.questions[0].qname, 'example.com.')


if __name__ == '__main__':
    unittest.main()
