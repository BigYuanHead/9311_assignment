import struct
import sys
import threading
import time
import unittest
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

import dataStructures.dns_dataTypes as DDT

from src import caching
from src.dns_resolver import resolver_C
from src.helpers.flagOpt import dnsFlag_C as FO
from src.msg_parser import dnsParser_C
from src.respond_builder import dnsResponseBuilder_C



def make_query(txid: int,
               qname: str = 'example.com.',
               qtype: int = DDT.dnsType_ENUM.A
               ) -> bytes:
    result = bytearray()
    result.extend(struct.pack(
        '!HHHHHH',
        txid,
        0x0100,
        1,
        0,
        0,
        0
    ))

    for label in qname.rstrip('.').split('.'):
        label_bytes = label.encode('ascii')
        result.append(len(label_bytes))
        result.extend(label_bytes)

    result.append(0)
    result.extend(struct.pack(
        '!HH',
        qtype,
        DDT.dnsClass_ENUM.IN
    ))
    return bytes(result)



class fakeServerSocket_C:

    def __init__(self, received_queries=None):
        self.received_queries = list(received_queries or [])
        self.sent_responses = []
        self.lock = threading.Lock()

    def recvfrom(self, size):
        with self.lock:
            if len(self.received_queries) == 0:
                raise StopIteration()

            return self.received_queries.pop(0)

    def sendto(self, data, address):
        with self.lock:
            self.sent_responses.append((data, address))



class resolverConcurrencyTest_C(unittest.TestCase):

    def test_slow_query_does_not_block_another_client(self):
        slow_address = ('127.0.0.1', 50001)
        fast_address = ('127.0.0.1', 50002)

        resolver = resolver_C.__new__(resolver_C)
        resolver.sock = fakeServerSocket_C([
            (b'slow', slow_address),
            (b'fast', fast_address)
        ])

        slow_started = threading.Event()
        fast_started = threading.Event()
        release_slow = threading.Event()
        server_finished = threading.Event()

        def handle_query(query_data):
            if query_data == b'slow':
                slow_started.set()
                release_slow.wait(1)
            else:
                fast_started.set()

            return b'response-' + query_data

        resolver._handle_query = handle_query

        def run_server():
            try:
                resolver.start()
            except StopIteration:
                pass
            finally:
                server_finished.set()

        server_thread = threading.Thread(target=run_server)
        server_thread.start()

        try:
            self.assertTrue(slow_started.wait(0.5))
            self.assertTrue(fast_started.wait(0.5))
            self.assertTrue(server_finished.wait(0.5))
        finally:
            release_slow.set()
            server_thread.join(1)

        deadline = time.time() + 1
        while len(resolver.sock.sent_responses) < 2:
            if time.time() >= deadline:
                break
            time.sleep(0.01)

        self.assertIn(
            (b'response-slow', slow_address),
            resolver.sock.sent_responses
        )
        self.assertIn(
            (b'response-fast', fast_address),
            resolver.sock.sent_responses
        )

    def test_worker_exception_only_fails_that_client(self):
        client_address = ('127.0.0.1', 50003)
        query_data = make_query(0x1234)

        resolver = resolver_C.__new__(resolver_C)
        resolver.sock = fakeServerSocket_C()
        resolver.response_builder = dnsResponseBuilder_C()

        def fail_query(data):
            raise RuntimeError('test failure')

        resolver._handle_query = fail_query
        resolver._handle_client(query_data, client_address)

        self.assertEqual(len(resolver.sock.sent_responses), 1)
        response_data, response_address = resolver.sock.sent_responses[0]
        response = dnsParser_C(data=response_data).parse()

        self.assertEqual(response_address, client_address)
        self.assertEqual(response.header.id, 0x1234)
        self.assertEqual(
            FO.get_rcode(response.header.flags),
            DDT.flag_respondCode_ENUM.SERVFAIL
        )



class cacheConcurrencyTest_C(unittest.TestCase):

    def test_shared_cache_is_safe_for_concurrent_workers(self):
        cache = caching.dnsCache_C()
        question = DDT.a_question_S(
            'cache.example.',
            DDT.dnsType_ENUM.A,
            DDT.dnsClass_ENUM.IN
        )

        start_workers = threading.Barrier(9)
        errors = []

        def use_cache(worker_id):
            try:
                record = DDT.a_rr_S(
                    name=question.qname,
                    rr_type=question.qtype,
                    rr_class=question.qclass,
                    ttl=60,
                    rdata='192.0.2.{}'.format(worker_id + 1)
                )

                start_workers.wait()

                for _ in range(100):
                    cache.put_chain(question, [record])
                    records = cache.get_chain(question)

                    if records is None or len(records) != 1:
                        raise AssertionError('invalid cache result')
            except Exception as e:
                errors.append(e)

        workers = []
        for worker_id in range(8):
            worker = threading.Thread(
                target=use_cache,
                args=(worker_id,)
            )
            workers.append(worker)
            worker.start()

        start_workers.wait()

        for worker in workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())

        self.assertEqual(errors, [])
        self.assertIsNotNone(cache.get_chain(question))



if __name__ == '__main__':
    unittest.main()
