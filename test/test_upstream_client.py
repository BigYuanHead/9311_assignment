import socket
import struct
import unittest
from unittest.mock import patch

from dns_test_utils import (
    make_question,
    make_query,
    make_response_wire
)

import dataStructures.dns_dataTypes as DDT
import src.iterOpt.upstream_client as UC
from src.helpers.flagOpt import dnsFlag_C as FO
from src.iterOpt.upstreamQuery_builder import upstreamQueryBuilder_C
from src.request_parser import dnsParser_C



class fakeSocket_C:

    def __init__(self, events):
        self.events = list(events)
        self.timeouts = []
        self.sent = []
        self.recv_counter = 0
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendto(self, data, address):
        self.sent.append((data, address))

    def recvfrom(self, size):
        self.recv_counter = self.recv_counter + 1
        event = self.events.pop(0)

        if isinstance(event, Exception):
            raise event

        return event

    def close(self):
        self.closed = True



class upstreamQueryBuilderTest_C(unittest.TestCase):

    def test_query_header_and_question(self):
        builder = upstreamQueryBuilder_C()
        builder._make_txid = lambda: 0x4321

        txid, wire = builder.build_query(
            'www.example.',
            DDT.dnsType_ENUM.MX,
            DDT.dnsClass_ENUM.IN
        )
        request = dnsParser_C(data=wire).parse()
        flags = FO.decode(request.header.flags)

        self.assertEqual(txid, 0x4321)
        self.assertEqual(request.header.id, 0x4321)
        self.assertEqual(flags.QR, 0)
        self.assertEqual(flags.Opcode, 0)
        self.assertEqual(flags.AA, 0)
        self.assertEqual(flags.TC, 0)
        self.assertEqual(flags.RD, 0)
        self.assertEqual(flags.RA, 0)
        self.assertEqual(flags.RCODE, 0)
        self.assertEqual(request.header.qdCount, 1)
        self.assertEqual(request.header.anCount, 0)
        self.assertEqual(request.header.nsCount, 0)
        self.assertEqual(request.header.arCount, 0)
        self.assertEqual(request.questions[0].qname, 'www.example.')
        self.assertEqual(
            request.questions[0].qtype,
            DDT.dnsType_ENUM.MX
        )


class upstreamClientTest_C(unittest.TestCase):

    SERVER_IP = '192.0.2.53'
    TXID = 0x1234

    def setUp(self):
        self.question = make_question()

    def _ask(self, events, monotonic_values=None):
        fake_socket = fakeSocket_C(events)
        client = UC.upstreamClient_C()
        client.query_builder._make_txid = lambda: self.TXID

        with patch.object(
            UC.socket,
            'socket',
            return_value=fake_socket
        ):
            if monotonic_values is None:
                result = client.ask(
                    self.SERVER_IP,
                    self.question,
                    1
                )
            else:
                with patch.object(
                    UC.time,
                    'monotonic',
                    side_effect=monotonic_values
                ):
                    result = client.ask(
                        self.SERVER_IP,
                        self.question,
                        1
                    )

        return result, fake_socket

    def test_unmatched_datagrams_are_ignored_until_match(self):
        valid = make_response_wire(
            self.question,
            txid=self.TXID
        )
        wrong_txid = make_response_wire(
            self.question,
            txid=0x9999
        )
        wrong_qname = make_response_wire(
            make_question('other.example.'),
            txid=self.TXID
        )
        wrong_qtype = make_response_wire(
            make_question(
                self.question.qname,
                DDT.dnsType_ENUM.NS
            ),
            txid=self.TXID
        )
        wrong_qclass = make_response_wire(
            make_question(
                self.question.qname,
                self.question.qtype,
                2
            ),
            txid=self.TXID
        )

        events = [
            (valid, ('198.51.100.1', 53)),
            (valid, (self.SERVER_IP, 5300)),
            (wrong_txid, (self.SERVER_IP, 53)),
            (wrong_qname, (self.SERVER_IP, 53)),
            (wrong_qtype, (self.SERVER_IP, 53)),
            (wrong_qclass, (self.SERVER_IP, 53)),
            (valid, (self.SERVER_IP, 53))
        ]

        result, fake_socket = self._ask(
            events,
            monotonic_values=[
                100.0,
                100.1,
                100.2,
                100.3,
                100.4,
                100.5,
                100.6,
                100.7
            ]
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.header.id, self.TXID)
        self.assertEqual(fake_socket.recv_counter, 7)
        self.assertEqual(len(fake_socket.timeouts), 7)
        self.assertTrue(all(
            fake_socket.timeouts[index]
            > fake_socket.timeouts[index + 1]
            for index in range(len(fake_socket.timeouts) - 1)
        ))
        self.assertTrue(fake_socket.closed)

    def test_matching_truncated_response_fails_candidate(self):
        valid = bytearray(make_response_wire(
            self.question,
            txid=self.TXID
        ))
        flags = struct.unpack('!H', valid[2:4])[0]
        valid[2:4] = struct.pack('!H', flags | 0x0200)

        result, fake_socket = self._ask([
            (bytes(valid), (self.SERVER_IP, 53)),
            (
                make_response_wire(
                    self.question,
                    txid=self.TXID
                ),
                (self.SERVER_IP, 53)
            )
        ])

        self.assertIsNone(result)
        self.assertEqual(fake_socket.recv_counter, 1)

    def test_matching_malformed_response_fails_candidate(self):
        malformed = struct.pack(
            '!HHHHHH',
            self.TXID,
            0x8000,
            1,
            0,
            0,
            0
        )

        result, fake_socket = self._ask([
            (malformed, (self.SERVER_IP, 53)),
            (
                make_response_wire(
                    self.question,
                    txid=self.TXID
                ),
                (self.SERVER_IP, 53)
            )
        ])

        self.assertIsNone(result)
        self.assertEqual(fake_socket.recv_counter, 1)

    def test_matching_invalid_question_count_fails_candidate(self):
        packet = struct.pack(
            '!HHHHHH',
            self.TXID,
            0x8000,
            2,
            0,
            0,
            0
        )
        first_question = make_query(
            self.question.qname,
            self.question.qtype
        )[12:]
        second_question = make_query(
            'other.example.',
            self.question.qtype
        )[12:]
        packet += first_question + second_question

        result, fake_socket = self._ask([
            (packet, (self.SERVER_IP, 53))
        ])

        self.assertIsNone(result)
        self.assertEqual(fake_socket.recv_counter, 1)

    def test_error_RCODE_is_returned_to_iterative_layer(self):
        packet = make_response_wire(
            self.question,
            rcode=DDT.flag_respondCode_ENUM.SERVFAIL,
            txid=self.TXID
        )

        result, _ = self._ask([
            (packet, (self.SERVER_IP, 53))
        ])

        self.assertIsNotNone(result)
        self.assertEqual(
            FO.get_rcode(result.header.flags),
            DDT.flag_respondCode_ENUM.SERVFAIL
        )

    def test_socket_timeout_fails_candidate(self):
        result, fake_socket = self._ask([
            socket.timeout()
        ])

        self.assertIsNone(result)
        self.assertTrue(fake_socket.closed)


if __name__ == '__main__':
    unittest.main()

