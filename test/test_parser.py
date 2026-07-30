from contextlib import redirect_stdout
import io
import struct
import unittest

from dns_test_utils import (
    RESOURCE_DIR,
    encode_name,
    make_rr_wire
)

import dataStructures.dns_dataTypes as DDT
from src.helpers.dnsDisplay import dnsDisplay_C
from src.request_parser import dnsParser_C



class dnsParserTest_C(unittest.TestCase):

    def _parse(self, data: bytes):
        output = io.StringIO()
        with redirect_stdout(output):
            result = dnsParser_C(data=data).parse()

        self.assertEqual(output.getvalue(), '')
        return result

    def _pointer_packet(self, jump_count: int) -> bytes:
        result = bytearray(struct.pack(
            '!HHHHHH',
            jump_count,
            0,
            1,
            0,
            0,
            0
        ))

        result.extend(b'\xc0\x14')
        result.extend(struct.pack('!HH', 1, 1))
        result.extend(b'\x00\x00')

        current_offset = 20
        for _ in range(jump_count - 1):
            target_offset = current_offset + 2
            result.extend(bytes([
                0xC0 | ((target_offset >> 8) & 0x3F),
                target_offset & 0xFF
            ]))
            current_offset = target_offset

        result.extend(b'\x00')
        return bytes(result)

    def test_assignment_resource_files(self):
        files = sorted(RESOURCE_DIR.glob('*.bin'))
        self.assertGreater(len(files), 0)

        for filename in files:
            with self.subTest(filename=filename.name):
                request = dnsParser_C(filename=str(filename)).parse()
                self.assertFalse(request.is_malformed)

    def test_multiple_questions_are_parsed_in_wire_order(self):
        packet = bytearray(struct.pack(
            '!HHHHHH',
            100,
            0,
            2,
            0,
            0,
            0
        ))
        packet.extend(encode_name('first.example.'))
        packet.extend(struct.pack('!HH', 1, 1))
        packet.extend(encode_name('second.example.'))
        packet.extend(struct.pack('!HH', 15, 1))

        request = self._parse(bytes(packet))

        self.assertFalse(request.is_malformed)
        self.assertEqual(
            [question.qname for question in request.questions],
            ['first.example.', 'second.example.']
        )
        self.assertEqual(
            [question.qtype for question in request.questions],
            [1, 15]
        )

    def test_supported_records_in_all_sections(self):
        question = encode_name('example.com.') + struct.pack('!HH', 1, 1)
        answer = make_rr_wire(
            'example.com.',
            DDT.dnsType_ENUM.A,
            b'\xc0\x00\x02\x01'
        )
        authority = make_rr_wire(
            'example.com.',
            DDT.dnsType_ENUM.NS,
            encode_name('ns.example.com.')
        )
        additional = make_rr_wire(
            'mail.example.com.',
            DDT.dnsType_ENUM.MX,
            struct.pack('!H', 10) + encode_name('mx.example.com.')
        )

        packet = struct.pack(
            '!HHHHHH',
            101,
            0x8000,
            1,
            1,
            1,
            1
        ) + question + answer + authority + additional

        request = self._parse(packet)

        self.assertFalse(request.is_malformed)
        self.assertEqual(request.answers[0].rdata, '192.0.2.1')
        self.assertEqual(
            request.authority[0].rdata,
            'ns.example.com.'
        )
        self.assertEqual(
            request.additional[0].rdata,
            '10 mx.example.com.'
        )

    def test_compressed_owner_and_rdata_names(self):
        question = encode_name('example.com.') + struct.pack('!HH', 2, 1)
        answer = b'\xc0\x0c' + struct.pack(
            '!HHIH',
            DDT.dnsType_ENUM.NS,
            1,
            60,
            2
        ) + b'\xc0\x0c'

        packet = struct.pack(
            '!HHHHHH',
            102,
            0x8400,
            1,
            1,
            0,
            0
        ) + question + answer

        request = self._parse(packet)

        self.assertFalse(request.is_malformed)
        self.assertEqual(request.answers[0].name, 'example.com.')
        self.assertEqual(request.answers[0].rdata, 'example.com.')

    def test_unknown_record_type_is_skipped_safely(self):
        packet = struct.pack(
            '!HHHHHH',
            103,
            0x8000,
            0,
            1,
            0,
            0
        )
        packet += make_rr_wire('.', 41, b'\x00\x01\x02\x03')

        request = self._parse(packet)

        self.assertFalse(request.is_malformed)
        self.assertEqual(request.answers[0].rr_type, 41)
        self.assertEqual(request.answers[0].rdata, 'RDLENGTH 4')

    def test_short_header_is_malformed_without_traceback(self):
        request = self._parse(b'\x00')
        self.assertTrue(request.is_malformed)

    def test_pointer_loop_is_malformed(self):
        packet = struct.pack(
            '!HHHHHH',
            104,
            0,
            1,
            0,
            0,
            0
        )
        packet += b'\xc0\x0c' + struct.pack('!HH', 1, 1)

        request = self._parse(packet)

        self.assertTrue(request.is_malformed)
        self.assertIn('pointer loop', request.malformed_reason)

    def test_pointer_jump_limit(self):
        accepted = self._parse(self._pointer_packet(20))
        rejected = self._parse(self._pointer_packet(21))

        self.assertFalse(accepted.is_malformed)
        self.assertTrue(rejected.is_malformed)
        self.assertIn('too many', rejected.malformed_reason)

    def test_wire_name_length_limit(self):
        labels_255 = [
            b'a' * 63,
            b'b' * 63,
            b'c' * 63,
            b'd' * 61
        ]
        labels_256 = [
            b'a' * 63,
            b'b' * 63,
            b'c' * 63,
            b'd' * 62
        ]

        def build_packet(labels):
            qname = b''.join(
                bytes([len(label)]) + label
                for label in labels
            ) + b'\x00'

            return struct.pack(
                '!HHHHHH',
                105,
                0,
                1,
                0,
                0,
                0
            ) + qname + struct.pack('!HH', 1, 1)

        accepted = self._parse(build_packet(labels_255))
        rejected = self._parse(build_packet(labels_256))

        self.assertFalse(accepted.is_malformed)
        self.assertTrue(rejected.is_malformed)
        self.assertIn('length > 255', rejected.malformed_reason)

    def test_invalid_supported_rdata_is_malformed(self):
        cases = [
            (
                DDT.dnsType_ENUM.A,
                b'\x01\x02\x03'
            ),
            (
                DDT.dnsType_ENUM.NS,
                b'\x00\xaa\xbb'
            ),
            (
                DDT.dnsType_ENUM.MX,
                struct.pack('!H', 10) + b'\x00\xaa'
            )
        ]

        for rr_type, rdata in cases:
            with self.subTest(rr_type=rr_type):
                packet = struct.pack(
                    '!HHHHHH',
                    106,
                    0x8000,
                    0,
                    1,
                    0,
                    0
                )
                packet += make_rr_wire('.', rr_type, rdata)

                request = self._parse(packet)
                self.assertTrue(request.is_malformed)

    def test_display_contains_all_required_sections(self):
        request = self._parse(struct.pack(
            '!HHHHHH',
            107,
            0x8009,
            0,
            0,
            0,
            0
        ))

        output = io.StringIO()
        with redirect_stdout(output):
            dnsDisplay_C(request).display()

        text = output.getvalue()
        self.assertIn('ID: 107', text)
        self.assertIn('RCODE: 9', text)
        self.assertIn('--- FLAGS ---', text)
        self.assertIn('--- COUNTS ---', text)
        self.assertIn('--- QUESTIONS ---', text)
        self.assertIn('--- ANSWERS ---', text)
        self.assertIn('--- AUTHORITY ---', text)
        self.assertIn('--- ADDITIONAL ---', text)


if __name__ == '__main__':
    unittest.main()

