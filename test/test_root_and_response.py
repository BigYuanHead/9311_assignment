from pathlib import Path
import tempfile
import unittest

from dns_test_utils import (
    RESOURCE_DIR,
    make_question,
    make_query,
    make_record
)

import dataStructures.dns_dataTypes as DDT
from src.helpers.flagOpt import dnsFlag_C as FO
from src.request_parser import dnsParser_C
from src.respond_builder import dnsResponseBuilder_C
from src.rootHints_parser import rootHints_C



class rootHintsTest_C(unittest.TestCase):

    def test_accepted_subset_and_file_order(self):
        text = """
; full line comment
$TTL 600
. IN 518400 NS A.ROOT.
. 518401 IN NS b.root.
A.ROOT. IN A 192.0.2.1
b.root. 3600 IN A 192.0.2.2 ; trailing comment
b.root. IN 3601 A 192.0.2.3
b.root. 3600 IN AAAA 2001:db8::1
"""

        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / 'named.root'
            filename.write_text(text)

            hints = rootHints_C(str(filename))
            hints.parse()

        ns_records = hints.get_rootNS_records()
        self.assertEqual(
            [record.rdata for record in ns_records],
            ['A.ROOT.', 'b.root.']
        )
        self.assertEqual(
            [record.ttl for record in ns_records],
            [518400, 518401]
        )

        a_records = hints.get_records_with_name('B.ROOT.')
        self.assertEqual(
            [record.rdata for record in a_records],
            ['192.0.2.2', '192.0.2.3']
        )
        self.assertEqual(
            [record.ttl for record in a_records],
            [3600, 3601]
        )

    def test_ttl_directive_is_used_when_record_ttl_is_omitted(self):
        text = """
$TTL 900
. IN NS a.root.
a.root. IN A 192.0.2.1
"""

        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / 'named.root'
            filename.write_text(text)

            hints = rootHints_C(str(filename))
            hints.parse()

        self.assertEqual(hints.ns_records[0].ttl, 900)
        self.assertEqual(hints.a_records[0].ttl, 900)

    def test_omitted_ttl_before_directive_defaults_to_zero(self):
        text = """
. IN NS a.root.
a.root. IN A 192.0.2.1
"""

        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / 'named.root'
            filename.write_text(text)

            hints = rootHints_C(str(filename))
            hints.parse()

        self.assertEqual(hints.ns_records[0].ttl, 0)
        self.assertEqual(hints.a_records[0].ttl, 0)

    def test_root_ns_local_result_contains_matching_additional_A(self):
        hints = rootHints_C(str(RESOURCE_DIR / 'named.root'))
        hints.parse()

        result = hints.find_local_result(make_question(
            '.',
            DDT.dnsType_ENUM.NS
        ))

        self.assertIsNotNone(result)
        self.assertEqual(len(result.answers), 13)
        self.assertEqual(len(result.additional), 13)
        self.assertEqual(result.aa, 0)

    def test_root_server_A_local_result_is_case_insensitive(self):
        hints = rootHints_C(str(RESOURCE_DIR / 'named.root'))
        hints.parse()
        root_name = hints.a_records[0].name

        result = hints.find_local_result(make_question(
            root_name.upper(),
            DDT.dnsType_ENUM.A
        ))

        self.assertIsNotNone(result)
        self.assertGreater(len(result.answers), 0)
        self.assertTrue(all(
            record.rr_type == DDT.dnsType_ENUM.A
            for record in result.answers
        ))


class responseBuilderTest_C(unittest.TestCase):

    def _request(self,
                 name='example.com.',
                 qtype=DDT.dnsType_ENUM.A,
                 txid=0x4321,
                 flags=0x0930):
        return dnsParser_C(data=make_query(
            name,
            qtype,
            txid=txid,
            flags=flags
        )).parse()

    def test_header_flags_and_counts(self):
        request = self._request()
        answers = [
            make_record(
                'example.com.',
                DDT.dnsType_ENUM.A,
                '192.0.2.1'
            )
        ]
        authority = [
            make_record(
                'example.com.',
                DDT.dnsType_ENUM.NS,
                'ns.example.com.'
            )
        ]
        additional = [
            make_record(
                'ns.example.com.',
                DDT.dnsType_ENUM.A,
                '192.0.2.53'
            )
        ]

        wire = dnsResponseBuilder_C().build_response(
            request,
            answers,
            authority,
            additional,
            rcode=DDT.flag_respondCode_ENUM.NXDOMAIN,
            aa=1
        )
        response = dnsParser_C(data=wire).parse()
        flags = FO.decode(response.header.flags)
        query_flags = FO.decode(request.header.flags)

        self.assertEqual(response.header.id, request.header.id)
        self.assertEqual(flags.QR, 1)
        self.assertEqual(flags.Opcode, query_flags.Opcode)
        self.assertEqual(flags.RD, query_flags.RD)
        self.assertEqual(flags.RA, 1)
        self.assertEqual(flags.AA, 1)
        self.assertEqual(flags.TC, 0)
        self.assertEqual(flags.Z, 0)
        self.assertEqual(flags.AD, 0)
        self.assertEqual(flags.CD, 0)
        self.assertEqual(
            flags.RCODE,
            DDT.flag_respondCode_ENUM.NXDOMAIN
        )
        self.assertEqual(response.header.qdCount, 1)
        self.assertEqual(response.header.anCount, 1)
        self.assertEqual(response.header.nsCount, 1)
        self.assertEqual(response.header.arCount, 1)

    def test_supported_record_types_round_trip(self):
        cases = [
            (
                DDT.dnsType_ENUM.A,
                '192.0.2.1'
            ),
            (
                DDT.dnsType_ENUM.NS,
                'ns.example.com.'
            ),
            (
                DDT.dnsType_ENUM.CNAME,
                'target.example.com.'
            ),
            (
                DDT.dnsType_ENUM.PTR,
                'host.example.com.'
            ),
            (
                DDT.dnsType_ENUM.MX,
                '10 mail.example.com.'
            )
        ]

        for rr_type, rdata in cases:
            with self.subTest(rr_type=rr_type):
                request = self._request(qtype=rr_type)
                record = make_record(
                    'example.com.',
                    rr_type,
                    rdata
                )
                wire = dnsResponseBuilder_C().build_response(
                    request,
                    [record],
                    [],
                    []
                )
                response = dnsParser_C(data=wire).parse()

                self.assertFalse(response.is_malformed)
                self.assertEqual(response.answers[0].rdata, rdata)

    def test_small_uncompressed_response_is_valid(self):
        request = self._request()
        record = make_record(
            'example.com.',
            DDT.dnsType_ENUM.A,
            '192.0.2.1'
        )
        wire = dnsResponseBuilder_C().build_response(
            request,
            [record],
            [],
            []
        )

        self.assertLessEqual(len(wire), 512)
        self.assertFalse(dnsParser_C(data=wire).parse().is_malformed)

    def test_root_ns_response_fits_non_EDNS_UDP_limit(self):
        hints = rootHints_C(str(RESOURCE_DIR / 'named.root'))
        hints.parse()
        request = dnsParser_C(data=make_query(
            '.',
            DDT.dnsType_ENUM.NS
        )).parse()
        result = hints.find_local_result(request.questions[0])

        wire = dnsResponseBuilder_C().build_response(
            request,
            result.answers,
            result.authority,
            result.additional,
            rcode=result.rcode,
            aa=result.aa
        )

        self.assertLessEqual(len(wire), 512)


if __name__ == '__main__':
    unittest.main()
