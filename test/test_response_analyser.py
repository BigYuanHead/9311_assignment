import unittest

from dns_test_utils import (
    make_question,
    make_record,
    make_response
)

import dataStructures.dns_dataTypes as DDT
from src.iterOpt.response_analyser import responseAnalyser_C



class responseAnalyserTest_C(unittest.TestCase):

    def setUp(self):
        self.analyser = responseAnalyser_C(10)

    def test_direct_answer_is_final(self):
        question = make_question()
        answer = make_record(
            question.qname,
            question.qtype,
            '192.0.2.1'
        )
        response = make_response(
            question,
            answers=[answer],
            aa=1
        )

        path = self.analyser.find_answer_path(
            response,
            question,
            0,
            {question.qname.lower()}
        )

        self.assertTrue(path.is_final)
        self.assertEqual(path.records, [answer])
        self.assertIsNone(path.next_name)

    def test_same_response_CNAME_chain_reaches_final_answer(self):
        question = make_question('alias.example.')
        first = make_record(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME,
            'middle.example.'
        )
        second = make_record(
            'middle.example.',
            DDT.dnsType_ENUM.CNAME,
            'target.example.'
        )
        final_A = make_record(
            'target.example.',
            DDT.dnsType_ENUM.A,
            '192.0.2.1'
        )
        response = make_response(
            question,
            answers=[first, second, final_A],
            aa=1
        )

        path = self.analyser.find_answer_path(
            response,
            question,
            0,
            {question.qname.lower()}
        )

        self.assertTrue(path.is_final)
        self.assertEqual(path.records, [first, second, final_A])

    def test_incomplete_CNAME_chain_returns_next_name(self):
        question = make_question('alias.example.')
        cname = make_record(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME,
            'target.example.'
        )
        response = make_response(
            question,
            answers=[cname],
            aa=1
        )

        path = self.analyser.find_answer_path(
            response,
            question,
            0,
            {question.qname.lower()}
        )

        self.assertFalse(path.is_final)
        self.assertEqual(path.records, [cname])
        self.assertEqual(path.next_name, 'target.example.')

    def test_direct_CNAME_query_does_not_chase_target(self):
        question = make_question(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME
        )
        cname = make_record(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME,
            'target.example.'
        )
        unrelated_target = make_record(
            'target.example.',
            DDT.dnsType_ENUM.CNAME,
            'another.example.'
        )
        response = make_response(
            question,
            answers=[cname, unrelated_target],
            aa=1
        )

        path = self.analyser.find_answer_path(
            response,
            question,
            0,
            {question.qname.lower()}
        )

        self.assertTrue(path.is_final)
        self.assertEqual(path.records, [cname])

    def test_CNAME_loop_is_invalid(self):
        question = make_question('a.example.')
        response = make_response(
            question,
            answers=[
                make_record(
                    'a.example.',
                    DDT.dnsType_ENUM.CNAME,
                    'b.example.'
                ),
                make_record(
                    'b.example.',
                    DDT.dnsType_ENUM.CNAME,
                    'a.example.'
                )
            ],
            aa=1
        )

        path = self.analyser.find_answer_path(
            response,
            question,
            0,
            {'a.example.'}
        )

        self.assertFalse(path.is_final)
        self.assertIn('loop', path.invalid_reason)

    def test_CNAME_limit_allows_10_and_rejects_11(self):
        question = make_question('name0.example.')
        ten_records = []

        for index in range(10):
            ten_records.append(make_record(
                'name{}.example.'.format(index),
                DDT.dnsType_ENUM.CNAME,
                'name{}.example.'.format(index + 1)
            ))

        response_10 = make_response(
            question,
            answers=ten_records,
            aa=1
        )
        path_10 = self.analyser.find_answer_path(
            response_10,
            question,
            0,
            {question.qname.lower()}
        )

        response_11 = make_response(
            question,
            answers=ten_records + [
                make_record(
                    'name10.example.',
                    DDT.dnsType_ENUM.CNAME,
                    'name11.example.'
                )
            ],
            aa=1
        )
        path_11 = self.analyser.find_answer_path(
            response_11,
            question,
            0,
            {question.qname.lower()}
        )

        self.assertIsNone(path_10.invalid_reason)
        self.assertEqual(len(path_10.records), 10)
        self.assertEqual(path_10.next_name, 'name10.example.')
        self.assertIn('depth', path_11.invalid_reason)

    def test_authoritative_NODATA(self):
        question = make_question()
        authoritative = make_response(question, aa=1)
        non_authoritative = make_response(question, aa=0)

        self.assertTrue(
            self.analyser.is_authoritative_nodata(
                authoritative,
                question
            )
        )
        self.assertFalse(
            self.analyser.is_authoritative_nodata(
                non_authoritative,
                question
            )
        )

    def test_referral_lower_zone_and_glue_wire_order(self):
        question = make_question('www.example.com.')
        response = make_response(
            question,
            authority=[
                make_record(
                    'unrelated.net.',
                    DDT.dnsType_ENUM.NS,
                    'ns.unrelated.net.'
                ),
                make_record(
                    'com.',
                    DDT.dnsType_ENUM.NS,
                    'first.gtld.example.'
                ),
                make_record(
                    'example.com.',
                    DDT.dnsType_ENUM.NS,
                    'ns.example.com.'
                )
            ],
            additional=[
                make_record(
                    'ns.unrelated.net.',
                    DDT.dnsType_ENUM.A,
                    '192.0.2.1'
                ),
                make_record(
                    'first.gtld.example.',
                    DDT.dnsType_ENUM.A,
                    '192.0.2.2'
                ),
                make_record(
                    'unrelated-additional.example.',
                    DDT.dnsType_ENUM.A,
                    '192.0.2.3'
                ),
                make_record(
                    'ns.example.com.',
                    DDT.dnsType_ENUM.A,
                    '192.0.2.4'
                )
            ],
            aa=0
        )

        referral = self.analyser.find_referral(response, question)

        self.assertIsNotNone(referral)
        self.assertEqual(
            referral.ns_names,
            ['first.gtld.example.', 'ns.example.com.']
        )
        self.assertEqual(
            referral.glue_ips,
            ['192.0.2.2', '192.0.2.4']
        )

    def test_authoritative_NS_is_not_referral(self):
        question = make_question('www.example.com.')
        response = make_response(
            question,
            authority=[
                make_record(
                    'example.com.',
                    DDT.dnsType_ENUM.NS,
                    'ns.example.com.'
                )
            ],
            aa=1
        )

        self.assertIsNone(
            self.analyser.find_referral(response, question)
        )


if __name__ == '__main__':
    unittest.main()

