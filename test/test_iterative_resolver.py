import io
import unittest
from contextlib import redirect_stdout

from dns_test_utils import (
    make_question,
    make_record,
    make_response,
    rootHintsStub_C,
    upstreamSequence_C
)

import dataStructures.dns_dataTypes as DDT
from src.iterative_resolver import iterativeResolver_C



class iterativeResolverTest_C(unittest.TestCase):

    def _resolve(self, resolver, question):
        with redirect_stdout(io.StringIO()):
            return resolver.resolve(question)

    def test_candidates_are_tried_in_root_file_order(self):
        question = make_question()
        answer = make_record(
            question.qname,
            question.qtype,
            '192.0.2.80'
        )
        client = upstreamSequence_C([
            None,
            make_response(question, answers=[answer], aa=1)
        ])
        resolver = iterativeResolver_C(
            rootHintsStub_C(['198.41.0.1', '198.41.0.2']),
            1
        )
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.rcode, 0)
        self.assertEqual(result.answers, [answer])
        self.assertEqual(
            [call[0] for call in client.calls],
            ['198.41.0.1', '198.41.0.2']
        )

    def test_referral_with_glue(self):
        question = make_question('www.example.com.')
        referral = make_response(
            question,
            authority=[
                make_record(
                    'com.',
                    DDT.dnsType_ENUM.NS,
                    'ns.com.'
                )
            ],
            additional=[
                make_record(
                    'ns.com.',
                    DDT.dnsType_ENUM.A,
                    '192.0.2.53'
                )
            ]
        )
        final_A = make_record(
            question.qname,
            DDT.dnsType_ENUM.A,
            '192.0.2.80'
        )
        client = upstreamSequence_C([
            referral,
            make_response(
                question,
                answers=[final_A],
                aa=1
            )
        ])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers, [final_A])
        self.assertEqual(
            [call[0] for call in client.calls],
            ['198.41.0.4', '192.0.2.53']
        )

    def test_referral_without_glue_starts_nested_A_lookup_from_root(self):
        question = make_question('www.example.com.')

        def route(server_ip, current_question, timeout):
            if current_question.qname == 'www.example.com.':
                if server_ip == '198.41.0.4':
                    return make_response(
                        current_question,
                        authority=[
                            make_record(
                                'example.com.',
                                DDT.dnsType_ENUM.NS,
                                'ns.example.com.'
                            )
                        ]
                    )

                return make_response(
                    current_question,
                    answers=[
                        make_record(
                            current_question.qname,
                            DDT.dnsType_ENUM.A,
                            '192.0.2.80'
                        )
                    ],
                    aa=1
                )

            return make_response(
                current_question,
                answers=[
                    make_record(
                        'ns.example.com.',
                        DDT.dnsType_ENUM.A,
                        '192.0.2.53'
                    )
                ],
                aa=1
            )

        client = upstreamSequence_C([route, route, route])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers[-1].rdata, '192.0.2.80')
        self.assertEqual(
            [
                (call[0], call[1], call[2])
                for call in client.calls
            ],
            [
                ('198.41.0.4', 'www.example.com.', 1),
                ('198.41.0.4', 'ns.example.com.', 1),
                ('192.0.2.53', 'www.example.com.', 1)
            ]
        )

    def test_same_response_CNAME_chain_keeps_authoritative_AA(self):
        question = make_question('alias.example.')
        cname = make_record(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME,
            'target.example.'
        )
        final_A = make_record(
            'target.example.',
            DDT.dnsType_ENUM.A,
            '192.0.2.80'
        )
        client = upstreamSequence_C([
            make_response(
                question,
                answers=[cname, final_A],
                aa=1
            )
        ])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers, [cname, final_A])
        self.assertEqual(result.aa, 1)
        self.assertEqual(len(client.calls), 1)

    def test_cross_response_CNAME_chain_has_AA_zero(self):
        question = make_question('alias.example.')
        cname = make_record(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME,
            'target.example.'
        )
        final_A = make_record(
            'target.example.',
            DDT.dnsType_ENUM.A,
            '192.0.2.80'
        )

        def first(server_ip, current_question, timeout):
            return make_response(
                current_question,
                answers=[cname],
                aa=1
            )

        def second(server_ip, current_question, timeout):
            return make_response(
                current_question,
                answers=[final_A],
                aa=1
            )

        client = upstreamSequence_C([first, second])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers, [cname, final_A])
        self.assertEqual(result.aa, 0)
        self.assertEqual(
            [call[1] for call in client.calls],
            ['alias.example.', 'target.example.']
        )

    def test_direct_CNAME_query_does_not_chase(self):
        question = make_question(
            'alias.example.',
            DDT.dnsType_ENUM.CNAME
        )
        cname = make_record(
            question.qname,
            DDT.dnsType_ENUM.CNAME,
            'target.example.'
        )
        client = upstreamSequence_C([
            make_response(
                question,
                answers=[cname],
                aa=1
            )
        ])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers, [cname])
        self.assertEqual(len(client.calls), 1)

    def test_authoritative_NXDOMAIN_is_terminal(self):
        question = make_question()
        client = upstreamSequence_C([
            make_response(
                question,
                aa=1,
                rcode=DDT.flag_respondCode_ENUM.NXDOMAIN
            )
        ])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(
            result.rcode,
            DDT.flag_respondCode_ENUM.NXDOMAIN
        )
        self.assertEqual(result.aa, 1)
        self.assertEqual(len(client.calls), 1)

    def test_non_authoritative_NXDOMAIN_tries_next_candidate(self):
        question = make_question()
        answer = make_record(
            question.qname,
            question.qtype,
            '192.0.2.80'
        )
        client = upstreamSequence_C([
            make_response(
                question,
                aa=0,
                rcode=DDT.flag_respondCode_ENUM.NXDOMAIN
            ),
            make_response(
                question,
                answers=[answer],
                aa=1
            )
        ])
        resolver = iterativeResolver_C(
            rootHintsStub_C(['198.41.0.1', '198.41.0.2']),
            1
        )
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers, [answer])
        self.assertEqual(len(client.calls), 2)

    def test_authoritative_NODATA_is_terminal(self):
        question = make_question()
        client = upstreamSequence_C([
            make_response(question, aa=1)
        ])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.rcode, 0)
        self.assertEqual(result.answers, [])
        self.assertEqual(result.aa, 1)

    def test_error_RCODE_tries_next_candidate(self):
        question = make_question()
        answer = make_record(
            question.qname,
            question.qtype,
            '192.0.2.80'
        )
        client = upstreamSequence_C([
            make_response(question, rcode=2),
            make_response(
                question,
                answers=[answer],
                aa=1
            )
        ])
        resolver = iterativeResolver_C(
            rootHintsStub_C(['198.41.0.1', '198.41.0.2']),
            1
        )
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers, [answer])
        self.assertEqual(len(client.calls), 2)

    def test_attempt_limit_returns_SERVFAIL(self):
        question = make_question()
        client = upstreamSequence_C([None, None])
        resolver = iterativeResolver_C(
            rootHintsStub_C(['198.41.0.1', '198.41.0.2']),
            1
        )
        resolver.max_attempts = 1
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(
            result.rcode,
            DDT.flag_respondCode_ENUM.SERVFAIL
        )
        self.assertEqual(len(client.calls), 1)

    def test_referral_limit_returns_SERVFAIL(self):
        question = make_question('www.example.com.')
        referral = make_response(
            question,
            authority=[
                make_record(
                    'com.',
                    DDT.dnsType_ENUM.NS,
                    'ns.com.'
                )
            ],
            additional=[
                make_record(
                    'ns.com.',
                    DDT.dnsType_ENUM.A,
                    '192.0.2.53'
                )
            ]
        )
        client = upstreamSequence_C([referral])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.max_referrals = 0
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(
            result.rcode,
            DDT.flag_respondCode_ENUM.SERVFAIL
        )
        self.assertEqual(len(client.calls), 1)

    def test_no_glue_lookup_uses_shared_referral_budget(self):
        question = make_question('www.example.com.')
        referral = make_response(
            question,
            authority=[
                make_record(
                    'example.com.',
                    DDT.dnsType_ENUM.NS,
                    'ns.example.com.'
                )
            ]
        )
        client = upstreamSequence_C([referral])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.max_referrals = 1
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(
            result.rcode,
            DDT.flag_respondCode_ENUM.SERVFAIL
        )
        self.assertEqual(len(client.calls), 1)

    def test_optional_upstream_sections_are_not_returned(self):
        question = make_question()
        answer = make_record(
            question.qname,
            question.qtype,
            '192.0.2.80'
        )
        soa = make_record(
            'example.',
            6,
            'RDLENGTH 20'
        )
        opt = make_record(
            '.',
            41,
            'RDLENGTH 0',
            rr_class=4096
        )
        client = upstreamSequence_C([
            make_response(
                question,
                answers=[answer],
                authority=[soa],
                additional=[opt],
                aa=1
            )
        ])
        resolver = iterativeResolver_C(rootHintsStub_C(), 1)
        resolver.upstream_client = client

        result = self._resolve(resolver, question)

        self.assertEqual(result.answers, [answer])
        self.assertEqual(result.authority, [])
        self.assertEqual(result.additional, [])


if __name__ == '__main__':
    unittest.main()
