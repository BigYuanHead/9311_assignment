"""
Iterative DNS resolver.

Main idea:
    client question
    -> ask root
    -> follow referral
    -> use glue if possible
    -> if no glue, temporarily resolve NS hostname A record
    -> continue original question
"""



import socket
import time
from dataclasses import dataclass

import src.helpers.myLogger as myL
from src.helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT

import src.request_parser as RP
import src.upstreamQuery_builder as uQb
import src.rootHints_parser as RhP

import src.iterOpt.nested_lookup_handler as NLH
import src.iterOpt.cname_handler as CH
import src.iterOpt.noData_handler as NDH


log = myL.logger_C('ITERATIVE', debug=True)


@dataclass
class resolutionResult_DC:
    answers: list
    authority: list
    additional: list
    rcode: int




@dataclass
class resolveState_DC:
    current_question: DDT.question_S
    current_servers: list
    attempt_counter: int
    referral_depth: int
    start_time: float
    total_cap: int



class iterativeResolver_C:

    def __init__(self,
                 root_hints: RhP.rootHints_C,
                 timeout):
        self.root_hints = root_hints
        self.timeout = int(timeout)
        self.query_builder = uQb.upstreamQueryBuilder_C()

        self.max_attempts = 50
        self.max_referrals = 10

    def _norm_name(self, name: str):
        return name.lower()

    def _servfail(self):
        return resolutionResult_DC(
            [],
            [],
            [],
            DDT.flag_respondCode_ENUM.SERVFAIL
        )

    def _get_rootServer_ips(self):
        result = []
        root_ns_records = self.root_hints.get_rootNS_records()

        for ns_record in root_ns_records:
            a_records = self.root_hints.get_records_with_name(ns_record.rdata)

            for a_record in a_records:
                result.append(a_record.rdata)

        return result

    def _can_continue(self, state: resolveState_DC):
        if state.attempt_counter >= self.max_attempts:
            log.debug('[iterative] reach max attempts')
            return False

        if state.referral_depth >= self.max_referrals:
            log.debug('[iterative] reach max referral depth')
            return False

        if time.time() - state.start_time > state.total_cap:
            log.debug('[iterative] total timeout')
            return False

        if len(state.current_servers) == 0:
            log.debug('[iterative] no current servers')
            return False

        return True

    def _check_response(self,
                        parser: RP.dnsParser_C,
                        expected_txid,
                        expected_question: DDT.question_S):

        if parser.id != expected_txid:
            log.debug('[upstream] txid not match')
            return False

        if not FO.is_upstreamResponse_valid(parser.flags):
            flags = FO.decode(parser.flags)
            log.debug('[upstream] not expected flags {}'.format(flags))
            return False

        if len(parser.questions) != 1:
            log.debug('[upstream] question count not 1')
            return False

        response_question = parser.questions[0]

        if self._norm_name(response_question.qname) != self._norm_name(expected_question.qname):
            return False

        if response_question.qtype != expected_question.qtype:
            return False

        if response_question.qclass != expected_question.qclass:
            return False

        return True

    def _ask_server(self, server_ip, question: DDT.question_S):
        txid, query_bytes = self.query_builder.build_query(
            question.qname,
            question.qtype,
            question.qclass
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            sock.sendto(query_bytes, (server_ip, 53))
            response_data, address = sock.recvfrom(4096)

            source_ip = address[0]
            source_port = address[1]

            if source_ip != server_ip:
                log.debug('[upstream] wrong source IP {}'.format(source_ip))
                return None

            if source_port != 53:
                log.debug('[upstream] wrong source port {}'.format(source_port))
                return None

            parser = RP.dnsParser_C(data=response_data)
            parser.parse()

            if not self._check_response(parser, txid, question):
                return None

            return parser

        except socket.timeout:
            log.warn('timeout from {}'.format(server_ip))
            return None

        except Exception as e:
            log.exception(e)
            return None

        finally:
            sock.close()

    def _get_matching_answers(self,
                              parser: RP.dnsParser_C,
                              question: DDT.question_S):
        result = []

        for record in parser.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == question.qtype:
                    result.append(record)

        return result

    def resolve(self, question: DDT.question_S):
        """
        Main iterative resolver.

        current_question:
            what we are asking now

        current_servers:
            which servers we ask now

        referral_handler:
            owns referral stack and no-glue logic
        """

        NL_handler = NLH.nestedLookupHandler_C()
        CN_handler = CH.cnameHandler_C()
        ND_handler = NDH.nodataHandler_C()

        log.info('[iterative] start resolve {} type {}'.format(
            question.qname,
            question.qtype
        ))

        state = resolveState_DC(
            current_question=question,
            current_servers=self._get_rootServer_ips(),
            attempt_counter=0,
            referral_depth=0,
            start_time=time.time(),
            total_cap=min(30, 50 * self.timeout)
        )

        while True:

            log.debug('[iterative] current question: {} type {}'.format(
                state.current_question.qname,
                state.current_question.qtype
            ))
            log.debug('[iterative] current servers: {}'.format(state.current_servers))
            log.debug('[iterative] attempts={}, referrals={}'.format(
                state.attempt_counter,
                state.referral_depth
            ))

            if not self._can_continue(state):
                log.warn('[iterative] stop, cannot continue')
                return self._servfail()

            made_progress = False

            for server_ip in state.current_servers:

                if state.attempt_counter >= self.max_attempts:
                    return self._servfail()

                state.attempt_counter = state.attempt_counter + 1

                log.debug('[iterative] ask {} for {} type {}'.format(
                    server_ip,
                    state.current_question.qname,
                    state.current_question.qtype
                ))

                parser = self._ask_server(server_ip, state.current_question)

                if parser is None:
                    log.debug('[iterative] no usable response from {}'.format(server_ip))
                    continue

                rcode = FO.get_rcode(parser.flags)
                log.debug('[iterative] response from {}, rcode={}, answer={}, authority={}, additional={}'.format(
                    server_ip,
                    rcode,
                    len(parser.answers),
                    len(parser.authority),
                    len(parser.additional)
                ))

                if rcode == DDT.flag_respondCode_ENUM.NXDOMAIN:
                    log.info('[iterative] NXDOMAIN for {}'.format(state.current_question.qname))
                    return resolutionResult_DC(
                        [],
                        [],
                        [],
                        DDT.flag_respondCode_ENUM.NXDOMAIN
                    )

                if rcode != DDT.flag_respondCode_ENUM.NOERROR:
                    log.debug('[iterative] skip server {}, rcode={}'.format(server_ip, rcode))
                    continue

                answers = self._get_matching_answers(
                    parser,
                    state.current_question
                )

                log.debug('[iterative] matching answers: {}'.format(len(answers)))

                # 1. We got matching answers.
                if len(answers) > 0:

                    # 1A. This answer is for internal NS-name A lookup.
                    if NL_handler.has_pending_lookup():
                        resumed, original_question, next_servers = NL_handler.resume_from_ns_answer(answers)

                        if resumed:
                            log.info('[iterative] NS-name A lookup success, resume {}'.format(
                                original_question.qname
                            ))
                            log.debug('[iterative] next servers from NS A: {}'.format(next_servers))

                            state.current_question = original_question
                            state.current_servers = next_servers
                            state.referral_depth = state.referral_depth + 1
                            made_progress = True
                            break

                        log.debug('[iterative] pending NS lookup has no A answer')
                        continue

                    # 1B. This answer is for original client question.
                    final_answers = CN_handler.build_final_answers(answers)

                    log.success('[iterative] final answer found for {} type {}, count={}'.format(
                        state.current_question.qname,
                        state.current_question.qtype,
                        len(final_answers)
                    ))
                    return resolutionResult_DC(
                        final_answers,
                        parser.authority,
                        parser.additional,
                        DDT.flag_respondCode_ENUM.NOERROR
                    )

                # 2. No requested answer. Check CNAME chasing.
                if state.current_question.qtype != DDT.dnsType_ENUM.CNAME:
                    cname_record = CN_handler.find_cname(
                        parser,
                        state.current_question
                    )

                    if cname_record is not None:
                        if not CN_handler.can_chase(cname_record):
                            return self._servfail()

                        state.current_question = CN_handler.chase(
                            cname_record,
                            state.current_question
                        )
                        state.current_servers = self._get_rootServer_ips()
                        made_progress = True
                        break

                # 3. No requested answer and no CNAME. Check authoritative NODATA.
                if ND_handler.is_authoritative_nodata(
                    parser,
                    state.current_question
                ):
                    final_answers = CN_handler.build_final_answers([])
                    log.info('[iterative] authoritative NODATA for {}'.format(
                        state.current_question.qname
                    ))
                    return resolutionResult_DC(
                        final_answers,
                        parser.authority,
                        parser.additional,
                        DDT.flag_respondCode_ENUM.NOERROR
                    )

                # 4. No answer, no CNAME, no NODATA. Check referral / nested A lookup.
                referral = NL_handler.analyse(parser)

                if referral.is_referral:

                    # 4A. Referral with glue.
                    if len(referral.glue_ips) > 0:
                        log.info('[iterative] referral with glue, move to next servers')
                        log.debug('[iterative] glue servers: {}'.format(referral.glue_ips))

                        state.current_servers = referral.glue_ips
                        state.referral_depth = state.referral_depth + 1
                        made_progress = True
                        break

                    # 4B. Referral without glue.
                    log.info('[iterative] referral without glue, start NS-name A lookup')

                    state.current_question = NL_handler.start_no_glue_lookup(
                        state.current_question,
                        referral
                    )
                    state.current_servers = self._get_rootServer_ips()
                    state.referral_depth = state.referral_depth + 1
                    made_progress = True
                    break

                # useless response, try next server at same level
                continue

            if made_progress:
                log.debug('[iterative] progress made, continue next round')
                continue

            # 3. Current round failed.
            # If it was no-glue NS-name lookup, try next NS name.
            has_next, next_question = NL_handler.try_next_ns_name()

            if has_next:
                log.info('[iterative] try next NS-name A lookup {}'.format(next_question.qname))
                state.current_question = next_question
                state.current_servers = self._get_rootServer_ips()
                continue

            log.warn('[iterative] no useful response and no next NS name, SERVFAIL')
            return self._servfail()