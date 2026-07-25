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


log = myL.logger_C('ITERATIVE', debug=True)


@dataclass
class resolutionResult_DC:
    answers: list
    authority: list
    additional: list
    rcode: int


@dataclass
class _pausedTask_DC:
    """ a paused original question while resolving no-glue NS names."""
    original_question: DDT.question_S
    ns_names: list
    current_index: int


@dataclass
class _resolveState_DC:
    """ all states for one client request """
    current_question: DDT.question_S
    current_servers: list
    paused_tasks: list[_pausedTask_DC]
    attempt_counter: int
    referral_depth: int
    start_time: float
    total_cap: int


@dataclass
class _stepResult_DC:
    """
    result of handling one upstream response

    final_result:
        not None means resolution finished.

    next_servers:
        not empty means move to these servers next.
    """
    final_result: resolutionResult_DC | None
    next_servers: list


class iterativeResolver_C:

    def __init__(self,
                 root_hints: RhP.rootHints_C,
                 timeout):
        self.root_hints = root_hints
        self.timeout = int(timeout)
        self.query_builder = uQb.upstreamQueryBuilder_C()

        self.max_attempts = 50
        self.max_referrals = 10

    # ========= small helpers =========

    def _norm_name(self, name: str):
        return name.lower()

    def _servfail(self):
        return resolutionResult_DC([], [], [], DDT.flag_respondCode_ENUM.SERVFAIL)

    def _make_A_question(self, name: str, qclass: int):
        """ A question for name server IP lookup """
        return DDT.question_S(
            qname=name,
            qtype=DDT.dnsType_ENUM.A,
            qclass=qclass
        )

    def _get_rootServer_ips(self):
        """get root server IPv4 addresses from root hints, in file order"""

        result = []
        root_ns_records = self.root_hints.get_rootNS_records()

        for ns_record in root_ns_records:
            a_records = self.root_hints.get_records_with_name(ns_record.rdata)
            for a_record in a_records:
                result.append(a_record.rdata)

        return result

    def _can_continue(self, state: _resolveState_DC):
        if state.attempt_counter >= self.max_attempts:
            log.debug('[iterative] reach max attempts')
            return False

        if state.referral_depth >= self.max_referrals:
            log.debug('[iterative] reach max referrals')
            return False

        if time.time() - state.start_time > state.total_cap:
            log.debug('[iterative] total timeout')
            return False

        if len(state.current_servers) == 0:
            log.debug('[iterative] no current servers')
            return False

        return True

    # ========= upstream send, validation =========
    def _check_response(self,
                        parser: RP.dnsParser_C,
                        expected_txid,
                        expected_question: DDT.question_S):

        if parser.id != expected_txid:
            log.debug('[Upstream R] return ID not send ID')
            return False

        flags = FO.decode(parser.flags)

        if flags.QR != 1:
            log.debug('[Upstream R] QR not 1')
            return False

        if flags.Opcode != 0:
            log.debug('[Upstream R] Opcode not 0')
            return False

        if flags.TC != 0:
            log.debug('[Upstream R] TC not 0')
            return False

        if len(parser.questions) != 1:
            log.debug('[Upstream R] return question not 1')
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
        """
        send one non recursive DNS query to one upstream server.

        return:
            parsed response if success
            None if timeout / invalid / malformed
        """
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
                log.debug('ignore response from wrong IP {}'.format(source_ip))
                return None

            if source_port != 53:
                log.debug('ignore response from wrong port {}'.format(source_port))
                return None

            parser = RP.dnsParser_C(data=response_data)
            parser.parse()

            if not self._check_response(parser, txid, question):
                log.debug('invalid upstream response from {}'.format(server_ip))
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

    # ========= answer helpers =========

    def _has_matching_answer(self,
                             parser: RP.dnsParser_C,
                             question: DDT.question_S):
        for record in parser.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == question.qtype:
                    return True

        return False

    def _get_matching_answers(self,
                              parser: RP.dnsParser_C,
                              question: DDT.question_S
                              ) -> list[DDT.resourceRecord_S]:
        result: list[DDT.resourceRecord_S] = []
        for record in parser.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == question.qtype:
                    result.append(record)

        return result

    # ========= referral helpers =========

    def _get_nsNames_from_referral(self, parser: RP.dnsParser_C):
        """ Get NS names from authority section in wire order """

        result = []

        for record in parser.authority:
            if record.rr_type == DDT.dnsType_ENUM.NS:
                result.append(record.rdata)

        return result

    def _get_glueIPs_from_referral(self, parser: RP.dnsParser_C):
        """
        Referral with glue:
            Authority has NS records.
            Additional has matching A records.
        """

        result = []
        ns_names = self._get_nsNames_from_referral(parser)

        for ns_name in ns_names:
            for record in parser.additional:
                if record.rr_type == DDT.dnsType_ENUM.A:
                    if self._norm_name(record.name) == self._norm_name(ns_name):
                        result.append(record.rdata)

        return result

    # ========= not glue task helpers =========

    def _start_nested_lookup(self,
                             state: _resolveState_DC,
                             ns_names: list):
        """
            no glue case.
            pause current question, then start resolving first NS hostname A record.
        """ 

        # pause original question
        task = _pausedTask_DC(
            original_question = state.current_question,
            ns_names = ns_names,
            current_index = 0
        )

        state.paused_tasks.append(task)

        # redirect to new NS look up
        ns_name = ns_names[0]
        log.debug('[iterative] no glue, lookup NS name {}'.format(ns_name))

        state.current_question = self._make_A_question(ns_name, state.current_question.qclass)
        state.current_servers = self._get_rootServer_ips()
        state.referral_depth = state.referral_depth + 1

    def _try_next_paused_ns(self, state: _resolveState_DC):
        """
        current nested NS lookup failed.
        Try next NS name in latest paused task.
        """

        while len(state.paused_tasks) > 0:
            task = state.paused_tasks[-1]
            task.current_index = task.current_index + 1

            if task.current_index < len(task.ns_names):
                ns_name = task.ns_names[task.current_index]
                log.debug('[iterative] try next NS name {}'.format(ns_name))

                state.current_question = self._make_A_question(ns_name, task.original_question.qclass)
                state.current_servers = self._get_rootServer_ips()
                return True

            state.paused_tasks.pop()

        return False

    def _resume_paused_question(self,
                                state: _resolveState_DC,
                                ns_a_answers: list[DDT.resourceRecord_S]):
        """
        Nested NS-name A lookup succeeded.
        Use returned A records as next servers for paused original question.
        """

        if len(state.paused_tasks) == 0:
            return False

        task = state.paused_tasks.pop()
        next_servers = []

        for record in ns_a_answers:
            if record.rr_type == DDT.dnsType_ENUM.A:
                next_servers.append(record.rdata)

        if len(next_servers) == 0:
            return False

        state.current_question = task.original_question
        state.current_servers = next_servers
        state.referral_depth = state.referral_depth + 1

        return True

    # ========= response handling =========

    def _handle_answer(self,
                       state: _resolveState_DC,
                       parser: RP.dnsParser_C):

        answers = self._get_matching_answers(parser, state.current_question)

        # Current answer is for an internal NS hostname A lookup.
        if len(state.paused_tasks) > 0:
            resumed = self._resume_paused_question(state, answers)

            if resumed:
                return _stepResult_DC(None, state.current_servers)

        final_result = resolutionResult_DC(
            answers,
            parser.authority,
            parser.additional,
            DDT.flag_respondCode_ENUM.NOERROR
        )

        return _stepResult_DC(final_result, [])

    def _handle_referral(self,
                         state: _resolveState_DC,
                         parser: RP.dnsParser_C):

        glue_ips = self._get_glueIPs_from_referral(parser)

        # if find glue ips
        if len(glue_ips) > 0:
            state.referral_depth = state.referral_depth + 1
            return _stepResult_DC(None, glue_ips)

        # if no glue ip
        ns_names = self._get_nsNames_from_referral(parser)

        if len(ns_names) > 0:
            self._start_nested_lookup(state, ns_names)
            return _stepResult_DC(None, state.current_servers)

        return _stepResult_DC(None, [])

    def _handle_response(self,
                         state: _resolveState_DC,
                         parser: RP.dnsParser_C
                         ) -> _stepResult_DC:
        
        flags = FO.decode(parser.flags)
        rcode = flags.RCODE

        if rcode == DDT.flag_respondCode_ENUM.NXDOMAIN:
            final_result = resolutionResult_DC([], [], [], rcode)
            return _stepResult_DC(final_result, [])

        if rcode != DDT.flag_respondCode_ENUM.NOERROR:
            return _stepResult_DC(None, [])

        if self._has_matching_answer(parser, state.current_question):
            return self._handle_answer(state, parser)

        return self._handle_referral(state, parser)

    # ========= main loop =========

    def resolve(self, question: DDT.question_S):
        """
        Main iterative resolution entry.
        """

        # init reslover state
        state = _resolveState_DC(
            current_question = question,
            current_servers = self._get_rootServer_ips(),
            paused_tasks = [],
            attempt_counter = 0,
            referral_depth = 0,
            start_time = time.time(),
            total_cap = min(30, 50 * self.timeout)
        )

        while True:

            # check state
            if not self._can_continue(state):
                return self._servfail()

            tmp_nextServers = []
            for server_ip in state.current_servers:
                state.attempt_counter = state.attempt_counter + 1

                parser = self._ask_server(server_ip, state.current_question)

                if parser is None:
                    continue
                step = self._handle_response(state, parser)

                if step.final_result is not None:
                    return step.final_result

                # referral has next server ip
                if len(step.next_servers) > 0:
                    tmp_nextServers = step.next_servers
                    break

            # has referral
            if len(tmp_nextServers) > 0:
                state.current_servers = tmp_nextServers
                continue

            # no referral
            if self._try_next_paused_ns(state):
                continue

            return self._servfail()
