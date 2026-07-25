
"""
从 root hints 开始
问 root server
看 response 是 final answer 还是 referral
有 glue 就用 glue
没 glue 就 nested A lookup
处理 CNAME chain
控制 50 attempts / 10 referral levels
timeout
最后返回一个 resolution result
"""



import socket
import time
from dataclasses import dataclass

import helpers.myLogger as myL
from helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT

import request_parser as RP
import upstreamQuery_builder as uQb
import rootHints_parser as RhP


log = myL.logger_C('ITERATIVE', debug=True)


@dataclass
class resolutionResult_DC:
    answers: list
    authority: list
    additional: list
    rcode: int


@dataclass
class pendingTask_DC:
  original_question: DDT.question_S
  ns_names: list
  current_index: int


class iterativeResolver_C:

    def __init__(self, 
                 root_hints: RhP.rootHints_C,
                 timeout):
        """
            @input: 
            root_hints:
            timeout: 
        """
        self.root_hints = root_hints
        self.timeout = int(timeout)
        self.query_builder = uQb.upstreamQueryBuilder_C()

        self.max_attempts = 50
        self.max_referrals = 10

    def _norm_name(self, name: str):
        return name.lower()

    
    def _get_rootServer_ips(self):
        """
        get root server IP4 addresses from root hints
        order as file order
        """

        result = []
        root_ns_records = self.root_hints.get_rootNS_records()

        for ns_record in root_ns_records:
            a_records = self.root_hints.get_records_with_name(ns_record.rdata)
            for a_record in a_records:
                result.append(a_record.rdata)

        return result

    def _check_response(self,
                           parser: RP.dnsParser_C,
                           expected_txid,
                           expected_question: DDT.question_S
                           ):

        if parser.id != expected_txid:
            log.debug("[Upstream R] return ID not send ID")
            return False

        flags = FO.decode(parser.flags)

        if flags.QR != 1: # not response
            log.debug("[Upstream R] QR not 1")
            return False

        if flags.Opcode != 0:
            log.debug("[Upstream R] Opcode not 0")
            return False

        if flags.TC != 0:
            log.debug("[Upstream R] TC not 0")
            return False

        if len(parser.questions) != 1:
            log.debug("[Upstream R] return question not 1")
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
            parsered obj if success
            None if timeout, invalid, malformed
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
                log.warn('ignore response from wrong IP {}'.format(source_ip))
                return None

            if source_port != 53:
                log.warn('ignore response from wrong port {}'.format(source_port))
                return None

            # get response
            parser = RP.dnsParser_C(data=response_data)
            parser.parse()

            if not self._check_response(parser, txid, question):
                log.warn('invalid upstream response from {}'.format(server_ip))
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



    def _has_AAanswer(self,
                          parser: RP.dnsParser_C,
                          question: DDT.question_S):
        """ record respond == question name & type== """

        for record in parser.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.type == question.qtype:
                    return True

        return False

    def _get_match_AAanswers(self, parser: RP.dnsParser_C, question: DDT.question_S):
        """ extract want answer """
        result = []

        for record in parser.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.type == question.qtype:
                    result.append(record)

        return result

    # ========== referring ===========
    def _get_nsNames_from_referral(self, parser: RP.dnsParser_C):
        """
            Get NS names from Authority section in wire order.
            These names are used when referral has no usable glue.
        """

        result = []

        for record in parser.authority:
            if record.type == DDT.dnsType_ENUM.NS:
                result.append(record.rdata)

        return result

    def _make_A_question(self, name: str, qclass: int):
        """make internal A question for NS hostname lookup"""

        return DDT.question_S(
            qname=name,
            qtype=DDT.dnsType_ENUM.A,
            qclass=qclass
        )

    def _start_nested_ns_lookup(self, paused_tasks, current_question, ns_names):
        """
        Pause current question and start resolving first NS name to A.
        """

        task = pendingTask_DC(
            original_question=current_question,
            ns_names=ns_names,
            current_index=0
        )

        paused_tasks.append(task)

        ns_name = ns_names[0]
        log.debug('[iterative] no glue, lookup NS name {}'.format(ns_name))

        next_question = self._make_A_question(ns_name, current_question.qclass)
        next_servers = self._get_rootServer_ips()

        return next_question, next_servers

    def _try_next_paused_ns(self, paused_tasks):
        """
        Current nested NS-name lookup failed.
        Try next NS name from the latest paused task.
        """

        while len(paused_tasks) > 0:
            task = paused_tasks[-1]
            task.current_index = task.current_index + 1

            if task.current_index < len(task.ns_names):
                ns_name = task.ns_names[task.current_index]
                log.debug('[iterative] try next NS name {}'.format(ns_name))

                next_question = self._make_A_question(ns_name, task.original_question.qclass)
                next_servers = self._get_rootServer_ips()

                return next_question, next_servers, True

            paused_tasks.pop()

        return None, [], False

    def resolve(self, question: DDT.question_S):
        """
        Main iterative resolution entry.

        This first version:
            root -> referral with glue -> next server ...
            final answer -> return answer
            fail -> SERVFAIL

        Later we will add:
            no-glue nested A lookup
            CNAME chasing
            authoritative NODATA / NXDOMAIN handling
            caching integration
        """

        attempt_counter = 0 # server asked
        referral_depth = 0 # heigh level

        paused_tasks = []
        current_question = question
        current_servers = self._get_rootServer_ips()

        start_time = time.time()
        total_cap = min(30, 50 * self.timeout)

        while True:

            if attempt_counter >= self.max_attempts:
                log.debug("[iterative] reach max attemptation ")
                return resolutionResult_DC([], [], [], 2)

            if referral_depth >= self.max_referrals:
                log.debug("[iterative] reach max referral ")
                return resolutionResult_DC([], [], [], 2)

            if time.time() - start_time > total_cap:
                log.debug("[iterative] timeout ")
                return resolutionResult_DC([], [], [], 2)

            if len(current_servers) == 0:
                log.debug("[iterative] curr server = 0 ")
                return resolutionResult_DC([], [], [], 2)

            next_servers = []
            for server_ip in current_servers:

                attempt_counter = attempt_counter + 1
                parser = self._ask_server(server_ip, current_question)

                if parser is None: # no answer
                    continue

                flags = FO.decode(parser.flags)
                rcode = flags.RCODE

                # nx
                if rcode == DDT.flag_respondCode_ENUM.NXDOMAIN:
                    return resolutionResult_DC([], [], [], rcode)

                # error
                if rcode !=  DDT.flag_respondCode_ENUM.NOERROR:
                    continue

                # get answer for current question
                if self._has_AAanswer(parser, current_question):
                    answers = self._get_match_AAanswers(parser, current_question)

                    # If current question is a nested NS-name A lookup,
                    # use the returned A records as next servers for original question.
                    if len(paused_tasks) > 0:
                        pending_task = paused_tasks.pop()
                        next_servers = []

                        for record in answers:
                            if record.type == DDT.dnsType_ENUM.A:
                                next_servers.append(record.rdata)

                        if len(next_servers) > 0:
                            current_question = pending_task.original_question
                            referral_depth = referral_depth + 1
                            break

                    return resolutionResult_DC(
                        answers,
                        parser.authority,
                        parser.additional,
                        0
                    )

                # Referral with glue
                glue_ips = self._get_glueIPs_from_referral(parser)

                if len(glue_ips) > 0:
                    next_servers = glue_ips
                    referral_depth = referral_depth + 1
                    break

                # No usable glue.
                # Pause current question, then resolve referred NS hostname to A.
                ns_names = self._get_nsNames_from_referral(parser)

                if len(ns_names) > 0:
                    current_question, next_servers = self._start_nested_ns_lookup(
                        paused_tasks,
                        current_question,
                        ns_names
                    )

                    referral_depth = referral_depth + 1
                    break

                continue

            if len(next_servers) == 0:
                if len(paused_tasks) > 0:
                    current_question, next_servers, has_next = self._try_next_paused_ns(paused_tasks)

                    if has_next:
                        current_servers = next_servers
                        continue

                return resolutionResult_DC([], [], [], 2)

            current_servers = next_servers

