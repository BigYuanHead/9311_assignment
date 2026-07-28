from dataclasses import dataclass

import src.helpers.myLogger as myL
import dataStructures.dns_dataTypes as DDT
import src.request_parser as RP


log = myL.logger_C('NESTED', debug=True)


@dataclass
class referralResult_DC:
    is_referral: bool
    ns_names: list
    glue_ips: list


@dataclass
class pausedTask_DC:
    original_question: DDT.a_question_S
    ns_names: list
    current_index: int


class nestedLookupHandler_C:
    """
    Handle referral and no-glue nested A lookup.

    It owns:
        - Authority NS parsing
        - Additional glue parsing
        - no-glue stack
        - start NS-name A lookup
        - resume original query
        - try next NS name
    """

    def __init__(self):
        self.paused_tasks = []

    def _norm_name(self, name: str):
        return name.lower()

    def _make_A_question(self, name: str, qclass: int):
        return DDT.a_question_S(
            qname=name,
            qtype=DDT.dnsType_ENUM.A,
            qclass=qclass
        )

    def _get_ns_names(self, parser: RP.dnsParser_C):
        result = []

        for record in parser.authority:
            if record.rr_type == DDT.dnsType_ENUM.NS:
                result.append(record.rdata)

        return result

    def _get_glue_ips(self, parser: RP.dnsParser_C, ns_names: list):
        result = []

        for ns_name in ns_names:
            for record in parser.additional:
                if record.rr_type == DDT.dnsType_ENUM.A:
                    if self._norm_name(record.name) == self._norm_name(ns_name):
                        result.append(record.rdata)

        return result

    def analyse(self, parser: RP.dnsParser_C):
        ns_names = self._get_ns_names(parser)

        if len(ns_names) == 0:
            log.debug('no NS records in authority')
            return referralResult_DC(
                is_referral=False,
                ns_names=[],
                glue_ips=[]
            )

        glue_ips = self._get_glue_ips(parser, ns_names)

        log.debug('ns names: \n{}'.format(ns_names))
        log.debug('glue ips: \n{}'.format(glue_ips))

        return referralResult_DC(
            is_referral=True,
            ns_names=ns_names,
            glue_ips=glue_ips
        )

    def has_pending_lookup(self):
        return len(self.paused_tasks) > 0

    def start_no_glue_lookup(self,
                             current_question: DDT.a_question_S,
                             referral: referralResult_DC):
        task = pausedTask_DC(
            original_question=current_question,
            ns_names=referral.ns_names,
            current_index=0
        )

        self.paused_tasks.append(task)

        ns_name = referral.ns_names[0]
        log.info('no glue, lookup {}'.format(ns_name))

        return self._make_A_question(
            ns_name,
            current_question.qclass
        )

    def _get_ips_from_A_answers(self, answers: list):
        result = []

        for record in answers:
            if record.rr_type == DDT.dnsType_ENUM.A:
                result.append(record.rdata)

        return result

    def resume_from_ns_answer(self, answers: list):
        if len(self.paused_tasks) == 0:
            return False, None, []

        next_servers = self._get_ips_from_A_answers(answers)

        if len(next_servers) == 0:
            return False, None, []

        task = self.paused_tasks.pop()

        return True, task.original_question, next_servers

    def try_next_ns_name(self):
        while len(self.paused_tasks) > 0:
            task = self.paused_tasks[-1]
            task.current_index = task.current_index + 1

            if task.current_index < len(task.ns_names):
                ns_name = task.ns_names[task.current_index]
                log.info('try next NS name {}'.format(ns_name))

                next_question = self._make_A_question(
                    ns_name,
                    task.original_question.qclass
                )

                return True, next_question

            self.paused_tasks.pop()

        return False, None