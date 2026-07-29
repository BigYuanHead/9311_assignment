"""analyse one validated upstream DNS response"""



from dataclasses import dataclass

from src.helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT




@dataclass
class referralResult_DC:
    ns_names: list[str]
    glue_ips: list[str]


@dataclass
class answerPath_DC:
    records: list[DDT.a_rr_S]
    next_name: str | None
    is_final: bool
    invalid_reason: str | None
    visited_names: set[str]



class responseAnalyser_C:

    def __init__(self, max_cname_depth: int):
        self.max_cname_depth = max_cname_depth

    def _norm_name(self, name: str) -> str:
        return name.lower()

    def _get_records(self,
                     records: list[DDT.a_rr_S],
                     name: str,
                     rr_type: int) -> list[DDT.a_rr_S]:
        result: list[DDT.a_rr_S] = []
        check_name = self._norm_name(name)

        for record in records:
            if self._norm_name(record.name) == check_name:
                if record.rr_type == rr_type:
                    result.append(record)

        return result

    def find_answer_path(self,
                         response: DDT.dns_request_S,
                         question: DDT.a_question_S,
                         cname_count: int,
                         visited_names: set[str]
                         ) -> answerPath_DC:
        records: list[DDT.a_rr_S] = []
        current_name = question.qname
        check_visited = set(visited_names)

        while True:
            answers = self._get_records(
                response.answers,
                current_name,
                question.qtype
            )

            if len(answers) > 0:
                for answer in answers:
                    records.append(answer)

                return answerPath_DC(
                    records=records,
                    next_name=None,
                    is_final=True,
                    invalid_reason=None,
                    visited_names=check_visited
                )

            # direct CNAME query should not chase target
            if question.qtype == DDT.dnsType_ENUM.CNAME:
                return answerPath_DC(
                    records=[],
                    next_name=None,
                    is_final=False,
                    invalid_reason=None,
                    visited_names=check_visited
                )

            cname_records = self._get_records(
                response.answers,
                current_name,
                DDT.dnsType_ENUM.CNAME
            )

            if len(cname_records) == 0:
                next_name = None
                if len(records) > 0:
                    next_name = current_name

                return answerPath_DC(
                    records=records,
                    next_name=next_name,
                    is_final=False,
                    invalid_reason=None,
                    visited_names=check_visited
                )

            cname_record = cname_records[0]
            target_name = cname_record.rdata
            norm_target = self._norm_name(target_name)

            if cname_count + len(records) >= self.max_cname_depth:
                return answerPath_DC(
                    records=[],
                    next_name=None,
                    is_final=False,
                    invalid_reason='reach max CNAME depth',
                    visited_names=visited_names
                )

            if norm_target in check_visited:
                return answerPath_DC(
                    records=[],
                    next_name=None,
                    is_final=False,
                    invalid_reason='CNAME loop detected {}'.format(target_name),
                    visited_names=visited_names
                )

            records.append(cname_record)
            check_visited.add(norm_target)
            current_name = target_name

    def is_authoritative_nodata(self,
                                response: DDT.dns_request_S,
                                question: DDT.a_question_S
                                ) -> bool:
        flags = FO.decode(response.header.flags)

        if flags.RCODE != DDT.flag_respondCode_ENUM.NOERROR:
            return False

        if flags.AA != 1:
            return False

        answers = self._get_records(
            response.answers,
            question.qname,
            question.qtype
        )

        if len(answers) > 0:
            return False

        if question.qtype != DDT.dnsType_ENUM.CNAME:
            cname_records = self._get_records(
                response.answers,
                question.qname,
                DDT.dnsType_ENUM.CNAME
            )

            if len(cname_records) > 0:
                return False

        return True

    def find_referral(
        self,
        response: DDT.dns_request_S
    ) -> referralResult_DC | None:
        flags = FO.decode(response.header.flags)

        # authoritative NS records are not referral
        if flags.AA == 1:
            return None

        ns_names: list[str] = []

        for record in response.authority:
            if record.rr_type == DDT.dnsType_ENUM.NS:
                ns_names.append(record.rdata)

        if len(ns_names) == 0:
            return None

        glue_ips: list[str] = []

        # NS wire order first, then matching Additional A wire order
        for ns_name in ns_names:
            for record in response.additional:
                if record.rr_type == DDT.dnsType_ENUM.A:
                    if self._norm_name(record.name) == self._norm_name(ns_name):
                        glue_ips.append(record.rdata)

        return referralResult_DC(
            ns_names=ns_names,
            glue_ips=glue_ips
        )
