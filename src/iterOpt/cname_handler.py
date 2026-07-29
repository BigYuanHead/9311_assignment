import src.helpers.myLogger as myL
import dataStructures.dns_dataTypes as DDT


log = myL.logger_C('CNAME', debug=True)


class cnameHandler_C:
    """
    Handle CNAME chasing.

    It owns:
        - CNAME chain
        - CNAME loop check
        - CNAME depth limit
        - final answer chain
    """

    def __init__(self):
        self.cname_chain = []
        self.visited_names = set()
        self.max_cname_depth = 10

    def _norm_name(self, name: str):
        return name.lower()

    def find_cname(self,
                   response: DDT.dns_request_S,
                   question: DDT.a_question_S):
        for record in response.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == DDT.dnsType_ENUM.CNAME:
                    return record

        return None

    def can_chase(self, cname_record):
        if len(self.cname_chain) >= self.max_cname_depth:
            log.warn('[cname] reach max CNAME depth')
            return False

        target_name = cname_record.rdata
        norm_target = self._norm_name(target_name)

        if norm_target in self.visited_names:
            log.warn('[cname] CNAME loop detected {}'.format(target_name))
            return False

        return True

    def chase(self,
              cname_record,
              current_question: DDT.a_question_S):
        self.cname_chain.append(cname_record)

        self.visited_names.add(
            self._norm_name(current_question.qname)
        )

        target_name = cname_record.rdata

        log.info('[cname] chase {} -> {}'.format(
            current_question.qname,
            target_name
        ))

        return DDT.a_question_S(
            qname=target_name,
            qtype=current_question.qtype,
            qclass=current_question.qclass
        )

    def build_final_answers(self, final_answers: list):
        result = []

        for record in self.cname_chain:
            result.append(record)

        for record in final_answers:
            result.append(record)

        return result
