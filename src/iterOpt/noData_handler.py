import src.helpers.myLogger as myL
from src.helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT


log = myL.logger_C('NODATA', debug=True)


class nodataHandler_C:
    """
    Handle authoritative NODATA.

    NODATA means:
        rcode = NOERROR
        AA = 1
        no requested type answer
        no CNAME to chase
        not referral
    """

    def _norm_name(self, name: str):
        return name.lower()

    def _has_requested_type(self,
                            response: DDT.dns_request_S,
                            question: DDT.a_question_S):
        for record in response.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == question.qtype:
                    return True

        return False

    def _has_cname(self,
                   response: DDT.dns_request_S,
                   question: DDT.a_question_S):
        for record in response.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == DDT.dnsType_ENUM.CNAME:
                    return True

        return False

    def is_authoritative_nodata(self,
                                response: DDT.dns_request_S,
                                question: DDT.a_question_S):
        flags = FO.decode(response.header.flags)

        if flags.RCODE != DDT.flag_respondCode_ENUM.NOERROR:
            return False

        if flags.AA != 1:
            return False

        if self._has_requested_type(response, question):
            return False

        if self._has_cname(response, question):
            return False

        log.info('[nodata] authoritative NODATA for {}'.format(
            question.qname
        ))

        return True
