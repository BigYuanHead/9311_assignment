import src.helpers.myLogger as myL
from src.helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT
import src.request_parser as RP


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
                            parser: RP.dnsParser_C,
                            question: DDT.question_S):
        for record in parser.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == question.qtype:
                    return True

        return False

    def _has_cname(self,
                   parser: RP.dnsParser_C,
                   question: DDT.question_S):
        for record in parser.answers:
            if self._norm_name(record.name) == self._norm_name(question.qname):
                if record.rr_type == DDT.dnsType_ENUM.CNAME:
                    return True

        return False

    def is_authoritative_nodata(self,
                                parser: RP.dnsParser_C,
                                question: DDT.question_S):
        flags = FO.decode(parser.flags)

        if flags.RCODE != DDT.flag_respondCode_ENUM.NOERROR:
            return False

        if flags.AA != 1:
            return False

        if self._has_requested_type(parser, question):
            return False

        if self._has_cname(parser, question):
            return False

        log.info('[nodata] authoritative NODATA for {}'.format(
            question.qname
        ))

        return True