from dataclasses import dataclass

from dataStructures.dns_dataTypes import flag_S
from dataStructures.dns_dataTypes import flag_respondCode_ENUM as FRc_E



class dnsFlag_C:
    """flag tool box"""

    @staticmethod
    def decode(flags: int) -> flag_S:
        """ header flags -> flag_S"""

        return flag_S(
            QR      = (flags >> 15) & 1,
            Opcode  = (flags >> 11) & 0xF,
            AA      = (flags >> 10) & 1,
            TC      = (flags >> 9) & 1,
            RD      = (flags >> 8) & 1,
            RA      = (flags >> 7) & 1,
            Z       = (flags >> 6) & 1,
            AD      = (flags >> 5) & 1,
            CD      = (flags >> 4) & 1,
            RCODE   = flags & 0xF
        )

    @staticmethod
    def encode(flag: flag_S):
        """flag_S -> DNS header flags int"""

        flags = 0
        flags = flags | ((flag.QR & 1) << 15)
        flags = flags | ((flag.Opcode & 0xF) << 11)
        flags = flags | ((flag.AA & 1) << 10)
        flags = flags | ((flag.TC & 1) << 9)
        flags = flags | ((flag.RD & 1) << 8)
        flags = flags | ((flag.RA & 1) << 7)
        flags = flags | ((flag.Z & 1) << 6)
        flags = flags | ((flag.AD & 1) << 5)
        flags = flags | ((flag.CD & 1) << 4)
        flags = flags | (flag.RCODE & 0xF)

        return flags

    @staticmethod
    def make_upstreamQuery_flags():
        """
            for upstream iterative query
            all bits should be 0
        """
        flags = 0
        return flags

    @staticmethod
    def make_clientResponse_flags(query_flags: int, rcode: int = 0):
        """
            respond client using

            Keep:
            - Opcode from client query
            - RD from client query

            Set:
            - QR = 1
            - RA = 1
            - RCODE = given rcode
        """

        query = dnsFlag_C.decode(query_flags)

        response = flag_S(
            QR = 1,
            Opcode = query.Opcode,
            AA = 0,
            TC = 0,
            RD = query.RD,
            RA = 1,
            Z = 0,
            AD = 0,
            CD = 0,
            RCODE = rcode
        )

        return dnsFlag_C.encode(response)

    @staticmethod
    def is_upstreamResponse_valid(flags: int):
        """
            upstream respond using
            
            expect:
                QR = 1
                Opcode = 0
                TC = 0
        """

        parsed = dnsFlag_C.decode(flags)

        if parsed.QR != 1:
            return False
        if parsed.Opcode != 0:
            return False
        if parsed.TC != 0:
            return False

        return True


    @staticmethod
    def get_rcode(flags: int):
        parsed = dnsFlag_C.decode(flags)
        return parsed.RCODE

    @staticmethod
    def is_authoritative(flags: int):
        parsed = dnsFlag_C.decode(flags)
        return parsed.AA == 1

    @staticmethod
    def is_truncated(flags: int):
        parsed = dnsFlag_C.decode(flags)
        return parsed.TC == 1

    @staticmethod
    def is_nxdomain(flags: int):
        parsed = dnsFlag_C.decode(flags)
        return parsed.RCODE == 3

    @staticmethod
    def is_noerror(flags: int):
        parsed = dnsFlag_C.decode(flags)
        return parsed.RCODE == 0
