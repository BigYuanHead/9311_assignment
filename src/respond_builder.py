import helpers.myLogger as myL

import dataStructures.dns_dataTypes as DDT
import helpers.bytesOpt as BO

import rootHints_parser as RhP
import request_parser as RP



class dnsResponseBuilder_C:

    def __init__(self):
        pass

    def _encode_name(self, name):
        """domain name string -> DNS wire format"""

        result = bytearray()

        if name == '.':
            result.append(0)
            return bytes(result)

        parts = name.rstrip('.').split('.')

        for part in parts:
            part_bytes = part.encode('ascii')
            result.append(len(part_bytes))
            result.extend(part_bytes)

        result.append(0)
        return bytes(result)

    def _encode_ip(self, ip):
        """IPv4 string -> 4 bytes"""

        result = bytearray()

        parts = ip.split('.')

        for part in parts:
            result.append(int(part))

        return bytes(result)

    def _make_flags(self, query_flags, rcode=0):
        """build response flags"""

        rd = query_flags & 0x0100

        flags = 0
        flags = flags | 0x8000      # QR = 1, response
        flags = flags | rd          # copy RD from query
        flags = flags | (rcode & 0xF)

        return flags

    def _build_question(self, question):
        builder = BO.byteBuilder_C()

        builder.add_bytes(self._encode_name(question.qname))
        builder.add_u16(question.qtype)
        builder.add_u16(question.qclass)

        return builder.get_bytes()

    def _build_rdata(self, rr_type, rdata):
        if rr_type == DDT.dnsType_ENUM.A:
            return self._encode_ip(rdata)

        if rr_type == DDT.dnsType_ENUM.NS:
            return self._encode_name(rdata)

        return b''

    def _build_rr(self, record):
        builder = BO.byteBuilder_C()

        rdata_bytes = self._build_rdata(record.rr_type, record.rdata)

        builder.add_bytes(self._encode_name(record.name))
        builder.add_u16(record.rr_type)
        builder.add_u16(DDT.dnsClass_ENUM.IN)
        builder.add_u32(record.ttl)
        builder.add_u16(len(rdata_bytes))
        builder.add_bytes(rdata_bytes)

        return builder.get_bytes()

    def build_response(self, parser, answer_records, authority_records, additional_records, rcode=0):
        builder = BO.byteBuilder_C()

        flags = self._make_flags(parser.flags, rcode)

        builder.add_u16(parser.id)
        builder.add_u16(flags)
        builder.add_u16(len(parser.questions))
        builder.add_u16(len(answer_records))
        builder.add_u16(len(authority_records))
        builder.add_u16(len(additional_records))

        for question in parser.questions:
            builder.add_bytes(self._build_question(question))

        for record in answer_records:
            builder.add_bytes(self._build_rr(record))

        for record in authority_records:
            builder.add_bytes(self._build_rr(record))

        for record in additional_records:
            builder.add_bytes(self._build_rr(record))

        return builder.get_bytes()