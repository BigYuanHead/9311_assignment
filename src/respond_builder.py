import dataStructures.dns_dataTypes as DDT
import src.helpers.bytesOpt as BO
from src.helpers.flagOpt import dnsFlag_C as FO



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

    def _encode_mx(self, rdata):
        """
        MX rdata format:
            2 bytes preference
            exchange name
        """

        parts = str(rdata).split(maxsplit=1)

        preference = int(parts[0])
        exchange = parts[1]

        builder = BO.byteBuilder_C()
        builder.add_u16(preference)
        builder.add_bytes(self._encode_name(exchange))

        return builder.get_bytes()


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

        if rr_type == DDT.dnsType_ENUM.CNAME:
            return self._encode_name(rdata)

        if rr_type == DDT.dnsType_ENUM.PTR:
            return self._encode_name(rdata)

        if rr_type == DDT.dnsType_ENUM.MX:
            return self._encode_mx(rdata)

        return b''

    def _build_rr(self, record: DDT.a_rr_S):
        builder = BO.byteBuilder_C()

        rdata_bytes = self._build_rdata(record.rr_type, record.rdata)

        builder.add_bytes(self._encode_name(record.name))
        builder.add_u16(record.rr_type)
        builder.add_u16(record.rr_class)
        builder.add_u32(record.ttl)
        builder.add_u16( len(rdata_bytes) )
        builder.add_bytes(rdata_bytes)

        return builder.get_bytes()

    def build_response(self, 
                       request: DDT.dns_request_S,
                       answer_records: list[DDT.a_rr_S],
                       authority_records: list[DDT.a_rr_S],
                       additional_records: list[DDT.a_rr_S],
                       rcode=0,
                       aa=0):
        builder = BO.byteBuilder_C()

        flags = FO.make_clientResponse_flags(
            request.header.flags,
            rcode,
            aa
        )

        builder.add_u16(request.header.id)
        builder.add_u16(flags)
        builder.add_u16(len(request.questions))
        builder.add_u16(len(answer_records))
        builder.add_u16(len(authority_records))
        builder.add_u16(len(additional_records))

        for question in request.questions:
            builder.add_bytes(self._build_question(question))

        for record in answer_records:
            builder.add_bytes(self._build_rr(record))

        for record in authority_records:
            builder.add_bytes(self._build_rr(record))

        for record in additional_records:
            builder.add_bytes(self._build_rr(record))

        return builder.get_bytes()
