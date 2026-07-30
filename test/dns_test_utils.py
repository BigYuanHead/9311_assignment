from pathlib import Path
import struct
import sys



BASE_DIR = Path(__file__).resolve().parents[1]
RESOURCE_DIR = BASE_DIR / 'dns-assignment-resources'

sys.path.insert(0, str(BASE_DIR))


import dataStructures.dns_dataTypes as DDT
from src.helpers.flagOpt import dnsFlag_C as FO
from src.respond_builder import dnsResponseBuilder_C



def encode_name(name: str) -> bytes:
    if name == '.':
        return b'\x00'

    result = bytearray()
    for label in name.rstrip('.').split('.'):
        label_bytes = label.encode('ascii')
        result.append(len(label_bytes))
        result.extend(label_bytes)

    result.append(0)
    return bytes(result)


def make_query(name: str,
               qtype: int,
               qclass: int = DDT.dnsClass_ENUM.IN,
               txid: int = 0x1234,
               flags: int = 0x0100
               ) -> bytes:
    result = bytearray()
    result.extend(struct.pack(
        '!HHHHHH',
        txid,
        flags,
        1,
        0,
        0,
        0
    ))
    result.extend(encode_name(name))
    result.extend(struct.pack('!HH', qtype, qclass))
    return bytes(result)


def make_question(name: str = 'www.example.',
                  qtype: int = DDT.dnsType_ENUM.A,
                  qclass: int = DDT.dnsClass_ENUM.IN
                  ) -> DDT.a_question_S:
    return DDT.a_question_S(name, qtype, qclass)


def make_record(name: str,
                rr_type: int,
                rdata: str,
                ttl: int = 60,
                rr_class: int = DDT.dnsClass_ENUM.IN
                ) -> DDT.a_rr_S:
    return DDT.a_rr_S(
        name=name,
        rr_type=rr_type,
        rr_class=rr_class,
        ttl=ttl,
        rdata=rdata
    )


def make_response(question: DDT.a_question_S,
                  answers=None,
                  authority=None,
                  additional=None,
                  aa: int = 0,
                  rcode: int = DDT.flag_respondCode_ENUM.NOERROR,
                  tc: int = 0,
                  txid: int = 0x1234
                  ) -> DDT.dns_request_S:
    result = DDT.dns_request_S()
    result.header.id = txid
    result.header.flags = FO.encode(DDT.flag_S(
        QR=1,
        AA=aa,
        TC=tc,
        RCODE=rcode
    ))
    result.header.flag_readable = FO.decode(result.header.flags)
    result.questions = [question]
    result.answers = answers or []
    result.authority = authority or []
    result.additional = additional or []
    return result


def make_response_wire(question: DDT.a_question_S,
                       answers=None,
                       authority=None,
                       additional=None,
                       aa: int = 0,
                       rcode: int = DDT.flag_respondCode_ENUM.NOERROR,
                       txid: int = 0x1234
                       ) -> bytes:
    request = DDT.dns_request_S()
    request.header.id = txid
    request.header.flags = 0
    request.questions = [question]

    return dnsResponseBuilder_C().build_response(
        request,
        answers or [],
        authority or [],
        additional or [],
        rcode=rcode,
        aa=aa
    )


def make_rr_wire(name: str,
                 rr_type: int,
                 rdata: bytes,
                 ttl: int = 60,
                 rr_class: int = DDT.dnsClass_ENUM.IN
                 ) -> bytes:
    result = bytearray()
    result.extend(encode_name(name))
    result.extend(struct.pack(
        '!HHIH',
        rr_type,
        rr_class,
        ttl,
        len(rdata)
    ))
    result.extend(rdata)
    return bytes(result)


class rootHintsStub_C:

    def __init__(self, ips=None):
        self.ips = ips or ['198.41.0.4']

    def get_rootNS_records(self):
        return [
            make_record(
                '.',
                DDT.dnsType_ENUM.NS,
                'root{}.example.'.format(index)
            )
            for index in range(len(self.ips))
        ]

    def get_records_with_name(self, name):
        for index, ip in enumerate(self.ips):
            expected_name = 'root{}.example.'.format(index)
            if name.lower() == expected_name:
                return [
                    make_record(
                        expected_name,
                        DDT.dnsType_ENUM.A,
                        ip
                    )
                ]

        return []


class upstreamSequence_C:

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def ask(self, server_ip, question, query_timeout):
        self.calls.append((
            server_ip,
            question.qname,
            question.qtype,
            query_timeout
        ))

        response = self.responses.pop(0)
        if callable(response):
            return response(server_ip, question, query_timeout)

        return response

