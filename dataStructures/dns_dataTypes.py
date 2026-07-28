from dataclasses import dataclass



# ============== COMMON ==============
@dataclass
class dnsType_ENUM:
    """ QTYPE """
    A = 1
    NS = 2
    CNAME = 5
    PTR = 12
    MX = 15

    mapper = {
        A: 'A',
        NS: 'NS',
        CNAME: 'CNAME',
        PTR: 'PTR',
        MX: 'MX',
    }


@dataclass
class dnsClass_ENUM:
    """ QCLASS """
    IN = 1

    mapper = {
        IN: 'IN',
    }


# -------- Header using ----------
"""
    ID FLAGS QDCOUNT ANCOUNT NSCOUNT ARCOUNT
"""

@dataclass
class flag_respondCode_ENUM:
    """ RCODE in Flag field """
    NOERROR = 0 # no error
    FORMERR = 1 # ...
    SERVFAIL = 2 # serv fail
    NXDOMAIN =  3 # nx domain

    mapper = {
        NOERROR: 'NOERROR',
        FORMERR: 'FORMERR',
        SERVFAIL: 'SERVFAIL',
        NXDOMAIN: 'NXDOMAIN',
    }

@dataclass
class flag_S:
    QR: int = 0         # 0: query, 1: response
    Opcode: int = 0     # operation code: 0 standard Query
    AA: int = 0         # Authoritative Answer: 1
    TC: int = 0         # Truncated 0: all recodes, 1: some left
    RD: int = 0         # recursion desired
    RA: int = 0         # recursive available
    Z: int = 0          # DNSSEC x
    AD: int = 0         # ... x
    CD: int = 0         # ... x
    RCODE: int = 0      # response code


class header_S:
    id: int = 0         # ID
    flags: int = 0      # FLAGS
    qdCount: int = 0    # QDCOUNT
    anCount: int = 0    # ANCOUNT
    nsCount: int = 0    # NSCOUNT
    arCount: int = 0    # ARCOUNT


# ----------------- DNS question and resource record -----------------
@dataclass
class a_question_S:
    qname: str
    qtype: int
    qclass: int


@dataclass
class a_rr_S:
    """ rr - resource record """
    name: str = ''
    type: int = 0
    rr_class: int = dnsClass_ENUM.IN
    ttl: int = 0
    rdlength: int = 0   # record data length
    rdata: str = ''      # record data


class dns_request_S:
    """ a full request """

    header: header_S
    questions: list[a_question_S] = []
    answers: list[a_rr_S] = []
    authority: list[a_rr_S] = []
    additional: list[a_rr_S] = []

class dns_response_S:
    """ a full response """
    pass

# ----------------- root record -----------------
@dataclass
class rootRecord_S:
    name: str
    ttl: int
    rr_class: int
    rr_type: int
    rdata: str






