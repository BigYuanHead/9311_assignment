from dataclasses import dataclass



# ============== COMMON ==============
class dnsType_ENUM:
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


class dnsClass_ENUM:
    IN = 1

    mapper = {
        IN: 'IN',
    }

# -------- for flags ----------

@dataclass
class flag_respondCode_ENUM:
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
    QR: int         # 0: query, 1: response
    Opcode: int     # operation code: 
    AA: int         # Authoritative Answer
    TC: int         # Truncated
    RD: int         # recursion desired
    RA: int         # recursive available
    Z: int          # DNSSEC
    AD: int         # ...
    CD: int         # ...
    RCODE: int      # response code



# ----------------- DNS question and resource record -----------------
@dataclass
class question_S:
    qname: str
    qtype: int
    qclass: int


@dataclass
class resourceRecord_S:
    name: str
    rr_type: int
    rr_class: int
    ttl: int
    rdlength: int
    rdata: str


# ----------------- root record -----------------
@dataclass
class rootRecord_S:
    name: str
    ttl: int
    rr_class: int
    rr_type: int
    rdata: str






