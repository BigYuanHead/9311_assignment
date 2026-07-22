from dataclasses import dataclass



# ============== COMMON ==============
class dnsType_C:
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


class dnsClass_C:
    IN = 1

    mapper = {
        IN: 'IN',
    }


# ----------------- DNS question and resource record -----------------
@dataclass
class question_DC:
    qname: str
    qtype: int
    qclass: int


@dataclass
class resourceRecord_DC:
    name: str
    type: int
    rr_class: int
    ttl: int
    rdlength: int
    rdata: str


# ----------------- root record -----------------
@dataclass
class rootRecord_C:
    name: str
    ttl: int
    rr_class: int
    rr_type: int
    rdata: str




