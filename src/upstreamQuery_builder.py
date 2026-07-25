""" 把 qname / qtype / qclass 变成发给 upstream DNS server 的 query bytes """



import random

import helpers.bytesOpt as BO
import dataStructures.dns_dataTypes as DDT


class upstreamQueryBuilder_C:

    def __init__(self):
        pass

    def _make_txid(self):
        return random.randint(0, 65535) # 16 bits

    def _encode_name(self, name: str):
        """ domain name string -> DNS wire format """

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


    def build_query(self,
                    qname: str,
                    qtype: int,
                    qclass: int
                    ):
        """
        build std non recursive upstream DNS query

        return:
            txid, query_bytes
        """

        txid = self._make_txid()

        builder = BO.byteBuilder_C()

        # Header
        builder.add_u16(txid)

        # Flags = 0
        # QR=0, Opcode=0, AA=0, TC=0, RD=0, RA=0, RCODE=0
        builder.add_u16(0)

        # QDCOUNT = 1
        builder.add_u16(1)

        # ANCOUNT = 0
        builder.add_u16(0)

        # NSCOUNT = 0
        builder.add_u16(0)

        # ARCOUNT = 0
        builder.add_u16(0)

        # Question
        builder.add_bytes(self._encode_name(qname))
        builder.add_u16(qtype)
        builder.add_u16(qclass)

        return txid, builder.get_bytes()