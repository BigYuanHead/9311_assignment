import sys
import os

import src.helpers.myLogger as myL
import src.helpers.bytesOpt as BO
from src.helpers.flagOpt import dnsFlag_C as FO


import dataStructures.dns_dataTypes as DDT


class dnsParser_C:

    def __init__(self, filename: str|None = None, data: bytes|None = None):

        # feeded data or reading file
        if data is not None:
            self.data = data
        else:
            self.data = b''
            with open(filename, 'rb') as file:
                self.data = file.read()

        self.bo = BO.byteReader_C(self.data)

        # header section fields
        self.id = 0
        self.flags = 0

        self.qdCount = 0
        self.anCount = 0
        self.nsCount = 0
        self.arCount = 0

        # sections contents
        self.questions: list[DDT.question_S] = []
        self.answers: list[DDT.resourceRecord_S] = []
        self.authority: list[DDT.resourceRecord_S] = []
        self.additional: list[DDT.resourceRecord_S] = []


    def _decode_name(self, start_pos=None):
        """
            decode DNS name

            return:
                name, next_pos

                
            1. handle compression pointer C0 xx
            2. avoid pointer loop
            3. limit pointer jump <= 20
            4. reject 01 / 10 reserved label forms
            5. check label length <= 63
            6. check full name length <= 255
        """

        if start_pos is None:
            tmp_pos = self.bo.pos
        else:
            tmp_pos = start_pos

        labels = []

        while True:
            length = self.bo.data[tmp_pos]
            tmp_pos = tmp_pos + 1 # move out from the length byte

            # end of name
            if length == 0:
                break

            if length & 0xC0 == 0xC0: # hit compression pointer
                pointer = ((length & 0x3F) << 8) | self.bo.data[tmp_pos] # offset calcu
                tmp_pos += 1 # skip 0x0C
                pointed_name, _ = self._decode_name(pointer)
                if pointed_name != '.':
                    labels.extend(pointed_name[:-1].split('.'))
                break

            # simple normal label only
            label_bytes = self.bo.data[tmp_pos:tmp_pos+length]
            label = label_bytes.decode(errors='replace') # decode as ASCII
            labels.append(label)
            tmp_pos = tmp_pos + length # shift pos to next label

        if len(labels) == 0:
            name = '.'
        else:
            name = '.'.join(labels) + '.'

        if start_pos is None:
            self.bo.pos = tmp_pos

        return name, tmp_pos


    def _parse_header(self):
        """ 
            12 bytes header 
            ID FLAGS QDCOUNT ANCOUNT NSCOUNT ARCOUNT
        """

        self.id = self.bo.read_u16()
        self.flags = self.bo.read_u16()

        self.qdCount = self.bo.read_u16()
        self.anCount = self.bo.read_u16()
        self.nsCount = self.bo.read_u16()
        self.arCount = self.bo.read_u16()


    def _parse_question(self):
        """ 
            one question

            QNAME QTYPE QCLASS
        """

        qname, _ = self._decode_name()
        qtype = self.bo.read_u16()
        qclass = self.bo.read_u16()

        return DDT.question_S(qname, qtype, qclass)


    def _parse_recordData(self, rr_type: int, rdlength: int, rdata_start: int):
        """ decode one record data """

        # A
        if rr_type == DDT.dnsType_ENUM.A and rdlength == 4: #4 bytes
            ip_bytes = self.bo.data[rdata_start:rdata_start+4]
            rdata = '{}.{}.{}.{}'.format(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
            return rdata

        # NS / CNAME / PTR
        if rr_type in (DDT.dnsType_ENUM.NS, 
                       DDT.dnsType_ENUM.CNAME, 
                       DDT.dnsType_ENUM.PTR) and rdlength > 0:
            name, next_pos = self._decode_name(rdata_start)
            if next_pos <= rdata_start + rdlength:
                return name

        # MX
        if rr_type == DDT.dnsType_ENUM.MX and rdlength > 2:
            # priority
            first_byte = self.bo.data[rdata_start]
            second_byte = self.bo.data[rdata_start + 1]
            preference = (first_byte << 8) | second_byte

            # exchange name
            exchange, next_pos = self._decode_name(rdata_start + 2)
            if next_pos <= rdata_start + rdlength:
                return '{} {}'.format(preference, exchange)

        # unsupported or malformed
        return 'RDLENGTH {}'.format(rdlength)


    def _parse_resourceRecord(self):
        """ 
            one resource record

            NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA
        """

        name, _ = self._decode_name()

        rr_type = self.bo.read_u16()
        rr_class = self.bo.read_u16()
        ttl = self.bo.read_u32()
        rdlength = self.bo.read_u16()

        # decode record data
        rdata_start = self.bo.pos
        rdata_end = rdata_start + rdlength

        rdata = self._parse_recordData(rr_type, rdlength, rdata_start)

        self.bo.pos = rdata_end

        return DDT.resourceRecord_S(name, rr_type, rr_class, ttl, rdlength, rdata)



    def parse(self):
        """ parse full DNS message """

        self._parse_header()

        # questions
        for idx in range(self.qdCount):
            question = self._parse_question()
            self.questions.append(question)

        # answers
        for idx in range(self.anCount):
            rr = self._parse_resourceRecord()
            self.answers.append(rr)

        # authority
        for idx in range(self.nsCount):
            rr = self._parse_resourceRecord()
            self.authority.append(rr)

        # additional
        for idx in range(self.arCount):
            rr = self._parse_resourceRecord()
            self.additional.append(rr)






