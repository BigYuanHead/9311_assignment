import sys
import os

# cfg
import configs.global_cfg as Gcfg

# src files
import src.helpers.myLogger as myL
import src.helpers.bytesOpt as BO
from src.helpers.flagOpt import dnsFlag_C as FO

# ds
import dataStructures.dns_dataTypes as DDT


myL.logger_C('', debug=Gcfg.LOGGER_DEBUG)

class malformedDNSPacket_E(Exception):
    """ malformed packet handle  """
    pass


class dnsParser_C:

    def __init__(self,
                 filename: str|None = None,
                 data: bytes|None = None):
        """
            @input:
                file or a byte series

            !! only parse once !! 
            Destroy it when finfish
        """
        # feeded data or reading file
        if data is not None:
            self.data = data
        else:
            self.data = b''
            with open(filename, 'rb') as file:
                self.data = file.read()

        self.pointer = 0 # parser manage byte pointer
        
        self.bo = BO.byteReader_C(self.data)
        self.request = DDT.dns_request_S()



    def _decode_name(self, start_pos=None) -> tuple[str, int]:
        """
            decode DNS name

            @input:
                start_pos: pointer start position

            @return:
                name: ...
                next_pos: pointer next position
                
            
            2. avoid pointer loop
            3. limit pointer jump <= 20
            4. reject 01 / 10 reserved label forms
            5. check label length <= 63
            6. check full name length <= 255
        """

        if start_pos is None:
            tmp_pos = self.pointer
        else:
            tmp_pos = start_pos

        # limitation
        pointerJump_counter = 0
        visited_offsets = set() # log jumper visited 
        labels = []

        while True:
            length = self.data[tmp_pos]
            tmp_pos = tmp_pos + 1 # move out from the length byte

            # end of name 00
            if length == 0:
                break

            # handle compression pointer C0 xx
            if length & 0xC0 == 0xC0: # hit compression pointer
                pointer_jumpTo = ((length & 0x3F) << 8) | self.data[tmp_pos] # offset calcu
                tmp_pos += 1 # skip 0x0C
                pointed_name, _ = self._decode_name(pointer_jumpTo)
                if pointed_name != '.':
                    labels.extend(pointed_name[:-1].split('.')) # remove the last .
                break

            # handle 01 10
            if length & 0xC0 != 0:
                raise ValueError('reserved DNS label form')
            
            # normal label
            label_bytes = self.bo.data[tmp_pos:tmp_pos+length]
            label = label_bytes.decode(errors='replace') # decode as ASCII
            labels.append(label)

            # shift pos to next label
            tmp_pos = tmp_pos + length

        # root
        if len(labels) == 0:
            name = '.'
        else: # non root
            name = '.'.join(labels) + '.'

        if start_pos is None:
            self.pointer = tmp_pos

        return name, tmp_pos


    def _parse_header(self):
        """ 
            12 bytes header 
            ID FLAGS QDCOUNT ANCOUNT NSCOUNT ARCOUNT
        """
        _header = self.request.header

        _header.id, _np = self.bo.read_u16(self.pointer)
        _header.flags, _np = self.bo.read_u16(_np)
        _header.flag_readable = FO.decode(_header.flags)

        _header.qdCount, _np = self.bo.read_u16(_np)
        _header.anCount, _np = self.bo.read_u16(_np)
        _header.nsCount, _np = self.bo.read_u16(_np)
        _header.arCount, _np = self.bo.read_u16(_np)

        self.pointer = _np # update


    def _parse_question(self) -> DDT.a_question_S:
        """ one question """

        qname, _np = self._decode_name() # QNAME
        qtype, _np = self.bo.read_u16(_np)  # QTYPE
        qclass, _np = self.bo.read_u16(_np) # QCLASS

        self.pointer = _np # update

        return DDT.a_question_S(qname, qtype, qclass)


    def _parse_recordData(self,
                          rr_type: int,
                          rdlength: int,
                          rdata_start: int
                          )-> str:
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



    def _parse_resourceRecord(self)-> DDT.a_rr_S:
        """ one resource record """

        tmp_rr = DDT.a_rr_S()

        tmp_rr.name, _np = self._decode_name() # NAME

        tmp_rr.type, _np = self.bo.read_u16(_np) # TYPE
        tmp_rr.rr_class, _np = self.bo.read_u16(_np) # CLASS
        tmp_rr.ttl, _np = self.bo.read_u32(_np) # TTL
        tmp_rr.rdlength, _np = self.bo.read_u16(_np) # RDLENGTH

        # decode record data
        rdata_start = self.pointer
        rdata_end = rdata_start + tmp_rr.rdlength
        self.pointer = rdata_end

        tmp_rr.rdata = self._parse_recordData(tmp_rr.type,
                                       tmp_rr.rdlength,
                                       rdata_start)
        

        return tmp_rr



    def parse(self) -> DDT.dns_request_S:
        """ parse full DNS message """

        # header
        self._parse_header()

        # questions
        for _ in range(self.request.header.qdCount):
            question = self._parse_question()
            self.request.questions.append(question)

        # answers
        for _ in range(self.request.header.anCount):
            rr = self._parse_resourceRecord()
            self.request.answers.append(rr)

        # authority
        for _ in range(self.request.header.nsCount):
            rr = self._parse_resourceRecord()
            self.request.authority.append(rr)

        # additional
        for _ in range(self.request.header.arCount):
            rr = self._parse_resourceRecord()
            self.request.additional.append(rr)

        return self.request
