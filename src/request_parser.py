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


log = myL.logger_C('', debug=Gcfg.REQUEST_PARSER_DEBUG)

class malformedPkg_E(Exception):
    """DNS packet format is malformed."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)

    @staticmethod
    def reserved_label_form():
        return malformedPkg_E('reserved DNS label form 01/10')

    @staticmethod
    def pointer_loop():
        return malformedPkg_E('DNS name pointer loop')

    @staticmethod
    def too_many_pointer_jumps():
        return malformedPkg_E('too many DNS name pointer jumps')

    @staticmethod
    def label_too_long():
        return malformedPkg_E('DNS label length > 63')

    @staticmethod
    def name_too_long():
        return malformedPkg_E('DNS full name length > 255')

    @staticmethod
    def packet_boundary():
        return malformedPkg_E('read out of DNS packet boundary')

    @staticmethod
    def rdlength_out_of_range():
        return malformedPkg_E('RDLENGTH out of packet boundary')

    @staticmethod
    def set_error_request(request: DDT.dns_request_S, e):
        request.is_malformed = True
        request.malformed_reason = e.reason

        # header - flags
        # if request.header.flag_readable is not None:
        #     request.header.flag_readable.RCODE = DDT.flag_respondCode_ENUM.FORMERR
        #     request.header.flags = FO.encode(request.header.flag_readable)

        # question and resources
        request.answers = []
        request.authority = []
        request.additional = []


    

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

        self.data = b''
        # feeded data or reading file
        if data is not None:
            self.data = data
        elif filename is not None:
            with open(filename, 'rb') as file:
                self.data = file.read()
        else:
            raise ValueError("filename or data is expected")

        self.pointer = 0 # parser manage byte pointer
        
        self.bo = BO.byteReader_C(self.data)

        self.request = DDT.dns_request_S()
        self.request.is_malformed = False
        self.request.malformed_reason = ''
        log.debug("parser created, packet size = {} bytes".format(len(self.data)))
    

    def _check_pos(self, pos: int):
        if pos < 0 or pos >= len(self.data):
            raise malformedPkg_E.packet_boundary()

    def _check_range(self, pos: int, length: int):
        if pos < 0 or pos + length > len(self.data):
            raise malformedPkg_E.packet_boundary()


    def _decode_name(self, start_pos=None) -> tuple[str, int]:
        """
        decode DNS name

        @return:
            name: ...
            next_pos: position after the encoded name in the original path
        """

        if start_pos is None:
            tmp_pos = self.pointer
        else:
            tmp_pos = start_pos
        log.debug(f"decode name start_pos={start_pos}, tmp_pos={tmp_pos}")

        labels = []
        visited_offsets = set() # log visited offsets
        pointerJump_counter = 0
        jumped = False
        next_pos = tmp_pos

        while True:
            self._check_pos(tmp_pos)

            length = self.data[tmp_pos]
            tmp_pos = tmp_pos + 1

            # end of name 00
            if length == 0:
                if not jumped:
                    next_pos = tmp_pos
                break

            # compression pointer 11
            if length & 0xC0 == 0xC0:
                self._check_pos(tmp_pos)

                second_byte = self.data[tmp_pos]
                tmp_pos = tmp_pos + 1

                pointer_jumpTo = ((length & 0x3F) << 8) | second_byte
                log.debug(f"DNS compression pointer from {tmp_pos-2} go to {pointer_jumpTo}")

                # avoid pointer loop
                if pointer_jumpTo in visited_offsets:
                    log.warn(f"DNS name pointer loop detected, at offset: {pointer_jumpTo}")
                    raise malformedPkg_E.pointer_loop()
                visited_offsets.add(pointer_jumpTo)

                # count jump times
                pointerJump_counter = pointerJump_counter + 1
                if pointerJump_counter > Gcfg.MAXIMUM_POINTER_JUMP:
                    log.warn(f"too many DNS pointer jump times: {pointerJump_counter}")
                    raise malformedPkg_E.too_many_pointer_jumps()

                if not jumped:
                    next_pos = tmp_pos

                jumped = True
                tmp_pos = pointer_jumpTo
                continue

            # label forms start with 01 or 10
            if length & 0xC0 != 0:
                log.warn(f"reserved DNS label from at offsest: {tmp_pos-1}, byte: {length:02x}")
                raise malformedPkg_E.reserved_label_form()

            # normal label length check
            if length > Gcfg.MAXIMUM_LABEL_LENGTH:
                log.warn(f"DNS label too long at offset: {tmp_pos-1}, byte: {length}")
                raise malformedPkg_E.label_too_long()

            self._check_range(tmp_pos, length)

            label_bytes = self.data[tmp_pos:tmp_pos + length]
            label = label_bytes.decode(errors='replace')
            labels.append(label)

            tmp_pos = tmp_pos + length

        if len(labels) == 0:
            name = '.'
        else:
            name = '.'.join(labels) + '.'

        if len(name) > Gcfg.FULL_NAME_LENGTH:
            log.warn(f"DNS name too long, length: {len(name)}")
            raise malformedPkg_E.name_too_long()

        if start_pos is None:
            self.pointer = next_pos
        log.debug(f"decode name: {name}, next_pos={next_pos}")

        return name, next_pos


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
        log.debug(f"header parsed: \
                  id={_header.id}, \
                  flags={_header.flag_readable}, \
                    qd={_header.qdCount}, \
                    an={_header.anCount}, \
                    ns={_header.nsCount}, \
                    ar={_header.arCount}, \
                        ")


    def _parse_question(self) -> DDT.a_question_S:
        """ one question """

        qname, _np = self._decode_name() # QNAME
        qtype, _np = self.bo.read_u16(_np)  # QTYPE
        qclass, _np = self.bo.read_u16(_np) # QCLASS

        self.pointer = _np # update

        log.debug(f"question parsed: \
                  qname={qname}, \
                    qtype={qtype}, \
                        qclass={qclass}, \
                        ")
        return DDT.a_question_S(qname, qtype, qclass)


    def _parse_recordData(self,
                          rr_type: int,
                          rdlength: int,
                          rdata_start: int
                          )-> str:
        """ decode one record data """

        log.debug(f"parse rdata, rr_type={rr_type}, rdlength={rdlength}, rdata_start={rdata_start}")

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
        log.warn(f"??unsupport rdata??")
        return 'RDLENGTH {}'.format(rdlength)



    def _parse_resourceRecord(self)-> DDT.a_rr_S:
        """ one resource record """

        tmp_rr = DDT.a_rr_S()

        tmp_rr.name, _np = self._decode_name() # NAME

        tmp_rr.type, _np = self.bo.read_u16(_np) # TYPE
        tmp_rr.rr_class, _np = self.bo.read_u16(_np) # CLASS
        tmp_rr.ttl, _np = self.bo.read_u32(_np) # TTL
        tmp_rr.rdlength, _np = self.bo.read_u16(_np) # RDLENGTH
        self.pointer = _np # update

        # decode record data
        rdata_start = self.pointer
        rdata_end = rdata_start + tmp_rr.rdlength

        if rdata_end > len(self.data):
            raise malformedPkg_E.rdlength_out_of_range()

        self.pointer = rdata_end

        tmp_rr.rdata = self._parse_recordData(tmp_rr.type,
                                       tmp_rr.rdlength,
                                       rdata_start)
        
        log.debug(f"RR parsed: \
                  name={tmp_rr.name}, \
                    type={tmp_rr.type}, \
                        class={tmp_rr.rr_class}, \
                            ttl={tmp_rr.ttl}, \
                                rdlength={tmp_rr.rdlength}, \
                                    rdata={tmp_rr.rdata}"
                                    )
        return tmp_rr



    def parse(self) -> DDT.dns_request_S:
        """
        Parse full DNS message.

        This method catches malformedDNSPacket_E and still returns request.
        Caller can check:
            request.is_malformed
            request.malformed_reason
        """

        try:
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

        except malformedPkg_E as e:
            log.warn('malformed DNS packet: {}'.format(e.reason))
            malformedPkg_E.set_error_request(self.request, e)


        return self.request
