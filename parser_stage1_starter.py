import sys
import struct
import os
from dataclasses import dataclass

# -------- logger --------
SEP_LINE = '-'*20


# ----------------- mapper -----------------
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


# ----------------- data structure -----------------
@dataclass
class question_C:
    qname: str
    qtype: int
    qclass: int


@dataclass
class resourceRecord_C:
    name: str
    type: int
    rr_class: int
    ttl: int
    rdlength: int
    rdata: str




class dnsParser_C:

    def __init__(self, filename: str):

        self.filename = filename

        self.data = b''
        with open(filename, 'rb') as file:
            self.data = file.read()

        self.pos = 0 # data pointer

        # header section fields
        self.id = 0
        self.flags = 0

        self.qdCount = 0
        self.anCount = 0
        self.nsCount = 0
        self.arCount = 0

        # sections contents
        self.questions: list[resourceRecord_C] = []
        self.answers: list[resourceRecord_C] = []
        self.authority: list[resourceRecord_C] = []
        self.additional: list[resourceRecord_C] = []


    def _read_u8(self, pos=None):
        """ read 1 byte """

        if pos is None:
            pos = self.pos
            self.pos = self.pos + 1

        return self.data[pos]


    def _read_u16(self):
        """ get 2 bytes """

        # ! = network byte order，也就是大端序
        # H = unsigned short，也就是 2 bytes 无符号整数
        value = struct.unpack('!H', self.data[self.pos:self.pos+2])[0]
        self.pos = self.pos + 2
        return value


    def _read_u32(self):
        """ read 4 bytes """

        value = struct.unpack('!I', self.data[self.pos:self.pos+4])[0]
        self.pos = self.pos + 4
        return value


    def _type_name(self, t: int):
        """ type number -> name """

        if t in dnsType_C.mapper:
            return dnsType_C.mapper[t]
        else:
            return 'TYPE{}'.format(t)


    def _class_name(self, c: int):
        """ class number -> name """

        if c in dnsClass_C.mapper:
            return dnsClass_C.mapper[c]
        else:
            return 'CLASS{}'.format(c)


    def _rcode_name(self, rcode: int):
        """ rcode number -> name """

        if rcode == 0:
            return 'NOERROR'
        elif rcode == 2:
            return 'SERVFAIL'
        elif rcode == 3:
            return 'NXDOMAIN'
        else:
            return 'RCODE{}'.format(rcode)


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
            pos = self.pos
        else:
            pos = start_pos

        labels = []

        while True:
            length = self.data[pos]
            pos = pos + 1 # move out from the length byte

            # end of name
            if length == 0:
                break

            if length & 0xC0 == 0xC0: # hit compression pointer
                pointer = ((length & 0x3F) << 8) | self.data[pos] # offset calcu
                pos += 1 # skip 0x0C
                pointed_name, _ = self._decode_name(pointer)
                if pointed_name != '.':
                    labels.extend(pointed_name[:-1].split('.'))
                break

            # simple normal label only
            label_bytes = self.data[pos:pos+length]
            label = label_bytes.decode(errors='replace') # decode as ASCII
            labels.append(label)
            pos = pos + length

        if len(labels) == 0:
            name = '.'
        else:
            name = '.'.join(labels) + '.'

        if start_pos is None:
            self.pos = pos

        return name, pos


    def _parse_header(self):
        """ 
            12 bytes header 
            ID FLAGS QDCOUNT ANCOUNT NSCOUNT ARCOUNT
        """

        self.id = self._read_u16()
        self.flags = self._read_u16()

        self.qdCount = self._read_u16()
        self.anCount = self._read_u16()
        self.nsCount = self._read_u16()
        self.arCount = self._read_u16()


    def _get_flags(self):
        """ split flags """

        flags = {}

        flags['QR'] = (self.flags >> 15) & 1
        flags['Opcode'] = (self.flags >> 11) & 0xF
        flags['AA'] = (self.flags >> 10) & 1
        flags['TC'] = (self.flags >> 9) & 1
        flags['RD'] = (self.flags >> 8) & 1
        flags['RA'] = (self.flags >> 7) & 1
        flags['RCODE'] = self.flags & 0xF

        return flags


    def _parse_question(self):
        """ 
            one question

            QNAME QTYPE QCLASS
        """

        qname, _ = self._decode_name()
        qtype = self._read_u16()
        qclass = self._read_u16()

        return question_C(qname, qtype, qclass)


    def _parse_recordData(self, rr_type: int, rdlength: int, rdata_start: int):
        """ decode one record data """

        # A
        if rr_type == dnsType_C.A and rdlength == 4: #4 bytes
            ip_bytes = self.data[rdata_start:rdata_start+4]
            rdata = '{}.{}.{}.{}'.format(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
            return rdata

        # NS / CNAME / PTR
        if rr_type in (dnsType_C.NS, dnsType_C.CNAME, dnsType_C.PTR) and rdlength > 0:
            name, next_pos = self._decode_name(rdata_start)
            if next_pos <= rdata_start + rdlength:
                return name

        # MX
        if rr_type == dnsType_C.MX and rdlength > 2:
            preference = struct.unpack_from('!H', self.data, rdata_start)[0]
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

        rr_type = self._read_u16()
        rr_class = self._read_u16()
        ttl = self._read_u32()
        rdlength = self._read_u16()

        # decode record data
        rdata_start = self.pos
        rdata_end = rdata_start + rdlength

        rdata = self._parse_recordData(rr_type, rdlength, rdata_start)

        self.pos = rdata_end

        return resourceRecord_C(name, rr_type, rr_class, ttl, rdlength, rdata)



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


    def _print_flags(self):
        """ print flags """

        flags = self._get_flags()

        print('ID: {}'.format(self.id))
        print('--- FLAGS ---')
        print('QR: {}'.format(bool(flags['QR'])))
        print('Opcode: {}'.format(flags['Opcode']))
        print('AA: {}'.format(bool(flags['AA'])))
        print('TC: {}'.format(bool(flags['TC'])))
        print('RD: {}'.format(bool(flags['RD'])))
        print('RA: {}'.format(bool(flags['RA'])))
        print('RCODE: {}'.format(self._rcode_name(flags['RCODE'])))


    def _print_counts(self):
        """ print counts """

        print('--- COUNTS ---')
        print('Questions: {}'.format(self.qdCount))
        print('Answers: {}'.format(self.anCount))
        print('Authority: {}'.format(self.nsCount))
        print('Additional: {}'.format(self.arCount))


    def _print_questions(self):
        """ print questions """

        print('--- QUESTIONS ---')

        for q in self.questions:
            line = '{} {} {}'.format(
                q.qname,
                self._class_name(q.qclass),
                self._type_name(q.qtype)
            )
            print(line)


    def _print_rr_list(self, 
                       title: str, 
                       rr_list: list[resourceRecord_C]):
        """ print rr section """

        print(title)

        for rr in rr_list:
            line = '{} {} {} {} {}'.format(
                rr.name,
                rr.ttl,
                self._class_name(rr.rr_class),
                self._type_name(rr.type),
                rr.rdata
            )
            print(line)


    def display(self):
        """ display result """

        self._print_flags()
        self._print_counts()
        self._print_questions()
        self._print_rr_list('--- ANSWERS ---', self.answers)
        self._print_rr_list('--- AUTHORITY ---', self.authority)
        self._print_rr_list('--- ADDITIONAL ---', self.additional)


def main(filename=None):

    if filename is None:
        if len(sys.argv) != 2:
            print('Usage: python3 parser.py message_file')
            return
        filename = sys.argv[1]  

    parser = dnsParser_C(filename)
    parser.parse()
    parser.display()




if __name__ == '__main__':

    folder = 'dns-assignment-resources'
    bin_files = []

    # collect all .bin files
    for filename in os.listdir(folder):
        if filename.endswith('.bin'):
            full_path = os.path.join(folder, filename)
            bin_files.append(full_path)

    bin_files.sort()

    if len(bin_files) == 0:
        print('No .bin files found in {}'.format(folder))
    else:
        print('Available DNS message files:')
        print(SEP_LINE)

        for idx in range(len(bin_files)):
            print('{}: {}'.format(idx + 1, bin_files[idx]))

        print(SEP_LINE)
        user_input = input('Choose file number: ')

        try:
            choice = int(user_input)

            if choice < 1 or choice > len(bin_files):
                print('Invalid choice')
            else:
                selected_file = bin_files[choice - 1]
                print('Selected: {}'.format(selected_file))
                print(SEP_LINE)
                main(selected_file)

        except ValueError:
            print('Please enter a number')
