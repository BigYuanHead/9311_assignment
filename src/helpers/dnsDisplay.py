import src.dataStructures.dns_dataTypes as DDT


class dnsDisplay_C:

    def __init__(self, parser):
        self.parser = parser

    def _type_name(self, t: int):
        if t in DDT.dnsType_C.mapper:
            return DDT.dnsType_C.mapper[t]
        else:
            return 'TYPE{}'.format(t)

    def _class_name(self, c: int):
        if c in DDT.dnsClass_C.mapper:
            return DDT.dnsClass_C.mapper[c]
        else:
            return 'CLASS{}'.format(c)

    def _rcode_name(self, rcode: int):
        if rcode == 0:
            return 'NOERROR'
        elif rcode == 2:
            return 'SERVFAIL'
        elif rcode == 3:
            return 'NXDOMAIN'
        else:
            return 'RCODE{}'.format(rcode)

    def _print_flags(self):
        flags = self.parser._get_flags()

        print('ID: {}'.format(self.parser.id))
        print('--- FLAGS ---')
        print('QR: {}'.format(bool(flags['QR'])))
        print('Opcode: {}'.format(flags['Opcode']))
        print('AA: {}'.format(bool(flags['AA'])))
        print('TC: {}'.format(bool(flags['TC'])))
        print('RD: {}'.format(bool(flags['RD'])))
        print('RA: {}'.format(bool(flags['RA'])))
        print('RCODE: {}'.format(self._rcode_name(flags['RCODE'])))

    def _print_counts(self):
        print('--- COUNTS ---')
        print('Questions: {}'.format(self.parser.qdCount))
        print('Answers: {}'.format(self.parser.anCount))
        print('Authority: {}'.format(self.parser.nsCount))
        print('Additional: {}'.format(self.parser.arCount))

    def _print_questions(self):
        print('--- QUESTIONS ---')

        for q in self.parser.questions:
            line = '{} {} {}'.format(
                q.qname,
                self._class_name(q.qclass),
                self._type_name(q.qtype)
            )
            print(line)

    def _print_rr_list(self, title: str, rr_list: list[DDT.resourceRecord_DC]):
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
        self._print_flags()
        self._print_counts()
        self._print_questions()
        self._print_rr_list('--- ANSWERS ---', self.parser.answers)
        self._print_rr_list('--- AUTHORITY ---', self.parser.authority)
        self._print_rr_list('--- ADDITIONAL ---', self.parser.additional)