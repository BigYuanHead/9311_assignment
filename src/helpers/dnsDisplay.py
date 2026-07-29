import dataStructures.dns_dataTypes as DDT


class dnsDisplay_C:

    def __init__(self, request: DDT.dns_request_S):
        self.request = request

    def _print_malformed(self):
        print('--- MALFORMED DNS PACKET ---')

        if hasattr(self.request, 'malformed_reason'):
            print('Reason: {}'.format(self.request.malformed_reason))
        else:
            print('Reason: unknown')

        if hasattr(self.request, 'header'):
            print('ID: {}'.format(self.request.header.id))

        print()


    def _type_name(self, t: int):
        """ incase unknow type name happened """
        if t in DDT.dnsType_ENUM.mapper:
            return DDT.dnsType_ENUM.mapper[t]
        else:
            return 'TYPE: {}'.format(t)

    def _class_name(self, c: int):
        """ incase unknow class happened """
        if c in DDT.dnsClass_ENUM.mapper:
            return DDT.dnsClass_ENUM.mapper[c]
        else:
            return 'CLASS: {}'.format(c)


    def _print_flags(self):
        flags = self.request.header.flag_readable
        id = self.request.header.id
        rcode = DDT.flag_respondCode_ENUM.mapper.get(
            flags.RCODE,
            str(flags.RCODE)
        )

        print('ID: {}'.format(id))
        print('--- FLAGS ---')
        print('QR: {}'.format(bool(flags.QR)))
        print('Opcode: {}'.format(flags.Opcode))
        print('AA: {}'.format(bool(flags.AA)))
        print('TC: {}'.format(bool(flags.TC)))
        print('RD: {}'.format(bool(flags.RD)))
        print('RA: {}'.format(bool(flags.RA)))
        print('RCODE: {}'.format(rcode))
        print()

    def _print_counts(self):
        print('--- COUNTS ---')
        print('Questions: {}'.format(self.request.header.qdCount))
        print('Answers: {}'.format(self.request.header.anCount))
        print('Authority: {}'.format(self.request.header.nsCount))
        print('Additional: {}'.format(self.request.header.arCount))
        print()

    def _print_questions(self):
        print('--- QUESTIONS ---')

        for q in self.request.questions:
            line = '{} {} {}'.format(
                q.qname,
                self._class_name(q.qclass),
                self._type_name(q.qtype)
            )
            print(line)
        print()

    def _print_rr_list(self, title: str, rr_list: list[DDT.a_rr_S]):
        print(title)

        for rr in rr_list:
            line = '{} {} {} {} {}'.format(
                rr.name,
                rr.ttl,
                self._class_name(rr.rr_class),
                self._type_name(rr.rr_type),
                rr.rdata
            )
            print(line)
        print()

    def display(self):

        # handle malformed
        if self.request.is_malformed is True:
            self._print_malformed()
            return

        self._print_flags()
        self._print_counts()
        self._print_questions()
        self._print_rr_list('--- ANSWERS ---', self.request.answers)
        self._print_rr_list('--- AUTHORITY ---', self.request.authority)
        self._print_rr_list('--- ADDITIONAL ---', self.request.additional)
