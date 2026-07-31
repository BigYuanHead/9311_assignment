
import configs.global_cfg as Gcfg
import src.helpers.myLogger as myL


import dataStructures.dns_dataTypes as DDT

log = myL.logger_C('', debug=Gcfg.RESOLVER_DEBUG)


class rootHints_C:
    """ put all root hints records """

    def __init__(self, filename: str):
        self.filename = filename

        # parser storages
        self.ns_records: list[DDT.a_rr_S] = []
        self.a_records: list[DDT.a_rr_S] = []
        self.current_ttl: int = 0

    # =========== helper func ===========
    def _clean_line(self, line: str) -> str:
        if ';' in line: # remove comment
            line = line.split(';', 1)[0]

        line = line.strip() # remove spaces
        return line

    def _is_number(self, text: str) -> bool:
        return text.isdigit()

    def _norm_name(self, name: str) -> str:
        return name.lower() # case insensitive

    def _parse_TTLline(self, parts: list[str]) -> None:
        if len(parts) >= 2 and self._is_number(parts[1]):
            self.current_ttl = int(parts[1])


    # ============ parse =============
    def _parse_one_recordLine(self, parts: list[str]) -> None:

        owner_name = parts[0]
        
        ttl = None
        rr_class = None
        rr_type = None
        rdata = None

        rdata_idx = None

        # TTL and IN can appear before type, in either order
        for idx, item in enumerate(parts[1:], start=1):

            upper_item = item.upper()

            if self._is_number(item):
                ttl = int(item)

            elif upper_item == 'IN':
                rr_class = DDT.dnsClass_ENUM.IN

            else:
                rr_type = upper_item
                rdata_idx = idx + 1
                break

        if ttl is None:
            ttl = self.current_ttl

        if rr_class is None:
            rr_class = DDT.dnsClass_ENUM.IN

        if rdata_idx is not None and rdata_idx < len(parts):
            rdata = parts[rdata_idx]
        else:
            return

        if rr_type == 'NS':
            record = DDT.a_rr_S(
                name=owner_name,
                rr_type=DDT.dnsType_ENUM.NS,
                rr_class=rr_class,
                ttl=ttl,
                rdata=rdata
            )
            self.ns_records.append(record)

        elif rr_type == 'A':
            record = DDT.a_rr_S(
                name=owner_name,
                rr_type=DDT.dnsType_ENUM.A,
                rr_class=rr_class,
                ttl=ttl,
                rdata=rdata
            )
            self.a_records.append(record)


    def parse(self) -> None:
        """ resolve root hints and storage in this parser """
        with open(self.filename, 'r') as file:
            for line in file:

                line = self._clean_line(line)

                # ignore blank lines
                if line == '':
                    continue

                parts = line.split()

                # directive
                if parts[0].upper() == '$TTL':
                    self._parse_TTLline(parts)
                    continue

                self._parse_one_recordLine(parts)


    def get_rootNS_records(self) -> list[DDT.a_rr_S]:
        """ return root NS records in file order """

        result: list[DDT.a_rr_S] = []
        for record in self.ns_records:
            if self._norm_name(record.name) == '.':
                result.append(record)

        return result

    def get_records_with_name(self, name: str) -> list[DDT.a_rr_S]:
        """ NS -> A records """

        result: list[DDT.a_rr_S] = []
        check_name = self._norm_name(name)

        for record in self.a_records:
            if self._norm_name(record.name) == check_name:
                result.append(record)

        return result

    def find_local_result(self, question: DDT.a_question_S) -> DDT.resolutionResult_S | None:
        """ find local answer from parsed root hints """

        answers: list[DDT.a_rr_S] = []
        authority: list[DDT.a_rr_S] = []
        additional: list[DDT.a_rr_S] = []

        qname = self._norm_name(question.qname)

        # QNAME:.  +  QTYPE NS
        if qname == '.' and question.qtype == DDT.dnsType_ENUM.NS:
            answers = self.get_rootNS_records()

            for ns_record in answers:
                a_records = self.get_records_with_name(ns_record.rdata)
                for a_record in a_records:
                    additional.append(a_record)

            return DDT.resolutionResult_S(
                answers,
                authority,
                additional,
                DDT.flag_respondCode_ENUM.NOERROR,
                aa=0
            )

        # QNAME: root server name + QTYPE A
        if question.qtype == DDT.dnsType_ENUM.A:
            answers = self.get_records_with_name(question.qname)

            if len(answers) > 0:
                return DDT.resolutionResult_S(
                    answers,
                    authority,
                    additional,
                    DDT.flag_respondCode_ENUM.NOERROR,
                    aa=0
                )

        return None
