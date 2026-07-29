
import configs.global_cfg as Gcfg
import src.helpers.myLogger as myL


import dataStructures.dns_dataTypes as DDT

log = myL.logger_C('', debug=Gcfg.RESOLVER_DEBUG)


class rootHints_C:
    """
        put all root hints records in here
    """

    def __init__(self, filename):
        self.filename = filename
        self.ns_records = []
        self.a_records = []
        self.current_ttl = 0

    # =========== helper func ===========
    def _clean_line(self, line):
        if ';' in line: # remove comment
            line = line.split(';', 1)[0]

        line = line.strip() # remove spaces
        return line

    def _is_number(self, text):
        return text.isdigit()

    def _norm_name(self, name):
        return name.lower() # case insensitive

    def _parse_TTLline(self, parts):
        if len(parts) >= 2 and self._is_number(parts[1]):
            self.current_ttl = int(parts[1])


    # ============ parse =============
    def _parse_one_recordLine(self, parts):

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
            record = DDT.rootRecord_S(
                owner_name,
                ttl,
                rr_class,
                DDT.dnsType_ENUM.NS,
                rdata
            )
            self.ns_records.append(record)

        elif rr_type == 'A':
            record = DDT.rootRecord_S(
                owner_name,
                ttl,
                rr_class,
                DDT.dnsType_ENUM.A,
                rdata
            )
            self.a_records.append(record)


    def parse(self):

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


    def get_rootNS_records(self):
        """return root NS records in file order"""

        result = []
        for record in self.ns_records:
            if self._norm_name(record.name) == '.':
                result.append(record)

        return result

    def get_records_with_name(self, name):
        """ NS -> A records """

        result = []
        check_name = self._norm_name(name)

        for record in self.a_records:
            if self._norm_name(record.name) == check_name:
                result.append(record)

        return result