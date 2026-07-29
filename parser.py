import os
import sys

import src.helpers.myLogger as myL

import src.helpers.dnsDisplay as DDSP
from src.request_parser import dnsParser_C

FILE_PATH = "dns-assignment-resources/example.com-MX-12002-response.bin"

def main(filename=None):

    if filename is None:
        if len(sys.argv) != 2:
            print('Usage: python3 parser.py message_file')
            return
        filename = sys.argv[1]

    parser = dnsParser_C(filename)
    a_dns_request = parser.parse()

    display = DDSP.dnsDisplay_C(a_dns_request)
    display.display()


if __name__ == "__main__":
    main(FILE_PATH)