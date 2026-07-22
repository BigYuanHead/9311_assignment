
import sys
import socket

import helpers.myLogger as myL

import dataStructures.dns_dataTypes as DDT
import helpers.bytesOpt as BO

import rootHints_parser as RHp
import dnsRequest_parser as dRp
import dnsRespond_builder as dRb


log = myL.logger_C('RESOLVER', debug=True)


class resolver_C:

    def __init__(self, root_hints_file, timeout, listen_port):
        
        self.root_hints_file = root_hints_file
        self.timeout = int(timeout)
        self.listen_port = int(listen_port)

        self.root_hints = RHp.rootHints_C(root_hints_file)
        self.root_hints.parse()

        self.response_builder = dRb.dnsResponseBuilder_C()

        # bring up UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', self.listen_port))
        log.info('Resolver listening on 127.0.0.1:{}'.format(self.listen_port))



    def _norm_name(self, name):
        return name.lower()

    def _find_stage2_records(self, question: DDT.question_DC):
        """return answers, authority, additional for Stage 2 local answers"""

        answers = []
        authority = []
        additional = []

        qname = self._norm_name(question.qname)

        # QNAME ., QTYPE NS
        if qname == '.' and question.qtype == DDT.dnsType_C.NS:
            answers = self.root_hints.get_rootNS_records()

            for ns_record in answers:
                a_records = self.root_hints.get_records_with_name(ns_record.rdata)
                for a_record in a_records:
                    additional.append(a_record)

            return answers, authority, additional

        # QNAME root-server-name, QTYPE A
        if question.qtype == DDT.dnsType_C.A:
            answers = self.root_hints.get_records_with_name(question.qname)
            return answers, authority, additional

        return answers, authority, additional


    def _handle_query(self, query_data: bytes):

        # parse a query
        parser = dRp.dnsParser_C(data=query_data)
        parser.parse()

        # if query question empty, return SERVFAIL
        if len(parser.questions) == 0:
            return self.response_builder.build_response(parser, [], [], [], rcode=2)

        # 
        question = parser.questions[0]
        answers, authority, additional = self._find_stage2_records(question)

        # Stage 2 allowance: unanswered valid DNS query can be empty NOERROR
        return self.response_builder.build_response(parser, answers, authority, additional, rcode=0)


    def start(self):
        
        while True:
            query_data, client_address = self.sock.recvfrom(512)

            try:
                response_data = self._handle_query(query_data)
            except Exception as e:
                log.warn('resolver warning: {}'.format(e))
                continue

            self.sock.sendto(response_data, client_address)



def main():
    root_hints_file = sys.argv[1]
    timeout = sys.argv[2]
    listen_port = sys.argv[3]

    resolver = resolver_C(root_hints_file, timeout, listen_port)
    resolver.start()


if __name__ == '__main__':
    main()