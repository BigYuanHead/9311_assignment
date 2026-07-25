
import sys
import socket

import src.helpers.myLogger as myL

import dataStructures.dns_dataTypes as DDT

import src.rootHints_parser as RhP
import src.request_parser as RP
import src.respond_builder as RB
import src.iterative_resolver as IR
from src import caching



log = myL.logger_C('RESOLVER', debug=True)


class resolver_C:

    def __init__(self, root_hints_file, timeout, listen_port):

        self.timeout = int(timeout)
        self.listen_port = int(listen_port)
        
        # root hints
        self.root_hints_file = root_hints_file
        self.root_hints = RhP.rootHints_C(root_hints_file)
        self.root_hints.parse()

        # modules
        self.response_builder = RB.dnsResponseBuilder_C()
        self.cache = caching.dnsCache_C()
        self.iterative_resolver = IR.iterativeResolver_C(self.root_hints, self.timeout)

        # UDP
        ## bring up UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', self.listen_port))
        log.info('Resolver listening on 127.0.0.1:{}'.format(self.listen_port))



    def _norm_name(self, name):
        return name.lower()

    def _find_rootHints_records(self, question: DDT.question_S):
        """return answers, authority, additional for local answers"""

        answers = []
        authority = []
        additional = []

        qname = self._norm_name(question.qname)

        # QNAME ., QTYPE NS
        if qname == '.' and question.qtype == DDT.dnsType_ENUM.NS:
            answers = self.root_hints.get_rootNS_records()

            for ns_record in answers:
                a_records = self.root_hints.get_records_with_name(ns_record.rdata)
                for a_record in a_records:
                    additional.append(a_record)

            return answers, authority, additional

        # QNAME root-server-name, QTYPE A
        if question.qtype == DDT.dnsType_ENUM.A:
            answers = self.root_hints.get_records_with_name(question.qname)
            return answers, authority, additional

        return answers, authority, additional


    def _handle_query(self, query_data: bytes):
        """
            inbounce query will be processed in here
        """

        # parse a query
        parser = RP.dnsParser_C(filename=None, data=query_data)
        parser.parse()

        # if query question empty, return SERVFAIL
        if len(parser.questions) == 0:
            return self.response_builder.build_response(parser, [], [], [], rcode=2)

        question = parser.questions[0]

        # 1. if root require -> find in local root hints file
        answers, authority, additional = self._find_rootHints_records(question)

        if len(answers) > 0:
            log.success('answer from root hints')
            return self.response_builder.build_response(
                parser,
                answers,authority,
                additional,
                rcode=0
            )
        

        # 2. if Cache?
        cached_answers = self.cache.get(
            question.qname,
            question.qtype,
            question.qclass
        )

        if cached_answers is not None:
            log.success('cache hit')
            return self.response_builder.build_response(
                parser,
                cached_answers,
                [],
                [],
                rcode=0
            )

        # 3. Iterative resolver
        log.info('NO cache, start iterative resolution')

        result = self.iterative_resolver.resolve(question)

        # 4. Cache positive answer
        if result.rcode == 0 and len(result.answers) > 0:
            self.cache.put_answer_records(result.answers)
            log.success('answer cached')

        # 5. fresh response
        return self.response_builder.build_response(
            parser,
            result.answers,
            result.authority,
            result.additional,
            rcode=result.rcode
        )


    def start(self):
        """
            bringup multi thread
        """
        while True:
            query_data, client_address = self.sock.recvfrom(512)

            try:
                response_data = self._handle_query(query_data)
            except Exception as e:
                raise e
                # log.warn('resolver warning: {}'.format(e))
                # continue

            self.sock.sendto(response_data, client_address)



