
import sys
import socket
import threading

import configs.global_cfg as Gcfg
import src.helpers.myLogger as myL

import dataStructures.dns_dataTypes as DDT

import src.rootHints_parser as RhP
import src.msg_parser as RP
import src.respond_builder as RB
import src.iterative_resolver as IR
from src import caching



log = myL.logger_C('', debug=Gcfg.RESOLVER_DEBUG)


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


    def _build_SERVFAIL(self, request: DDT.dns_request_S) -> bytes:
        return self.response_builder.build_response(
            request,
            [],
            [],
            [],
            rcode=DDT.flag_respondCode_ENUM.SERVFAIL
        )


    def _handle_query(self, query_data: bytes) -> bytes:
        """
            inbounce query will be processed in here
        """

        # parse a query
        parser = RP.dnsParser_C(filename=None, data=query_data)
        request = parser.parse()

        # if query malformed or question empty, return SERVFAIL
        if request.is_malformed or len(request.questions) == 0:
            log.warn("malformed question")
            return self._build_SERVFAIL(request)

        question = request.questions[0]

        # unsupported client QTYPE -> SERVFAIL
        if question.qtype not in DDT.dnsType_ENUM.mapper:
            log.warn(f"question type: {question.qtype} not supported")
            return self._build_SERVFAIL(request)

        # 1. if root require -> find in local root hints file
        result = self.root_hints.find_local_result(question)

        if result is not None:
            log.success('answer from root hints')

        # root hints can not answer
        else: 
            # 2. if Cache?
            cached_answers = self.cache.get_chain(question)
            if cached_answers is not None:
                log.success('cache hit full chain')
                result = DDT.resolutionResult_S(
                    cached_answers,
                    [],
                    [],
                    DDT.flag_respondCode_ENUM.NOERROR,
                    aa=0
                )
            
            else:
                # 3. Iterative resolver
                log.info('NO cache, start iterative resolution')
                result = self.iterative_resolver.resolve(question)

                # 4. Cache positive answer
                if result.rcode == DDT.flag_respondCode_ENUM.NOERROR and len(result.answers) > 0:
                    self.cache.put_chain(question, result.answers)
                    log.success('answer cached')

        # 5. build response
        return self.response_builder.build_response(
            request,
            result.answers,
            result.authority,
            result.additional,
            rcode=result.rcode,
            aa=result.aa
        )


    def _handle_client(self,
                       query_data: bytes,
                       client_address: tuple[str, int]
                       ) -> None:
        """
            one client query runs in one worker thread
        """

        try:
            response_data = self._handle_query(query_data)
        except Exception as e:
            log.exception(e)

            parser = RP.dnsParser_C(filename=None, data=query_data)
            request = parser.parse()
            response_data = self._build_SERVFAIL(request)

        try:
            self.sock.sendto(response_data, client_address)
        except Exception as e:
            log.exception(e)


    def start(self) -> None:
        """
            receive query and bring up one worker for each client
        """
        while True:
            query_data, client_address = self.sock.recvfrom(512)

            worker = threading.Thread(
                target=self._handle_client,
                args=(query_data, client_address),
                daemon=True
            )
            worker.start()
