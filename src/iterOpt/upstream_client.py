"""send one query to one upstream DNS server"""



import socket

import configs.global_cfg as Gcfg
import src.helpers.myLogger as myL
from src.helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT

import src.request_parser as RP
import src.iterOpt.upstreamQuery_builder as uQb


log = myL.logger_C('', debug=Gcfg.ITEROR_DEBUG)



class upstreamClient_C:

    def __init__(self):
        self.query_builder = uQb.upstreamQueryBuilder_C()

    def _norm_name(self, name: str) -> str:
        return name.lower()

    def _check_response(self,
                        response: DDT.dns_request_S,
                        expected_txid: int,
                        expected_question: DDT.a_question_S
                        ) -> bool:

        if response.is_malformed:
            log.debug('[upstream] malformed response')
            return False

        if response.header.id != expected_txid:
            log.debug('[upstream] txid not match')
            return False

        if not FO.is_upstreamResponse_valid(response.header.flags):
            flags = FO.decode(response.header.flags)
            log.debug('[upstream] not expected flags {}'.format(flags))
            return False

        if len(response.questions) != 1:
            log.debug('[upstream] question count not 1')
            return False

        response_question = response.questions[0]

        if self._norm_name(response_question.qname) != self._norm_name(expected_question.qname):
            log.debug('[upstream] qname not match')
            return False

        if response_question.qtype != expected_question.qtype:
            log.debug('[upstream] qtype not match')
            return False

        if response_question.qclass != expected_question.qclass:
            log.debug('[upstream] qclass not match')
            return False

        return True

    def ask(self,
            server_ip: str,
            question: DDT.a_question_S,
            query_timeout: float
            ) -> DDT.dns_request_S | None:
        txid, query_bytes = self.query_builder.build_query(
            question.qname,
            question.qtype,
            question.qclass
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(query_timeout)

        try:
            sock.sendto(query_bytes, (server_ip, 53))
            response_data, address = sock.recvfrom(4096)

            source_ip = address[0]
            source_port = address[1]

            if source_ip != server_ip:
                log.debug('[upstream] wrong source IP {}'.format(source_ip))
                return None

            if source_port != 53:
                log.debug('[upstream] wrong source port {}'.format(source_port))
                return None

            parser = RP.dnsParser_C(data=response_data)
            response = parser.parse()

            if not self._check_response(response, txid, question):
                return None

            return response

        except socket.timeout:
            log.warn('timeout from {}'.format(server_ip))
            return None

        except Exception as e:
            log.exception(e)
            return None

        finally:
            sock.close()
