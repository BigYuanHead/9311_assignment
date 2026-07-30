import socket
import time

import configs.global_cfg as Gcfg
import src.helpers.myLogger as myL
from src.helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT

import src.request_parser as RP
import src.iterOpt.upstreamQuery_builder as uQb


log = myL.logger_C('upstream', debug=Gcfg.ITEROR_DEBUG)


class upstreamClient_C:
    """ sending operations """

    def __init__(self):
        self.query_builder = uQb.upstreamQueryBuilder_C()

    def _norm_name(self, name: str) -> str:
        return name.lower()

    def _check_response(self,
                        response: DDT.dns_request_S,
                        expected_txid: int,
                        expected_question: DDT.a_question_S
                        ) -> tuple[bool, bool]:
        """
            return:
                is_matching, is_usable
        """

        if response.header.id != expected_txid:
            log.debug('txid not match')
            return False, False

        if response.is_malformed:
            log.debug('malformed matching response')
            return True, False

        if len(response.questions) != 1:
            log.debug('question count not 1')
            return True, False

        response_question = response.questions[0]

        if self._norm_name(response_question.qname) != self._norm_name(expected_question.qname):
            log.debug('qname not match')
            return False, False

        if response_question.qtype != expected_question.qtype:
            log.debug('qtype not match')
            return False, False

        if response_question.qclass != expected_question.qclass:
            log.debug('qclass not match')
            return False, False

        if not FO.is_upstreamResponse_valid(response.header.flags):
            flags = FO.decode(response.header.flags)
            log.debug('not expected flags {}'.format(flags))
            return True, False

        return True, True


    def ask(self,
            server_ip: str,
            question: DDT.a_question_S,
            query_timeout: float
            ) -> DDT.dns_request_S | None:
        """ ask upstream one question """

        txid, query_bytes = self.query_builder.build_query(
            question.qname,
            question.qtype,
            question.qclass
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        deadline = time.monotonic() + query_timeout

        try:
            sock.sendto(query_bytes, (server_ip, 53))

            while True:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    log.warn('timeout from {}'.format(server_ip))
                    return None

                sock.settimeout(remaining_time)
                response_data, address = sock.recvfrom(4096)

                # got udp frame
                source_ip = address[0]
                source_port = address[1]

                if source_ip != server_ip:
                    log.debug('ignore wrong source IP {}'.format(source_ip))
                    continue

                if source_port != 53:
                    log.debug('ignore wrong source port {}'.format(source_port))
                    continue

                # decode dns bin
                parser = RP.dnsParser_C(data=response_data)
                response = parser.parse()

                # check
                is_matching, is_usable = self._check_response(
                    response,
                    txid,
                    question
                )

                if not is_matching:
                    continue

                if not is_usable:
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
