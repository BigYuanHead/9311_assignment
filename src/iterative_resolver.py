"""
Iterative DNS resolver.

Main idea:
    resolve one logical question at a time
    -> ask candidate servers in order
    -> return final answer / NODATA / NXDOMAIN
    -> follow CNAME from root when required
    -> follow referral with glue
    -> resolve NS hostname A for referral without glue
"""



import time
from dataclasses import dataclass

import configs.global_cfg as Gcfg
import src.helpers.myLogger as myL
from src.helpers.flagOpt import dnsFlag_C as FO

import dataStructures.dns_dataTypes as DDT

import src.rootHints_parser as RhP
import src.iterOpt.response_analyser as RA
import src.iterOpt.upstream_client as UC


log = myL.logger_C('', debug=Gcfg.ITEROR_DEBUG)




@dataclass
class resolveContext_DC:
    """ share all limitations """
    attempt_counter: int
    referral_counter: int
    start_time: float
    total_time: float # timeout using



class iterativeResolver_C:

    def __init__(self,
                 root_hints: RhP.rootHints_C,
                 timeout):
        
        self.root_hints = root_hints
        self.timeout = int(timeout)

        # global config
        self.max_attempts = Gcfg.MAX_ATTEMPTS
        self.max_referrals = Gcfg.MAX_REFERRALS
        self.max_cnameDepth = Gcfg.MAX_CNAME_DEPTH

        self.upstream_client = UC.upstreamClient_C()
        self.response_analyser = RA.responseAnalyser_C(
            self.max_cnameDepth
        )

    # =========== common helper ===========
    def _norm_name(self, name: str):
        return name.lower()

    def _servfail(self) -> DDT.resolutionResult_S:
        return DDT.resolutionResult_S(
            [], [], [],
            DDT.flag_respondCode_ENUM.SERVFAIL,
            aa=0
        )

    def _get_rootServer_IPs(self) -> list[str]:
        result: list[str] = []
        root_ns_records = self.root_hints.get_rootNS_records()

        for ns_record in root_ns_records:
            a_records = self.root_hints.get_records_with_name(
                ns_record.rdata
            )

            for a_record in a_records:
                result.append(a_record.rdata)

        return result

    def _build_dnsQuestion(self,
                       name: str,
                       rr_type: int,
                       rr_class: int) -> DDT.a_question_S:
        return DDT.a_question_S(
            qname=name,
            qtype=rr_type,
            qclass=rr_class
        )

    def _build_finalAnswers(self,
                             cname_chain: list[DDT.a_rr_S],
                             final_records: list[DDT.a_rr_S]
                             ) -> list[DDT.a_rr_S]:
        result: list[DDT.a_rr_S] = []

        for record in cname_chain:
            result.append(record)

        for record in final_records:
            result.append(record)

        return result

    def _get_result_AA(self,
                       response: DDT.dns_request_S,
                       cname_chain: list[DDT.a_rr_S]
                       ) -> int:
        """
            copy upstream AA only when client records
            come from this one upstream response
        """

        if len(cname_chain) > 0:
            return 0

        flags = FO.decode(response.header.flags)
        return flags.AA

    # =========== budget ===========
    def _remaining_time(self, context: resolveContext_DC) -> float:
        used_time = time.time() - context.start_time
        return context.total_time - used_time

    def _can_attempt(self, context: resolveContext_DC) -> bool:
        if context.attempt_counter >= self.max_attempts:
            log.debug('reach max attempts')
            return False

        if self._remaining_time(context) <= 0:
            log.debug('reach total timeout')
            return False

        return True

    def _consume_referral(self, context: resolveContext_DC) -> bool:
        if context.referral_counter >= self.max_referrals:
            log.debug('reach max referrals')
            return False

        context.referral_counter = context.referral_counter + 1
        return True

    # =========== nested NS lookup ===========
    def _resolve_nameServer_IPs(self,
                                ns_names: list[str],
                                rr_class: int,
                                context: resolveContext_DC
                                ) -> list[str]:
        for ns_name in ns_names:

            # starting each no-glue NS hostname lookup uses referral budget
            if not self._consume_referral(context):
                return []

            log.info('no glue, lookup {}'.format(ns_name))

            ns_question = self._build_dnsQuestion(
                ns_name,
                DDT.dnsType_ENUM.A,
                rr_class
            )

            ns_result = self._resolve_question(ns_question, context)

            if ns_result.rcode != DDT.flag_respondCode_ENUM.NOERROR:
                log.debug('NS-name lookup failed {}'.format(ns_name))
                continue

            result: list[str] = []

            for record in ns_result.answers:
                if record.rr_type == DDT.dnsType_ENUM.A:
                    result.append(record.rdata)

            if len(result) > 0:
                return result

            log.debug('NS-name lookup has no A answer {}'.format(ns_name))

        return []


    def _resolve_question(self,
                          question: DDT.a_question_S,
                          context: resolveContext_DC
                          ) -> DDT.resolutionResult_S:
        """ one logical lookup """

        # 1. start from root
        current_question = question
        candidateServer_IPs = self._get_rootServer_IPs()

        cname_chain: list[DDT.a_rr_S] = []
        visited_names: set[str] = {
            self._norm_name(question.qname) # avoid loop back
        }

        while True:
            log.debug('current question: {} type {}'.format(
                current_question.qname,
                DDT.dnsType_ENUM.mapper[current_question.qtype]
            ))
            log.debug(f"candidate server IPs: \n{candidateServer_IPs}")
            log.debug('attempts={}, referrals={}'.format(
                context.attempt_counter,
                context.referral_counter
            ))

            # STOP
            if len(candidateServer_IPs) == 0:
                log.debug('no candidate server IPs')
                return self._servfail()


            # 2. candidate NS IPs -> 
            #       find someone can answer next level rr
            for a_IP in candidateServer_IPs:

                # limit
                if not self._can_attempt(context):
                    return self._servfail()
                context.attempt_counter = context.attempt_counter + 1

                log.debug('ask {} for {} type {}'.format(
                    a_IP,
                    current_question.qname,
                    DDT.dnsType_ENUM.mapper[current_question.qtype]
                ))

                # timeout
                remaining_time = self._remaining_time(context)
                if remaining_time <= 0:
                    return self._servfail()

                # 3. ask upstream once
                query_timeout = min(self.timeout, remaining_time)
                response = self.upstream_client.ask(
                    a_IP,
                    current_question,
                    query_timeout
                )

                # respond not vaild
                if response is None:
                    log.debug('no usable response from {}'.format(a_IP))
                    continue

                # ******** respond vaild ********
                rcode = FO.get_rcode(response.header.flags)
                log.debug('response from {}, rcode={}, answer={}, authority={}, additional={}'.format(
                    a_IP,
                    rcode,
                    len(response.answers),
                    len(response.authority),
                    len(response.additional)
                ))

                ## terminal NXDOMAIN for this logical lookup
                if rcode == DDT.flag_respondCode_ENUM.NXDOMAIN:
                    # NOT AA
                    if FO.is_authoritative(response.header.flags) is False:
                        log.debug('ignore non-authoritative NXDOMAIN')
                        continue
                    # IS AA
                    log.info('NXDOMAIN for {}'.format(current_question.qname))
                    result_AA = self._get_result_AA(
                        response,
                        cname_chain
                    )
                    # END - AA no rr
                    return DDT.resolutionResult_S(
                        cname_chain,
                        [],
                        [],
                        DDT.flag_respondCode_ENUM.NXDOMAIN,
                        aa=result_AA
                    )

                ## ERROR
                if rcode != DDT.flag_respondCode_ENUM.NOERROR:
                    log.debug('skip server {}, rcode={}'.format(
                        a_IP,
                        rcode
                    ))
                    continue

                # >>>>>>>>>>>>>>>>> final answer or CNAME path >>>>>>>>>>>>>>>>>
                answer_path = self.response_analyser.find_answer_path(
                    response,
                    current_question,
                    len(cname_chain),
                    visited_names
                )

                if answer_path.invalid_reason is not None:
                    log.warn('[cname] {}'.format(
                        answer_path.invalid_reason
                    ))
                    continue

                ## $$$$$$$$ [ - END - ] Get Final answer $$$$$$$$
                if answer_path.is_final:
                    final_answers = self._build_finalAnswers(
                        cname_chain,
                        answer_path.records
                    )

                    log.success('final answer found for {}, type: {}, count={}'.format(
                        current_question.qname,
                        DDT.dnsType_ENUM.mapper[current_question.qtype],
                        len(final_answers)
                    ))

                    result_AA = self._get_result_AA(
                        response,
                        cname_chain
                    )

                    return DDT.resolutionResult_S(
                        final_answers,
                        [],
                        [],
                        DDT.flag_respondCode_ENUM.NOERROR,
                        aa=result_AA
                    )

                ## no final answer, BUT CNAME !!
                if answer_path.next_name is not None:
                    for record in answer_path.records:
                        cname_chain.append(record)

                    visited_names = answer_path.visited_names

                    log.info('[cname] chase {} -> {}'.format(
                        current_question.qname,
                        answer_path.next_name
                    ))

                    ### redirect to NEW entry -> the end of CNAME chain
                    current_question = self._build_dnsQuestion(
                        answer_path.next_name,
                        current_question.qtype,
                        current_question.qclass
                    )
                    candidateServer_IPs = self._get_rootServer_IPs()
                    break # @@@@@@ Break FOR Loop @@@@@@

                # >>>>>>>>>>>>>>>>> AA NODATA >>>>>>>>>>>>>>>>>
                ## $$$$$$$$ [ - END - ] Reach AA but no Final answer $$$$$$$$
                if self.response_analyser.is_authoritative_nodata(
                    response,
                    current_question
                ):
                    log.info('authoritative NODATA for {}'.format(
                        current_question.qname
                    ))
                    result_AA = self._get_result_AA(
                        response,
                        cname_chain
                    )
                    return DDT.resolutionResult_S(
                        cname_chain,
                        [],
                        [],
                        DDT.flag_respondCode_ENUM.NOERROR,
                        aa=result_AA
                    )

                ## >>>>>>>>>>>>>>>>> referral >>>>>>>>>>>>>>>>>
                referral = self.response_analyser.find_referral(
                    response,
                    current_question
                )

                if referral is None:
                    log.debug('no useful data from {}'.format(a_IP))
                    continue

                # following one referral uses referral budget
                if not self._consume_referral(context):
                    return self._servfail()

                # A. referral contain IPs
                if len(referral.glue_ips) > 0: 
                    log.debug("referral with glue, next name servers: \n{}".format(
                        referral.ns_names
                    ))
                    log.debug('glue servers IPs: \n{}'.format(
                        referral.glue_ips
                    ))

                    # use those IPs and enter next level
                    candidateServer_IPs = referral.glue_ips
                    break # @@@@@@ Break FOR Loop @@@@@@
                

                ### B. referral does NOT have IPs
                nextCandidateServer_IPs = self._resolve_nameServer_IPs(
                    referral.ns_names,
                    current_question.qclass,
                    context
                )

                ##### Got IPs for referral NS
                if len(nextCandidateServer_IPs) > 0:
                    log.info('NS-name lookup success, move to next servers')
                    log.debug('next candidate server IPs: \n{}'.format(
                        nextCandidateServer_IPs
                    ))

                    candidateServer_IPs = nextCandidateServer_IPs
                    break # @@@@@@ Break FOR Loop @@@@@@

                # unusable referral, try next candidate at current level
                log.debug('referral has no usable server address')
            else:
                log.warn('all candidate servers failed')
                return self._servfail()




    def resolve(self,
                question: DDT.a_question_S
                ) -> DDT.resolutionResult_S:
        """ !!! main iterative resolver entrance !!! """

        log.info('start resolve {}, type: {}'.format(
            question.qname,
            DDT.dnsType_ENUM.mapper[question.qtype]
        ))

        # init limitations
        context = resolveContext_DC(
            attempt_counter=0,
            referral_counter=0,
            start_time=time.time(),
            total_time=min(30, 50 * self.timeout)
        )


        result = self._resolve_question(question, context)

        log.debug('resolve finished, attempts={}, referrals={}'.format(
            context.attempt_counter,
            context.referral_counter
        ))

        return result
