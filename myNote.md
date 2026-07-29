# root hints workflow

root hints file
      ↓ parse()
rootHints_C
  ├── ns_records
  └── a_records
      ↓
resolver_C + iterativeResolver_C 共用

# iter resolver
iterative_resolver.py
  ├── 控制 attempt/referral/time budget
  ├── current question / candidate servers
  ├── CNAME chain
  ├── no-glue nested lookup
  └── 决定下一步
          │
          ├── upstream_client.py
          │     UDP query + validation
          │
          └── response_analyser.py
                纯 response 分析

_resolve_question()
询问 candidate server
→ NXDOMAIN
→ final answer / CNAME
→ NODATA
→ referral with glue
→ referral without glue
→ 尝试下一个 candidate
→ SERVFAIL

## 
dns_resolver
    ↓
iterativeResolver_C.resolve(question)
    ↓
_resolve_question(question, shared_context)
    ├── upstream_client.ask()
    └── response_analyser
          ├── find_answer_path()
          ├── is_authoritative_nodata()
          └── find_referral()