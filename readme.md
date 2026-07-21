client query:
只考虑 UDP
只考虑 IPv4
只考虑 QDCOUNT = 1
只考虑 QCLASS = IN
只考虑 A / NS / CNAME / PTR / MX

upstream response:
可能出现其他 record type
不认识的 type 不能崩
用 RDLENGTH 跳过
OPT TYPE41 不 cache，不转发给 client

