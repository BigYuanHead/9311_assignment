
# Quality Functions

## client query scope:
```
    UDP
    IPv4
    syntactically valid DNS message
    QR = 0
    OPCODE = 0
    RD = 1
    QDCOUNT = 1
    QCLASS = IN
    QTYPE = A / NS / CNAME / PTR / MX
```
for unsupport QTYPE
SERVFAIL, RCODE = 2

## root hints query and answer

. NS
root-server-name A

root question direct answer, no upstream pkg

e.g.
. NS:
    Answer = root NS records
    Additional = matching root server A glue
    Authority = empty

root-server-name A:
    Answer = matching A record
    Authority = empty
    Additional = empty

## normal query
receive client query
parse query
if root-hints local answer exists:
    answer locally
else if valid cache entry exists:
    answer from cache
else:
    perform iterative resolution
    if answer obtained:
        build response and update cache
    else:
        build SERVFAIL
send response to client

## upstream query must non-recursive

root/TLD/authoritative server query -> generate query ID
header:
```
QR = 0
OPCODE = 0
AA = 0
TC = 0
RD = 0
RA = 0
RCODE = 0
QDCOUNT = 1
ANCOUNT = 0
NSCOUNT = 0
ARCOUNT = 0
Z/AD/CD = 0
```

## upstream response
check
```
QR = 1
OPCODE = 0
TC = 0
QDCOUNT = 1
valid counts
valid RDLENGTH boundaries
Question section matches
source IP matches
source port = 53
transaction ID matches
qname/qtype/qclass match
```

## referral handling
if available:
```
non-authoritative
没有 final answer
Authority section 有 NS
Additional 可能有 matching A glue
```
- 按 Authority NS wire order 看
- 再按 Additional A glue wire order 找 matching glue
- 有 glue -> 用 glue IP 问下一个 server
- 没 glue -> nested A lookup 查 NS hostname

## CNAME handling
- if client ask: A / NS / MX / PTR
but authoritative response CNAME: keep digging

finally
```
CNAME chain first
then final requested-type records
```

- if client ask: CNAME
```
return original QNAME - CNAME
NO chase target
```
! CNAME chain MAX 10, if loop, then SERVFAIL

## final client respond reconstruction
DONT forward upstream pkg to client, since
```
transaction ID
flags
question
section counts
```
NOT the same

DO! restore original client transaction ID and question!!

# NO quality function

## Correctness


## Robustness
```
timeout
SERVFAIL
REFUSED
FORMERR
malformed
wrong transaction ID
wrong source IP/port
question mismatch
TC = 1 truncated
```
candidate server failed, but iterate all candidate server
finally SERVFAIL

## Boundedness
limitation
```
max outbound attempts = 50
max referral levels = 10
total wall-clock cap <= min(30 seconds, 50 * timeout)
CNAME chain <= 10
```
if NOT then SERVFAIL

## Performance
```
至少 cache successful client response 里的 positive answer records
包括 followed CNAME records
key 至少是 (name, type, class)
name 要 fully-qualified + case-insensitive
TTL 到期不能用
TTL = 0 不能 reuse
```

## Concurrency

## Security
```
不要接受 wrong txid response
不要接受 wrong source IP/port response
不要接受 question mismatch response
不要用 OS DNS resolver
不要 socket.sendto 域名
不要 hard-code answers
不要被 malformed packet / compression loop 卡死
```


# What I should DO

1. client-facing response builder
2. root hints local answer
3. cache lookup / update
4. iterative resolver 主循环
5. referral with glue
6. referral without glue nested lookup
7. CNAME chase
8. timeout / attempt / referral / CNAME limits
9. upstream response validation
10. concurrency + cache lock