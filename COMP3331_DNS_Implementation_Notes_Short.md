# COMP3331/9331 DNS Resolver - 实现注意点短版

> 写代码时只看这个：哪些地方最容易漏、最容易扣分。

---

## 1. 总原则

- 先写 `parser.py`，resolver 后面也要用同一套 DNS decode 逻辑。
- 不要 hard-code sample domain、server IP、TTL、packet offset。
- 最后要能在 VLAB/CSE 跑，不要依赖本机 package / venv / IDE。
- resolver 正常运行时不要 `print()` debug，不要 `input()`，不要随便 `sleep()`。

---

## 2. 不能用的东西

不要用：

```text
dnspython
dns.resolver
dns.message
gethostbyname()
getaddrinfo()
dig/nslookup inside code
subprocess 调 dig/nslookup
DNS parser / resolver / cache framework
```

socket 发包时不要传域名：

```python
# wrong
sock.sendto(packet, ("a.root-servers.net", 53))

# right
sock.sendto(packet, ("198.41.0.4", 53))
```

---

## 3. 支持范围

client query 只需要支持：

```text
UDP
IPv4
QDCOUNT = 1
QCLASS = IN
QTYPE = A / NS / CNAME / PTR / MX
```

对应数字：

```text
A      = 1
NS     = 2
CNAME  = 5
PTR    = 12
MX     = 15
IN     = 1
```

如果 client 问不支持的 type，返回：

```text
SERVFAIL, RCODE = 2
```

不用做：

```text
TCP fallback
IPv6 / AAAA
DNSSEC
EDNS(0)
DoH / DoT
international domain name
authoritative server
disk cache
all record types
```

---

## 4. DNS name / compression 注意点

普通 name：

```text
www.example.com. -> 03 www 07 example 03 com 00
```

compression pointer：

```text
C0 0C -> jump to offset 12
```

实现 name decoder 时注意：

- `00` 结束。
- top two bits `00` 是普通 label。
- top two bits `11` 是 pointer。
- pointer 解完后，当前读取位置只前进 2 bytes。
- 防止 pointer loop。
- pointer 最多跳 20 次。
- label 不能超过 63 bytes。
- name 总长度不能超过 255 bytes。
- RDATA 里的 name 可以压缩。
- **RR 的下一个 offset 永远由 RDLENGTH 决定**，不要被 pointer target 带跑。

---

## 5. Parser 必做

`parser.py`：

```bash
python3 parser.py message_file
```

必须打印这些 heading：

```text
--- FLAGS ---
--- COUNTS ---
--- QUESTIONS ---
--- ANSWERS ---
--- AUTHORITY ---
--- ADDITIONAL ---
```

必须解析：

- Header
- Flags
- Counts
- 所有 Questions，不要假设 parser 永远 QDCOUNT = 1
- Answer / Authority / Additional records
- A / NS / CNAME / PTR / MX
- unsupported type 要按 RDLENGTH 跳过，不能崩

RDATA 注意：

```text
A: RDLENGTH = 4, IPv4
NS/CNAME/PTR: 一个 domain name
MX: 2 bytes preference + domain name
OPT: TYPE 41，当 unsupported 跳过
```

---

## 6. Resolver Stage 2 必做

`resolver.py`：

```bash
python3 resolver.py root_hints_file timeout listen_port
```

必须 bind：

```text
127.0.0.1:<listen_port>
```

必须 parse `named.root`，不能 hard-code root server。

Stage 2 local positive answer 只有两个：

```text
. NS
root-server-name A
```

`. NS` response：

```text
Answer: root NS records
Authority: empty
Additional: matching root server A records
```

`a.root-servers.net A` response：

```text
Answer: matching A records
Authority: empty
Additional: empty
```

---

## 7. Client-facing response header 规则

这是最容易扣分的地方。

你的 resolver 回给 client 的 response 必须：

```text
ID      = copy client ID
OPCODE  = copy client OPCODE
QR      = 1
RD      = copy client RD
RA      = 1
AA      = 大部分 0；直接来自 authoritative upstream response 才 copy AA
TC      = 0
Z/AD/CD = 0
RCODE   = success/NODATA 0, SERVFAIL 2, NXDOMAIN 3
QDCOUNT = 1
ANCOUNT = 实际 encode 的 Answer 数量
NSCOUNT = 实际 encode 的 Authority 数量
ARCOUNT = 实际 encode 的 Additional 数量
```

Question section 要保留原问题：

```text
same QNAME
same QTYPE
same QCLASS
```

不能直接把 upstream response 原封不动发给 client。

---

## 8. Stage 3 iterative resolver 注意点

对普通 query：

```text
client -> your resolver
your resolver -> root
root -> referral to TLD
your resolver -> TLD
TLD -> referral to authoritative
your resolver -> authoritative
authoritative -> final answer
your resolver -> client
```

upstream query 必须：

```text
RD = 0
QDCOUNT = 1
ANCOUNT/NSCOUNT/ARCOUNT = 0
send to server IP, port 53
use your own 16-bit transaction ID
no EDNS OPT record
```

用 upstream response 前检查：

```text
QR = 1
OPCODE = 0
TC = 0
QDCOUNT = 1
source IP/port match
transaction ID match
question name/type/class match
RDLENGTH boundaries valid
```

---

## 9. Referral 处理

如果 response 是 referral：

```text
Authority section 有 NS
Additional section 可能有 matching A glue
```

处理顺序：

1. 按 Authority NS wire order 看。
2. 找 Additional 里 owner name 匹配这个 NS name 的 A glue。
3. 有 glue：用 glue IP 问下一个 server。
4. 没 glue：nested A lookup，重新从 root hints 查这个 NS name 的 A。

限制：

```text
最多 50 次 outbound attempts
最多 10 层 referral
超过就 SERVFAIL
```

不要把中间 referral 直接返回给 client。

---

## 10. CNAME 处理

如果 client 问：

```text
A / NS / MX / PTR
```

但 authoritative response 给了 CNAME，没有最终 requested type：

```text
继续查 CNAME target 的原始 QTYPE
```

最终 response：

```text
CNAME chain first
then final requested-type records
```

如果 client 直接问：

```text
CNAME
```

那就：

```text
返回 original QNAME 的 CNAME
不要 chase target
```

限制：

```text
CNAME chain 最多 10
发现 loop -> SERVFAIL
```

---

## 11. Cache 注意点

必须 cache 至少：

```text
successful client response 里用到的 positive answer records
followed CNAME records
```

cache key 至少：

```text
(lowercase fully-qualified name, type, class)
```

TTL：

```text
expiry = now + TTL
returned TTL = floor(expiry - now)
TTL <= 0 就过期
TTL = 0 不要 reuse
```

CNAME cache 注意：

```text
不能只 cache final target
要能从 original name 重建完整 CNAME chain
任何一环过期/缺失，就重新 upstream 查
```

如果多线程，cache 要加 lock。

---

## 12. Timeout / error 注意点

`timeout` 是每个 upstream response 等待时间。

一个 client request 总时间最多：

```text
min(30 seconds, 50 * timeout)
```

这些情况当成 candidate server failed，试下一个：

```text
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

不要还有 candidate 没试就立刻 SERVFAIL。

---

## 13. Concurrency 注意点

resolver 要能同时处理多个 client。

每个 request 的这些状态要分开：

```text
client address/port
client transaction ID
original question
current query
upstream transaction ID
candidate servers
attempt count
referral depth
CNAME depth
deadline
```

不能让一个慢 DNS lookup 卡住所有其他 client。

---

## 14. 最后测试清单

Parser：

```bash
python3 parser.py sample-query.bin
python3 parser.py sample-response.bin
```

Resolver Stage 2：

```bash
python3 resolver.py named.root 2 53000
dig +noedns @127.0.0.1 -p 53000 . NS
dig +noedns @127.0.0.1 -p 53000 a.root-servers.net A
```

Resolver Stage 3：

```bash
dig +noedns @127.0.0.1 -p 53000 unsw.edu.au A
dig +noedns @127.0.0.1 -p 53000 example.com MX
```

还要测：

```text
same query twice -> cache hit
unsupported QTYPE -> SERVFAIL
timeout / wrong response -> try next / SERVFAIL
multiple clients at same time
```

提交前必须在 VLAB/CSE 测一次。
