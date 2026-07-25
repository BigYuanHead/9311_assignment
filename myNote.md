1. no-glue nested A lookup
2. CNAME chasing
3. authoritative NODATA
4. 完整 cache chain
5. concurrency 接入



1. 有 requested answer
   -> 如果是 nested A lookup，就 resume 原问题
   -> 否则 final answer = CNAME chain + answers

2. 没有 requested answer
   -> 先检查 CNAME chasing

3. 没有 CNAME
   -> 检查 authoritative NODATA

4. 都不是
   -> 检查 referral / no-glue nested A lookup