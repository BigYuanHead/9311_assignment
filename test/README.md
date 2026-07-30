# DNS resolver tests

Run the complete deterministic test suite from the project root:

```bash
python3 test/run_tests.py
```

The tests use only the Python standard library. Upstream DNS communication is
tested with fake UDP sockets, so the suite does not require internet access or
the operating system DNS resolver.

Test groups:

- `test_parser.py`: released binary messages, compression, malformed names,
  `RDLENGTH`, unknown records, and display output.
- `test_root_and_response.py`: root hints parsing, local answers, response
  flags, counts, supported record encoding, and UDP response size.
- `test_cache.py`: cache keys, TTL reduction, expiry, TTL zero, full CNAME
  chains, and copy isolation.
- `test_response_analyser.py`: final answers, CNAME rules, NODATA, referrals,
  glue matching, and wire order.
- `test_iterative_resolver.py`: candidates, referrals, nested no-glue lookups,
  CNAME resolution, terminal responses, limits, and client section filtering.
- `test_upstream_client.py`: upstream query flags, UDP matching, malformed and
  truncated responses, error RCODEs, and timeouts.
- `test_dns_resolver.py`: root/cache/iterative dispatch, SERVFAIL paths,
  loopback binding, caching integration, and exception isolation.
- `test_entrypoints.py`: parser command-line behaviour.

Concurrency tests should be added after the resolver concurrency model is
implemented.

Current known failure:

- `test_root_ns_response_fits_non_EDNS_UDP_limit`: the complete local `. NS`
  response is currently 862 bytes because outgoing DNS name compression has
  not been implemented. The assignment limit is 512 bytes for this non-EDNS
  client response.
