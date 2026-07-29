# HiveRelay Blind WIRE 1.2 / ABI v3

This additive authority imports WIRE v2 ABI
`cc1abb0e24bd4c75e0cb99b824e114cf50ad91270362f39d8594a826e29d5053`
without changing it. IDs 74 and 75 remain compatibility-only and are never selectable.
The successor allocates only request ID 76 and result ID 77.

Both public records are exactly 65,536 bytes. ID 76 has a 668-byte header and
ID 77 has a 773-byte header. All unused bytes are zero. DATA is capped at
64,000 bytes. OPEN, DATA, WINDOW, and CLOSE remain the only global FORWARD
operations. POLL, ACK, and NOOP are direct-HTTPS adapter controls only.

An origin request contains a canonical 294-byte capability prefix followed by
zero exporter and signature slots. Its exporter mirror, origin commitment, and
source transform signature are also zero. This lets the browser construct and
persist the exact request before a TLS exporter exists. The source daemon alone
may transform it into the forwarded role. The transform may change only the
role byte, capability exporter and signature, exporter mirror, origin
commitment, and source-transform signature.

The stable session hash excludes live exporter and signature material. Every
later sequence binds the exact preceding TARGET_RESULT chain hash. Target
results, source pre-forward errors, and source post-forward ambiguity use three
distinct signature domains. Only a TARGET_RESULT advances the sequence or
chain. Source results retain the outstanding origin request unchanged.

ABI v3 adds HASH_DOMAIN purpose 4 and recipes 3 and 4 locally to the v3 ABI;
the frozen v1 registry is unchanged. Domains 216 through 219 cover stable
session, target-result chain, TLS-exporter context, and TLS-exporter binding.
The context and binding use separate domains and exact 72-byte and 64-byte
payloads respectively.

Source and target keep independent 16 MiB transport ledgers. An admitted
request/result exchange reserves exactly 131,072 bytes. A retained definitive
result is authenticated before live expiry, TLS, dial, or new-dispatch checks,
then must reserve one exchange in the current relay ledger. Cache retention is
inclusive through capability expiry plus 900 seconds. A cache hit with fewer
than 131,072 bytes remaining terminalizes only that local session with
`FORWARD_HTTPS_BUDGET_EXHAUSTED`; it emits no ID 77 and mutates no ledger,
cache, replay claim, or chain.

All descriptor, advertised, readiness, runtime-ready, browser-evidence, and
release-ready values remain zero or false.
