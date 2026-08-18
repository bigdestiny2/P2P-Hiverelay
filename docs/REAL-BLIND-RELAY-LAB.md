# Real local blind-relay lab

`npm run lab:blind:real` runs measured code paths rather than the fleet or capacity models. It starts several relay assemblies in one Node process and on one host, with separate store roots, store identities, signing keys, WALs, and loopback TLS edges. It writes independently allocated and encrypted fixed-class CELL copies concurrently, reads and authenticates every copy through its public edge, stops all assemblies, reassembles them against the retained stores, and repeats every integrity check. These are independent copies of one deterministic logical corpus; the lab does not exercise a network replica, placement, repair, or consensus protocol.

The machine-readable result deliberately uses the evidence class `MEASURED_LOCAL_REAL_HTTP_IPC_FILESYSTEM`. It always reports `releaseReady: false`. Admission is a synthetic adapter with no economic settlement, both production release gates are bypassed test seams, and all assemblies share one uid, process, and host. The report now splits `correctnessGateReady` from `performanceGateReady`; `localGateReady` requires both.

## Run it

```sh
npm run lab:blind:real
npm run lab:blind:real:assert
node scripts/run-real-blind-relay-lab.mjs \
  --relays 4 --records 10000 --concurrency 32 \
  --output /private/tmp/blind-real-relay-lab.json --pretty --assert-local
node scripts/verify-real-blind-relay-report.mjs \
  --input /private/tmp/blind-real-relay-lab.json \
  --require-correctness --require-performance --pretty
```

`--records` is per assembly. Every logical record gets a separately allocated and encrypted CELL copy in every assembly, so four assemblies and 10,000 records execute 40,000 durable writes, 40,000 pre-restart reads, and 40,000 recovered reads. The harness accepts up to eight assemblies and 250,000 records per assembly; those are input bounds, not capacity claims.

`--assert-correctness` and `--assert-performance` can be used independently. The local performance smoke gate requires at least 32 operations on each path, 5 staged writes/s with p99 no higher than 5 seconds, 20 reads/s with p99 no higher than 2 seconds before and after restart, and restart/recovery within 15 seconds. These deliberately broad loopback smoke thresholds detect severe regressions. They are not capacity results, Internet SLOs, or release thresholds. Tiny integration runs can pass correctness while failing only the minimum performance sample.

The verifier recomputes a key-sorted canonical SHA-256 checksum, checks the gate results against the measurements, and rejects tampering or misleading scope fields. That checksum is only integrity and a content address. It is unsigned, anyone can recompute it, and it proves no author, operator, machine, or release authenticity; signed release evidence must bind it separately.

## Exact measured boundary

- DESCRIBE.GET and DESCRIBE.CHALLENGE traverse the real self-signed loopback TLS edge, private unary IPC, coordinator, and signed descriptor/readiness code.
- CELL.PUT traverses the exported blind-edge authenticated content-stream client, the real Unix stream socket, staged parser, coordinator, WAL, and opaque filesystem store.
- CELL.GET traverses the public TLS edge, private unary IPC, coordinator, WAL-backed store, client wire decoder, hash check, and authenticated cell decryption.
- Every local assembly is cleanly closed and newly assembled against its retained store before the recovery reads.

The production edge now bridges staged public CELL.PUT into the private content stream (pow-issuance-v1 one-use public-write admission plus the staged-PUT dispatch in `packages/blind-edge/server.js`); this lab harness predates that bridge and still does not exercise or claim the public write path. It also records that ordinary blind-client CELL qualification currently refuses the signed health result because the storage engine advertises degraded integrity while final store-format, scrub, repair, and related authorities remain unpublished. The lower-level public GET exercise is explicitly labeled an unqualified local wire seam; it is useful data-plane evidence, not a client-readiness claim.

INBOX and CORE unary public execution are now assembled in the production runtime (see the readiness disclosure in `POW-ISSUANCE-V1.md` for the remaining hardening gaps); this harness does not exercise them. FORWARD is not mocked and remains an explicit blocker until its production public runtime exists.

## Evidence that is still required

The local lab does not establish real admission or settlement, a production release gate, process or host isolation, a public-CA TLS chain, independent operators, Internet latency and packet loss, a multi-relay replication/repair protocol, relay churn or partitions, kill-during-commit behavior, disk-full/corruption or resource-saturation behavior, a signed rollback, or a long soak. INBOX, CORE, and FORWARD are also unmeasured. Those gaps and the assembled runtime's exact exclusion list remain in the JSON blocker list and cannot be converted into release evidence by increasing `--records`.
