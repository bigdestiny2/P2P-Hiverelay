# HiveRelay Blind Envelope Efficiency Plan

Status: implementation plan. It preserves the frozen public WIRE v1 authority
and does not authorize a release or fleet change.

## 1. Problem

`CellBlobV1` and public outer envelopes share 4/16/64/256-KiB and 1-MiB
boundaries. The six-byte outer header and 45-byte dispatch frame mean a complete
Cell never fits the same-sized outer class. The current client also selects one
class for both request and response, while Private IPC v2 treats a generous
16,384-byte operation cap as the actual maximum PUT receipt.

Current one-relay lower bounds are therefore:

| Operation | Request | Response | Total |
| --- | ---: | ---: | ---: |
| 4-KiB Cell GET | 16 KiB | 16 KiB | 32 KiB |
| 1-MiB Cell GET | 8 MiB | 8 MiB | 16 MiB |
| 4-KiB Cell PUT | 64 KiB | 64 KiB | 128 KiB |

At three replicas the final row is 384 KiB for one 4-KiB Cell before TLS,
retransmission, OHTTP, or Tor.

## 2. Non-negotiable safety constraints

- Do not alter WIRE v1 bytes, hashes, vectors, class IDs, media type, routes, or
  existing signed transport profiles.
- New behavior is server-first and selected only through an exact signed
  transport-profile hash on a distinct descriptor endpoint/listener authority.
  A listener has exactly one profile hash and never infers or silently switches
  response semantics from client behavior.
- Found, absent, and correlated error outcomes use the same request-bound result
  class for an operation/profile.
- No unauthenticated small request may demand a large padded response.
- Admission and accounting charge exact outer egress bytes, not logical payload.
- No app-specific class, class set, schedule, endpoint, or padding policy exists.

## 3. Phase 0 — correct planning evidence

The capacity lab now derives Cell PUT/GET ingress and egress from the exact
minimum-fitting v1 symmetric outer classes selected by the current client default.
Each operation reports mean class bytes per direction and per-touch round-trip,
plus ingress, egress, round-trip bytes, and useful-byte amplification for the
complete logical operation after replica/fanout touches. Deliberate privacy
up-classing remains an explicit unmodeled input rather than being mistaken for the
minimum.

Report v3 binds the capacity-model revision and frozen WIRE v1 authority profile,
protocol version, specification hash, ABI hash, and vector-set hash into its
scenario manifest and digest. Reports from the older logical-byte model cannot
share the corrected report identity.

All economic and year-one workload projections that used logical Cell bytes as
network bytes MUST be regenerated from the corrected report before they support
bandwidth, pricing, or operator-income decisions.

## 4. Phase 1 — compact mutation results without changing WIRE v1

Introduce the signed direct-HTTPS transport profile
`hiverelay/direct-https-compact-cell-mutation/1` and Private IPC v3. The existing
same-class profile and IPC v2 remain byte-identical.

Because a public v1 request carries no transport-profile hash, a relay advertises
the compact profile on an additional signed descriptor endpoint whose canonical
listener authority is distinct from the legacy endpoint. The old endpoint remains
available during compatibility rollout. Each listener is configured with exactly
one profile hash, and its edge/daemon readiness projection binds that same hash;
sharing one URL/port and guessing the profile from request size is forbidden. The
additional endpoint is universal for the profile and is never app-specific.

The structural maximum result sizes are:

```text
BlindReceiptV1 with durability-profile-2 witness: 1,021 bytes
BlindErrorV1:                                      8 bytes
complete receipt dispatch plus outer framing:     1,072 bytes
```

A class-1 Cell PUT with a maximum 4,096-byte admission token fits a class-2
request. Its receipt/error fits a class-1 response:

```text
current: 64 KiB request + 64 KiB response = 128 KiB/relay
compact: 16 KiB request +  4 KiB response =  20 KiB/relay
```

At three replicas this changes the exact blind-envelope lower bound from
384 KiB to 60 KiB per logical class-1 PUT, an 84.375% reduction before TLS,
retries, OHTTP, or Tor.

Private IPC v3 carries separate request/result classes and byte counts while
retaining v2 peer credentials, TLS exporter binding, readiness, replay, FIN,
half-close, EOF, staging, precommit validation, fsync, and correlation rules.

The first profile's signed allowed tuple is exactly `(CELL, PUT)` with required
admission and a generated small structural result bound. It does not authorize
Cell renew/drop, Inbox create/append/renew/close, Core mirror, or any other
mutation. Adding one of those operations requires a separately versioned
profile, exact structural bounds, descriptor tuple, vectors, and gates. Reads
remain same-class. General asymmetric reads would allow a tiny request to elicit
an 8-MiB padded `NOT_FOUND` response and are therefore forbidden until
authenticated egress reservation exists.

Required gates:

1. generated structural-bound authority and vectors;
2. exact `(CELL, PUT)` descriptor/profile rejection for every other family and
   operation, plus maximum admission-sized PUT for every Cell class;
3. profile-1 and profile-2 receipts and every correlated error;
4. separate-direction FIN, fragmentation, EOF, replay, restart, and cancellation;
5. edge/daemon atomic activation and fail-closed readiness;
6. distinct-listener profile demultiplexing and dual-endpoint rollout;
7. old-profile client/server interoperability and downgrade rejection; and
8. captured exact wire bytes matching the capacity planner.

## 5. Phase 2 — negotiated public protocol major 2

The complete correction belongs to a new `hiverelay-blind/2` protocol major,
not the existing additive WIRE 1.1/1.2 authorities whose document filenames use
`WIRE-V2` and `WIRE-V3`. Protocol major 2 uses independent request/result
classes and a universal headroom ladder:

```text
4 KiB
8 KiB
16 KiB
32 KiB
64 KiB
80 KiB
256 KiB
272 KiB
1 MiB
1,040 KiB
4,112 KiB
8 MiB
```

The inserted classes carry a fixed Cell or maximum batch/proof body plus framing
without promotion to the next large bucket. More classes reveal a finer size
bucket, so high-privacy policy may deliberately choose a coarser class from the
same universal set.

Each request cryptographically binds an exact `resultOuterClass` in the new
request commitment. Transport integrity by itself is not egress authority. For an
optional-admission read, an absent admission permits only
`resultOuterBytes <= requestOuterBytes`; the client must therefore up-pad the
request to the result class. A smaller request may select a larger result only
with an egress-admission grant bound to the operation, request commitment, exact
result class, endpoint, and expiry. The rule is checked before resource lookup, so
`NOT_FOUND` cannot be used as an unauthenticated padded-response oracle.

The relay:

1. validates it against the operation/resource result bound;
2. verifies any required egress-admission binding and reserves global, endpoint,
   connection, and admission egress before work;
3. rejects positive unauthenticated response/request amplification before lookup;
4. charges exact request and result outer bytes;
5. returns found, absent, and error outcomes in the selected result class; and
6. echoes the class through authenticated correlation.

Stored Cells and existing capabilities do not need migration. Public protocol,
descriptor, endpoint masks, routes, transport pins, client negotiation, and
vectors are versioned independently from v1.

## 6. SDK mitigations available before protocol changes

- Calculate exact v1 envelope and replica amplification in `plan()`.
- Let applications set hard foreground byte and amplification ceilings.
- Recommend app-authorized batching for sparse 4-KiB Cells.
- Use `BATCH_GET` only as a latency optimization; never claim read-interest
  privacy from it.
- Prefer Blind Core or direct P2P for native bulk data and media.
- Put media manifests and checkpoints in Cells rather than every hot body.
- Queue high-privacy Tor operations for background execution.
- Never silently switch privacy profile, destination, primitive, or semantic
  service to meet a latency goal.

## 7. Benchmark matrix

Every accepted run pins:

```text
protocol/profile: hiverelay-blind/1 same-class | hiverelay/direct-https-compact-cell-mutation/1 | hiverelay-blind/2 (protocol 2.0; ABI v4)
runtime:          browser | Node | Bare/Pear | Tor Browser
primitive:        Cell | Inbox | Core | Forward/P2P
operation and class
useful and opaque bytes
request and result outer bytes
replicas/fanout and acknowledgement target
durability profile
transport:        direct | OHTTP | split native | Tor
warm/cold connection or circuit
RTT/loss/jitter/bandwidth
CPU, allocations, copies, fsync, WAL and external quorum
```

Reports publish p50/p95/p99/p999 latency, useful throughput, exact ingress and
egress, useful-byte amplification, CPU, peak memory, admission failures, repair
traffic, and raw samples. Direct/OHTTP/split/Tor results are never combined into
one percentile.
