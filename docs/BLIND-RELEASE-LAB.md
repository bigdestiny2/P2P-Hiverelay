# HiveRelay blind-substrate release laboratory

**Status:** executable local/model gate; production evidence still incomplete.

This laboratory exists to prevent modeled capacity, local benchmarks, signed
operator claims, or multiple URLs from being mistaken for a production-ready
decentralized network. Every result carries an evidence class and claim boundary.

## Commands

```sh
node scripts/simulate-blind-fleet.mjs --assert
node scripts/blind-capacity-lab.mjs --pretty
node scripts/plan-blind-capacity.mjs --release-profile release --assert-fit --pretty
PEERIT_ROOT=/path/to/peerit node scripts/run-blind-release-lab.mjs \
  --profile smoke --assert-lab --out reports/blind-lab-smoke.json
PEERIT_ROOT=/path/to/peerit node scripts/run-blind-release-lab.mjs \
  --profile release --assert-lab --out reports/blind-lab-release.json
```

`--assert-lab` covers deterministic model invariants and local Peerit scale.
`--assert-mainnet` is deliberately stricter and remains red until production
runtime, hardware, browser, independent-operator, soak, signing, and rollback
evidence is wired into the verifier.

## Evidence ladder

| Evidence | What it can establish | What it cannot establish |
| --- | --- | --- |
| Deterministic fleet simulation | Algorithmic placement, accounting, lease, repair, failure and fairness invariants | Kernel, database, disk, Internet, GC or implementation performance |
| Analytical capacity model | Sensitivity to disk, IOPS, CPU, network, replication, WAL, checkpoint, scrub and repair assumptions | Actual sustainable throughput or tail latency |
| Local implementation measurement | Real code-path latency, memory and correctness on the named machine/backend | Browser, mobile, multi-host or production behavior |
| Crash/fault injection | Recovery semantics at enumerated durable boundaries | Unenumerated hardware/filesystem faults or long-term stability |
| Cross-browser/device measurement | IndexedDB, service worker, render, memory and transport behavior on tested versions | Other versions/devices and live operator independence |
| Multi-host operator drill | Real failover, repair, routing and failure-domain evidence for the named operators | General Internet anonymity or permanent availability |
| Seven-day soak/canary | Resource drift, churn and recurring fault behavior over the measured window | Future behavior outside the tested envelope |
| Signed release evidence | Exact artifacts, sequence, authority and rollback identity | Correctness not exercised by the bound tests |

An unkeyed report digest or content hash is only a checksum: it can detect
accidental or post-capture byte drift when the expected digest is already
trusted. It does not authenticate who produced the report, when it was
produced, or which deployment produced it. Authentic release evidence must bind
the report digest into a verified signature whose signer, trust root, sequence,
freshness and rollback floor are checked separately.

## Current evidence position

| Rung | Evidence currently exercised | Honest claim ceiling |
| --- | --- | --- |
| Deterministic simulation | Family-aware fleet scenarios exercise placement, leases, failures, repair, accounting and fairness; the release profile models 72 relays, 24 operator groups and 8 regions | Model invariants only; no measured disk, kernel, database or Internet performance |
| Analytical capacity | Family-specific CELL, INBOX, CORE and FORWARD resource ceilings and bottlenecks are computed from explicit assumptions | Planning sensitivity only; the reported operations per second are not benchmarks |
| Local assembled relay | Three signed relay identities with separate store roots exercise a real TLS edge, private Unix IPC, staged CELL writes, reads and restart recovery | One host and one process, CELL only; it does not prove process isolation, multi-host operation, independent operators or all-family production composition |
| Local application scale | Peerit's journal/index harness exercises 10,000 intents and 100,000 records | The named local backend only; no public-relay, mobile or production claim |
| Desktop browser scale | The same 10,000-intent/100,000-record/reopen ceiling has been exercised in Chromium, Firefox and WebKit desktop engines | The tested engine versions only; mobile, live relay delivery, crash/kill and quota-pressure release gates remain separate evidence |
| Component recovery | Daemon tests exercise individual WAL, checkpoint, replay and recovery boundaries | A complete assembled format-2 all-family crash, rebalance and garbage-collection matrix is still missing |
| Multi-host, operator and soak | No qualifying evidence is yet wired into the release gate | No independence, Internet-scale availability or long-duration stability claim |
| Signed deployment | Generated artifacts and checksums can be reproduced locally | No production release authenticity claim until the signed manifest, sequence, rollback and canary evidence verify |

## Required scenario matrix

| Scenario | Required observations |
| --- | --- |
| Mixed steady/burst | CELL/INBOX/CORE/FORWARD throughput, p50/p95/p99/p999 latency, queue depth, rejection-before-allocation, family fairness |
| Storage fill | Logical/physical bytes, padding/index/WAL/checkpoint overhead, safe fill, refusal behavior, lease expiry and reclamation |
| Operator outage | Readable and quorum fractions by independent operator group; no duplicate-key independence claims |
| Region partition | Local availability, cross-region repair backlog, recovery convergence and no lower-floor acceptance |
| Destructive disk loss | Lost copies, source-required repair, data loss, exact accounting and checkpoint/restore behavior |
| Retained-storage crash | Restart terminalization, WAL replay/tail truncation, no stream resurrection and no false receipt |
| Rebalance | Copy/catch-up/fence/map commit crashes, one writer, no lost/double-counted object, bounded foreground impact |
| Clock fault | Unsafe state, lease mutation stop, explicit confirmation and no retention extension through downtime |
| Admission abuse | Cross-family spend races, retry identity, token replay, expensive-work rejection and weighted fairness |
| Late third app | No daemon code/config/restart/digest change; disk/log/metric sentinel scan remains app-free |
| Browser ceiling | 10,000 intents, 100,000 records, paged feeds/search, reload, quota pressure, hung relays and mobile long tasks |
| Privacy paths | Direct, split/OHTTP, native two-hop and Tor claim ceilings; source, Origin, locator, timing and size observations recorded honestly |

## Current executable coverage

- `simulate-blind-fleet.mjs` models independent operator groups, regions,
  bandwidth, storage, admissions, churn, leases, partitions, crashes, destructive
  loss, repair, fairness, latency, and exact accounting with digest-bound output.
- `blind-capacity-lab.mjs` models storage overhead, WAL/group commit, checkpoint,
  scrub/repair, CPU, IOPS, disk and network bottlenecks. It never labels modeled
  throughput as measured.
- `plan-blind-capacity.mjs` binds the exact fleet-derived operation mix and
  offered load into a relay-count/per-relay-hardware search. It reports modeled
  content capacity, minimum enumerated bundles and bottleneck transitions while
  keeping `authorizesRelease` and `changesBaselineReleaseGate` false. See
  [BLIND-CAPACITY-SIZING.md](./BLIND-CAPACITY-SIZING.md).
- Peerit's `peerit-scale-lab.mjs` measures the transactional journal and local
  index at the configured ceiling. Its report remains non-production evidence.
- `peerit-delivery-concurrency.mjs` proves bounded concurrent intents/relays and
  deadline handling for a deliberately hung target.
- Existing daemon tests cover many individual WAL, checkpoint, recovery and
  family semantics. Format-2 all-family crash/rebalance/GC tests remain required.

The root test command uses a 120-second per-test ceiling because the existing
custody-sweep linkage case legitimately takes about 30 seconds. Raising that
runner ceiling removes a harness timeout; it is not performance evidence and it
does not relax any release gate.

## Deprecation gates

Legacy code is not deleted merely because a replacement is designed.

1. **G0 authority:** final signed wire/store/IPC/client authorities and release pin.
2. **G1 runtime:** one production store serves all five families through the real edge.
3. **G2 blindness:** recursive disk/WAL/log/metric/snapshot sentinel scans are clean.
4. **G3 semantics:** capability, lease, replay, fork, retry and proof matrices pass.
5. **G4 durability/scale:** crash, restore, rebalance, exhaustion and soak pass.
6. **G5 decentralization:** three independently administered operator/failure domains pass drills.
7. **G6 consumers:** browser, Pear/Bare, mobile and publishing clients preserve app invariants.
8. **G7 migration:** verified cutoff/import or explicitly approved clean genesis, plus rollback.
9. **G8 removal:** zero legacy traffic for the window, archived recovery works, imports/routes are absent.

OutboxLog, shard-store, custody, service plugins, app registries, semantic
directories, Poker, WitnessLog and RepairTicket remain in a separately signed,
sunset-bounded compatibility product until their applicable gates pass. They are
never loaded by the strict blind artifact.

## Security-theatre retirement rule

A signed capability document authenticates a claim; it does not prove execution,
blindness, storage, independence or health. A roster authenticates listed keys;
it does not prove independent operators. Ciphertext-shaped JSON does not prove
encryption. A possession attestation is not a fresh retrieval proof. Tor support
does not prove traffic used Tor. Multiple receipts do not prove distinct failure
domains. `unseed` is not cryptographic erasure.

Only executable, adversarial evidence at the corresponding boundary advances a
gate. Marketing and deployment automation consume the verified gate report; they
do not override it.

The checked policy reports are available through package scripts:

```sh
# Inspection validates structure and prints the computed, currently blocked report.
npm run verify:blind-retirement
npm run verify:blind-ecosystem-migration

# Strict commands intentionally fail until their code-owned evidence is complete.
npm run verify:blind-retirement:strict
npm run verify:blind-ecosystem-migration:strict-cutovers
npm run verify:blind-ecosystem-migration:strict-removals
```
