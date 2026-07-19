# Giga Release Architecture — How the Features Fit Together

**Date:** 2026-07-17 · **Status:** composition map for the giga release; four features shipped, one (WAL) in flight · **Feature docs:** [BLIND-CELLS](./BLIND-CELLS.md) · [TOR-ONION-TRANSPORT](./TOR-ONION-TRANSPORT.md) · [HTTPS-GATEWAY](./HTTPS-GATEWAY.md) · [NAMESPACE](./NAMESPACE.md) · WAL (this doc §5)

> This is the map of how the release's five subsystems compose into one product: **blind cells** (verifiable threshold custody), **Tor v3 onion transport** (relay location privacy), **HTTPS gateway** (public read plane), **namespace** (app-neutral messaging), and the **WAL** (durability spine, in flight). Each feature has its own deep-dive doc; this one exists to answer "how do they fit, and what still gates the release."

## 1. The stack in one diagram

```mermaid
flowchart TB
  subgraph Edge["App / publisher edge (keys never leave)"]
    Seal["blind seal + encrypt"]
    Split["PVSS split (blind cells)"]
    Sign["ed25519 intents / records"]
    Policy["privacy-policy resolver"]
  end

  subgraph Privacy["Privacy transports"]
    Tor["Tor v3 onion<br/>relay location hidden"]
    Nym["Nym mixnet lane<br/>(bounded control, spec'd)"]
    Fwd["forward-relay<br/>(zero-dep baseline)"]
  end

  subgraph Relay["HiveRelay node"]
    GW["HTTPS gateway<br/>public read plane"]
    OL["OutboxLog namespaces<br/>app-neutral messaging"]
    SS["shard-store<br/>(blind cells custody)"]
    Reg["custody registry<br/>intents · receipts · commits"]
    API["control plane API<br/>(operator, authed)"]
  end

  subgraph Spine["Durability spine (in flight)"]
    WAL["blind-daemon WAL<br/>fsync-before-ack journal"]
  end

  Seal --> Split --> Sign
  Policy --> Tor & Nym & Fwd
  Sign --> Reg
  Split --> SS
  Tor & Fwd --> GW & OL & SS & Reg
  GW --> Public["browsers / curl / CDN<br/>(public content only)"]
  OL --> Apps["apps (Peerit, Poked, …)"]
  SS --- WAL
  Reg --- WAL
```

The design invariant across all five: **relays are blind** (content and keys stay at the edge), **authorization is signature-based at every layer** (no transport grants authority), and **privacy claims stay on their ladders** (each lane advertises exactly what it proves — no more).

## 2. What each feature contributes

| Feature | Job | Trust it removes | Deep dive |
|---|---|---|---|
| **Blind cells** | k-of-n verifiable custody of encrypted secrets across independent relays | trusting any single operator with the key; unverifiable custody claims | [BLIND-CELLS](./BLIND-CELLS.md) |
| **Tor v3 onion transport** | hides the relay's network location; restricted discovery for private relays | relay IP exposure; open enumeration of private endpoints | [TOR-ONION-TRANSPORT](./TOR-ONION-TRANSPORT.md) |
| **HTTPS gateway** | serves declared-public drives to HTTP clients (browsers, mobile, CDN) | "you must speak Hyperswarm to read anything" | [HTTPS-GATEWAY](./HTTPS-GATEWAY.md) |
| **Namespace** | one relay hosts many apps' outbox logs, operator-admitted, with blind mode + takedown | relay-per-app coupling; content exposure in moderation | [NAMESPACE](./NAMESPACE.md) |
| **WAL** | atomic one-use spend, fsync-before-ack durability, fail-closed recovery for the blind store | torn writes, replayed spend tokens, unverifiable recovery | §5 below |

## 3. One full journey, end to end

```mermaid
sequenceDiagram
  participant P as Publisher edge
  participant Pol as Policy resolver
  participant T as Tor onion (relay endpoint)
  participant R as Relay i
  participant Reg as Custody registry
  participant Rd as Reader

  P->>P: encrypt content, PVSS split to n cells
  P->>Pol: intent: source-ip-hidden, hidden-onion, deny
  Pol-->>P: selected: tor-v3-onion-v1 (evidence-bearing)
  P->>Reg: signed custody intent v2 (to EVERY relay first)
  P->>T: PUT cell i + signed pin (over onion)
  T->>R: peer vport then shard-store
  R->>R: pin sig + roster match then store (dedup)
  R->>Reg: custody receipt (shareVerified) at seed time
  P->>Reg: commit at quorum, then optional source-retired

  Note over Rd: public reader path
  Rd->>T: GET /v1/hyper/:key/... (or nginx app origin)
  T->>R: read-plane vport then gateway
  R-->>Rd: streamed bytes (public tier only, blind gives 403)

  Note over Rd: threshold reader path
  Rd->>R: GET /api/v1/shard/:hash (k relays)
  Rd->>Rd: re-hash, commitment-bind, DLEQ,<br/>reconstruct key, decrypt locally
```

Read it as three independent compositions:

1. **Custody composition** — blind cells + registry + (soon) WAL: intent → cells → receipts → commit → burn/witness. The Tor/Nym lanes hide *who submitted* and *where the relay is*; the custody layer proves *what is stored* and *that it was burned*.
2. **Read composition** — HTTPS gateway + Tor read plane + capability doc: one read plane, multiple ingresses (clearnet nginx, onion vport), with the signed capability doc advertising each ingress and its honest coverage labels.
3. **Messaging composition** — namespaces + wake hints + privacy transports: app-neutral signed logs at the relay, with bounded encrypted wake/head hints as the exact messages the Tor/Nym control lanes were built to carry.

## 4. The honesty layer (shared across features)

```mermaid
flowchart TD
  Doc["signed capability doc"] --> T1["supported_transports"]
  Doc --> T2["privacyTransports (health-gated)"]
  Doc --> T3["relayLocation + coverage labels"]
  Pol2["client policy resolver"] -->|"deny → fail closed"| X1["no silent downgrade"]
  Pol2 -->|"ordered list"| X2["recorded downgrade"]
  Red["redaction audit gate"] --> Y["no onion addrs / roster /<br/>keys in public logs+metrics"]
  Ladder["claim ladders"] --> Z["never: TA-resistant on Tor;<br/>never: full-coverage on Nym;<br/>never: private content on gateway"]
```

Every feature reports its properties through the same vocabulary (the orthogonal privacy axes), and every claim that cannot be evidenced is deliberately *not* made. This is a product feature in itself.

## 5. WAL — the gate that ties the release

**What it is:** the blind custody store's write-ahead log, living in the blind-daemon line (`packages/blind-daemon/` in the vnext/hq lanes — **not** in the main hiverelay checkout). A hash-chained, fsync-before-ack journal (`wal.v2`, magic `HRWL`) providing:

- **atomic one-use spend** — admission tokens burn exactly once (`SPEND_REPLAY` guard),
- **durability** — every frame write + `sync()` before ack,
- **fail-closed recovery** — full re-verification, torn-tail truncation, hard error on interior breaks,
- writer fencing + `durabilityContinuityHash` + monotone epoch floor.

```mermaid
sequenceDiagram
  participant C as Client
  participant E as storage engine
  participant W as WAL (wal.v2)
  C->>E: PUT (admission token)
  E->>W: INGRESS_RESERVED (burn spend tag)
  W->>W: fsync before ack
  E->>W: ATTEMPT_CONSUMED (+ fsync)
  E->>E: stage blob
  E->>W: PUT_COMMITTED (+ fsync)
  W-->>C: ack (durable)
  Note over E,W: legacy flow (pre-2026-07-18): 3 frames/PUT, serialized on one lock<br/>→ ~58 PUTs/s/relay, 64 appenders gain 0% — superseded by Phases 1–2 below
```

**Why the release waits on it (status verified 2026-07-18):**

| Phase | Content | Status |
|---|---|---|
| 0 — measure | capacity model + portable harnesses | **done** (macOS upper bounds; Linux fleet rerun required for release-grade evidence) |
| 1 — group commit | batching in the `'\0wal'` mutex + fdatasync + preallocation | **shipped** 2026-07-18 (v1-integration `f0b4376`; 64 concurrent appenders 128 → ~8k commits/s macOS) |
| 2 — single-commit PUT | 3 frames → 1 | **shipped** 2026-07-18 (v1-integration; the atomic staged path is the *only* public CELL.PUT route — 3 → 1 WAL frame/datasync per PUT, 1,841 → 971 WAL bytes/PUT, serial p50 23 → 33 PUTs/s ≈ 1.4× on macOS; legacy 3-frame codecs/frames retained — recovery reads both, wire format unchanged) |
| 3 — segmented WAL | pruning + checkpoint-anchored recovery, one format rev paired with the D-6 `K_partition` decision | **not implemented** (`walPruningSupported: false`) |
| 4 — model rerun | scenarios with measured constants | partially done in Phase 0 |

Phase-2 follow-up candidate measured 2026-07-18: under 64-way concurrency the atomic PUT commits serialize on the global `quota:atomic-staging` lock held across publication + the type-17 fsync (~35 PUTs/s vs ~126 for the legacy per-spend locking) — narrow that lock scope before relying on P1×P2 composition. **Resolved 2026-07-19:** the commit critical section now holds only the per-spend/per-cell locks (the legacy `#putCell` discipline); the global lock is held solely around the staged-quota ledger mutations (stage-time claim + the brief release inside `#releaseAtomicStaging`, which acquires it itself). Same-authority commit/cancel exclusion was never provided by the global lock (cancel takes no locks) — it rests on the synchronous phase recheck → `'committing'` transition; same-spend/same-slot exclusion on the keyed locks with `#applyAtomicPut` revalidating uniqueness before they release. Measured (macOS, `bench-results-macos-20260719-atomic-put-lockfix.json`): 64-way concurrent atomic PUTs **34 → 140 PUTs/s** (legacy per-spend path 120–125; P1×P2 composition now ≥ 1×, was 0.27×), serial path unchanged (~31). WAL commit-group size still measures 1 for both paths in this bench — publication latency dominates inter-arrival, so throughput comes from pipelining, not shared groups.

Phase 3 **must** land before the blind store-format authority and protocol hashes freeze — it shares one migration with D-6 and therefore gates the giga release's freeze. Invariants every phase must preserve: atomic one-use spend, fsync-before-ack (group fsync allowed), 15-min canonical retry, O(1) drop-wins, fail-closed recovery, writer fence + continuity hash, epoch floor, spent-marker horizon.

**Do-not-overclaim flags:** no WAL code exists in the main hiverelay repo (it lives in the blind line); phases 1–3 shipped on v1-integration 2026-07-18 (P1 `f0b4376` group commit · P2 `290bebd` single-commit PUT · P3 `76eff20` segmented WAL + checkpoint-anchored pruning, `walPruningSupported: true`) with macOS-only numbers (Linux fleet rerun still required); Phase 0 numbers are macOS-only upper bounds.

## 6. Release readiness map

| Feature | Lane | Code | Tests | Gate to release |
|---|---|---|---|---|
| Drift cleanup | hiverelay | merged | full unit suite green | — done |
| Blind cells | hiverelay | shipped v0.22+ | e2e fleet tests green | repair/AutoHeal is roadmap (not a gate) |
| Tor onion transport | hiverelay | shipped 2026-07-17; follow-ups shipped 2026-07-18 (`69a51dde` pairing enrollment hookup + peer-vport listener) | 148/148 across 12 suites + live-tor e2e green | 100 MB bulk-over-onion measurement (env-gated) |
| HTTPS gateway (path) | hiverelay | shipped | streaming integration green | — done |
| HTTPS gateway (app origins) | v1-integration | Phase-1 canary merged | canary suites + G1–G6 evidence executed 2026-07-18 (role boundary T2-no-gateway ✓, heuristic-free storage classification ✓, signing foundation suites ✓, compatibility suites ✓, blind-substrate green pre-rebase ✓, clean v1-integration line ✓) | G7–G13: owner/fleet evidence (two operators, signed-tag digests, operator-contract digests, Docker nginx capture, real host ceiling) |
| Namespace | hiverelay | shipped v0.24.1 | unit + config/env green | — done (`bytesPerDay` enforced 2026-07-18 `d9bdb405`, rolling-24h with documented restart boundaries) |
| WAL | blind line (v1-integration) | v2 shipped; **phases 1–3 all shipped 2026-07-18** | Phase-0 + P1/P2/P3 evidence (concurrent 128→7,975 commits/s; 3→1 frames & 1,841→971 B/PUT; prune bounded 7.9 MB→0.7 MB oscillating, horizon-safe) | **Linux Phase-0 rerun** (fleet) — the last freeze-gate item |

## 7. The final test matrix (what "test everything out" means)

1. **Per-feature suites** — all green today (unit suites incl. 48 new tor tests; custody/dispersal fleet e2e; gateway streaming; namespace config).
2. **Cross-feature journeys** —
   - disperse k-of-n cells over Tor onion endpoints; receipts commit; reconstruct client-side (blind × tor);
   - public app served via gateway while custody entries hard-403; same relay reachable over onion (gateway × tor);
   - two apps sharing one relay's outboxlog under distinct blind namespaces, with takedown (namespace × blind);
   - wake hints over the onion control path into namespaced outboxes (namespace × tor/nym).
3. **Adversarial/privacy gates** — fail-closed downgrade suites ✓, redaction audit sweeps on public payloads ✓, orphan-pin (403 UNAUTHORIZED_PIN) ✓ and cross-namespace replay rejection ✓ verified 2026-07-18. **Gap: negative-probe on private onion endpoints is NOT implemented** — the health machine verifies positive reachability (HS_DESC uploads + SOCKS self-probe) but never verifies an intentionally-unauthorized client is refused; an all-invalid roster silently degrades to fail-open at the tor daemon level. Required before RC: a health-gate negative probe on restricted-discovery services.
4. **Release-gate holdouts** — Linux Phase-0 rerun (durability/throughput; harness portable at `00-core/wal-phase0-evidence-2026-07-13/`), app-origin gateway G7–G13 operator/fleet evidence, 100 MB bulk-over-onion measurement. Recorded follow-ups (not gates): P1×P2 atomic-staging lock narrowing (measured ~35 vs ~126 PUTs/s under 64-way concurrency), storage-startup-rollback corestore-7 teardown drain (merge-surfaced), pre-existing v1-tip failures (blind-protocol-vectors, vnext-program-state, vnext-protocol-remediation, blind-client-late-app).

## 8. Sources of truth

- Feature docs: [BLIND-CELLS](./BLIND-CELLS.md), [TOR-ONION-TRANSPORT](./TOR-ONION-TRANSPORT.md), [HTTPS-GATEWAY](./HTTPS-GATEWAY.md), [NAMESPACE](./NAMESPACE.md), plus `docs/tor-transport.md` (operator guide).
- Research vault (`00-brain/research/`): Nym × HiveRelay spec, Nym economics deep dive, relay-anonymity decision matrix, Tor v3 spec, M0 evidence pack.
- WAL: `00-core/WAL-DESIGN-ATTACK-2026-07-13.md`, `00-core/wal-phase0-evidence-2026-07-13/`, blind line (`hr-blind-review`, vnext/hq lanes).
- Gateway canary: `00-core/hr-https-gateway/docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md` and canary runbook.
