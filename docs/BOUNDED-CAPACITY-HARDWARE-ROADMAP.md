# Bounded capacity: hardware map and delivery roadmap

Status: implementation baseline plus gated roadmap, 2026-08-05.
Updated 2026-08-06 with R1a: a declared profile now narrows the enforced
adoption ceiling. See "Enforced today vs planned" below.

This is the capacity contract for growing HiveRelay beyond a few test apps.
The central decision is simple: a relay is not a copy of the whole ecosystem.
Catalog and routing metadata may converge broadly, but payloads, history,
media, repair fragments, and persistent service state live only on explicitly
selected holders with finite commitments.

## Non-negotiable invariants

1. Every storage-producing operation has a finite byte commitment before it
   can write.
2. The sum of actual bytes, durable commitments, pending reservations, and
   unbounded legacy debt is never advertised twice.
3. Operator caps are ceilings. Hardware discovery and a profile may narrow a
   cap but never raise it.
4. Capacity is measured after RAID/parity and on the exact filesystem that
   receives the data. Raw SSD label capacity is not usable capacity.
5. Cache, repair, durable payload, service/control state, and burst space are
   separate budgets. A cache miss must not evict a paid or custody-bound pin.
6. Local RAID protects against a disk failure; it does not create another P2P
   holder. Every chassis has one network failure-domain identity.
7. A relay with unknown commitment debt, stale measurements, incomplete
   recovery, or no required hard quota advertises zero trusted capacity.
8. Services are explicit placements. A general edge relay does not silently
   run every persistent provider.

## What is implemented now

| Surface | Current behavior |
|---|---|
| Capacity planner | `config/capacity-plan.js` implements five stable profiles, exact integer pool allocation, a 15%/32 GiB planning reserve, operator-cap narrowing, conservative debt accounting, and a whole-filesystem free-space bound for shared hosts. |
| Operator declaration | `capacityProfile` can be persisted through the management config API or supplied with `--capacity-profile` / `HIVERELAY_CAPACITY_PROFILE`. No hardware class is inferred by default. |
| Enforced ceiling | A declared profile narrows new adoption to its durable pool. `StorageAdmissionAuthority.capacityCeiling()` derives it from `planCapacityCeiling()` on every reservation; `evaluateStorageAdmission()` takes `min(operator cap, ceiling)`. An undeclared profile changes nothing. |
| Status | Relay stats and public `/status` expose an allowlisted `planning-only` capacity snapshot plus the enforced `capacityCeilingBytes` / `effectiveCapBytes`. Status reads cached measurement/ledger state, reports sample freshness, and never starts a synchronous disk walk. |
| Advertisement safety | Planning headroom is distinct from network-advertisable capacity. Network advertisement is hard-disabled (zero bytes) for this tranche even when local checks are green; independently cached samples are not an identity-bound capacity lease. |
| Admission | Existing drive, core, gateway, and bounded journal ingress continue to use the shared `StorageAdmissionAuthority`. The planner supplies only the ceiling; it never decides an individual reservation. |
| AutoHeal | Archive recruitment now prices the candidate drive through that shared authority, so it inherits the profile ceiling for free. It no longer trusts `Seeder.totalBytesStored`, runs cheap backoff/jitter first, and caps exact disk admission walks per tick. |
| Appliance defaults | Umbrel, the general Docker Compose path, and the systemd unit are core-only by default. Umbrel starts in review mode with a 10 GB managed cap and declares `edge-community` (3.5 GB durable); utility services require explicit operator opt-in. |

The planner is intentionally stricter than today's logical admission reserve.
`STORAGE-CAP-SAFETY.md` documents the current runtime reserve of 10% with a
2 GiB floor and 20 GiB ceiling. The capacity profile reserves the larger of
15% and 32 GiB for long-horizon hardware planning. That larger reserve stays a
planning input: it shapes the ceiling, but the runtime free-space gate is still
the 10%/2 GiB/20 GiB reserve.

## Enforced today vs planned

Exactly one number on this surface is enforced: the durable-pool ceiling a
declared profile imposes on new adoption. Everything else — cache, repair,
service/control, and burst budgets, and every `advertisableBytes` value — is
planning output with no runtime mechanism behind it yet.

The ceiling is safe to enforce now precisely because it needs nothing R1 and R2
have not built. It is derived from `statfs` total bytes and the operator cap
alone, so it never waits on a storage tree walk and can never be stale. And
because no commitment yet carries a `poolId`, both the planner and the ceiling
charge every existing byte to `durable` — so status and enforcement are
arithmetically identical rather than merely consistent.

Two consequences an operator must expect:

1. Declaring a profile narrows the effective cap. `edge-community` on a 10 GB
   operator cap enforces 3.5 GB of durable payload; the remaining 6.5 GB is
   reserved for the pools that R2 will make real. Leaving `capacityProfile`
   unset changes nothing at all.
2. Crossing the ceiling behaves exactly like crossing the operator cap: new
   adoption pauses, nothing is deleted, and existing pins stay serveable. The
   distinct `capacity-profile-cap-reached` reason tells the two apart.

A profile that cannot be evaluated — unknown id, or a filesystem whose size
cannot be measured — fails admission closed. It never falls back to the wider
operator cap, because an operator who declared a role did not consent to the
unnarrowed value.

### Measurement freshness on large hardware

The storage tree walk is timestamped at its start, so on archive-class hardware
the newest finished sample is already `duration + interval` old. A fixed
5-minute budget therefore marked exactly the hardware this work exists for
permanently stale. The window is now derived from the host's own observed walk
cost — `max(5 min, 2 × duration + interval)` — and hard-capped at one hour. A
root that cannot be walked inside that cap stays fail-closed; splitting the
store is the remedy, not a wider window. The cheap `statfs` sample keeps the
strict 5-minute floor on every host.

The walk also no longer treats a vanished path as incomplete evidence. A file
deleted between `readdir()` and `stat()` holds zero bytes, and Corestore deletes
files constantly, so the previous behavior left `diskMeasurementComplete` false
on every busy relay — fail-closing the whole capacity surface. A missing storage
*root* is still incomplete: an unmounted store must never read as zero bytes
used.

## Planning formula

Given a measured post-parity payload filesystem `P`, its current free bytes
`F`, and optional operator cap `O`:

```text
physical reserve = min(P, max(15% × P, 32 GiB))
post-reserve      = P - physical reserve
managed capacity = min(post-reserve, O)  // O omitted means post-reserve
future debt       = committed + pending + untracked debt
physical headroom = max(0, F - physical reserve - future debt)

conservative demand = actual + committed + pending + untracked debt
logical headroom     = max(0, managed capacity - conservative demand)
global headroom      = min(logical headroom, physical headroom)
```

The live relay always supplies `F` from the exact mounted filesystem, and only
uses a complete, age-bounded storage traversal, so data written by other
Umbrel apps, the OS, or an operator is not silently treated as HiveRelay
headroom. Actual HiveRelay bytes are already reflected in `F`; future debt is
subtracted because it may still materialize. Offline hardware modeling may
omit `F`; the result explicitly marks that it assumed an empty filesystem and
must not be treated as live capacity evidence.

Pool allocation uses largest-remainder integer arithmetic, so every managed
byte belongs to exactly one pool and the sum can never exceed the managed
capacity. Until per-pool attribution exists, all existing demand is also
charged against the durable pool when calculating planning headroom.

A payload filesystem at or below 32 GiB therefore plans zero managed capacity.
That is deliberate: very small boot media can participate in routing and
metadata without being sold as durable storage.

## Stable capacity profiles

| Profile | Durable | Service/control | Repair | Cache | Burst/slack | Intended posture |
|---|---:|---:|---:|---:|---:|---|
| `edge-community` | 35% | 10% | 10% | 30% | 15% | Review/allowlist edge, small selected pins, no persistent services by default |
| `seeder-standard` | 60% | 10% | 15% | 15% | 0% | Dedicated low-power seeder with predictable payload retention |
| `seeder-regional` | 60% | 10% | 15% | 15% | 0% | Higher-throughput regional holder; same storage ratios, stronger CPU/network SLO |
| `services-s2` | 8/13.056 | 0 | 2/13.056 | 1.5/13.056 | 1.556/13.056 | Custom S2 payload roots; service state lives on a separate mirrored volume |
| `archive-storage` | 70% | 5% | 20% | 5% | 0% | NAS/archive holder with slow, durable capacity and a repair reserve |

`services-s2` uses integer weights `8000:0:2000:1500:1556`, not rounded
percentages. On two independent 7.68 TB payload roots (15.36 decimal TB total),
the 15% reserve leaves 13.056 TB and produces exactly 8 TB durable, 2 TB
repair, 1.5 TB cache, and 1.556 TB slack.

## Mapping to hardware

All cap ranges below are starting envelopes, not automatic configuration.
Endurance, free-space history, thermal behavior, upstream bandwidth, other
apps, and operator risk appetite can only narrow them.

| Hardware class | Typical resources | Profile | Initial posture |
|---|---|---|---|
| Consumer edge / Pi-class box | 4–8 efficient cores, 8–16 GiB RAM, 1–2 TB TLC NVMe, 1 GbE | `edge-community` | Review or allowlist; no persistent services; small explicit cap; routing, metadata, and selected best-effort pins |
| Dedicated mini-PC seeder | Intel N100/N150/N305 or comparable efficient x86, 16–32 GiB RAM, 2–4 TB high-endurance NVMe, 1/2.5 GbE, UPS | `seeder-standard` | Dedicated payload role; 0.5–2 TB operator cap after burn-in; no service farm |
| Umbrel Home | Current product class: Intel N150, 16 GB RAM, one onboard NVMe up to 4 TB, 1 GbE | `edge-community` | Shipped package starts at review + 10 GiB + services off. Increase only after observing other Umbrel apps and backups. |
| Umbrel Pro | Current product class: Intel i3-N300, 16 GB RAM, four NVMe slots up to 32 TB, 2.5 GbE, optional FailSafe | `seeder-regional` when dedicated; `edge-community` when mixed-use | Use measured post-FailSafe capacity. Treat the whole unit as one failure domain. RAM, not SSD slots, limits co-resident service density. |
| HiveRelay Services Box S2 | 12 server-class cores, 128 GiB ECC, mirrored state SSDs, two 7.68 TB payload SSDs, dual 10 GbE or 10/25 GbE, UPS/BMC | `services-s2` | Dedicated service/control host plus selected payload commitments; never present both payload roots as independent network holders |
| Archive NAS | 32–64 GiB ECC, RAIDZ2/RAID6-class array, 30–100+ TB post-parity, 10 GbE preferred | `archive-storage` | Archive assignments and repair source; latency-tolerant; no hot service workload on the archive pool |

Umbrel specifications are time-sensitive. The mapping above is based on the
official product page as checked on 2026-08-05:
<https://umbrel.com/umbrel-pro>. Umbrel documents USB/NAS/external-drive support
for files and backups; this plan does not assume that an App Store container's
durable app data can be transparently moved to arbitrary external media.

## Custom HiveRelay Services Box S2

### Physical layout

| Component | Baseline |
|---|---|
| CPU | 12 physical/server-class cores with sustained cooling; avoid counting short boost clocks as service capacity |
| Memory | 128 GiB ECC; expose measured available memory, not installed memory |
| State volume | 2 × 1.92 TB enterprise NVMe mirrored; approximately 1.92 TB post-parity |
| Payload roots | 2 × 7.68 TB enterprise NVMe as separately enforceable local stores; combined planning input 15.36 decimal TB only when both are mounted and measured |
| Network | Redundant links where possible; 10 GbE minimum target, 25 GbE optional; WAN egress is advertised separately |
| Power/ops | UPS telemetry, graceful shutdown, BMC/watchdog, spare SSD, thermal and wear monitoring |

The mirrored state volume starts with an 800 GB aggregate service-state
ceiling. Per-service and per-namespace quotas are carved inside that ceiling;
it is not 800 GB for every service. The remainder covers OS/runtime,
journals/snapshots, compaction headroom, upgrades, and state-volume reserve.

The two payload SSDs are separate local store IDs so one failed device does not
make the other unwritable. They are still in one chassis, power domain,
operator domain, and network domain. A durable object placed on both roots has
two local copies but only one network holder for quorum purposes.

### S2 resource slots

The eventual scheduler should admit resources as independent finite slots:

```text
payload bytes: durable / repair / cache / burst
state bytes:   per service and namespace
memory:        reserved + working-set bytes
CPU:           sustained millicores, not burst peak
network:       egress Mbps and monthly transfer envelope
IOPS:          read and write reservations per store
```

No service may consume payload slack merely because its own state quota is
full. Cross-pool borrowing requires an explicit, reversible operator policy.

## Why the current runtime is not the final model

The current node has a strong global admission foundation but not yet a full
multi-pool allocator:

- one configured storage root, not multiple independently enforceable store
  IDs;
- no durable per-object mapping from a commitment to a pool and physical root;
- no real host quota adapter in the default distribution;
- incomplete accounting/enforcement across every append-capable service
  writer, listed in `STORAGE-CAP-SAFETY.md`;
- no signed network capacity descriptor or assignment lease;
- no scheduler that distinguishes disk replicas from independent network
  failure domains;
- service processes do not yet have hard memory/CPU/IO isolation;
- ordinary unseed closes logical ownership and releases its commitment, but it
  does not yet prove that every physical byte was reclaimed; scheduling needs
  one crash-safe, audited retire-to-purge lifecycle before it can reuse those
  bytes with confidence.

For these reasons the current profile output says `planning-only`. It must not
be copied into the signed capability document as available storage yet. The
durable ceiling of R1a is the sole exception, and it is a local brake on growth
rather than a claim made to anyone else: it can only refuse work this relay
would otherwise have accepted, so no peer relies on it being accurate.

## Delivery roadmap

### R0 — baseline landed

- Deterministic profiles and exact pool arithmetic.
- Operator-declared profile in config/CLI/environment.
- Side-effect-free status projection with explicit advertisement blockers.
- AutoHeal routed through shared admission.
- Core-only appliance and host defaults.

Exit gate: unit tests prove no oversell, no cap widening, fail-closed malformed
state, and safe appliance defaults.

### R1a — make the declared profile bind

R0 published pool budgets that nothing enforced, which left invariant 3
("a profile may narrow a cap") as documentation rather than behavior. R1a closes
that gap with the one pool that needs no new accounting.

- Derive an enforcement ceiling from the profile, the measured filesystem size,
  and the operator cap; narrowing only, and zero is a valid answer.
- Bind the ceiling to the same re-sampled filesystem the admission usage terms
  came from, so a mount swap mid-admission cannot mix two devices.
- Fail admission closed on an unusable declared profile.
- Report `operatorCapBytes`, `capacityCeilingBytes`, and `effectiveCapBytes` on
  status so the binding limit is never implicit.
- Restore measurement availability on archive-class hardware and busy relays
  (derived freshness window, benign-race tolerance in the walk).

Exit gate: a pin that fits the operator cap but not the durable pool is refused;
the same pin is admitted with no profile declared; the ceiling never exceeds the
operator cap for any profile, filesystem size, or cap; and an unevaluable
profile never widens to the operator cap. *Met.*

### R1 — close the single-root accounting ledger

- Route or disable every append-capable writer named in
  `STORAGE-CAP-SAFETY.md`.
- Persist workload/pool ownership beside each commitment.
- Define crash-safe `retire -> drain -> purge -> measure -> release` semantics.
- Preserve unknown physical residue as debt instead of freeing it on unseed.
- Extend measurement age/completeness from the current global status signal to
  every writer and commitment owner.

Exit gate: restart, disk-full, killed-write, failed-purge, and concurrent-ingress
tests cannot create acknowledged bytes without owned debt. The global logical
authority is complete for one storage root.

### R2 — multi-store and pool enforcement

- Introduce stable `storeId` and `poolId` in local commitment records.
- Bind each store to path, realpath, device/inode, filesystem identity, and
  post-parity capacity.
- Add adapters for ZFS datasets/quotas and Linux project quotas or an
  equivalent reviewed provider.
- Give cache an independently purgeable lifecycle; never commingle it with
  durable or custody data.
- Add migration tooling that copies, verifies, switches authority, and only
  then retires the old root.

Exit gate: a synthetic write cannot cross its pool hard limit, and removing one
store leaves commitments on other stores valid and observable.

### R3 — signed capacity and assignment protocol

- Define a versioned, domain-separated capacity descriptor containing measured
  store bytes, commitments, RAM/CPU slots, WAN envelope, enforcement status,
  UPS signal, and failure-domain tokens.
- Sign fresh descriptors with the relay identity; reject stale, replayed, or
  widening-without-proof updates.
- Replace opportunistic deficit adoption with explicit, expiring assignment
  leases: object, holder, bound, pool, retain-until, price/policy, and nonce.
- Reserve locally before accepting an assignment; publish acceptance only
  after the durable commitment is installed.
- Count a chassis once regardless of local mirrors or multiple store IDs.

Exit gate: adversarial simulations prove that concurrent schedulers cannot
sell the same byte twice and cannot satisfy replica diversity with one failure
domain.

### R4 — service isolation and placement

- Run persistent services in supervised workers/containers with hard memory,
  CPU, IO, open-file, and state-byte ceilings.
- Require a service manifest declaring resource needs, writer surfaces,
  namespace quotas, migration behavior, and shutdown bounds.
- Place services only on compatible profiles; edge/community remains opt-in
  and normally empty.
- Make service state portable through snapshot plus journal replay so a service
  assignment can move without moving unrelated payloads.

Exit gate: a deliberately hostile provider cannot exhaust relay payload disk,
memory, descriptors, or event-loop time beyond its declared envelope.

### R5 — hardware pilot

- Burn in three S2 prototypes with different operators, power, and upstreams.
- Validate SSD endurance, sustained thermal behavior, compaction amplification,
  recovery time, UPS shutdown, and replacement procedure.
- Run one Umbrel Home, one Umbrel Pro/FailSafe, consumer mini-PCs, and an archive
  NAS in the same assignment simulation.
- Calibrate defaults from 30/90-day measurements; do not tune from benchmark
  peaks.

Exit gate: loss of any one chassis plus any one SSD leaves target durability
intact, and every survivor stays below its enforced pools during repair.

### R6 — economics and erasure coding

- Add paid assignment only after byte ownership and expiry are enforceable.
- Price byte-time, repair bandwidth, proof load, and egress separately.
- Add erasure coding only for large cold objects where repair cost and tail
  latency beat simple replication.
- Keep hot app metadata and small objects replicated; coding everything would
  add complexity without useful savings.

Exit gate: settlement cannot outlive a commitment, expiry cannot delete the
last required holder, and repair budgets remain funded under the modeled
failure rates.

## Immediate operator guidance

1. Keep catalog mode `review` or `allowlist` on mixed-use and consumer boxes.
2. Set a finite operator cap from observed free space, not SSD label size.
3. Leave persistent services off unless that box has a reviewed role and
   service-state budget.
4. Declare a capacity profile only when it matches the hardware's intended
   role; leaving it unset is safer than guessing. Declaring one narrows the
   enforced cap to that profile's durable share — check
   `capacity.enforcement.effectiveCapBytes` after setting it, and raise the
   operator cap if the resulting durable budget is smaller than the role needs.
5. Treat planning output as local sizing information. Until R2/R3 gates pass,
   do not sell or promise its `advertisableBytes` value to the network. The
   enforced `capacityCeilingBytes` is the only number that binds today.
6. Run at least three independent holders for durable data; mirrors within one
   Umbrel Pro, NAS, or S2 count as one holder.
7. Alert on free space, planner overcommit, unknown commitment count, physical
   enforcement loss, NVMe wear, memory pressure, sustained egress, and repair
   backlog.
