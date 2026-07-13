# Storage cap safety

HiveRelay treats the configured storage cap and physical disk headroom as two
different limits:

- An operator cap from `--max-storage`, `HIVERELAY_MAX_STORAGE`, persisted
  `maxStorageBytes`, setup, or the management API is explicit. Its byte value is
  never increased or reinterpreted because it happens to equal the built-in
  50 GiB default.
- An unset cap is resolved at startup to no more than the legacy 50 GiB. The
  resolver measures the exact storage directory and uses:

  `min(50 GiB, already-held bytes + max(0, available bytes - reserve))`

- The physical reserve is 10% of the storage filesystem, with a 2 GiB floor
  and a 20 GiB ceiling. Admission checks the current available bytes again at
  runtime, so unrelated disk use cannot consume that reserve unnoticed.

The storage path must already exist before a custom-path startup. HiveRelay
never measures the nearest existing ancestor of a missing path: `/data` may be
an intended mount, and measuring `/` in its place would prove the wrong
filesystem. The built-in `~/.hiverelay/storage` directory is owned and created
by HiveRelay. Operators that require a pinned mount identity may configure
`storageFilesystem.realpath` and/or `storageFilesystem.device`; a mismatch
pauses new adoption.

## Already over cap

Crossing the logical cap or physical reserve pauses new drive and bare-core
adoption. It does not stop the node, delete data, or silently enable eviction.
Existing pins can reopen after restart so they remain serveable and visible to
management. Health/config endpoints and manual unseed/purge recovery remain
available. Automatic eviction runs only when the operator has separately
enabled its existing eviction policy.

Lowering `maxStorageBytes` through the management API applies the new adoption
gate immediately and reports whether the node is over cap. Recovery remains an
operator decision: raise the explicit cap, free unrelated filesystem space,
manually unseed eligible content, or explicitly enable the reviewed eviction
policy.

## Persistence and precedence

Persisted cap presence is the source of truth; numeric equality is not used as
provenance. An explicit 50 GiB value is written to `config.json` and reloads as
explicit. A disk-derived unset value is not written as if the operator chose
it, so it is safely recomputed from the same storage filesystem on restart.

CLI flags override persisted configuration. `HIVERELAY_MAX_STORAGE` is used
until an explicit `maxStorageBytes` has been persisted; unrelated persisted
settings do not erase the environment designation.

Mode changes preserve an explicit designation byte-for-byte. When the cap was
derived from a mode default, switching modes may narrow it but never widens the
live ceiling. A larger ceiling requires an explicit operator designation.

## Physical ceiling provider and serve-only fallback

Logical admission is not an operating-system quota. A production operator may
inject a `physicalEnforcer` v1 that owns one exclusive, absolute allocation
ceiling for the complete configured storage root. The provider must install the
requested ceiling before a write and return an inspectable lease. Every proof
is bound to the provider, exclusive scope, stable lease, exact
path/realpath/device/inode identity, an unpredictable per-install operation ID,
and a fresh timestamp. Install generations must increase strictly; settlement
inspection of that exact lease must keep the same generation. A new hard limit
may stay equal or decrease but may never rise. Provider exceptions, stale or
replayed proofs, identity drift, reported usage drift, and ambiguous
post-mutation settlement fail the storage authority closed.

When already-held allocated bytes equal or exceed the logical cap, a provider
may still install a ceiling exactly equal to current usage. This is a valid
zero-growth, serve-only state: recovery can reopen existing content, but no
physical mutation callback begins.

No portable finite Corestore-to-filesystem allocation multiplier is treated as
a hard quota, and this candidate does not ship a real provider adapter yet.
`requirePhysicalEnforcement` is mandatory for the Public-T1 gateway profile and
is enabled automatically when an operator supplies a provider. With that gate
enabled but no usable provider configured, AppRegistry enters an explicit
read-only fallback: an existing validated Hyperbee or legacy JSON inventory may
hydrate,
but HiveRelay does not materialize the Bee protocol header, migrate/rename
legacy files, or accept registry mutations. Durable entry, anchor, deletion,
eviction, and explicit persistence APIs reject with
`APP_REGISTRY_PHYSICAL_ENFORCEMENT_UNAVAILABLE`; shutdown flush remains a safe
no-op when no registry write was admitted. Opening Corestore itself may create
implementation metadata, so a provider installed before process storage opens
is still required for a whole-process no-new-allocation guarantee.

Existing relay-core/Bare profiles remain on the documented logical admission
contract unless the operator explicitly enables hard enforcement. They do not
claim an OS-enforced ceiling. This preserves current P2P pinning behavior while
the host adapter is unfinished; it must not be used to enable Public-T1 pin
routes or to make a mainnet hard-quota claim.

Serve-only recovery may attach process-local drive and discovery handles to an
already validated durable row. That narrow attachment cannot create a row or
change durable metadata. It joins discovery so existing local blocks remain
serveable, but it does not eagerly replicate, install persistent download
ranges, run repair/anchor pulls, accept fresh or re-pin ingress, or begin a
durable forget/eviction/custody teardown. A fatal, stopped, missing, or
ceiling-exhausted physical authority makes this gate effective immediately;
the decision is not merely latched at boot. Legacy eviction sidecars are fully
validated and replace prior in-memory state atomically. Tombstoned JSON rows
are never re-adopted, and a header-only Bee defers to the still-authoritative
validated legacy inventory without migrating it.

The provider ceiling covers the entire storage root, not an isolated
AppRegistry sub-budget. Growth by another writer consumes the same ceiling and
is observed at the next inspection. Public-T1 pin routes must remain disabled
until a real host adapter is installed and the remaining workload-writer
inventory below is closed with multi-process/operator evidence.

## Per-pin bounds and admission authority

Every new drive or bare-core pin must carry a positive safe-integer byte bound.
This is a deliberate API break: a missing, zero, negative, fractional, or
unsafe `maxStorageBytes` value is rejected before Corestore adoption. The bound
must propagate from the publisher-signed request, registry/catalog record,
federation or repair record, operator HTTP request, or CLI
`--seed-max-storage` option. A relay never invents a per-pin bound at a later
hop.

The built-in OutboxLog journal follows the same rule. Fleet pinning is enabled
only when `outboxlog.seedMaxStorageBytes` is a positive safe integer; without
that separate fleet bound, the journal remains local-only and logs a warning.
Hypercore persistence additionally requires
`outboxlog.maxJournalStorageBytes`: one aggregate local journal commitment is
installed before the index or any partition core can materialize. Every append
consumes a monotonic ledger beneath that aggregate bound. Partition count does
not multiply the commitment, and announcing writer-owned cores does not create
duplicate Seeder commitments.

Drive and bare-core ingress share one synchronous admission authority. It
installs a keyed reservation before returning to the caller, so concurrent
drive, core, repair, federation, and re-pin attempts see one another. The
authority charges every durable bound in full, plus a fixed per-pin allowance,
in addition to the exact measured storage tree. Measured bytes never discount
the promise: cached attribution can become stale after fork, truncation,
compaction, or hole clearing. Physical admission also subtracts all existing
promises from current free space, so an unchanged `statfs` sample cannot be
promised twice.

The fixed allowance is 64 KiB for each bare core. A drive receives the same
64 KiB metadata allowance plus a 2 MiB auxiliary allowance. PVSS public share
bundles use one deterministic, isolated temporary Corestore slot per admitted
drive; the signed core must prove exactly one block and no more than 1 MiB
before any finite body range or `get(0)` is allowed. A worst-case one-block
Corestore fixture is required to fit within the 2 MiB allowance. The slot is
removed after success, failure, retry, or replaced-key handling.

AppRegistry's shared Hyperbee has its own aggregate authority record,
`workload:app-registry`. Recovery first measures the complete feed, validates
the current active rows and durable retirement tombstones, and derives a legacy
baseline. Its ceiling is the baseline plus 64 KiB for every distinct historical
app key. This deliberately reserves the registry allowance twice: once in the
individual drive promise and once as a whole-journal workload promise. The
conservative overlap prevents an append-only shared feed from becoming
unowned when an individual drive is retired.

Every registry mutation is built in an unflushed Hyperbee batch. HiveRelay
uses the batch's actual encoded blocks as the pre-append reservation, then
requires the feed length, byte length, and fork to settle to the exact planned
tuple. JSON length is not treated as a storage proof. Of each historical key's
64 KiB, at most 48 KiB may be consumed by active rows; 16 KiB remains reserved
for retirement state. Delete writes a charged tombstone instead of `bee.del`,
so delete/re-add and restart cannot reset history. A low-debt re-add adopts the
existing counter. Once retirement history makes an active row exceed 48 KiB,
the key is terminally retired with
`APP_REGISTRY_KEY_RETIRED_METADATA_EXHAUSTED`; denial appends no bytes and
restores the prior durable state in memory.

The durable ordering for a fresh pin is:

1. reserve the complete bound;
2. open and prove the bounded feed/drive;
3. persist the registry or seeded-core v3 record;
4. commit the in-memory reservation;
5. begin only finite bounded downloads and send success/ACK.

Failures before durable persistence first cancel ranges, close pinned sessions,
and wait for the failed Corestore session's settlement barrier; only then do
they roll back exactly the caller's reservation. Residual filesystem bytes are
charged by the next exact tree walk.
After persistence, a reservation-invariant failure is fail-closed and retains
the conservative debt; it is never freed merely because the caller saw an
error. Intentional unseed retires the in-memory entry, durably deletes it,
drains same-key HTTP/PVSS leases, destroys ranges and pinned snapshots, closes
the drive, and releases the commitment last.

Bare-core retirement follows the same release-last rule. The seeded-core v3
intent is rewritten first, then listeners and refresh work are quiesced, the
finite range is destroyed, the pinned snapshot is closed, the topic is left,
and the core session must close successfully before authority release. Failed
teardown retains both the commitment and a retryable retiring entry. The JSON
inventory is capped at 4096 rows and proves that the atomic target-plus-tmp
pair fits the aggregate 64 KiB-per-core metadata slots before writing.

## Restart and legacy recovery

Startup admission stays closed until the drive registry and seeded-core
inventory independently seal their recovery scans. Seeded bare cores persist
as schema v3 records containing a canonical key, explicit `bounded` or
`unknown-recovery` state, and the bound when present. AppRegistry persists a
complete drive proof tuple: drive version, metadata length/fork, blob
length/fork, and total bytes. Partial or inconsistent tuples invalidate the
whole inventory; a legacy anchor without the tuple hydrates unanchored and is
not ACK-eligible. Legacy v1 records and historical v2 null bounds become explicit
unknown recovery debt. They may be reopened and served, but they do not pull
new blocks and their unknown debt blocks every fresh admission.

An operator may unseed an unknown legacy pin, or re-pin it only after HiveRelay
obtains an authoritative metadata-plus-blob footprint and verifies that the new
bound is at least that large. A corrupt, duplicate, noncanonical, unreadable, or
present-but-invalid persisted row invalidates the complete inventory scan: no
valid prefix is hydrated and that recovery seal remains pending.

Periodic `lastAnchorCheck` cadence is live telemetry, not an independently
durable transition: writing every health tick would create unbounded Hyperbee
history. The latest timestamp is carried opportunistically by the next real
bounded registry mutation. Legacy `evicted.json` state is migrated into the
same measured Bee tombstones; the sidecar is retained only by the no-Corestore
compatibility mode.

## Bounded replication and filesystem proof

Hyperdrive admission measures and snapshots both metadata and blob cores after
bounded proof/update discovery. Persistent ranges use those exact snapshots.
Manifest reads use the proved metadata checkout plus the proved blob snapshot;
the public HTTP gateway requires the complete durable tuple and caches by that
tuple, never by drive version alone. A same-version higher fork therefore
cannot reuse an old cache entry. Bare Hypercore replication likewise proves a
fork/length/byteLength tuple and creates its finite range on that exact snapshot.
An append must pass a new proof before the range can extend. Open-ended
`end: -1` pulls are not permitted on a bounded pin.

The foundation gateway currently holds the same-drive mutation lane for the
entire HTTP response so unseed cannot close a snapshot beneath a stalled
stream. That is safe but serializes concurrent reads for one drive. Integration
must replace it with a concurrent read-lease primitive (shared readers,
exclusive retirement) without weakening the drain-before-close guarantee.

Node and Bare runtimes use the same exact-path proof. Every reservation
re-stats the configured path, resolves and verifies its realpath and device,
samples `statfs`, walks the resolved tree, then re-samples both identity and
current free space before installing a token. The public root may be a symlink
to the proved directory, but nested symlinks, nested mount devices, and a
directory identity change during enumeration fail closed. A stale proof,
missing path, changed mount, realpath/inode/device mismatch, invalid usage, or
sampling error pauses all new adoption. Custom raw storage paths must exist
before startup; no ancestor or fallback path is accepted as authority.

Storage-producing operations are lifecycle tracked. Normal stop first disables
ingress, timers, and append-capable providers while their final flushes can
still use the authority; it then closes mutation admission and drains the real
underlying write promises before Corestore teardown. Failed-start rollback
uses the same terminal drain rule. An Outbox append timeout does not
cancel Hypercore's append: its debt is retained and the actual append promise
remains tracked. If that promise cannot settle within the shutdown bound, stop
returns a terminal failure and deliberately leaves Corestore open for a later
supervisor retry; it never claims a graceful close while a write can still land.

## Outbox migration and current scope

When a relay has the shared storage authority, persistent OutboxLog operation
requires `journal="hypercore"` or `journal="hypercore-outboxes"` and a positive
`outboxlog.maxJournalStorageBytes`. File, snapshot, and JSONL persistence fail
startup with `OUTBOXLOG_BOUNDED_PERSISTENCE_REQUIRED`; operators must migrate to
a bounded Hypercore journal or explicitly disable persistence. The fleet
announcement bound remains separate and optional.

This document describes the storage-foundation candidate, not a claim that all
HiveRelay writers are globally cap-ready. Promotion remains blocked until the
follow-on workload-writer slice routes or disables every append-capable path,
including SeedingRegistry, StorageService, ShardStore, Notify, WitnessLog,
RepairTicket, Poker, and SchemaService. No mainnet-ready claim is valid while
that inventory remains open.
