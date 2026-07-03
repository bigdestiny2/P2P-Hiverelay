# Changelog

All notable changes to `p2p-hiverelay`, `p2p-hiveservices`,
`p2p-hiverelay-client`, and (from v0.6.0) `p2p-hiverelay-verifier` are
documented here. Dates in YYYY-MM-DD.

The packages are versioned in lockstep.

## [Unreleased]

### Added
- **Blind-shard dispersal + recovery client layer** (`p2p-hiverelay-client/blind-shards.js`)
  — the connective tissue between PVSS secret-sharing and the content-addressed
  blind shard store. `disperseSecret({count, threshold, put})` splits a secret
  into `n` self-verifying shares, encodes each as a canonical **opaque** shard
  blob (versioned, deterministic; `blake2b` content address byte-identical to the
  relay's), and disperses them; `recoverSecret({shareManifest, threshold, fetch})`
  collects ≥`k` shards, verifies each by content address, decodes, and
  reconstructs the secret **at the reader's edge** — no relay ever holds the whole
  thing. Transport-agnostic (`put`/`fetch` injected: HTTP `/api/v1/shard`, P2P
  RPC, or in-process). This is the "public plaintext, blind custody" path:
  encrypt content with a random key, store the ciphertext, and disperse the KEY
  as blind shards so no single operator can produce the plaintext.
- **End-to-end blind-custody proof** (`test/integration/blind-shard-dispersal-e2e.test.js`):
  a dealer disperses a secret across 5 real `ShardStoreService` relays (custody-pin
  authorized); the test asserts each relay holds exactly one opaque shard, **no
  single relay and no k-1 colluding relays can reconstruct**, and any `k` relays
  let a reader rebuild the exact secret. Plus a codec/driver unit suite
  (`test/unit/blind-shards.test.js`) covering determinism, k-of-n, and
  content-address integrity against a tampering relay.

## [0.23.0] — 2026-07-03

### Added

- **Operator storage designation.** An appliance operator can now set how much of
  the box's disk HiveRelay may use, live and without a restart, from the
  Blindspark page (a GB control) or `POST /api/manage/config { maxStorageBytes }`.
  The relay re-caps the seeder's adoption gate, enables eviction, and sheds
  surplus blind fragments down to the designated cap — the eviction sweep now
  triggers on *our measured usage vs the cap*, not only whole-disk pressure, and
  bypasses rank-deferral while over-cap so "give HiveRelay N GB and shrink to
  fit" works even when the physical disk is far from full. The replication floor
  + margin still protect the network; an unset cap (0) preserves the prior
  disk-pressure-only behaviour.

### Fixed

- **Release-tooling + custody test staleness.** The ecosystem-consumer audit and
  npm-latest-check tests hardcoded a release version (`0.20.2`) in fixtures and
  so rotted red on every version bump; they now read the current version
  dynamically. The custody-pvss "cleartext share material is forbidden" test was
  aligned to the intentional allowlist-first design (top-level forbidden fields
  are rejected by the positive allowlist; the recursive scan is the backstop for
  nested content). All previously-red on the v0.21.x/v0.22.0 line.

## [0.22.0] — 2026-07-03

Production-hardens the `dht-relay-ws` transport for the Phase 5 **pure-pipe**
path — an operator running a content-blind DHT byte-pipe 24/7. Every bound
added here is **content-neutral** (frame lengths, buffer sizes, timings — never
the Noise-encrypted payload), preserving the operator's §512(a)
transitory-conduit posture. The transport stays disabled by default
(`config.transports.dhtRelayWs`).

### Added

- **Connection supervisor** (one shared timer): WS ping/pong liveness
  (terminates half-open TCP), first-frame deadline (reaps clients that never
  speak the protocol — which the upstream heartbeat failsafe never catches, so
  they otherwise squat a `maxConnections` slot forever), sustained
  egress-backpressure termination, and an optional absolute session ceiling.
- **Byte metering**: aggregate `totalBytesIn/Out` in `getStats()` and
  Prometheus (`hiverelay_dhtrelay_*`), plus `totalReaped` — the signal a
  pure-pipe operator budgets/bills on. Optional per-connection ingress
  byte-rate cap (`flow.maxRxBytesPerSec`, default off).
- **Config surface**: `config.dhtRelayWs.{rateLimit,keepalive,flow,maxConnections,trustProxy}`.

### Fixed

- **`trustProxy`/XFF rate-limit keying** — behind a TLS reverse proxy the
  limiter keyed on the proxy's socket IP, collapsing per-IP limiting into one
  global bucket (a live issue on the two relays already running this behind
  Caddy). Now keys on the first `X-Forwarded-For` hop when `trustProxy` is set.
- **verifyClient concurrency-slot leak** — an upgrade that passed `verifyClient`
  but aborted before the `connection` event leaked its slot until restart,
  eventually locking the IP out; reservations now expire.
- **`maxPayload`** single-frame cap (default 8 MiB; the `ws` default is 100 MiB).
- **Distinct connection cap** — no longer forced to reuse the Hyperswarm swarm
  `maxConnections`; behind a proxy the ws server binds loopback.

### Security / dependency

- **Vendored + patched `@hyperswarm/dht-relay@0.4.3`** (upstream: "do not use in
  production") under `transports/dht-relay-ws/vendor/dht-relay`, pinned exact.
  Three marked patches root-fix confirmed prod-blockers that live in the
  upstream: egress backpressure (a slow reader no longer grows relay heap
  without bound), **per-connection crash containment** (a throw in a proxied DHT
  op no longer escapes as an `uncaughtException` that crash-loops the relay —
  only the faulting connection is torn down), and per-connection resource drain
  on close. See `vendor/dht-relay/VENDOR.md`.

## [0.21.1] — 2026-07-02

Hardening patch from the v0.21.0 pre-release expert-panel audit, plus a
release-critical custody-signing regression fix. Safe in-place upgrade from
0.21.0 — and v0.21.0 should not be deployed for custody: its dealer→relay
custody-intent path is broken (see below).

### Fixed (critical)

- **Custody-intent signing regression (v0.21.0).** v0.21.0 added an optional
  `shareManifest` field to the version-2 custody-intent *signable* field set,
  and `custodySignablePayload` emitted it as `["shareManifest", null]` even when
  absent — changing the canonical payload for **every** v2 custody-intent. The
  client's self-contained bare-safe signer (`_createCustodyIntent`, which by
  design never imports core's custody-signing) still omitted the field, so every
  real dealer→relay custody publish failed `INVALID_CUSTODY_ENTRY: bad
  signature`. The cross-impl parity guard (`client-custody-crossimpl.test.js`)
  was red on v0.21.0. Fix: an optional signature-covered field is now omitted
  from the payload when absent, making the payload byte-identical to pre-v0.21.0
  for any intent that doesn't carry it (and matching the client). Required
  fields keep their historical `?? null` inclusion, so v1/older signatures stay
  byte-identical.

### Fixed

- **SSE keepalive pings now honor backpressure/teardown (`witnesslog`,
  `repairticket`).** `startSsePing` wrote `: ping` frames unconditionally on
  its interval, bypassing the `res._ssePaused / writableEnded / destroyed` gate
  that `writeSseData` already enforces — a slow reader could keep the socket
  buffer growing. The ping now checks the same gate (matching the outboxlog
  adapter).
- **`notify` watch wakes honor send-cap revocation.** `_fireWatch` re-checked
  receive-cap, device, app, channel, and relay revocations on every fire but
  not the send-cap the watch was installed under; the direct-send path already
  honored it. Revoking a send-cap now stops watch wakes as well as direct
  sends.

### Security

- **`shard-store` HTTP adapter now rate-limits per IP.** The adapter (not yet
  mounted into the request path) had no per-IP throttle, unlike the sibling
  outboxlog / witnesslog / repairticket adapters. Added the same
  `{ windowMs, max }` token-bucket limiter — on by default via a process-wide
  bucket store, scoped/overridden via `state` / `rateLimit` / `trustProxy` in
  opts — closing the timing/enumeration-probe surface before the adapter is
  wired.

### Notes

- One HIGH audit finding (outboxlog "namespace not in signed payload") was a
  false positive: the namespace is bound by the signature through the message
  prefix (`pear.app.<driveKey>:<ns>:…`), so cross-namespace signature reuse
  fails verification. No change required.
- A follow-up cross-impl parity audit confirmed the custody fix above is complete
  for every current intent, and surfaced a **latent** (not-yet-live) sibling: the
  client's self-contained signer keeps its own `SHARE_FIELDS_BY_TYPE` that also
  omits `shareManifest`. It is harmless while the client cannot emit a manifest
  (the field is always absent → dropped from both payloads), but must be mirrored
  — as one cohesive change — before client-side shard-binding custody goes live.
  Guard comments were added at both field-set sites; see the follow-up task.

## [0.21.0] — 2026-07-02

### Added

- **Custody availability primitives — `witnesslog` + `repairticket`.** Two
  OutboxLog-backed signed logs that complete the shard store's
  placement/recovery story. `witnesslog` records signed third-party
  availability observations (the custody witness role — independent,
  non-storage observers sign what they see); `repairticket` records signed
  repair requests, claims, receipts, and closures for self-healing recovery
  (the AutoHeal loop). Both HTTP-bridge at `/api/witness` and `/api/repair`,
  are dashboard-selectable, and inherit the OutboxLog engine's hardening
  (re-verify-signatures-on-load, journal-first persistence, SSE backpressure).
- **Blind shard store (`shard-store`) — content-addressed blind blob surface
  for custody shares.** `PUT` opaque ciphertext, get back `shard:<hash>`
  (`hash = blake2b-256(ciphertext)`); `GET shard:<hash>` returns the exact
  bytes and the caller re-hashes to verify — the relay is trusted for nothing
  and never introspects a blob. Every `PUT` is authorized by a signed pin
  (custody: the hash is bound to a `shareIndex` assigned to this relay in a
  verified custody-intent's new signed `shareManifest`; or payment/quota), and
  the pin registry is the retention authority (re-verifies signatures on load).
  Adds domain-separated possession proofs (Mode R retrieval + Mode A
  attestation), non-serving tombstones, retention GC, client-side k-of-n
  `recoverShards`, an HTTP bridge, and aggregate (never per-hash) metrics.
  Opt-in (`config.plugins` includes `shard-store`). See
  `docs/BLIND-SHARD-STORE-SPEC.md`.


- **Notify service (`notify`) — relay-hosted encrypted wake-up push.** An
  always-on relay can now wake a peer's app through APNs/FCM/WebPush/runtime
  without ever seeing who is being notified or why. Capabilities split into
  ReceiveCap (the device consents to be woken) + SendCap (a peer is authorized
  to wake it); the relay verifies domain-separated Ed25519 signatures and stays
  blind — payloads are opaque ciphertext, wakes are generic. Modes:
  direct, watch (Mode 2), presence-fallback. Delivery events are relay-signed
  and redacted (no provider tokens/plaintext). Rule: *push wakes the app; p2p
  sync gives the app truth.*
- **Signed outbox log (`outboxlog`) — Peerit-compatible single-writer append
  log.** A blind-sealed, signature-gated per-pubkey log with a token-gated
  HTTP/SSE bridge, a hypercore operation journal, and an in-process swarm hub
  for browser peers. The relay stores and serves signed rows it cannot read.
- **Mode-2 `watch` runtime** — a `notify-feed-head` watch composes with a
  co-resident `outboxlog`: when the watched outbox head advances, the device
  gets one opaque, coalesced wake. Watches for a source kind with no attached
  observer are rejected (`SOURCE_UNAVAILABLE`) rather than silently accepted.
- **Client SDK** — `createNotifyDeliveryEventRequest` (device-signed
  delivery-event reads) and the `notify-feed-head` watch builders.

### Security

- **`notify.delivery-event` is authenticated** — it now requires a request
  signed by the receiving device key and returns only that device's events,
  closing a cross-tenant metadata IDOR (billable/device/timing leak). `status`
  counts are scoped to the caller's app/device instead of relay-global totals.
- **`outboxlog` re-verifies signatures on load** and drops unverifiable rows —
  the persisted state file / journal is no longer a trust root; only the
  writer key is.

### Changed

- **Hot-path persistence** — notify debounces snapshot writes (durability-
  critical replay/dedupe still persist synchronously *before* provider egress
  so a crash can't double-send); outboxlog treats the journal as the per-append
  WAL and the snapshot as a periodic checkpoint (restore = checkpoint + journal
  tail replay).
- **outboxlog SSE honors backpressure** (drops live events under a full socket
  buffer, resumes on drain) and the swarm hub gained an explicit
  `destroy()`/`close()`. Notify abuse limits (app/sender/device/channel) are
  now operator-configurable; a zero limit disables a scope (`quota_exhausted`).

Design review + benchmarks: `docs/NOTIFY-OUTBOX-REVIEW.md`. Issues #142–#146.

## [0.20.2] — 2026-06-24

### Added

- **Honest "Data served" metric** — a new replication-layer counter
  (`ServedAccounting`) attaches an `upload` listener to *every* core the
  corestore opens (registry log + every appRegistry drive's meta/blob
  cores) and sums the bytes. `seeder.totalBytesServed` only saw
  Seeder.seedCore-routed cores, so it read ~0 on a registry-drive relay
  that was actively serving app blocks — the served-bytes twin of the
  "Stored: 0 B" blind spot that `StorageAccounting` fixed. Surfaced as a
  top-level `served` block (`{ bytes, blocks, measured }`) and
  `seeder.totalBytesServedMeasured` on `/api/overview` (and the WS feed),
  as `hiverelay_bytes_served_measured` / `hiverelay_blocks_served_measured`
  in the Prometheus output, and preferred over the legacy counter in the
  `status`/`manage` CLI views.

### Changed

- **Blindspark dashboard restores a real "Data served" tile** — v0.16.3
  had swapped it for a "Storage used %" stopgap because no honest served
  source existed. The tile now reads the measured `served.bytes`; the
  absolute on-disk total moved into the "Storage used" sublabel
  (`<used> of <cap>`), so the 2x2 layout keeps every figure with nothing
  dropped.

## [0.20.1] — 2026-06-24

### Fixed

- **Pear/Bare client importability** — removed the Node-only `os` builtin import
  from `p2p-hiverelay-client` and replaced the proof verifier sandbox temp-dir
  path with a portable runtime helper. This keeps `client.proveSeeded()` working
  under Node while allowing Bare/Pear consumers, including PearBrowser worker
  bundles, to load the client without an `os` shim. A source-level regression
  guard prevents the import from returning.

## [0.20.0] — 2026-06-22

### Added

- **Proof-of-Storage live wiring — `StorageProofService` + `client.proveSeeded()`.**
  Drives the proof-of-storage primitive over the wire. Relay side: a builtin
  `storage-proof` service (opt-in via `config.plugins` / services.json on the
  Node runtime, or `config.services`/`HIVERELAY_STORAGE_PROOF=1` on the Bare
  appliance runtime) exposing `prove({ coreKey, index, nonce })` over the
  existing service RPC. Client side: `proveSeeded(driveKey, { relay, samples })`
  opens the drive to learn the metadata head, samples random block indices, and
  verifies each signed proof against an isolated temp-Corestore verifier
  (minLength-pinned to the head). Security hardening from adversarial review:
  (1) PRIVACY GATE — blind / privacy-redacted drives return `NOT_SEEDED`,
  indistinguishable from not-held, so prove() can't be used as a possession
  oracle that defeats catalog redaction; (2) a sybil-resistant GLOBAL proof-work
  rate cap (rotating identities can't bypass it) plus a bounded, idle-evicted
  per-caller bucket; (3) phantom-core DoS guard (only `appRegistry` keys; never
  `store.get` on attacker input). v1 proves the metadata core; blobs-core proofs
  are a follow-up.
- **Proof-of-Storage primitive (`core/protocol/proof-of-storage.js`)** — the
  trustless heart of Tier-2 seed verification. `buildStorageProof` (relay side)
  produces a real Hypercore block proof for a challenged index, read from LOCAL
  storage only, signed by the relay over `coreKey || index || nonce ||
  blake2b(block)`. `verifyStorageProof` (client side) feeds the proof to a
  key-only verifier core — Hypercore checks the block hashes into the drive
  key's SIGNED Merkle root, so forged content is rejected — then checks the
  relay signature for attribution + nonce-freshness (no replay). Fully
  adversarial-tested with real cores (forged content, wrong index, wrong core,
  forged/relabelled signature, replayed nonce, blockhash lie, and a relay that
  doesn't hold the block — all rejected). This is the verification primitive;
  the relay-side `StorageProofService` RPC + `client.proveSeeded()` that drive
  it over the wire land in a follow-up (gated, canaried). Complements Tier-1
  `verifySeeded` with a per-block, relay-attributable proof.

- **`HiveRelayClient.subscribeService(service, event, onEvent, opts?)`** — live
  service-event subscriptions over the pure-P2P service RPC, the streaming
  counterpart to `callService`. Sends `MSG_SUBSCRIBE` for the first local listener
  on a `(relay, topic)` pair, routes `MSG_EVENT` to the callback, and
  `MSG_UNSUBSCRIBE` on last detach; returns an unsubscribe fn. Topics follow the
  producer convention `<service>/<event>` (e.g. `arbitration/resolved`,
  `sla/created`, `events/<relay-event>`), published via `node.router.pubsub`.
  The server side (MSG_SUBSCRIBE/MSG_EVENT + pubsub) already existed — this adds
  the missing client half so apps get live fan-out without the HTTP/WS gateway.
  (#89 follow-up.)
- **Poker live events over P2P** — `PokerApp` now fans accepted appends out on a
  PER-TABLE pubsub topic `poker/<tableKey>` (was a single global `poker/entry`,
  a cross-table firehose), consumable via
  `client.subscribeService('poker', tableKey, …)`. Per-table = a subscriber only
  sees the table it holds the key for; card-blind (payload forwarded verbatim,
  same data as the open `/log`); only live appends publish — hydration is silent.
  Pass the tableKey lowercase (the relay's canonical form).
- **`HiveRelayClient.verifySeeded(driveKey, { relay })`** — trustless Tier-1
  seed verification: confirm a relay actually holds + serves a specific app
  (Hyperdrive) without trusting its self-reported catalog. Dials the relay,
  opens the drive, and downloads BOTH cores (metadata + blobs) to completion —
  Hypercore verifies every block against the drive key's signed Merkle root on
  arrival, so a relay cannot fake content it doesn't hold. Returns
  `{ complete, relayIsPeer, relayHasFullLength, contentVerified, metaLength,
  blobsLength, relayRemoteLength }`. Caveat: replication rides the shared swarm,
  so this proves the content is genuine + served and that the relay advertises
  the full length — it is NOT a per-block, relay-attributable, third-party
  -portable proof. (Tier 2, a signed proof-of-storage challenge, follows.)

## [0.19.4] — 2026-06-22

### Fixed

- **Storage accounting now counts ALLOCATED disk blocks (`st.blocks`), not
  apparent file size.** Relay block files are sparse — a partial replica's blocks
  file has holes for unfetched blocks — so `st.size` (apparent length) overcounts
  real disk usage badly (bern measured 51.5 GB by size vs 38 GB actual `du`).
  `dirBytes` now sums `st.blocks * 512`, matching `df`/`du`, so the adoption
  guard binds on true usage instead of refusing far too early. (Refines v0.19.3.)

## [0.19.3] — 2026-06-22

**Fix: storage accounting read ~0 on registry-driven relays → adoption never capped → disks filled to 100%.**

### Fixed

- **StorageAccounting now measures the REAL on-disk corestore footprint** (`du`
  of `config.storage`), not just the per-entry drive walk. Most registry entries
  on a busy relay are bare seeded cores or lazily-unloaded Hyperdrives with no
  live `entry.drive`, so the per-entry walk reported ~132 KB while the disk held
  19 GB (sing-1, 2026-06). `getSummary()` now reports the measured disk total
  (throttled `dirBytes` walk, default once/min, latched); adds `diskBytes` +
  `perEntryBytes`; new `measureDisk()`.
- **All four adoption guards now gate on the real measured bytes** via a shared
  `RelayNode._storageUsedBytes()` — `_scanRegistry`, `_onSeedRequest`, the
  replication-repair `_shouldAdopt`, and the follow-anchored headroom check
  previously computed `maxStorageBytes − seeder.totalBytesStored`, and
  `totalBytesStored` only counts `Seeder.seedCore` traffic (~0 on a
  registry-driven relay), so the cap never bound and adoption was effectively
  uncapped. Root cause of the fleet disk-full incidents.

## [0.19.2] — 2026-06-22

**Operator poker-services — opt-in, reachable over HTTP, WS, and pure-P2P service RPC.**

### Added

- **Poker as an opt-in operator service.** Registered as a builtin on both runtime
  paths — `RelayNode` (plugin-loader `BUILTIN_MAP` + a `poker → vrf,arbitration,zk`
  service bundle, auto-unioned by `expandServiceDeps`) and `BareRelay`
  (`HIVERELAY_POKER=1` / `config.services|plugins` includes `poker`); added to the
  `cli/setup.js` picker. App-level substrate, off by default. (#88, #89)
- **Reachable over three transports:** `/api/poker/*` HTTP gateway mount (table
  CREATE auth-gated; signed reads/moves open), a `PokerFeed` WebSocket fan-out for
  `/api/poker/:table/events`, and the P2P **service RPC**. The poker capabilities
  now accept the registry's `method(params, context)` params-object convention as
  well as the positional HTTP form (dual-convention on `submitEntry`/`getLog`/
  `getState`), so `callService('poker', …)` works. Card-blindness preserved —
  `options` stay opaque/deep-frozen; the signed log only checks sig/writer/seq/ts. (#89)
- **Honest, blind-safe metering.** Content-free, counterparty-signed `UsageReceipt`
  + `UsageLedger` (verify, replay-guard, aggregate, order-independent `receiptRoot`);
  `POST /api/usage/receipt` (open, verified-only) + `GET /api/usage` (auth digest);
  `GET /api/poker/usage` derives poker's payout signal from the player-signed log.
  Self-reported registry counters are labeled `statsVerified:false` — only
  counterparty-signed receipts are payout-eligible. Surfaced in the services GUI. (#88)

## [0.19.1] — 2026-06-22

**Curated catalog-bee advertising + storage/catalogue dedup (blind-safe).**

### Added

- **`catalogBeeKey` advertising** — an operator can set `catalogBeeKey` (a bare
  64-hex key of a signed Hyperbee catalog) in config; the relay advertises it in
  both `/catalog.json` and the gateway catalog firehose so clients that can
  replicate + verify a signed P2P catalog (e.g. PearBrowser) PREFER it over the
  HTTP firehose. Only emitted for a valid 64-hex key — the default response shape
  is unchanged for operators who don't configure one. (`/catalog.json` already
  surfaced it since v0.19.0; this adds the gateway firehose surface + the
  documented `catalogBeeKey` config default.)

**Storage + catalogue dedup (blind-safe).** Identical content is already
deduped (Corestore content-addresses by appKey == driveKey); cross-publisher
content dedup is intentionally NOT done — it would break the blind model. These
are the blind-safe gaps:

- **Duplication report** — `getStats().storage.dedup` estimates reclaimable
  bytes from superseded versions still resident on disk (an `app`-type entry
  whose appId is indexed to a newer appKey), summed from StorageAccounting.
  Read-only; never buckets by ciphertextRoot/blindContentId; blind entries never
  appear.
- **`EvictionManager.reclaimSuperseded()`** + **`POST /api/dedup/reclaim`** —
  reclaim disk held by superseded app versions. Dry-run by default
  (`{ execute: true }` to perform); reuses the proven unseed → tombstone → purge
  teardown; gated by `assertPurgable` (archive/custody/lease are never reclaimed
  even when superseded); `retainVersions` knob. Single-relay dedup — ignores the
  fleet census, distinct from the disk-pressure eviction sweep.

### Changed

- **`catalogForBroadcast()`** now collapses `app`-type rows by appId (keep
  latest version), matching the HTTP `catalog()` view — the P2P broadcast
  previously leaked superseded versions to peers. (Redacted/blind rows + non-app
  types pass through.)

## [0.19.0] — 2026-06-17

### Added

- **DHT-resolvable relay discovery** (iroh adoption Phase 1, see
  `docs/IROH-ADOPTION-ROADMAP.md`). The relay publishes a signed self-description
  `pubkey → { gatewayUrl, indexRoom }` as a hyperdht MUTABLE record keyed by its
  identity key (`RelayNode.publishRelayRecord` — on boot, on indexRoom change,
  and a 30-min republish). A client that knows only a relay's pubkey can resolve
  its current gateway + index room over the DHT, signature-verified by hyperdht,
  with no trusted directory and no Mainline/pkarr dependency — the pkarr
  property native to Holepunch. `relay-record.js` codec + `resolveRelayRecord`.
  Carries only already-public relay self-description (blind-safe).

## [0.18.1] — 2026-06-16

**Services tab — host an AI model on your relay.** The Blindspark dashboard
gains a Services card: toggle the on-device AI service on (persisted; applied on
restart), add a QVAC model, and see hosted-service status. Default OFF — enabling
only loads the services layer; it does nothing until a model is added. Also fixes
two bugs that made the existing services endpoint render empty (it read a stale
provider shape; restart poked the wrong methods).

**Tier-2 index layer (schema-sheets) — relay advertise/proxy + out-of-process
sidecar.** A relay's catalogue, pins, relay-directory and verifications are
mirrored into a signed, JMESPath-queryable `schema-sheets` room that clients
blind-replicate read-only. Additive and off by default — a relay without a
sidecar simply omits `indexRoom` and clients fall back to `catalogBeeKey` /
`/catalog.json`. See [`docs/INDEX-LAYER.md`](docs/INDEX-LAYER.md).

The index runs as a dependency-isolated **sidecar** because schema-sheets is
built on corestore-7/hypercore-11/ajv-8, which collide with the relay's
corestore-6/hypercore-10/ajv-6 (a spike confirmed an in-process load crashes).
It bridges until the relay's own hypercore-11 migration lands.

### Added

- **Services tab** in the Blindspark dashboard: enable/disable the AI service
  (persisted to `<storage>/services.json`, applied on restart), add a QVAC model,
  hosted-service status. New `GET /api/manage/services/available`,
  `POST /api/manage/services/config`; fixed `GET /api/manage/services` (read the
  registry's `ServiceEntry`) and the restart path (`registry.restart`).
- **Relay (Tier-0):** additive `indexRoom` field in the signed capability doc
  (schemaVersion stays 1; the canonical signer covers it, so old verifiers still
  validate) + in the `/catalog.json` envelope. `RelayNode.setIndexRoom` /
  `_loadIndexRoom` persist the pointer in `index-room.json`. Loopback
  `POST /api/manage/index-room` (operator-authed) for the sidecar to publish its
  room key. Optional reverse-proxy of `GET /index/*` + `/api/index/room` to
  `indexSidecarUrl` (env `HIVERELAY_INDEX_SIDECAR_URL`) so clients use one
  gatewayUrl — forwards method+path+query only, no client headers/IP.
- **`services/index-sidecar/`** (`p2p-hiverelay-index`): four schemas
  (pin-registry, relay-directory, app-manifest, verification), pure registry→row
  mappers with a redaction gate, a primary-keyed room manager, a
  content-debounced projector (write-amp guard — Autobase rows measured at
  ~18KB), the §2 query server (JMESPath + page/pageSize), and a swarm announce
  for blind read-only replication. Node `node:test` suite (25 tests) incl. an
  e2e blind-replication check.

## [0.18.0] — 2026-06-16

Two features, both off/inert by default:

**Paid pin-lease** — a relay can charge a publisher (the network case) to keep
their Hyperdrive seeded for a window. Off by default; self-host stays free.
Zero-custody — funds settle to the operator's own Lightning node and the only
durable artifact a payment creates is the lease deadline. Blind model untouched:
pricing keys on (appKey, declared maxStorage, leaseDays), never on content.

**Replicable signed catalog bee** — a relay's catalog can be published as a
Hyperbee whose core is pinned + advertised (`catalogBeeKey` in `/catalog.json`),
so consumers replicate + verify it over P2P instead of polling HTTP. Inert until
an operator publishes one.

### Added

- **`LeaseManager`** (`incentive/lease/`) — byte-days pricing
  (`ceil(maxStorageBytes/GiB) × leaseDays × satsPerGiBDay`), a relay-signed
  stateless quote (reuses the subsidy Ed25519 claim crypto), settlement
  verified via the operator's own LN node (`lookupInvoice`), and a persisted,
  time-aware replay-guard.
- **Shared gate** (`incentive/lease/gate.js`) applied at EVERY publisher seed
  entry point — HTTP `POST /api/v1/seed`, the Protomux publish-channel, the
  legacy seed-protocol, the seedingRegistry auto-accept, and the
  replication-repair monitor — so the charge can't be bypassed on any one
  transport. Operator `POST /seed` (API key) and a **verified** custody intent
  are exempt, so self-host and social-recovery stay free.
- HTTP `402` quote → pay → resubmit-proof handshake; the lease is enforced by
  reusing the custody-expiry sweep (`leaseManaged` + `retainUntil`) and is
  protected from eviction until it expires.
- API: `GET /api/lease` (status + live active-lease count) and `POST
  /api/lease/config` (runtime rate). Blindspark dashboard: an operator
  "Paid seeding" card (set sats/GiB/day, watch active leases + sats earned).
- `config.lease` (default **off**). MockProvider for test/demo; a real LN
  provider is operator-supplied (a boot-guard refuses to enable paid seeding
  without a provider that can verify settlement).
- **`POST /seed-core`** — pin a BARE Hypercore by public key via
  `Seeder.seedCore` (operator-authed); `/seed` opens a Hyperdrive, so a Hyperbee
  catalog had no pin path. Durable across restart: the Seeder persists its
  bare-core pin set (`<storage>/seeded-cores.json`) and re-seeds on start;
  teardown keeps the list, only `unseedCore` removes a pin.
- **`scripts/publish-catalog-bee.js`** — builds a replicable, signed Hyperbee
  catalog from a relay's `/catalog.json` (appKey → entry), authored by a
  persisted Ed25519 keypair. The signed `\x00meta` names `beeKey` (subscribe
  anchor) and `signerPubkey` (signer == core block authenticator) separately,
  so a consumer verifies against `signerPubkey` bound to
  `core.manifest?.signers[0].publicKey ?? core.key` — correct for both compat
  and manifest cores. Pins via `/seed-core`.
- **Catalog-bee discovery (read-side):** the relay advertises `catalogBeeKey` in
  `/catalog.json`; `POST /seed-core { catalog: true }` (and the script by
  default) pins the bee AND registers the pointer (persisted, survives restart),
  so consumers replicate + verify the catalog over P2P instead of polling HTTP.

### Notes

- MVP charges each relay individually (no free cross-relay mirroring); a full
  payer-facing GUI and the real LND `lookupInvoice` provider are fast-follows.
- Catalog-bee read-side consumer (PearBrowser replicating `catalogBeeKey`) is
  app-side, separate. Durable bare-core pinning persists for relay uptime + is
  re-seeded on restart.

## [0.17.0] — 2026-06-16

Minor: operators can seed their own app and list it — from the appliance
dashboard — plus app icons in the catalogue. Surfaces capability that
already existed at the API layer (`POST /seed`); no new seed/pin logic.

### Added

- **"Seed an app" in the Blindspark appliance dashboard** (`blindspark.html`,
  served on both Umbrel and StartOS via `ui.simple`). The operator pastes
  a drive key they published (with `pear` / publish-app), optionally names
  it, and ticks "Pin permanently" → the relay replicates + archive-pins it
  (`durability:1`, non-evictable, AutoHeal-maintained) and it auto-lists in
  the relay's `/catalog.json`, which PearBrowser reads. POSTs to the
  existing `/seed`; authenticates via the existing token shim behind the
  proxy. (Authoring a brand-new app from the box is a deferred follow-on.)
- **PearBrowser subscribe URL** — a copy-to-clipboard control showing the
  relay's own reachable base URL, for PearBrowser's "subscribe to this
  relay" quick-add. (PearBrowser is a client that subscribes to relay URLs
  and reads each `/catalog.json`; there is no central index to register.)
- **App `icon` field** end-to-end: parsed from the app's `manifest.json`
  (`icon` or `icons[0]`), normalized (string, trimmed, ≤512 chars) in the
  registry, surfaced in `catalog()` / `/catalog.json` / `/api/apps`, and
  rendered as a tile in the dashboard's hosted-apps list (drive-relative
  paths resolve through the gateway; falls back to the live dot on load
  error).

### Security

- **`icon` is stripped for blind/redacted catalogue entries** in
  `_redactCatalogEntry` — a drive-relative icon path would leak the
  addressKey and an external URL could beacon, so it's nulled alongside
  name/description for blind drives.

Pinned by `test/unit/app-registry-icon.test.js`: icon surfaces for
non-blind entries, normalizes junk/whitespace to null, length-caps to
512, survives a persistence reload, and is stripped for blind drives.

## [0.16.3] — 2026-06-15

Correctness + accessibility fixes for the new one-page Blindspark
dashboard, from an adversarial review of v0.16.2.

### Fixed

- **"Data stored" no longer hides a filling disk** — the page preferred
  `seeder.totalBytesStored`, which counts only Seeder.seedCore traffic
  and reads ~0 on registry-drive relays (the blindspot behind the
  2026-06-11 disk fill). It now trusts the server's honest measured
  `storage.used`. A new **Storage used %** tile (of the configured cap)
  replaces the old "Data served" tile, whose only available source
  (`seeder.totalBytesServed`) under-reported the same way with no honest
  fallback.
- **A running relay is no longer mislabeled "Offline"** — the status
  pill conflated `health.healthy` (a quality flag that flips on benign
  conditions like no-peers-yet or high disk) with liveness. It now shows
  **Online** whenever the API responds, **Degraded** (amber, with an
  explanatory tooltip) when a health check is unhappy, and **Offline**
  only when the relay doesn't answer.

### Accessibility

- The BTC payout-address copy control is now a real focusable `<button>`
  (was a mouse-only `<span>`); the copy-confirmation toast is a
  `role="status" aria-live="polite"` region so screen readers announce
  it; and `--text-faint` was lightened to meet WCAG AA contrast for
  secondary text and the app-key column.

## [0.16.2] — 2026-06-15

One-page Blindspark dashboard for the Umbrel appliance. The full
multi-tab operator UI is right for PC node operators and devs, but it
carries Docs/GitHub links, payment/credit/earnings panels, a
calculator, a leaderboard, and charts that are noise on a one-click
home-server appliance. Blindspark now serves a single, simple page
showing only what's real and live.

### Added

- **`dashboard/blindspark.html`** — single-page appliance UI: relay name
  + copyable public key + live online/uptime status, four real stats
  (apps held, connected peers, data stored, data served), accept-mode
  with a plain-English line, BTC payout wallet, uptime, and the list of
  hosted apps. A `Setup` link re-opens the wizard. No tabs, no
  Docs/GitHub, no payments/calculator/leaderboard.
- **`ui.simple` config + `HIVERELAY_UI_SIMPLE` env** — when enabled,
  `/dashboard` serves `blindspark.html` and the operator-only tabs
  (`/network`, `/docs`, `/payments`, `/calculator`, `/leaderboard`,
  `/catalog`) 302-redirect back to it; `/wizard` stays reachable. The
  Blindspark Umbrel package sets the flag; PC operators leave it off and
  get the unchanged full dashboard from the same image.

## [0.16.1] — 2026-06-15

### Fixed

- **Consistent top navigation on the Network and Docs pages** — both
  previously dead-ended (Network had no nav; Docs hid all but the last
  link on mobile). They now carry the same multi-tab top bar as the rest
  of the dashboard.

## [0.16.0] — 2026-06-15

### Changed

- **First-run wizard payout step is now an optional on-chain BTC
  address** (replaces the LNbits/Lightning step) — no external
  dependency, no account. The relay never holds funds; the destination
  is the operator's own wallet for future signed-claim payouts.

### Fixed

- **Self-healing `/data` permissions in the container** — the image
  entrypoint starts as root, chowns the bind-mounted `/data` to uid 999
  only when ownership is wrong, then drops to 999 via `gosu` before
  exec'ing node. Fixes the `EACCES: permission denied, mkdir
  '/data/.hiverelay'` crash-loop on Umbrel where the bind mount is owned
  by the host user.

## [0.15.6] — 2026-06-11

Patch: corruption resilience for accounting + eviction. Running at 0
bytes free truncates hypercore writes; the resulting corrupt cores (a)
fail `drive.purge()` with DECODING_ERROR and (b) wedge `core.info()`
awaits forever — one bad core froze the whole accounting sweep and the
eviction pass behind a never-clearing in-progress latch (utah + sing-1).

### Fixed

- **`raceTimeout` guards on every per-drive await** — accounting
  `info()` (8s), sweep census lookups (5s), measure (10s), unseed (30s),
  purge (60s). A wedged core now costs seconds and is recorded, not
  fatal. Race timers deliberately not unref'd (an unref'd race against a
  wedged promise reads as process deadlock).
- **`purgeDriveCores` fallback** — when the Hyperdrive purge path dies
  on a corrupt header (blobs core unlocatable), purge the meta core
  directly via the corestore and report `meta-only`. A corrupt drive
  serves nobody; freeing what is reachable + tombstoning beats leaving
  it. Used by both the sweep and `manualPurge`.
- **Tombstone ordering** — entries are tombstoned as soon as unseed
  succeeds, before the purge attempt, so a purge failure can no longer
  let repair re-adopt a just-evicted drive.
- **Unhandled `'error'` emits** from StorageAccounting/EvictionManager
  are now routed to logged `accounting-error`/`eviction-error` events
  (an `'error'` event with no listener crashes the process).

## [0.15.5] — 2026-06-11

Patch: eviction rank bypass under critical disk. The deterministic
stagger defers shedding to the FARTHEST holders of an entry — but
holders below `diskPressurePct` never sweep, so on an asymmetric fleet
the deferral never resolves and a critical box starves politely (utah:
337 entries rank-deferred at 99% disk while bern sat at 8%). Above
`rankBypassPct` (default 92) the rank check is skipped; the floor +
`floorMargin` checks — the actual safety mechanism — remain absolute,
and the margin absorbs the worst case of two pressured relays dropping
the same entry in the same sweep window.

## [0.15.4] — 2026-06-11

Patch: operator manual-purge surface (option-A disk recovery for boxes
wedged at 100% — too full for the registry census to even sync).

### Added

- **`RelayNode.manualPurge(appKey)`** — unseed + purge cores from disk +
  tombstone, bypassing the sweep's replica-census gates (the
  authenticated operator is the authorization). The sacred guard still
  applies: archive-tier (`durability ≥ 1`) and custody-bound entries are
  refused even here. Works regardless of `eviction.enabled`. Emits the
  standard eviction audit event with `manual: true`.
- **`GET /api/storage/top?n=30`** — largest measured drives
  (management-authed), the triage input for manual purges.
- **`POST /api/eviction/purge { appKeys: [...] }`** — batch manual purge
  (≤ 50 keys, per-key results, API-key required).

## [0.15.3] — 2026-06-11

Patch: acceptance reconciliation (census truth repair). Boot-replay
reseeds never wrote `seed-accept` records, so the shared registry census
undercounted true replication — 547/961 entries on the utah canary had
no census rows and 252 more were floor-blocked despite copies existing
fleet-wide. On start (15s after registry sync; `acceptanceReconcile:
false` to disable), each relay backfills "I hold this" records for
entries it actually holds, paced ~20/s. Eviction and replication-repair
then reason over real replica counts. Safe to re-run; logs a single
summary line.

## [0.15.2] — 2026-06-11

Patch: eviction census fallback. Boot-replayed entries with no active
registry request have no replication-health row and were permanently
un-evictable (417 of 961 on the utah canary). When the health row is
missing, the sweep now uses the registry acceptance records as the
census (`current` = acceptances — the same source the health map
computes from — with `target` = `targetReplicaFloor`). Entries with no
acceptance records at all remain untouchable: never evict blind. Floor,
margin, and stagger guards unchanged. Fallback usage is counted in
`lastSweep.skips.censusFallback`.

## [0.15.1] — 2026-06-11

Patch: eviction sweep observability. The utah canary reported
`candidates: 0` at 100% disk with nothing explaining why — sweeps now
count skip reasons (`archive`, `custody`, `young`, `noBirth`,
`noCensus`, `floor`, `rank`, `registryError`) in the sweep summary
(`/status` → `eviction.lastSweep.skips`). Also accepts `seededAt` as an
entry birth timestamp.

## [0.15.0] — 2026-06-11

Minor: storage truth + over-replication eviction. Root cause shipped
against: every fleet restart let replication-repair adopt entries from
the shared registry until each relay converged toward the UNION of all
catalogs (5/5 replicas of everything at `targetReplicaFloor: 2`), while
the adoption storage guard compared against the always-zero
`seeder.totalBytesStored`. utah and sing-1 hit 100% disk on 2026-06-11.

### Added

- **`StorageAccounting` (always on).** Paced background measurement of
  real per-drive on-disk bytes via `core.info({ storage: true })` (file
  stats of oplog/tree/blocks/bitfield for meta + blob cores; default 25
  drives per 5s ≈ a 1,200-drive pass in ~4 min). Feeds the repair
  storage guard, eviction ranking, `/status` (`storage` block),
  `/api/overview`, the WS feed, and the dashboard Storage panel.
- **`EvictionManager` (Phase A, default OFF — `eviction.enabled`).**
  Under disk pressure (≥ `diskPressurePct`, default 80) sheds entries
  the network holds above target + `floorMargin` replicas, biggest
  first, until projected usage clears `resumePct` or
  `maxEvictionsPerSweep` binds. Hard exclusions: archive tier
  (`durability ≥ 1` / operator pin), custody-bound entries, entries
  younger than `minAgeMs` (3d), and anything without a fresh replica
  census. Deterministic stagger — only the K farthest holders by
  XOR(relayPubkey, appKey) may shed a given entry, K = the network's
  replica surplus — so pressured relays can never race the same entry
  below the floor. Eviction = unseed + `drive.purge()` (bytes actually
  return to the OS) + tombstone. Every eviction logs an audit line with
  the replica math.
- **Eviction tombstones (app-registry sidecar).** `evicted.json`
  (atomic tmp+rename, bounded 5,000) stops boot-replay and
  replication-repair from resurrecting deliberately-shed entries —
  unless the network later falls under the floor, in which case the
  repair gate clears the tombstone and re-adopts (availability first).

### Fixed

- **Replication-repair storage guard now binds.** Uses measured bytes,
  and rejects adoption outright when the storage budget is exhausted
  (previously only requests that declared a size were ever checked).
- **`/api/overview` + WS feed report measured storage**, and the
  dashboard accepts both the nested (`storage.used`) and flat
  (`storageUsed`) shapes — the flat-only read was an extra reason the
  Storage panel always showed 0 B on the polling path.

Pinned by `test/unit/eviction.test.js` (10 tests / 32 asserts):
accounting math + batch pacing + cache pruning, pressure gate, archive/
custody/young/census-less exclusions, floor math, deterministic stagger,
biggest-first + cap + resumePct early-stop, tombstone reload semantics.

## [0.14.0] — 2026-06-11

Minor: dashboard UI/UX redesign — the node-runner dashboard was built
very early and carried real debt. One design system for both audiences:
Blindspark home runners (simple: is it up, what am I earning) and
HiveRelay fleet operators (dense: registry, system, peers).

### Changed

- **Design system pass across all 8 dashboard pages.** Refined dark
  palette (deep neutral background with a subtle glow, GitHub-dark-range
  hues replacing the saturated #0f0/#0af/#f90 primaries), shared radii,
  focus-visible outlines, `prefers-reduced-motion` support, and the
  spark-yellow accent reserved for identity + earnings. Sub-pages
  (catalog, payments, calculator, network, leaderboard, docs, wizard)
  get the same tokens + accent active-nav pill so the product reads as
  one surface.
- **Dashboard (index) rebuilt.** Sticky blurred topbar with a
  copy-to-clipboard pubkey chip; "Apps Kept Alive" framing; Earnings
  panel redesigned as a spark-accented card with a progress-to-daily-cap
  bar and a proper payout-destination dialog (replaces `window.prompt`)
  with inline validation errors; payment/credits row is now adaptive —
  hidden until the payment stack actually reports activity; charts get
  legends + friendlier empty states; responsive pass (auto-fit stat
  grid, horizontally scrollable nav on phones — Umbrel users open this
  on mobile).

### Fixed

- **"31.7 MB / 1 B" memory + storage readouts.** System bars fell back
  to `|| 1` denominators when a payload (notably the WS overview) lacked
  `heapTotal` / `storage.max`, rendering "/ 1 B" with a 100%-red bar on
  a healthy node. Unknown totals now show the used value alone and hide
  the ratio bar; the RSS bar (previously ratioed against a made-up
  `heapTotal*2`) is gone. Bars are threshold-colored (green→amber→red)
  instead of alarm-red at idle.
- **"Unknown App" rendered as if it were a real name.** Both the API
  and catalog.json report the literal placeholder "Unknown App" for
  metadata-less drives; tables now show the truncated key (dim mono)
  with a "no metadata" badge instead.
- **Error counter** reads green at 0 instead of permanent red.

## [0.13.1] — 2026-06-11

Patch: dashboard brand pass for the Umbrel app.

### Changed

- **Dashboard UI is now Blindspark-branded.** All seven dashboard pages
  (dashboard, catalog, payments, calculator, network, leaderboard, docs)
  swap the HiveRelay hexagon mark and titles for the yellow-spark
  Blindspark mark with a small "powered by HiveRelay" line under the
  wordmark; favicons updated to the spark. The wizard was already
  Blindspark-branded. Protocol/package naming (`p2p-hiverelay`, docs
  content, API) is unchanged — HiveRelay remains the infrastructure
  brand, Blindspark the operator-facing product.

## [0.13.0] — 2026-06-11

Minor: Phase 1 of the operator incentive layer — relay-side subsidy
accrual with signed claims. **No money moves through the relay**; this
release is the evidence-and-estimate half. The Phase-2 coordinator
(treasury side, off-relay) verifies claims and dispatches Lightning
payouts. Design + economics: docs/OPERATOR-INCENTIVES-Y1.md Prong 2.

### Added

- **`SubsidyAccrual` (`incentive/subsidy/`)** — when `subsidy.enabled`
  (default **off**), the node samples its stats on an epoch timer
  (default 10 min), accrues a sats ESTIMATE at `rateSatsPerDay`
  (default 500 ≈ $180/yr at $100k/BTC) hard-capped per UTC day, and
  records per-epoch evidence (uptime, connections, seeded/anchored).
  State persists to `<storage>/subsidy.json` via the v0.10.6 atomic
  tmp+rename pattern, writers serialized.
- **Non-custodial payout destination.** No wallet ships in the app —
  deliberate: a blind relay must not be a fund honeypot, and custody
  would contradict the operator-untrusted model. The operator assigns a
  destination they control — lightning address, BOLT12 offer, or
  on-chain address (light validation relay-side; the coordinator
  re-validates before paying). Set from the dashboard card, config, or
  `HIVERELAY_SUBSIDY_DESTINATION`.
- **Ed25519-signed claims.** `GET /api/subsidy/claim` exports a claim
  envelope signed by the relay keypair over
  `SHA256(relayPubkey || canonicalJson(body))` — same
  digest-then-detached-sign shape as SignedDirectory. Canonical JSON
  (sorted keys) so signer/verifier derive identical bytes.
  `verifyClaim()` exported for the coordinator. The relay's accrued
  figure is explicitly an estimate (`estimate: true`); coordinator
  verification (Operator Score gates, sybil checks, held schedule)
  decides actual payout.
- **API + dashboard.** `GET /api/subsidy` (status),
  `POST /api/subsidy/destination` — management-authed (bearer or
  localhost; works behind Umbrel's app_proxy via v0.12.0 exposeToken).
  Dashboard grows an earnings row (accrued / today vs cap / payout
  destination), hidden unless the relay reports `enabled`. `/status`
  exposes a `subsidy` block.
- **Env wiring** for containerized installs: `HIVERELAY_SUBSIDY_ENABLED`,
  `HIVERELAY_SUBSIDY_DESTINATION`.

Pinned by `test/unit/subsidy.test.js` (13 tests / 41 asserts): accrual
pro-rata + daily cap + UTC rollover, destination validation across the
three rails, claim sign/verify + tamper rejection, canonical-JSON
key-order independence, atomic persistence round-trip (no `.tmp`
orphan), corrupt-file recovery.

## [0.12.0] — 2026-06-11

Minor: revives the Umbrel App Store package (as **Blindspark by
HiveRelay** — a blind relay, no Lightning/earning component) and adds the
one piece of core machinery it needs: a way for the management UI to
authenticate behind a trusted reverse proxy. Also fixes a latent
dashboard-serving path bug that would 500 on a fresh checkout or the
Docker image.

### Added

- **`ui.exposeToken` — management UI auth behind a reverse proxy.** The
  dashboard and first-run wizard are localhost-only by default. Behind a
  proxy (e.g. Umbrel's `app_proxy`) the request arrives from the proxy's
  address, so that check can't apply — and v0.10.5 correctly removed the
  spoofable `X-Forwarded-For` trust the old packaging leaned on. When
  `ui.exposeToken` is enabled (env `HIVERELAY_UI_EXPOSE_TOKEN=1`), the
  relay derives a stable management token from `$APP_SEED`, embeds it in
  the HTML it serves, and the bundled UI returns it as
  `Authorization: Bearer`. `/wizard` and `/api/wizard/*` now accept the
  bearer token (via `_checkAuth`) instead of being strictly localhost.
  **Off by default** — direct/localhost and existing fleet deployments
  are unchanged (no key configured → the localhost-only behaviour is
  byte-for-byte the same). The token is embedded only when a key exists,
  attribute-escaped, and served `Cache-Control: no-store`. SECURITY: only
  enable when the API port is reachable solely through an authenticating
  proxy and never published to the host/LAN. New
  `deriveTokenFromSeed()` (domain-separated from the wizard's identity
  key) and `test/unit/api-ui-token.test.js` (10 tests).
- **Umbrel App Store package (`umbrel-app/`).** Manifest, compose, icon +
  gallery placeholders, and a submission checklist for **Blindspark by
  HiveRelay** (category: networking, no `lnbits` dependency, no earning
  language). The compose wraps the published multi-arch image, runs as
  uid/gid 999, persists `/data`, and derives a reinstall-safe identity
  from `$APP_SEED`. Restores the `umbrel-app-validate` CI workflow.

### Fixed

- **Dashboard/wizard could 500 on fresh installs and the Docker image.**
  `_serveDashboard` resolved assets only at `packages/core/dashboard`,
  which is not git-tracked and exists only as a stale leftover on
  long-lived boxes — a fresh clone or the `COPY . .` Docker image has the
  dashboard at the repo root, so `/dashboard` and `/wizard` would throw
  ENOENT. Now probes the repo-root (git-tracked) location first and falls
  back to the legacy path, caching the resolved dir.

## [0.11.0] — 2026-06-10

Minor: seed denials become visible end-to-end, operators can pin foreign
keys at archive tier through the authenticated API, and a long-standing
dependency-resolution fault is closed — `p2p-hiverelay-client` and
`p2p-hiveservices` were resolving a stale registry copy of core at
**v0.7.2** instead of the workspace.

### Fixed

- **Client + services depended on core 0.7.2 (exact pin).** npm nested an
  8-month-old registry copy under each package, shadowing the workspace.
  Every builtin service extended the v0.7.2 `ServiceProvider`; the client
  pulled its wire encodings, seeding-manifest, capability-doc, and
  fork-proof code from v0.7.2. Concretely: v0.7.2's `seedRequestEncoding`
  predates the revocable/unseedFreezeMs/durability tail, so an
  archive-tier seed request **silently dropped `durability` on the wire**
  while the v2 signature still covered it — relay-side signature mismatch
  → silent drop → publisher timeout. Pins are now caret-ranged to the
  workspace version. **Deploy note:** purge
  `packages/*/node_modules/p2p-hiverelay` before `npm install` on
  existing checkouts — npm does not prune the stale nested copies.
  **Publish note:** the npm registry's latest is 0.9.2; core MUST be
  published before (or with) client/services or their dependency ranges
  are unresolvable for external consumers.
- **`downloadWithTimeout` crashed on drives without the hyperdrive-11
  walk surface.** The #28 re-implementation (v0.10.1) called
  `drive.getBlobs()` unguarded; test doubles and forks without it threw
  `TypeError`, killing the unit-test runner mid-suite from v0.10.1 on
  (production unaffected — real hyperdrive 11.x has the surface). Such
  drives now fall back to racing the bare `download()` Promise against
  timeout/abort, the pre-#28 semantics.
- **Blind-custody e2e assertions raced working auto-attestation.** The
  suite pinned exact proof/witness counts from the era when the sweep
  silently never fired (pre-v0.9.2 challengeNonce bug); it had been red
  since the fix landed. Floors + membership are asserted instead.

### Added

- **`seedDeny` wire message — silent denial is gone.** Previously the
  only wire response was `seedAccept`: a refused publisher saw nothing
  and timed out. Relays now reply on the requesting channel with a
  relay-signed, machine-readable reason —
  `archive-requires-publisher-signature`, `signature-required`,
  `bad-signature`, `insufficient-storage`, `accept-mode:<mode>`,
  `delegation:<reason>`, or the non-terminal `queued-for-review`. No
  reply to rate-limited peers (no response amplification). Old peers
  drop the unknown message id, so mixed-version fleets degrade to the
  previous timeout behavior. The client verifies denies (claimed relay
  pubkey must match the noise-authenticated channel peer), tracks them
  per request, **fast-fails `seed()` when every connected relay
  terminally denies**, and carries reasons into the persistent-retry
  record.
- **Operator-pinned archive tier.** POLICY: archive (durability ≥ 1,
  AutoHeal-maintained) remains publisher-signature-only on the anonymous
  P2P channel — no anonymous conscription of the fleet's disks — but the
  API-key-authenticated `/seed` endpoint now accepts `durability`: the
  operator is the authority for their own node's storage and AutoHeal
  budget, so they may pin any key (including foreign bare keys) at
  archive tier. The API key is the operator signature; cross-relay,
  other operators stay in control via accept-mode.
- **401 observability.** API-key auth failures previously left zero
  server-side trace (the 401 fires before body parsing). They now
  increment per-route counters (hex ids collapsed to `:hex`, bounded
  cardinality), warn-log with the real socket IP (throttled per route),
  and export as `hiverelay_auth_failures_total{route="..."}` on
  `/metrics`.
- **Per-relay API keys in `publish-app.js`** — `--api-keys
  "url=KEY,url=KEY"` / `HIVERELAY_API_KEYS` for fleets running a
  distinct key per relay, plus a boxed AUTH FAILURE summary naming each
  refusing relay and exit code 1 when 0/N relays accept.
- **QVAC model routes** — model listing/routing endpoints on the API,
  `qvac` CLI subcommand, ai-service integration, plus a PearBrowser
  marketplace demo under `examples/`.

## [0.10.6] — 2026-06-10

Durability patch — make persisted JSON state crash-safe.

### Fixes

- **Atomic writes for persisted JSON state (MEDIUM).** Five stores
  rewrote their file in place with a single `writeFile`, so a crash or
  power loss mid-write left a truncated file that the loader then treated
  as corrupt and silently reset — losing peer reputation, credit/wallet
  balances, the bootstrap cache, and identity attestations/profiles. All
  five now write to a `.tmp` sibling and `rename()` into place (POSIX
  rename is atomic: readers see either the old file or the new one, never
  a partial), cleaning up the tmp on failure. The identity stores keep
  their `0o600` mode (rename preserves the mode set on the tmp file).
  Matches the pattern already used by `federation.js` /
  `app-registry.js`. Affected:
  `incentive/reputation/index.js`, `core/bootstrap-cache.js`,
  `incentive/credits/index.js`, `services/identity/attestation.js`,
  `services/identity/developer-store.js`.

### Tests

- `test/unit/reputation.test.js` — save round-trips with no leftover
  `.tmp`; a failed save leaves the existing file untouched.

## [0.10.5] — 2026-06-10

Security patch — two more audit findings on the auth boundary and the
forward-relay transport.

### Security

- **`trustProxy` + no API key auth bypass (MEDIUM).** `_isLocalRequest`
  — the authority for the API-key-less localhost auth fallback AND the
  `LOCAL_ONLY_DISPATCH_ROUTES` gate (`identity.sign`) — derived the
  client IP from `X-Forwarded-For`/`X-Real-IP` when `trustProxy` was on.
  A remote caller could send `X-Forwarded-For: 127.0.0.1` and pass every
  localhost-gated check. It now reads the real socket address (never the
  forwarded headers) and returns false whenever `trustProxy` is set (a
  co-located proxy's 127.0.0.1 socket is not a trusted admin), so those
  modes require an API key. A startup warning is emitted for the
  `trustProxy` + no-key combination. `X-Forwarded-For` is still used for
  rate-limit keying only. (`relay-node/api.js`)

- **Forward-relay: bound demand-dials (HIGH).** When an operator enables
  `forwardRelay`, the relay dials DHT peers for clients. The `allowTarget`
  policy hook was never wired (so an enabled relay would dial ANY 32-byte
  pubkey on demand), and only a per-peer concurrency cap existed — a peer
  could churn OPEN/CLOSE to dial in a tight loop (DHT scanning /
  connection laundering / outbound-dial amplification) without exceeding
  it. Adds a per-peer dial-rate limiter (`maxDialsPerMinPerPeer`, default
  30, sliding 60s window) and wires an optional operator allowlist
  (`config.forwardRelay.allowTargets`) through `allowTarget`. Off by
  default still; these bound it when on. (`protocol/forward-relay.js`,
  `relay-node/index.js`)

### Tests

- `test/unit/api-trustproxy-auth.test.js` — XFF spoof and trustProxy
  localhost fallback are rejected; valid key still authorizes; the
  no-proxy local case is unchanged.
- `test/unit/forward-relay-limits.test.js` — dial-rate cap and
  allowlist enforcement.

## [0.10.4] — 2026-06-09

Security patch — two issues from the codebase audit.

### Security

- **Verifier: bind anchor proofs to the requested drive (HIGH).**
  `fetchAnchorProof` reconstructs the signed payload from `proof.appKey`
  but never checked it against the drive key it asked for. A relay could
  answer a query for drive X with a validly-signed proof for a different
  drive Y it had anchored, and the audit would report X as anchored. It
  now rejects (`appkey-mismatch`) unless `proof.appKey` equals the
  requested `driveKeyHex` (case-insensitive), matching the in-tree
  `anchor-proof-verifier.js` `expectedAppKey` binding. (`packages/verifier/index.js`)

- **Redact transport secrets from unauthenticated `/status` +
  `/api/overview` (MEDIUM).** Both endpoints are intentionally
  unauthenticated but returned the holesail `connectionKey`, Tor
  `onionAddress`, disk `mountPath`, and seeding-registry `key`. Leaking
  the holesail key is an escalation: an attacker can tunnel to the API
  (the tunnel terminates on `127.0.0.1`) and ride the localhost auth
  fallback. `getStats({ includeSecrets })` now redacts these for
  unauthenticated callers; the handlers pass the request's auth result,
  so authenticated callers (valid API key, or localhost when no key is
  set) still see them. Trusted in-process consumers (CLI, metrics, the
  auth-gated WS feed) are unchanged. `/api/registry` and `/api/manage/*`,
  which also surface these values, were already behind auth.
  (`relay-node/index.js`, `relay-node/api.js`)

### Tests

- `test/unit/verifier.test.js` — proof rejected when appKey ≠ requested
  drive; accepted when it matches (case-insensitive).
- `test/unit/status-secrets-redaction.test.js` — secrets redacted when
  `includeSecrets:false`, present by default and when true.

## [0.10.3] — 2026-06-09

Critical restart-persistence patch. A clean restart — operator Ctrl+C,
systemd/Fly SIGTERM, or an in-process SelfHeal cycle — silently wiped
all seeded apps from disk and could fail to come back up. Four coupled
defects produced it; all are fixed, pinned by a new restart-persistence
integration test and a gateway-close unit test.

### Fixes

- **Shutdown no longer erases the app registry (data loss).** `stop()`
  tore down every seeded app via `unseedApp()`, which persisted a
  registry delete — so each restart emptied `app-registry`. `unseedApp`
  now takes a `forget` flag; the shutdown loop passes `forget:false`,
  releasing live drive/swarm handles while keeping the persisted entry
  for `reseedFromRegistry` to reload. (`relay-node/index.js`,
  `app-lifecycle.js`)

- **`HyperGateway.close()` no longer throws.** It iterated the
  `DriveCache` directly (not iterable) and unwrapped the wrong value,
  throwing `this._drives is not iterable` on every close — which
  aborted `RelayAPI.stop()` before `server.close()`, leaking the HTTP
  listener and causing `EADDRINUSE` when the next `start()` re-bound the
  port. Now iterates `.entries()` and closes `entry.drive`; the gateway
  close is also wrapped in `api.stop()` so `server.close()` always runs,
  and idle keep-alive sockets are terminated so close can't stall.
  (`gateway/hyper-gateway.js`, `relay-node/api.js`)

- **Registry Hyperbee reopens on a recreated store.** On a SelfHeal
  restart `start()` recreates the corestore, but the registry's bee
  still pointed at the closed old store, so reseed read a dead core
  (`SESSION_CLOSED`) and repopulated nothing. New
  `AppRegistry.detachStore()` is called when the store is recreated so
  the bee reopens cleanly. (`app-registry.js`, `relay-node/index.js`)

- **Registry writes are serialized; the bee is open before seeding.**
  Two latent persistence bugs surfaced under test: concurrent
  `bee.put()` calls raced as a read-modify-write and silently dropped
  entries (seeding two apps in quick succession could lose one, even
  without a restart); and `start()` returned before the
  fire-and-forget reseed opened the bee, so an app seeded in that gap
  was set in memory but never persisted. Bee writes now run through a
  serialized write-chain, and reseed is split into an awaited
  load/hydrate phase (opens the bee) plus a fire-and-forget
  drive-reseed phase. (`app-registry.js`, `app-lifecycle.js`,
  `relay-node/index.js`)

### Tests

- `test/integration/restart-persistence.test.js` — asserts seeded apps
  survive both an in-process `stop()`/`start()` cycle and a
  fresh-process restart over the same storage.
- `test/unit/gateway-close.test.js` — pins `HyperGateway.close()`
  draining the cache without throwing.

## [0.10.1] — 2026-06-07

Operator-facing observability + dev-experience patch release. Six
commits since v0.10.0 — four resolving operator-flagged issues
(#21/#27/#28/#29), two landing the forward-relay opt-in transport.

### Operator observability (#27 + #29)

- **Disk-usage signal in `/status`** (#27). New `disk` field exposes
  `usedPct`, `usedBytes`, `freeBytes`, `totalBytes`, `mountPath`, and
  `status` (`ok`/`warn`/`critical`). 30-second background `df -kP`
  poll; no I/O on the status hot path. Optional `diskHealthGate`
  config makes `/health` return 503 above the critical threshold so
  load balancers can drain traffic before the volume fills. Closes
  the cost-of-discovery gap that bit milkyb-iad with a 15-hour
  debugging fire when its 1 GB Fly volume hit 100%.

- **AppRegistry counts in `/status` + Prometheus** (#29). New
  `appRegistry` field exposes `entries`, `anchored`, `unanchored`,
  and `cores` (entries × 2 for meta+blob). Four new gauges:
  `hiverelay_app_registry_entries`, `hiverelay_app_registry_anchored`,
  `hiverelay_app_registry_unanchored`, `hiverelay_app_registry_cores`.
  Existing `hiverelay_cores_seeded` stays unchanged for dashboard
  compat; its HELP text now points at the new metric. On utah-us
  Prometheus will report `hiverelay_app_registry_cores=1154` instead
  of the misleading `hiverelay_cores_seeded=1`.

### Reliability (#28)

- **Promise-shape `drive.download()` cancellation.** Reimplements the
  download loop inside `downloadWithTimeout` so it can destroy every
  inner `blob.core.download` tracker when the LifecycleScope signal
  fires. `_eagerReplicate` and `repairUnanchored` now thread
  `scope.signal` through. Without this, `raceOr()` rejected cleanly
  via AbortError but the orphaned trackers kept the event loop alive
  (production-safe; broke `reliability-v2.test.js` cleanup).
  Reliability-v2 multi-cycle start/stop now completes all assertions
  in <1s wall time vs hanging at file-level timeout.

- **`AppRegistry.load()` quiets shutdown-race noise.** The fix above
  exposed a latent SESSION_CLOSED on `bee.createReadStream()` when
  `node.stop()` fires during start()'s registry hand-off. These are
  clean concurrent-shutdown signals, not stale-ref bugs; filtering
  prevents them from spamming the `'error'` event channel. Real
  errors (corruption, schema drift) still surface.

### Build infrastructure (#21)

- **Dockerfile: `node:20-alpine` → `node:22-bookworm-slim`.**
  `udx-native` and `sodium-native` ship glibc prebuilds but not musl
  ones. On Alpine, the first import crashes with
  `Cannot find module '/prebuilds/linux-x64-musl/udx-native.node'`.
  Public fleet images were already Debian-based so this didn't bite
  there, but anyone building from the repo Dockerfile against a
  fresh environment did. Stage transitions: `apk` → `apt-get`,
  `addgroup`/`adduser` → `groupadd`/`useradd` with fixed UID/GID
  999 so volume permissions stay consistent across rebuilds,
  `/sbin/tini` → `/usr/bin/tini`. ~50 MB image-size increase
  accepted in exchange for reliable native loads. Tracked upstream
  at [holepunchto/udx-native](https://github.com/holepunchto/udx-native).

### Forward-relay transport

- **Opt-in forward-relay support.** New `forward-relay.js` protocol
  + integration test + `PRODUCTION.md` operator enable guide.

## [0.10.2] — 2026-06-07

`SignedDirectory` service — relay-hosted openly-writable registry of
signed records keyed by author pubkey. Closes [#33](https://github.com/bigdestiny2/P2P-Hiverelay/issues/33).

### What ships

- `packages/core/core/services/signed-directory.js` — Protomux
  service exposing `PUBLISH` / `LIST_REQ` / `LIST_RES` / `NOTIFY` /
  `STATUS` messages on the `hiverelay-signed-directory` channel.
  Single-hop NOTIFY replication between enabled relays (publish at A
  → broadcast to all open channels → peer relays store, do not
  rebroadcast).
- Storage policy defaults: 8 KB per entry, 24h TTL, 1 entry per
  author (newest-timestamp-wins), 5 publishes/minute/peer, 10k total
  entries with TTL-oldest eviction under pressure, ±60s clock-skew
  tolerance.
- Ed25519 signatures over `SHA256(authorPubkey || timestamp_LE_8 ||
  payload)`. Relay never inspects payload semantics.
- Opt-in via `config.signedDirectory.enabled` (default false). Same
  posture as `forwardRelay`.
- `RelayNode` wires construct → attach per incoming connection →
  destroy on stop. `/status` exposes a `signedDirectory` block with
  entry count + replication counters + rejection-reason breakdown.
- Tests: 17 cases, 83 inner asserts. Cover trust-model primitives
  (digest determinism, tamper-detection), storage policy (size cap,
  timestamp validation, future-squat rejection, expired-on-arrival
  rejection, malformed shape), newest-timestamp-wins overwrite +
  idempotency, per-peer rate limit (with NOTIFY-replication bypass),
  global-cap eviction order, TTL cleanup, `getStats` shape, destroy
  cleanup, disabled-directory rejection, NOTIFY no-echo invariant.
- PRODUCTION.md "SignedDirectory (opt-in registry)" operator section
  with the full config block + threshold rationale + the critical
  clock-skew anti-squat note.

### First consumer

Marketplace offer discovery (anonGPT). Seller publishes a signed
`Offer` payload; buyer connects to the relay, lists, verifies signatures
locally. Topic-swarm announce remains as P2P fallback so nothing
regresses for buyers that can't reach an enabled relay.

### Trust + threat model

The relay can omit, reorder, refuse, or delay records. It cannot forge
them — every record carries a detached Ed25519 signature over the
canonical digest. Buyer-side `verifyDirectory()` adapter is the
authoritative validator; the relay's role is transport + storage only.

### Out of scope (intentional)

- Relay does NOT validate payload semantics
- Relay does NOT charge for publish
- Relay does NOT broadcast to non-subscribing clients (NOTIFY pushes
  only over channels that have already been attached, i.e. peer
  relays + clients that opened a directory channel)
- Hyperbee-backed persistence (v2; in-memory + short TTL + cross-
  relay replication is the v1 commitment)

### Risk

Backwards-compatible. Default off — existing operators see no
behavior change. Receivers that don't know about the new
`hiverelay-signed-directory` channel ignore it (protomux's default
policy is silent skip).

### Acknowledgments

Spec + design pattern co-developed with the anonGPT marketplace work;
mirror of the `ForwardRelay` opt-in transport posture.

## [Unreleased]

<!-- NOTE: stale entries below predate v0.11.0 and were never folded into a
     release section as 0.11–0.18 were cut. Needs a separate changelog-hygiene
     pass to attribute each to the version it actually shipped in. -->

### Added

- **Forward Relay** (`hiverelay-forward`) — a demand-dialled relay transport
  (`packages/core/core/protocol/forward-relay.js`, wired into `RelayNode`).
  A client sends `OPEN(targetPubkey)`; the relay dials that target over the
  DHT and byte-bridges the channel ⇄ target stream. Unlike CircuitRelay the
  target needs no reservation (it just sees a normal incoming connection).
  Turns a relay into a usable transport for NAT/UDP-blocked apps and composes
  into onion routing (reach relay2 through relay1, then the seller through
  relay2 — no single relay links client↔target). **Opt-in**
  (`config.forwardRelay.enabled`, OFF by default); bounded by per-peer
  concurrency + per-forward (64 MB) + per-frame (64 KB) caps, forwards only to
  DHT pubkeys (never an internet proxy), honours the SwarmFirewall, optional
  `allowTarget` policy hook. Client: `HiveRelayClient.connectViaForward(target,
  relay)` returns a Duplex over the relayed channel. Proven E2E in
  `test/integration/forward-relay.test.js` (byte round-trip + fail-closed when
  disabled). See `docs/forward-relay.md`.
- **VRF service** (`vrf`) at `packages/services/builtin/vrf-service.js` —
  Verifiable Random Functions via ECVRF-EDWARDS25519-SHA512-TAI
  (RFC 9381, suite 0x03). The relay produces deterministic,
  publicly-verifiable, unbiasable randomness: for any input `alpha` it
  returns an output `beta` plus an 80-byte proof `pi` checkable against
  the relay's VRF public key. Capabilities: `prove`, `verify`,
  `proof-to-hash`, `pubkey`, `info`, the verifiable-sortition RPCs
  (`select`/`shuffle`/`select-verify`/`shuffle-verify`), and the beacon
  reads (`beacon-info`/`-latest`/`-round`/`-range`/`-verify`).
  - **ECVRF core** at `packages/services/builtin/vrf/ecvrf.js`, built on
    the same vetted `@noble/curves` ed25519 / `@noble/hashes` SHA-512
    primitives the poker Chaum-Pedersen module uses. Validated
    **byte-exact** against all three RFC 9381 Appendix A.4 test vectors
    (`pi`, `beta`, `verify`) plus tamper/negative cases —
    `scripts/test-vrf-vectors.js` (30 assertions).
  - **Dedicated VRF key** derived from the node seed by domain
    separation (`SHA-512("hiverelay/vrf-key/v1" || node_seed)`), so the
    VRF scalar is never the same one used to sign protocol messages. The
    VRF public key is distinct from the node identity pubkey; consumers
    fetch it via `pubkey`.
  - **Chained randomness beacon** at
    `packages/services/builtin/vrf/beacon.js` (opt-in via
    `vrfBeacon: { enabled, intervalMs, domain, retain }`):
    `beta_N = VRF(beta_{N-1} || N)`, anchored at
    `beta_0 = SHA-512(domain || pubkey)`. Self-verifying and
    tamper-evident — `verifyBeaconChain()` re-derives the genesis and
    checks every round with no trust in the operator. Retained history
    is an in-memory ring buffer; durable persistence is a planned
    follow-on. Service + beacon covered by `scripts/test-vrf-service.js`
    (44 assertions).
  - **Verifiable sortition primitive** at
    `packages/services/builtin/vrf/sortition.js` — the bridge from raw
    `beta` to decisions. Deterministic and **integer-only** (no floating
    point, so every node/engine agrees bit-for-bit): a domain-separated
    counter-hash stream drives Fisher-Yates `seededShuffle` and
    sampling-without-replacement `weightedSample` (uniform or
    weighted via A-Res-style integer cumulative draws). Candidates are
    canonically sorted by id so the result depends on the *set*, not
    enumeration order; `quantizeWeights` maps real-valued weights to
    integers. `verifyCommittee` / `verifyShuffle` re-check a result and
    never throw. Covered by `scripts/test-vrf-sortition.js`
    (48 assertions).
  - **`select` / `shuffle` RPCs** on the VRF service bind a draw to a
    caller's `alpha` (e.g. a disputeId or poker handId), prove it, and
    apply the sortition primitive to `beta` — returning
    `{ alpha, pi, beta, pubkey, suite, committee/order }` that any third
    party reproduces. `select-verify` / `shuffle-verify` validate a
    proof + result in one call. Added to `scripts/test-vrf-service.js`
    (now 65 assertions).
  - Registered as a bare-safe builtin (uses only `@noble`/sodium, no
    Node-only deps) and added to the `service-operator` setup profile.
    Opt-in like every service via `enableServices`.
- **Verifiable arbitrator panels** (opt-in, default OFF) in the
  arbitration service. Instead of open voting by any eligible peer, a
  dispute can be judged by a fixed committee drawn by VRF from the
  eligible pool. `submit` binds `alpha` to immutable dispute content,
  snapshots the pool (parties excluded; weight = `score × reliability`),
  and calls the VRF `select` RPC; the dispute records the full proof
  material (`vrfPubkey`/`alpha`/`pi`/`beta`/`candidates`/`members`) so
  the committee is independently reproducible. `vote` then gates on panel
  membership (`ARBITRATOR_NOT_ON_PANEL`) and the quorum caps to panel
  size. Configurable globally (`arbitration: { panel: { enabled, size,
  weighted } }`) or per dispute (`params.panel`), with graceful fallback
  to open voting when VRF/reputation/pool are unavailable. Tested in
  `scripts/test-arbitration-panel.js` (27 assertions). Default-off means
  a relay that never opts in is byte-zero affected.
- **Verifiable per-hand poker randomness** at
  `packages/services/builtin/poker/hand-seed.js` — a pure, dependency-
  light (`@noble/hashes` only, Bare/Pear-portable) helper that anchors
  an unbiasable random number to a specific hand without the card-blind
  relay ever seeing a card. `handSeedAlpha(tableKey, handId)` is the
  canonical VRF input every seat derives identically;
  `verifyHandSeed(...)` checks the relay's proof (never throws);
  `handDeckOrder(beta)` is the nothing-up-my-sleeve starting permutation
  the clients' mental-poker shuffle layers on top of; `combineBetas([…])`
  XOR-combines per-seat betas over the same alpha into a seed no single
  party (not even the key-holding relay) controls. Re-exported from
  `poker/index.js`; tested in `scripts/test-poker-hand-seed.js`
  (37 assertions).

### Security

- **Poker block size-blindness** in `HypercorePersistence`
  (`packages/services/builtin/poker/persistence-hypercore.js`). The relay
  is card-blind — it never reads `entry.payload` — but the *size* of each
  Hypercore block still leaked the action type: a fold, a raise, and a
  card-reveal-with-decryption-shares produce very different JSON lengths,
  so anyone watching the (cross-relay-replicated) core could infer table
  activity by block size alone. Each block is now padded up to the next
  size bucket (`DEFAULT_PAD_BUCKETS = [1024, 4096, 16384, 65536]`) with
  trailing ASCII whitespace before append, so common betting actions
  become mutually size-indistinguishable. The pad is deliberately
  *whitespace outside the JSON object*, making it **signature-transparent**
  (the ed25519 signature covers only canonical entry fields),
  **reader-transparent** (`JSON.parse` ignores trailing whitespace, so
  replay and clients parse identically), and **backward-compatible**
  (legacy un-padded cores replay without migration). Opt out with
  `padding: false` or supply a custom ascending ladder. Tested in
  `test/unit/poker-block-padding.test.js` (15 tests / 26 assertions) with
  the real-Corestore write→restart→replay cycle reverified by
  `scripts/test-poker-persistence-hypercore.js` (22 assertions). Timing-
  channel decorrelation (append-order jitter) is intentionally deferred —
  it requires a serialized append queue to preserve strict log ordering.

## [0.10.0] — 2026-06-03

Minor: first application lands under the services-module pattern — a
card-blind signed-log substrate for turn-based games with hidden
information, with poker as the driving consumer. Backward-compatible:
opt-in via `new PokerApp({...})`; a relay that never instantiates it is
byte-zero affected. Seeding-manifest gains an optional `lifetime` hint;
manifests without the field canonicalize byte-identical to pre-0.10.0,
so existing signatures verify unchanged. Landed via PR #32,
restructured at merge to sit under
`packages/services/builtin/poker/` alongside the other builtin services.

### Added

- **SignedLog substrate** at
  `packages/services/builtin/poker/signed-log.js` — append-only signed
  log per table with per-writer monotonic `seq`, 60s clock-skew bound,
  byte-budget enforcement, opaque payload. Relay never inspects
  `entry.payload`; game rules live in the Pear client.
- **PokerApp service** as the first first-class consumer of the
  services-module pattern, alongside `ai-service`, `schema-service`,
  `zk-service`, `arbitration-service`. HTTP at
  `/api/poker/<tableKey>/{state,log,move}`; WebSocket fan-out at
  `ws://<host>/api/poker/<tableKey>/events` (initial-state-frame on
  connect, API-key auth via the existing gate).
- **HypercorePersistence adapter** — mirrors the in-memory signed-log
  to a hypercore for durability + replay-on-restart. Mirrored cores
  flow through the existing seeder + custody pipeline like any other
  seeded content (no relay-side special casing).
- **Seeding-manifest `lifetime` hint** — optional per-drive
  `lifetime: 'persistent' | 'session' | 'ephemeral'` so operators can
  evict per-hand / per-session content without conflating with
  publication drives. **Manifests without the field canonicalize to
  identical bytes** as pre-0.10.0 manifests; existing signatures
  verify unchanged. `defaultLifetimeTtlMs(lifetime)` helper exposed.
- **Arbitration extension for poker disputes** —
  `poker/missing-share`, `poker/invalid-share`, `poker/refused-reveal`
  dispute types with schema + size-cap validation. New
  `setAppEvidenceVerifier(appType, fn)` seam: pluggable per-app
  evidence verification. Disputes without a registered verifier
  resolve `inconclusive` rather than silently `claim-supported`.
- **Chaum-Pedersen share-equality verifier (REFERENCE QUALITY)** —
  refutes false `poker/invalid-share` claims with a real cryptographic
  proof rather than a vote. Hardened against ed25519 cofactor leak
  (mixed-order / torsion points rejected on all five points) and
  `@noble/curves` `Fn.mul` stress (50 random prove+verify cycles).
  **Not audited.** Real-money deployments should swap their own
  verifier in via `setAppEvidenceVerifier`. Called out in
  `packages/services/builtin/poker/README.md` and at the top of the
  verifier file.

### Changed

- **Architectural location of poker code.** PR #32 originally placed
  the substrate under `packages/core/core/poker/`. Relocated to
  `packages/services/builtin/poker/` to match the services-module
  pattern. `p2p-hiverelay-core` stays scoped to substrate primitives
  (signed-log primitives, custody, seeding, registry). Public HTTP/WS
  namespace unchanged at `/api/poker/*` (the existing per-service
  convention). JS import surface moves: `p2p-hiverelay/core/poker/*`
  → `p2p-hiveservices/builtin/poker/*`. Consumers go through the
  services package going forward.
- **Arbitration resolution path hardened** against throwing slash /
  reputation hooks. Verdict still records; error surfaces in the
  resolved payload; downstream subscribers still see the verdict.

### Notes

- 188/188 across the 7 new test suites under `scripts/test-poker-*.js`
  + `scripts/test-seeding-manifest-lifetime.js`, including
  `test-poker-flow-e2e.js` (sit → DKG commit → pre-committed reveal
  shares → betting → restart with hypercore replay → WS push fan-out →
  arbitration with a real CP proof).
- Targeted brittle regression on the merge's touched files —
  `seeding-manifest` 15/15 (35 asserts), `arbitration-service` 14/14
  (37 asserts), `custody-signing` 13/13 (43 asserts),
  `app-registry` 4/4 (40 asserts) — all green.
- Lockstep version bump 0.9.2 → 0.10.0 across `p2p-hiverelay`,
  `p2p-hiveservices`, `p2p-hiverelay-client`,
  `p2p-hiverelay-verifier`.

## [0.9.2] — 2026-05-31

Patch: the custody expiry sweep now actually emits non-serving-proofs (and
expiry-witnesses) for content seeded over the seed-request channel. A
publisher who claimed/retired a drop — or whose retain window elapsed — was
seeing committed:true / sourceRetired:true on the relays but
nonServingProofCount:0, with no third-party-provable destruction. Two
independent root causes, both fixed; no wire-format or public-API changes.

### Fixed

- **Sweep recovers the custody linkage by addressKey.** The binary
  seedRequestEncoding does not carry custody fields, so content seeded over
  the seed-request channel registers an appRegistry entry with
  custodyIntentId = null even though a signed intent for that addressKey
  exists in the registry (delivered separately over the custody channel). The
  expiry sweep keyed attestation off entry.custodyIntentId, so it could never
  link the two and never attested. The sweep now resolves the intent by
  addressKey (`SeedingRegistry.getCustodyIntentIdByAddressKey`) when the entry
  lacks it, and backfills custodyIntentId / retainUntil / blindContentId onto
  the entry (persisted, so it survives restart and shows on
  `GET /api/anchors?detailed=1`).
- **Auto-attestation now supplies a challengeNonce.** Even with a
  custodyIntentId, the sweep (and the periodic witness scan) called
  `createCustodyNonServingProof` / `createCustodyExpiryWitness` without a
  challengeNonce, and proof signing requires a 64-hex nonce — so every
  auto-attest threw "challengeNonce must be 64 hex characters". These now
  self-generate a nonce when the caller supplies none (a relay-signed
  self-attestation needs only a unique nonce, not a challenger-issued one).
  This is why v0.8.27's claim-path erasure witness never actually emitted a
  proof through the sweep.

### Added

- **Custody-linkage diagnostics on `catalog()` + `GET /api/anchors?detailed=1`**
  (`custodyIntentId`, `blind`, `storageClass`, `availabilityClass`) so a
  publisher can externally confirm whether the sweep can attest for an entry —
  `catalog()` previously dropped the custody binding entirely. `custodyIntentId`
  is preserved even on redacted/blind entries (it is already public via
  `GET /api/custody/{id}/status`; only the linkage is new information), while
  sensitive signals such as `retainUntil` stay redacted for blind entries.
  Via PR #31.

### Tests

- `test/integration/custody-sweep-linkage.test.js` — one sweep pass over a
  still-live entry (custodyIntentId backfilled, not expired) and an expired
  one (resolved by addressKey, unseeded, and attested), reproducing + fixing
  the Drop gap.

## [0.9.1] — 2026-05-31

Patch: makes v0.9.0 publicly verifiable blind custody work end-to-end over
the wire. The 0.9.0 release shipped the PVSS crypto, the v2 signing, and the
relay-side share verification, but two integration seams left the live
dealer→relay path non-functional. Both are fixed here, and a new in-process
integration test now drives the *real* split→receipt→commit→reconstruct
against a live relay over HTTP + Hyperswarm — the unit suite had stubbed
exactly those seams, which is why the gaps slipped through 0.9.0. No
wire-format or public-API changes; purely additive bug fixes.

### Fixed

- **`splitForCustody` now triggers the custody seed.** A PVSS share receipt
  is only produced inside a relay's `seedApp` path, but `splitForCustody`
  published the signed intent without ever asking any relay to seed the
  address key — so no relay verified its share, no receipt was anchored, and
  the dealer's receipt poll always timed out (`CUSTODY_QUORUM_TIMEOUT`). The
  client now POSTs an authenticated `/seed` to each relay (carrying the
  `custodyIntentId` and binding fields) after publishing the intent.
- **Public custody status now surfaces `receipts[]`.** The unauthenticated
  `GET /api/custody/:id/status` redacted the receipts array entirely, but that
  array is exactly what the dealer polls to confirm a share-verified quorum.
  It now exposes the four PUBLIC per-receipt fields (`relayPubkey`,
  `shareIndex`, `shareVerified`, `anchored`); all sensitive receipt fields and
  the full signed intent remain behind `?detailed=1` + Bearer auth.
- **Already-seeded re-pin anchors a custody receipt.** When an address key is
  already seeded — the canonical case being `client.publish()` (which
  auto-seeds the content) followed by `splitForCustody()` — `seedApp`
  short-circuited and never recorded a share receipt. The relay now verifies
  its assigned share and anchors a receipt on a custody re-pin as well.
  Fail-closed for PVSS: a share that does not verify yields no receipt.

### Tests

- `test/integration/pvss-custody-e2e.test.js` — real dealer→relay E2E with no
  stubs: both the clean first-seed and already-seeded re-pin paths, through
  share-verified receipt, quorum commit, and guardian reconstruct, plus
  relay-side blindness (the dealer key/secret never appear in relay state).
- `test/unit/custody-status-redaction.test.js` — guards the public-status
  redaction contract (`receipts[]` exposed; secrets + full intent stay behind
  auth).

## [0.9.0] — 2026-05-30

Publicly verifiable blind custody. Relays can now hold an *opaque,
guardian-encrypted share* of a secret that they can publicly verify but
cannot read, and any *t-of-n* guardians can later reconstruct the secret
entirely client-side. This extends HiveRelay's blind-content guarantee to
the keys themselves and gives serverless/Pear apps always-on, auditable
threshold custody — social recovery, team break-glass, inheritance — with
no party (relay or single guardian) ever able to reconstruct alone.

The custody scheme is Schoenmakers PVSS over secp256k1
(`pvss-secp256k1-v1`): Feldman commitments, per-share DLEQ proofs, and
Lagrange-in-exponent reconstruction. A relay verifies the share it
custodies against the published commitments before it signs a
share-verified receipt, so a malformed or substituted share is caught at
custody time rather than at recovery.

Minor bump: new public client API + v2 custody wire fields, additive and
backwards compatible.

### What ships

- **Client SDK — two new methods on `HiveRelayClient`:**
  - `splitForCustody({ secret?, guardians, threshold, relays, appKey, opts? })`
    — PVSS-split a secret to the guardians' recipient pubkeys, publish the
    PUBLIC share bundle over the P2P replication data plane, author + sign
    the v2 custody intent, collect a share-verified receipt from every
    relay, then sign + publish the quorum commit.
  - `reconstructFromCustody({ intentId, guardianSecretKeys, relays?, shareBundleKey?, threshold? })`
    — recover the secret from any `t` guardian secret keys, client-side.
- **New Bare-safe client subpath exports:**
  - `p2p-hiverelay-client/secret-sharing.js` — PVSS prover (`keygen`,
    `split`, `reconstruct`, `decryptShare`, `SCHEME`); deps limited to
    sodium-universal + b4a + @noble so it runs on Bare/Pear.
  - `p2p-hiverelay-client/custody.js` — self-contained intent/commit/
    receipt signing (no dependency on the frozen `p2p-hiverelay@0.7.2`).
- **Relay/core — v2 custody:**
  - `custody-signing.js` gains version-2 fields (`shareScheme`,
    `shareThreshold`, `commitmentRoot`, `shareBundleKey`,
    `shareAssignments`) with version-gated validation; v1 is unchanged.
  - `relay-node/app-lifecycle.js` verifies each custodied share (DLEQ +
    commitment) before emitting a `shareVerified` receipt.
  - `seed-request-builder.js` carries the PVSS public fields through the
    seed path.
  - `core/pvss.js` — shared verify-side PVSS primitives.
- **Share delivery (SD3):** the encrypted share bundle travels on the P2P
  replication data plane (a sibling hypercore named in the signed intent
  as `shareBundleKey`); the intent/commit control plane stays on the HTTP
  custody channel.
- **Docs:** a new `p2p-hiverelay-client/README.md` with a full PVSS
  blind-custody walkthrough; client import path corrected to
  `p2p-hiverelay-client` across the docs.

### Why this matters

Serverless/Pear apps are keypair-as-identity: lose the device, lose the
key, with no server to recover from. Publicly verifiable blind custody is
the first always-on recovery layer for that model that does not
reintroduce a trusted custodian — the relay fleet keeps the shares alive
24/7, can prove it is holding valid recovery material, and still cannot
read the secret. The relay can now hold both your encrypted content and
the key to it, reading neither.

### Backwards compatibility

- Additive only. v1 custody intents, commits, and receipts validate
  unchanged; the v2 fields are version-gated.
- The published-package boundary is preserved: `p2p-hiverelay-client` and
  `p2p-hiveservices` still pin `p2p-hiverelay@0.7.2`; the client gets
  custody + crypto from its own self-contained modules, never from core.
- No changes to existing client methods or to the relay wire for
  non-PVSS flows.

## [0.8.27] — 2026-05-29

Claim-path erasure witness. Closes the gap where a *claimed* custody drop
produced no third-party-provable destruction until its (often weeks-long)
`retainUntil` window elapsed — the exact piece dmc flagged as missing for
"provable to a third party," and what Drop saw as empty
`nonServingProofs` / `expiryWitnesses` on a committed-and-retired intent.

Before this release the expiry sweep only attested the *unclaimed*-expiry
path: content that sat untouched until `retainUntil` lapsed. A drop whose
publisher had already signed a `source-retired` entry (which requires a
validated `commit`, so the recipient/quorum already holds the content)
produced no destruction proof until that same window passed.

v0.8.27 relaxes the `retainUntil` floor on the claim path: once a validated
source-retirement exists, a relay may attest non-serving — and peers may
witness it — immediately.

### What ships

- `validateCustodyTransition` now discharges the `retainUntil` floor for
  both non-serving-proofs and expiry-witnesses when the status context
  carries a truthy source-retirement. It reads either `sourceRetired` or
  the `getCustodyStatus()` field name `sourceRetirement`, so callers on
  both shapes work. With no retirement the floor is unchanged.
- `_runCustodyExpiryPass` (relay-node) treats a committed-and-retired
  entry as expirable before `retainUntil` and attests it with
  `notServingReason: 'source-retired'` (vs `'expired-unseeded'` for the
  untouched-window path). The `custody-expired` /
  `custody-non-serving-attested` events now carry `reason`.
- `_runCustodyExpiryWitnessPass` lets peers witness a claim-path proof
  before `retainUntil` once the source is retired (skip gate keyed on
  `retainElapsed || sourceRetirement`).
- `summarizeCustodyStatus` threads the retirement through, so
  `validExpiryWitnessCount` counts claim-path witnesses.
- **Seed-path custody parity (latent fix):** `extractCustodySeedOpts(msg)`
  added to `seed-request-builder.js`; both the Node (`relay-node/index.js`)
  and Bare (`relay-node/bare-relay.js`) legacy `_onSeedRequest` handlers
  now spread it, so `custodyIntentId` / `blindContentId` / `ciphertextRoot`
  / `contentVersion` / `retainUntil` survive the legacy Protomux seed path.
  Previously a custody seed accepted there landed with no binding, so the
  relay could never sign a non-serving-proof for it.

### Why this matters

A claimed drop is the common case: the handoff completed, the publisher
retired the source, and the only thing standing between "done" and a
third-party-provable erasure record was a timer. Sealing the claim path
means the destruction proof lands when the claim completes, not weeks
later — which is what an auditor or the original publisher actually needs.

### Backwards compatibility

- Fully backwards-compatible. The `retainUntil` floor still holds on the
  unclaimed-expiry path (no source-retirement → behavior unchanged).
- No wire format changes. The binary `seedRequestEncoding` still carries
  and signs no custody fields, so the **publish channel remains the
  authenticated custody seed path**; `extractCustodySeedOpts` is a
  read-only, present-guarded handler propagation for already-enriched
  messages — absent/malformed fields spread to nothing, identical to
  prior behavior.
- Replication indexing only signature-checks non-serving-proofs and
  witnesses (it does not re-run `validateCustodyTransition`), so peers
  accept claim-path proofs without a code change.

### Tests

- `test/unit/custody-claim-path-witness.test.js` — 4 tests: two pin the
  pure `validateCustodyTransition` relaxation (non-serving-proof and
  expiry-witness, rejected pre-`retainUntil` without retirement, accepted
  with it, both `sourceRetired` and `sourceRetirement` aliases); two are
  `SeedingRegistry` integration tests (registry rejects a pre-`retainUntil`
  proof until `publishSourceRetired`, then indexes it; a peer witness
  counts as valid before `retainUntil` once retired).
- `test/unit/seed-request-builder.test.js` — +6 `extractCustodySeedOpts`
  tests (now 25): well-formed carry-through, hex lowercasing, malformed/
  absent omission, nullish → `{}`, integer flooring, and `0` kept as a
  valid floor value.

All adjacent custody + seed suites pass; the full unit suite is green
modulo one pre-existing, unrelated stale assertion in `private-mode.test.js`.

## [0.8.26] — 2026-05-28

`SeedingRegistry` Hyperbee indexed-views sidecar. A sibling Hypercore
named `seeding-registry-index-v1` mirrors `_applyEntry` output keyed
by entry-shape, so startup hydration restores the in-memory custody +
seed state without replaying every log block from offset 0.

The multi-writer logs remain the canonical source of truth — the bee
is a cache of derived state. `_indexLog` still runs after hydration
to catch up entries appended since the last bee write; the existing
`_applyEntry` timestamp deduping makes the replay idempotent so
duplicates are no-ops.

### What ships

- `Hyperbee` import + sibling-core open in `start()` before any log
  replay, with defensive fallback to log-only behavior if the bee
  can't open (test stubs, missing corestore caps).
- `_entryKey(entry)` — stable composite-key derivation per entry
  type (`entry:custody-intent:<intentId>`,
  `entry:custody-receipt:<intentId>:<relayPubkey>`,
  `entry:custody-proof:<intentId>:<observerPubkey>:<relayPubkey>:<challengeNonce>`,
  etc.)
- `_hydrateFromIndexBee()` — iterates the `entry:` prefix on startup
  and replays each entry through `_applyEntry(...{ source: 'hydrate' })`.
  Skips re-persistence on hydrate-source so we don't loop.
- `_persistToIndexBee(entry)` — fire-and-forget put hook inserted
  into `_applyEntry` after normalization. Tracks in-flight ops in
  `_pendingIndexOps` so `stop()` / `_flushIndexBee()` can drain.
- `stop()` awaits in-flight bee writes before closing the local log
  — guarantees the next start's hydration sees a complete view.
- `'hydrated'` event with `{ count, source: 'index-bee' }` so
  consumers/dashboards can observe restart speed.

### Why this matters

Pre-v0.8.26, every relay restart re-indexed every log from block 0.
On a relay with 2,400 entries across 5 logs that's an O(N·M)
sequential read. With the bee sidecar, hydration is O(M) and the
in-memory state is up before the swarm even reaches steady state.

### Backwards compatibility

- Fully backwards-compatible. Defensive fallback: if the bee can't
  open (e.g. test stubs, headless usage), `_indexBeeReady` stays
  false and the existing log-only behavior runs unchanged.
- No wire format changes. Logs are unaffected.
- Sidecar core is named `seeding-registry-index-v1` on the same
  corestore. Created on first start, populated incrementally.

### Tests

`test/unit/registry-index-bee.test.js` — 4 tests:
- End-to-end persistence + survival across restart (with real
  testnet + swarm)
- `_entryKey` returns stable composite keys per type
- Hydration is idempotent — dedup via timestamp on subsequent
  log replay
- `'hydrated'` event fires with the right shape

All 11 adjacent suites still pass.

### Third of three registry improvements

Completes the [REGISTRY-DESIGN-COMPARISON-2026-05-28.md](docs/REGISTRY-DESIGN-COMPARISON-2026-05-28.md)
plan (Priorities 4, 1, 2 in order — v0.8.24, v0.8.25, v0.8.26).

Deferred to v0.8.27+: secondary indexes on the bee
(`byPublisher:<pubkey>`, `byTimestamp:<ts>`) for cheap range queries
and per-log `lastIndexedOffset` tracking so subsequent restarts can
SKIP the log-replay catchup entirely.

## [0.8.25] — 2026-05-28

`AppRegistry` persistence migrated from JSON-blob to Hyperbee. Each
mutation now writes one small block to a Hyperbee sibling-core on
the relay's existing corestore, instead of rewriting the entire
`app-registry.json` file on every `setAnchored()` / `clearAnchored()`
/ `recordAnchorCheck()` etc. Public API surface unchanged; consumers
(`RelayNode`, `AppLifecycle`, etc.) see identical behavior.

### What ships

- `AppRegistry.setStore(corestore)` — attach the relay's corestore so
  persistence uses a Hyperbee on its `app-registry-v1` named core.
  Must be called before `load()`. `RelayNode.start()` + `BareRelay.start()`
  wire this automatically; legacy callers (tests, headless usage)
  fall back to the JSON path untouched.
- `_persistEntryToBee(appKey)` / `_deleteEntryFromBee(appKey)` —
  single-entry write/delete paths. Fire-and-forget by default;
  `flush()` awaits them for clean-shutdown semantics.
- One-time JSON → Hyperbee migration: on first `load()` with a
  store attached, if `app-registry.json` exists it gets migrated
  into the bee via a batched `put()`, then renamed to `.bak`. Subsequent
  loads read from the bee.
- `_hydrateEntry` and `_reseedEntry` and `_persistShape` helpers
  extracted so JSON and bee paths share normalization logic.

### Why this matters

This closes [#26](https://github.com/bigdestiny2/p2p-hiverelay/issues/26)
as a side effect — the hung-writeFile cascade the contributor's v0.8.22 timeouts
mitigated is fundamentally a JSON-blob fragility. Hyperbee's
underlying Hypercore handles partial writes / fsync natively, so
disk-full becomes a single-block append failure (loud, recoverable)
rather than a cascading whole-file rewrite failure. Plus:

- **No more 75KB rewrite per anchor check.** Each `setAnchored()`
  writes one block (~150 bytes for the entry's persistable shape).
- **Atomic startup load.** Hypercore enforces this; no
  "did the JSON file get half-written?" failure mode.
- **Free range queries.** `bee.createReadStream({ gte: …, lte: … })`
  becomes available for any future per-prefix iteration (not used
  yet; foundation for v0.8.26's indexed sidecar).
- **Free audit trail.** `bee.createHistoryStream()` exposes the
  per-entry change history for forensics with zero extra code.

### Backwards compatibility

- Legacy callers without a store get the original JSON-blob behavior
  unchanged.
- First-time migration from existing `app-registry.json` happens
  transparently on the next boot. The JSON is renamed to `.bak`,
  not deleted, so it's available as a manual rollback escape hatch.
- Empty registry files are also renamed cleanly (no re-migration
  attempt on next boot).

### Tests

`test/unit/app-registry-hyperbee.test.js` — 7 tests:
- Bee-mode empty start, set, restart preserves entries
- JSON file migrates to bee on first load
- set/update/delete/setAnchored persist + survive restart
- Legacy JSON-only mode still works (no setStore call)
- `setStore` after `load()` throws
- Concurrent mutations of different keys all persist
- Empty JSON file migrates cleanly (renamed but no entries to write)

All 17 smoke-test suites pass.

### Second of three registry improvements

From the [REGISTRY-DESIGN-COMPARISON-2026-05-28.md](docs/REGISTRY-DESIGN-COMPARISON-2026-05-28.md)
plan. Highest-leverage swap (~500 LOC of fragility removed without
changing the public API). Next up: v0.8.26 `SeedingRegistry`
indexed-views sidecar.

## [0.8.24] — 2026-05-28

Per-key mutation locks in `SeedingRegistry` — closes documented race
windows where concurrent custody mutations on the same intentId (or
seed mutations on the same appKey) could each observe a stale status,
each pass `validateCustodyTransition`, and each append, producing
duplicate entries.

Lifted from the Holepunch challenge `username-registry`'s
`_withMutationLock` pattern, but scoped **per-key** so unrelated
operations stay parallel — only mutations sharing a key serialize.
Lock map entries clean up automatically when no waiters are queued
behind, so the map doesn't grow unbounded.

### What ships

- New `SeedingRegistry._withKeyLock(key, fn)` helper
- `_appendCustodyEntry` now serializes on `custody:${intentId}` —
  closes the `read status → validate → append` race
- `publishRequest`, `recordAcceptance`, `cancelRequest` serialize on
  `seed:${appKey}` — closes the `append → applyEntry → emit` race
- 6 new unit tests in `test/unit/registry-mutation-locks.test.js`:
  same-key serialization, different-key parallelism, slot cleanup,
  chained queueing mid-flight, failure-doesn't-block-next-op,
  chained-failures-still-serialize

### Behavior in the no-contention case

Identical. The lock is a best-case noop — a non-contended key sees
the lock chain reduce to `await Promise.resolve()` which the engine
optimizes to nothing.

### Why this is the right starter

First of three registry-design improvements derived from the
Holepunch challenge comparison (see
[REGISTRY-DESIGN-COMPARISON-2026-05-28.md](docs/REGISTRY-DESIGN-COMPARISON-2026-05-28.md)).
Smallest surface, lowest risk, real race closure — good warm-up
before v0.8.25 (AppRegistry → Hyperbee) and v0.8.26 (SeedingRegistry
indexed-views sidecar).

## [0.8.23] — 2026-05-27

Three community-contributed maintenance + correctness changes from
the contributor. Two had been waiting since
v0.8.13 (pre-LifecycleScope vintage), now rebased + cherry-picked
cleanly. One was opened, reviewed, and shipped within hours of
its filing today.

### Partial-quorum custody-commit support (PR #16)

`validateCustodyTransition` now honors `commit.relayQuorum` as the
authoritative receipt subset when the commit carries an explicit
quorum list. Pre-fix, validation filtered to all receipts the relay
happened to have visible (`anchored.filter(r => r.anchored === true)`),
which rejected any T-of-N partial-quorum commit (T < N) the moment
the relay accumulated MORE receipts than the publisher's chosen
subset — e.g. receipt #4 gossiping in between collect-threshold
and commit-submit on a 3-of-4 quorum.

**The fix.** When `commit.relayQuorum` is a non-empty array, filter
the visible receipts to that exact pubkey set:

```js
const quorumSet = new Set(entry.relayQuorum)
receipts = anchored.filter(r => quorumSet.has(r.relayPubkey))
if (receipts.length !== entry.relayQuorum.length) {
  return { valid: false, reason: 'relayQuorum names receipts not yet visible' }
}
```

Phantom-pubkey protection: if the publisher names a relay we have
no receipt for, reject — they can't reference receipts we can't
see. Backwards-compat: missing/empty `relayQuorum` falls back to
the original "use all visible" behavior. Publisher's Ed25519
signature on the commit binds the chosen set so the quorum can't
be MitM-swapped after the fact.

**Downstream impact:** drop-pear v3.0.14 reverted to wait-for-n
on the publisher side as a workaround. With v0.8.23, drop-pear
can revert to the v3.0.7 partial-quorum design (collect fastest
T receipts, commit referencing them, slow relays catch up async
without blocking drop completion). Coordinate with the drop-pear
team before bumping.

**3 new tests** in `custody-signing.test.js`: relayQuorum honored
against named subset, phantom-pubkey rejected, legacy commits
without relayQuorum still validate against all-visible.

### Transient core error classification on Protomux publish channel (PR #17)

`'Mutex has been destroyed'` added to `TRANSIENT_MARKERS`. The three
Protomux registry-publish handlers (`onSubmitIntent`,
`onSubmitCommit`, `onSubmitSourceRetired`) now route through a
`wrapTransient` closure that mirrors `onSubmitSeed`'s `{ ok, result,
error, retryable }` contract. Previously, exceptions thrown by the
registry (corestore-close window, Mutex destroyed, etc.) bubbled
up to PublishProtocol's default catch which converted them to
`retryable: false` — making publishers give up on what were
actually recoverable transient relay-state issues. The HTTP API
already classified these correctly; this PR brings the Protomux
path to parity.

### Drop's import-subpath exports pinning (PR #30)

Pinned 5 subpaths Drop imports from `p2p-hiverelay` as explicit
named entries in `packages/core/package.json` `exports`. Today
they resolve via the `"./*": "./*"` wildcard catch-all; named
entries protect downstream code against future restructuring of
`core/` (moving to `dist/`, swapping to subpath patterns, etc.).
Both `bare-spec` and `.js`-spec entries per path. Named entries
placed before the wildcard so resolver hits them first. Wildcard
preserved as fallback — no regression possible for any other
subpath consumer.

This is the right precedent: the wildcard is convenient for
development but accidentally leaks the entire internal layout
as a stable contract. Pinning the genuinely-public subpaths
first gives us a clean migration path to eventually narrow the
wildcard (`"./*": null`) without a big-bang break.

### Acknowledgments

All three PRs by the contributor. #16 and
#17 were pre-v0.8.13 vintage (the contributor's original work that predated
the LifecycleScope cancellation contract); both rebased cleanly
against current main this week. #30 was opened, reviewed,
merged, and now released within ~24 hours of filing.

### Verification

15/15 smoke-test suites pass on current main with all three
landed (custody-signing, transient-core-errors, app-registry,
app-registry-provenance, blind-path-airtight, circuit-relay-
bridge, dht-relay-ws-privacy, lifecycle-scope, drive-close-
cascade, repin-cap-reconcile, cancellable-drive-update,
anchor-status, anchor-proof, anchor-channel, partial-pin-self-
heal integration). Total 5.3s wall time.

### Carryover follow-ups (v0.8.24+)

All filed as issues for tracking:

- [#26](https://github.com/bigdestiny2/P2P-Hiverelay/issues/26)
  — `app-registry save()` write-timeout (closes hung-disk
  cascade)
- [#27](https://github.com/bigdestiny2/P2P-Hiverelay/issues/27)
  — Operator-facing disk-usage signal in `/health` / status
- [#28](https://github.com/bigdestiny2/P2P-Hiverelay/issues/28)
  — Promise-shape `drive.download()` cancellation hook (test-
  runner artifact, no production impact)
- [#29](https://github.com/bigdestiny2/P2P-Hiverelay/issues/29)
  — `hiverelay_coresSeeded` metric scope expansion

## [0.8.22] — 2026-05-24

Defensive timeouts on the two `await`s in the reseed + anchor paths
that could (and did) deadlock the entire relay when one entry hit a
hung hypercore. Surfaced by the contributor's
investigation of milkyb-iad after the v0.8.21 deploy: iad's 1 GB Fly
volume hit 100%, which made `writeFile` hang on registry saves, which
compounded into hung `drive.ready()` calls + hung `getBlobs()` calls,
which made the sequential reseed + anchor-check loops stop making
forward progress entirely. 15 hours of silent partial-function before
the disk-full root cause was found.

### What ships

**1. `drive.ready()` timeout in `_seedAppInner` (8s, PR #25 commit 1).**
`reseedFromRegistry` awaits `seedApp` sequentially. One entry whose
hypercore can't `ready()` blocks every subsequent entry from being
opened. The new race-against-timeout throws on hang, lets `seedApp`'s
outer try/catch in `reseedFromRegistry` emit a `reseed-error`, and
the next entry proceeds. 8 seconds is a generous liveness floor —
healthy `ready()` resolves in milliseconds.

**2. `_isDriveFullyReplicated` timeout (3s, PR #25 commit 2).**
`_runAnchorCheck` iterates `appRegistry.apps` sequentially with
`await _isDriveFullyReplicated(drive)` per entry. Internally that
awaits `drive.getBlobs()` for the blob-layer lazy-init — which can
hang indefinitely if no current peer has the blob layer resolvable.
Body extracted to `_isDriveFullyReplicatedInner` so the public method
wraps the race cleanly; on timeout, returns false and the next pass
retries.

### Empirical proof (the contributor's milkyb-iad)

| Metric | v0.8.21 (= v0.8.20 + #22 + #24) | v0.8.22 (= v0.8.21 + #25) |
|---|---|---|
| iad reseed completion | 12 of 145 entries after 15h | All 145 within minutes |
| iad anchor-check pass | 0 entries after startup | Periodic ticks every 5min |
| iad Drop status | `anchored=false, len=0` for 15h+ | **`anchored=true, len=7999`** |
| Cross-fleet self-heal proof | fra + syd | **fra + syd + iad** |

### Behavior in the no-hang case

Identical to v0.8.21. Both timeouts are pure-additive — existing code
paths execute exactly as before; the timeout serves only as a fallback
when something hangs that previously would have hung silently forever.

### Acknowledgments

PR #25 by the contributor, with field
validation against milkyb-iad's recovery. Cherry-picked onto current
main (PR #25 branched from v0.8.20, not v0.8.21) preserving the contributor's
authorship on both commits.

### Known follow-ups

Both flagged by the contributor in PR #25, separate scope:

- `app-registry.js#save()` should also Promise.race a timeout against
  `writeFile` — closes the last leg of the hung-disk cascade
- Operator-facing disk-usage signal in `/health` or metrics — no
  visible indicator today for "this relay's volume is at 90%"
- (carried over from v0.8.21) Promise-shape `drive.download()`
  cancellation hook on scope abort — test-runner artifact, no
  production impact

## [0.8.21] — 2026-05-24

Self-heal that actually heals. v0.8.20 shipped the honest-anchor
signal but exposed two latent replication bugs that prevented the
repair loop from doing its job. v0.8.21 closes both — production
validation by the contributor on milkyb-fra
and milkyb-syd demonstrated the first cross-relay peer-to-peer
self-heal HiveRelay has ever shipped: syd anchored a previously-
unanchored drive within 5 seconds of restart by pulling
peer-to-peer from fra, with no publisher in the loop.

### What v0.8.20 left broken

After [v0.8.20](#0820--2026-05-23) deployed, drives correctly
downgraded to `anchored=false` (PR #19's honest-anchor signal),
but they sat there indefinitely without recovering. milkyb-fra
showed 11/112 entries unanchored for 30+ minutes despite the
publisher being online the entire time. Our 5-relay fleet showed
the same pattern: `hiverelay_coresSeeded=1` across 555 seeded
apps on utah alone — the lone seeded core was the registry log;
every per-app drive had no persistent download "want" registered
with the replicator.

Two distinct bugs:

1. **`downloadWithTimeout` was written for hyperdrive 10.x's
   tracker-shape `drive.download()` API.** Hyperdrive 11.x made
   `download()` async-returning-Promise — calling `.done()` on a
   Promise threw `TypeError: dl.done is not a function`, which
   the surrounding try/catch silently absorbed as "download
   didn't complete." Pre-v0.8.20 the relay marked entries
   `anchored=true` on metadata-only and `runRepairPass` skipped
   them, so the bug never executed. v0.8.20's honest signal
   surfaced it.

2. **Per-app Hyperdrives never registered persistent download
   ranges.** `seeder.seedCore()` does `core.download({ start: 0,
   end: -1 })` on the registry log core to maintain a persistent
   "want" with the replicator. The appRegistry path opened
   drives but never registered any such want on their meta or
   blob cores. Drives only requested blocks during the brief
   60s `_eagerReplicate` + `repairUnanchored` download windows
   — and only if a peer happened to be reachable in exactly that
   window. For drives whose publisher was intermittent, the
   window almost never landed; self-heal was structurally
   non-functional.

### What v0.8.21 ships

**1. Hyperdrive 11.x Promise-shape detection (PR #22).** New
`isOldTrackerApi` probe in `downloadWithTimeout` detects both
API shapes via `.done && .destroy`. Old-shape path preserves
`tracker.destroy()` cleanup on timeout. New-shape path races
the Promise against the timeout; orphaned inner
`blob.core.download` trackers settle naturally bounded by the
file's blob extent. 3 new unit tests covering both shapes;
all 16 in `cancellable-drive-update.test.js` pass.

**2. Persistent download ranges on Hyperdrive cores (PR #24).**
New `_registerPersistentDownloads(appKey, drive)` helper called
from `_seedAppInner` after the drive is registered. Issues
`core.download({ start: 0, end: -1 })` on `drive.db.core` +
the blob core (after `getBlobs()` resolves lazily), storing
trackers on `entry.downloadRanges`. `unseedApp` destroys the
trackers before drive close, matching the v0.8.13 LifecycleScope
defensive pattern. Idempotent, best-effort, non-throwing
(failures emit `persistent-download-error` event without
breaking the seed).

### Production validation

Empirical proof, fra:

| Time after publisher rejoins swarm | requests-rx | blocks-tx |
|---|---|---|
| 5s | 211 | 211 |
| 10s | 654 | 654 |
| 30s | 1,471 | 1,471 |
| 80s | 3,431 | 3,431 |

Pre-fix on identical setup: zero block requests for 30+
minutes. Post-fix: first block requests within 5 seconds of
publisher availability.

**Cross-relay self-heal, syd:**
After fra was on v0.8.21, syd was upgraded. Within ~5s of
restart, syd's newly-registered persistent download range on
the Drop drive's blob core discovered fra via DHT, pulled the
missing blob bytes peer-to-peer between relays, and marked
Drop `anchored=true` — **no external publisher involvement at
all**. This is the first cross-relay autonomous self-heal
HiveRelay has shipped.

### Why this matters

Pre-v0.8.21, the relay's repair loop was structurally
unreliable: bounded download windows + intermittent publisher
availability = drives that never recovered. v0.8.21 makes the
replicator-level "want" persistent, so the moment any peer
with the missing bytes becomes reachable — publisher OR another
relay — the missing blocks flow. The fleet now functions as a
cooperative self-healing mesh, not a collection of relays each
hoping the publisher comes back online during their 60s
window.

### Known follow-ups

- **v0.8.22 — Promise-shape cancellation hook.** PR #22's
  Promise-shape path doesn't currently cancel the underlying
  `drive.download()` Promise on scope abort — the outer
  `raceOr` returns cleanly via AbortError (so `stop()` drains
  in <10ms), but the inner Promise stays in-flight in
  background until the 120s timeout fires. Surfaces as
  `reliability-v2.test.js` test-runner timeout when tests
  seed random keys with no peers; production behavior with
  active peers is unaffected.
- **v0.8.22 — `coresSeeded` metric scope.** Persistent
  download ranges aren't routed through `seeder.seedCore()`,
  so the `hiverelay_coresSeeded` counter still shows 1 (the
  registry core). Per-drive storage accounting is operator-
  visibility, separate from the behavior fix that landed here.

### Acknowledgments

PR #22 + PR #24 by the contributor, with
production validation against three milkyb relays (fra, syd,
iad). The "syd anchored Drop in 5s peer-to-peer without
publisher" demonstration is the cleanest validation we've ever
gotten for a replication-layer change.

## [0.8.20] — 2026-05-23

Anchor honesty + custody auto-attestation. Two community-contributed
fixes by the contributor that close the
silent partial-pin trap and finally wire up the cryptographic loop
for blind-custody BURNED state.

Both shipped via [PR #19](https://github.com/bigdestiny2/P2P-Hiverelay/pull/19)
+ [PR #20](https://github.com/bigdestiny2/P2P-Hiverelay/pull/20),
with production validation against the milkyb-fra Fly.io relay
(11/112 false-anchored entries correctly downgraded on first
periodic check; full self-heal + 12/12 probe-deep post-fix on the
Drop drive that had been silently bricked for ~2 weeks).

### Anchor honesty (#19)

**The bug:** Relays set `anchored=true` whenever `drive.version > 0`
(metadata length), not when the blob blocks were actually present
locally. Three call sites (`_eagerReplicate`, `repairUnanchored`,
`_runAnchorCheck`) all made the same mistake. Because
`runRepairPass` skips entries marked anchored, any drive whose blob
download timed out mid-pull was silently locked out of self-heal
indefinitely. End users hit hangs-forever; operators bounced relays
as a workaround (`docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md` —
the "may need a bounce" recipe was lottery, not a fix).

Orthogonal to v0.8.13 (cancellation contract) and v0.8.14
(per-drive corestore session). Those addressed stop()-triggered and
continuous-operation corestore-close vectors. This addresses the
anchor-flag-on-metadata-only vector that persists when a download
just doesn't complete cleanly, with no corestore-close in sight.

**The fix:** New `AppLifecycle._isDriveFullyReplicated(drive)`
helper that checks `drive.blobs.core.has(0, blobs.core.length)` —
the canonical hypercore bitfield-presence API. Returns true for
empty blob cores (metadata-only drives), false for closed drives,
missing blob layers, or any block gap. All three anchoring sites
now gate `setAnchored` on `downloadComplete && _isDriveFullyReplicated(drive)`.
`_eagerReplicate` stops silently swallowing `downloadWithTimeout`
errors. `_runAnchorCheck` does `clearAnchored` with a partial-pin
reason code when it catches a downgrade. `repairUnanchored` returns
false on partial so the next repair tick re-queues.

**Backwards compatibility:** Upgraded relays self-heal on the first
periodic anchor check after restart (≤10 min). Existing
`anchored=true` registry entries get downgraded to false if their
blob cores have gaps; `runRepairPass` then pulls the missing
blocks. No protocol/RPC/schema changes. Expect a 5–15% honest
downgrade rate on existing fleets — that's the contract catching up
to reality, not a regression.

### Custody auto-attestation (#20)

**The gap:** Atomic Blind Custody had the cryptographic primitives
(`createCustodyNonServingProof`, `createCustodyExpiryWitness`) but
they were only invoked when something explicitly called
`/api/custody/{id}/non-serving-proof`. The periodic
`_runCustodyExpiryPass` deleted blobs cleanly on expiry but never
signed proof of having done so. Recipients probing for BURNED
state always got `QUORUM_UNAVAILABLE` because no proofs existed.

**The fix:**

1. **Auto-emit `custody-non-serving-proof` on expiry.** The expiry
   pass now captures `custodyIntentId + blindContentId` BEFORE
   `unseedApp` (since unseed removes the entry and
   `createCustodyNonServingProof` would otherwise throw
   `STILL_SERVING`), then signs + records a non-serving-proof for
   each expired entry. Skips silently for pre-pipeline blind
   entries without custody linkage. Surfaces attestation failures
   via `custody-non-serving-attest-error` event without failing
   the unseed.

2. **Cross-relay expiry-witness pass.** New
   `_runCustodyExpiryWitnessPass` scans all known custody intents
   past their `retainUntil` and signs an independent
   `custody-expiry-witness` attestation for every peer relay's
   non-serving-proof observed via registry gossip. Recipients now
   get dual cryptographic confirmation:
   - relay-X self-signs "I deleted my copy" (proof)
   - relay-Y independently witnesses "I observed relay-X's signed
     deletion" (witness with `nonServingProofHash`)

   Threshold-many witnesses give the recipient a BURNED guarantee
   resistant to a single relay self-attesting falsely. Refuses
   self-witness (`SELF_WITNESS_REFUSED`), deduplicates by
   (witnessPubkey, relayPubkey, intentId), opt-out via
   `config.custodyWitnessEnabled = false`.

3. **Composed scheduling.** Both passes run on the same interval
   tick (default 60s) via a `runBoth` closure in
   `_startCustodyExpiryMonitor`. Initial pass also fires 5s after
   start.

### Tests

- `test/unit/repair-loop.test.js` — 6 new tests covering partial-pin
  state, empty blob core, closed drive, missing blob layer,
  requeue-after-downgrade (#19)
- `test/integration/partial-pin-self-heal.test.js` — 4 new
  integration tests using real `Corestore` + `Hyperdrive`; test 2
  uses `blobs.core.clear(middle, middle+1)` to induce the exact
  on-disk shape of a real partial pin (#19)
- `test/unit/relay-node.test.js` — 8 new tests covering auto-emit
  happy path, no-intent skip, attest-error handling, witness happy
  path, self-skip, dedup, retainUntil gate, refuses-own-proofs (#20)

All 18 new tests pass locally. 133/133 across adjacent suites
(anchor-status, anchor-proof, anchor-channel, lifecycle-scope,
drive-close-cascade, repin-cap-reconcile, cancellable-drive-update,
app-registry, app-registry-provenance, blind-path-airtight) still
pass on merged main.

### Acknowledgments

Both PRs by the contributor, surfaced + driven
by the drop-pear v3 escrow flow against the public fleet. Drop
drive resurrected after ~2 weeks silent-brick.

### Follow-ups (separate work)

- Dockerfile/Alpine note: `udx-native@1.19.2` has no
  `linux-x64-musl` prebuild + no install hook. Use a glibc base
  (Debian/Ubuntu), not musl-based (Alpine). Tracked in
  [issue #21](https://github.com/bigdestiny2/P2P-Hiverelay/issues/21).
- `_custodyIntents.keys()` private enumeration → public iterator
  on SeedingRegistry (cleaner abstraction; not blocking)
- Witness v2: active-probe peer relays to verify catalog/gateway/
  swarm absence before signing (current v1 attests to
  proof-existence rather than active-not-serving)
- PRs #16 + #17 from same contributor pending rebase against
  current main — partial-quorum custody-commit + transient-error
  classification will land in v0.8.21

## [0.8.19] — 2026-05-22

Circuit-relay bridge data plane — fixes a silently-broken cross-NAT
pair path that never worked in production. Also closes a related
silent auth bypass on the reserve/connect handshake.

### Background

The `hiverelay-circuit` protocol's reservation + connect handshake
shipped working, but the actual bridge data plane never did. The
`_bridgeCircuit` code at `core/protocol/relay-circuit.js:206` called
`Relay.createCircuit(circuitId, sourceChannel.stream, destChannel.stream, ...)`.
But `channel.stream` is undefined in modern protomux (Channel exposes
`_mux.stream`, not `.stream`), so `createCircuit` would have been
called with `(circuitId, undefined, undefined, sourcePeerKey)` and
crashed at the first `.on('data')`. In practice the code path was
never exercised because no production app drove a reservation + a
matching connect from a different peer until PearPaste tried to use
the fleet for cross-NAT pairing.

Even if the bridge had worked, raw-byte forwarding between two
protomux `_mux.streams` would corrupt every channel sharing them
(channel-id space is per-mux; noise encryption is per-stream). The
design needed to be a data-plane message at the protomux channel
layer, not stream-level forwarding.

### What ships

**1. Proper data-plane message at the protomux channel layer.**
The `hiverelay-circuit` channel gets three new message types:
- `dataMsg { circuitId: 16 bytes, data: bytes }` — opaque payload
  forwarding. The relay validates the sender is one of the two
  endpoints of the named circuit, applies per-frame size cap
  (default 64 KB), per-circuit byte cap, and relay-wide bandwidth
  cap, then forwards to the other endpoint's channel.
- `readyMsg { circuitId, remotePubkey }` — server→client signal
  that a circuit is bridged and the client can start sending. Sent
  to BOTH peers, carrying the other end's pubkey so they can run a
  verified Noise handshake on top of the byte channel. Previously
  only the connecting side got a status; the reservation holder had
  no signal that anyone had connected.
- `closeMsg { circuitId, reason }` — explicit close notification
  with a coded reason (PEER_CLOSED, BYTES_EXCEEDED, BANDWIDTH_EXCEEDED,
  DURATION_EXCEEDED, FRAME_TOO_LARGE, FORWARD_FAILED, SHUTDOWN).

**2. Silent auth bypass closed.** The reserve/connect identity checks
at `relay-circuit.js:113,167` read `channel.stream?.remotePublicKey` —
which was always undefined, so `authenticatedKey` was undefined, so
the `if (authenticatedKey && ...)` short-circuited to false and the
identity check silently passed. Result: any peer could reserve under
any pubkey, and connect under any source pubkey. **This was a
MitM-enabling bug** had the bridge ever worked — an attacker could
insert themselves between two pairing peers. The check now reads
`channel._mux.stream.remotePublicKey` correctly (with a fallback to
the legacy `.stream` path for forward compat).

**3. New `Relay` accounting methods.** `registerCircuit`,
`recordCircuitBytes`, `closeCircuit` — channel-based equivalents of
the old stream-based `createCircuit`. Track per-peer circuit counts,
total bytes, bandwidth window, and feed the same `/status` counters
dashboards already read. Old `createCircuit` left in place for
backward compatibility but unused.

**4. Client SDK exposes the new data plane.** `packages/client`
adds `dataMsg`/`readyMsg`/`closeMsg` to the circuit channel attach,
plus `sendCircuitData(relayPubKey, circuitId, data)` method.
Emits `circuit-ready`, `circuit-data`, `circuit-closed` events.

**5. Connect-before-reserve queueing.** When a peer tries to connect
to a target that hasn't reserved yet, the request is queued in
`pendingConnects` rather than rejected outright. Existing semantics
preserved; previously the rejection was final.

### Tests

`test/unit/circuit-relay-bridge.test.js` — 12 tests / 49 asserts:
- Reserve + connect bridges a circuit, both peers receive ready
- Data forwards in both directions
- Data from a non-endpoint channel is dropped (no impersonation)
- Data for unknown circuitId is dropped silently (no oracle for attackers)
- Per-frame size cap closes the circuit
- Per-circuit byte cap closes the circuit
- Reserve with mismatched pubkey is rejected (auth bypass closed)
- Connect with mismatched sourcePubkey is rejected (auth bypass closed)
- Connect-before-reserve queues correctly
- Channel close tears down circuits the channel was part of
- Relay at-capacity refuses to register new circuit
- `getStats` exposes new `activeCircuits` field

### Risk

`Relay.createCircuit` (the old stream-based method) is left in place
but no longer called internally. No external callers. Safe to leave.

Protocol-wire change: receivers that don't know about `dataMsg` /
`readyMsg` / `closeMsg` will see them as unknown protomux message
types. Protomux's default policy is to silently ignore unknown
messages (no error, no disconnect), so old clients connecting to new
relays remain functional — they just can't use the bridge until they
upgrade.

### Customer

This unblocks PearPaste's cross-NAT pair flow (cellular ↔ home Wi-Fi)
once the fleet rolls v0.8.19. PearPaste already shipped the
`reserveRelay` + `connectViaRelay` plumbing on their side; they were
waiting on the bridge data plane.

## [0.8.18] — 2026-05-22

Provenance surfacing in the catalog broadcast — Phase A of the
fed-junk upstream policy. Closes the persistence + broadcast gap that
left federation receivers unable to distinguish published-with-
commitment content from pure-anonymous mirrors. The 444/455 (97.6%)
"anonymous mirror" share on utah-us was a symptom of this gap, not of
malicious publishers: publisher SDKs were sending provenance, but the
fields were being dropped at save() and stripped at broadcast.

### What ships

- `catalog()` and `catalogForBroadcast()` now include
  `publisherPubkey`, `durability`, `revocable`, `retainUntil` for
  non-redacted entries. Cascade with the v0.8.15 blind-path audit:
  redacted entries (blind drives) MUST not surface these — leaking
  `publisherPubkey` would link the publisher to the blind drive,
  leaking `durability` / `retainUntil` would signal which blind drives
  are "important." `_redactCatalogEntry` now explicitly nulls all four.
- `AppRegistry.save()` persists `publisherPubkey`, `durability`,
  `revocable` to disk. Previously these lived only in memory and
  vanished on every service bounce.
- `AppRegistry.load()` restores them on startup AND forwards them via
  the reseed return value so `_seedAppInner` doesn't clobber the
  freshly-loaded entry with undefined opts.

### Why now

The fed-junk analysis on utah-us (455 entries, all with
`durability: 0`, `revocable: true`, `publisherPubkey: null`) showed
the data needed to gate federation acceptance simply wasn't reaching
downstream relays. Phase A is the foundation: surface the fields so
they exist on the wire. Phase B (later — v0.9.0) adds an opt-in
`federation.acceptDurabilityFloor` gate that uses them. Phase C
covers SDK guidance + migration docs.

### Risk

Backwards-compatible. Older registry files load with default values
(`null` / `0` / `true`) matching pre-v0.8.18 behavior. Broadcast adds
4 new fields — receivers that ignore unknown fields (the safe default
in this codebase) are unaffected.

### Tests

`test/unit/app-registry-provenance.test.js` — 7 tests / 42 asserts:
non-blind surfacing in catalog + broadcast, blind force-stripping,
missing-provenance graceful defaults, save/load round-trip, legacy
registry file load. The v0.8.15 blind-path airtight tests still pass
unchanged.

### Side benefit

Once durability is on the wire, the janitor's Tier-2 can distinguish
"published-but-mirrored" from "pure-gossip" entries — partially
unlocks safe automation of fed-junk sweeping. Not enabled in v0.8.18
(janitor stays version-gated to v0.8.14+ data only).

## [0.8.17] — 2026-05-22

Operational release: turns on the `dht-relay-ws` transport — the
WebSocket bridge into HyperDHT that lets browsers / Android WebViews
reach the relay over `wss://`. Three of the five fleet relays
(utah-us, singapore-1, bern) are exposed at named subdomains under
`p2phiverelay.xyz`, fronted by Caddy + Let's Encrypt TLS. The privacy
hardening shipped in v0.8.16 is now active behind those endpoints.

### Added

- **CLI / env-var enablement for the transport.** `--dht-relay-ws`
  flag, or `HIVERELAY_DHT_RELAY_WS=1` env var, opts a relay into
  serving the WS bridge. Defaults to bind `127.0.0.1:8766` (the relay
  never goes directly internet-exposed — Caddy in front does TLS at
  443). Port and host overrides:
  `HIVERELAY_DHT_RELAY_WS_PORT` / `HIVERELAY_DHT_RELAY_WS_HOST`.
- Operational: Caddy reverse-proxy config templates per relay (in
  the deploy notes), no relay-side change required for TLS.

### Public WSS endpoints (for browser/Android clients)

| URL | Backed by | Pubkey |
| --- | --- | --- |
| `wss://relay-us.p2phiverelay.xyz/relay-ws` | utah-us | `37cf4bfbdf33320f34c41f5fa8b8095ed5eb2f49cef58c3194392c4f6be4e29a` |
| `wss://relay-sg.p2phiverelay.xyz/relay-ws` | singapore-1 | `17ba6ae38d69f489def7c7a94fbd94f873b40eb8b3b96df902d1a3eb2cb56c54` |
| `wss://relay-eu.p2phiverelay.xyz/relay-ws` | bern | `bc421fedea8a79607581da49210cd39fb5b08ce942b2a62884b831508c23d7ee` |

Reminder: these are DHT-relay-WS *transport* endpoints, not
application-level relay identities to hardcode. The HiveRelay SDK
auto-discovers relays over the DHT once one of these is used as a
WS bootstrap. Use a public Holepunch bridge instead if you want
metadata privacy from our fleet (we'd see your client IP — only as
a salted-hash within a session, never as raw, per the v0.8.16
hardening — plus your DHT lookups).

### Operational

- utah, singapore-2: transport stays disabled (no domain attached).
  They keep serving via DHT only.
- All emitted events (rate-limited / client-connected /
  client-disconnected / client-error / relay-error) now actually
  fire on real traffic against the 3 enabled relays — verified
  carrying `remoteAddressHash` only, no raw IP. Per the v0.8.16
  audit + tests.

### Compatibility

- **Backward-compatible.** Relays without the env var stay
  DHT-only as before. Existing publisher/seed flows untouched.
- Caddy is the only new dependency on the 3 domained relays.

## [0.8.16] — 2026-05-22

Pre-rollout privacy hardening of the `dht-relay-ws` transport. The
transport is still off by default; this release lands the IP-stripping
guards so we have a clean audit trail before flipping it on in a
follow-up release.

### Fixed (privacy)

- `dht-relay-ws` transport's emitted events (`rate-limited`,
  `client-connected`, `client-disconnected`, `client-error`,
  `relay-error`) now carry a salted, non-reversible
  `remoteAddressHash` (16 hex chars) instead of the raw client IP.
  The raw IP stays in-process in `_ipBuckets` for the rate-limiter
  only (5-minute TTL) and is never exposed to downstream subscribers
  (ws-feed, observatory, `/api/manage/*`, logs).
- `relay-error` and `client-error` events now run their `Error`
  through a `scrubError` helper that strips `.stack` (server-side
  paths) and IP-pattern substrings from `.message`, keeping only
  `{ message, code, name }`.
- Per-process random salt on the IP hash so the same client IP
  produces different hashes across relays / restarts — useful for
  in-session correlation, useless for cross-fleet tracking.

### Added

- Top-of-file threat-model doc-comment in
  `packages/core/transports/dht-relay-ws/index.js` enumerating what
  operators CAN and CANNOT see.
- 7 new unit tests in
  [`test/unit/dht-relay-ws-privacy.test.js`](test/unit/dht-relay-ws-privacy.test.js)
  asserting no raw IP survives the event boundary.

### Compatibility

- **Backward-compatible.** Transport is still disabled by default
  (`config.transports.dhtRelayWs` defaults false). No relay's runtime
  behavior changes. The hardening only takes effect once an operator
  opts the transport in (planned v0.8.17).
- Downstream subscribers expecting `info.remoteAddress` see
  `undefined`; switch to `info.remoteAddressHash` for in-session
  correlation. No known external subscribers depend on the field
  today.

## [0.8.15] — 2026-05-19

Hardening release: Hyperdrive-session audit follow-up + blind-path
audit. No protocol changes. Two surgical edits guard previously-leaky
paths against an operator-untrusted threat model.

See [`docs/RELEASE-NOTES-0.8.15.md`](docs/RELEASE-NOTES-0.8.15.md) for
full notes and the audit reports at
[`docs/audit/2026-05-19-blind-path-audit.md`](docs/audit/2026-05-19-blind-path-audit.md).

### Fixed (Hyperdrive-session audit follow-up to v0.8.14)

- **`gateway/hyper-gateway.js:497`** — `new Hyperdrive(this._store, …)`
  was passing the relay's raw `node.store`, so DriveCache evictions
  could close the root corestore. Now wrapped with `.session()`,
  matching v0.8.14's pattern.
- **`services/builtin/storage-service.js:65`** — same fix for the
  bare-relay storage service.
- **`gateway/server.js:43,98`** — same fix for the standalone gateway
  entrypoint. Defensive, not in fleet runtime.

The fleet ran 95.7h on v0.8.14 without wedging despite the canary's
trace showing 15 close-call events through the unguarded paths above
— v0.8.14's seed-path session() boundary absorbed the cascade, but
covering every site removes the residual exposure.

### Fixed (blind-path airtight audit)

- **`_indexAppManifest`** (`app-lifecycle.js:692`) — now early-returns
  when `entry.blind === true`. Previously it unconditionally opened
  `/manifest.json` on every anchored drive and persisted
  `appId`/`name`/`description`/`author`/`categories`/`version` into
  `app-registry.json`. Operator with disk access could read blind
  drives' manifest metadata. Cascade-closes the
  `app-replaced` / `app-version-rejected` event leaks (emitted from
  inside this method).
- **`_shouldRedactEntry`** (`app-registry.js:269`) — `entry.blind === true`
  now forces redaction unconditionally, independent of caller opts
  or `custody.redactedCatalog` config. Previously a config of
  `redactedCatalog: false` (or a bare `catalog()` call with no opts)
  exposed blind entries' full metadata via public `/catalog.json`
  and internal `/api/manage/*` endpoints. Cascade-closes the
  `/api/manage/*` catalog leak and any callsite that forgets to pass
  `redactPrivate: true`.

Internal code paths that legitimately need unredacted access continue
to work — they use `appRegistry.get(appKey)` directly, not the
`catalog()` projection.

### Added

- 7 new unit tests in
  [`test/unit/blind-path-airtight.test.js`](test/unit/blind-path-airtight.test.js)
  fuzzing the blind-flag boundary across catalog projections,
  broadcast, predicate behavior, and the public/non-blind regression
  guard.
- Audit report:
  [`docs/audit/2026-05-19-blind-path-audit.md`](docs/audit/2026-05-19-blind-path-audit.md)
  enumerating all 9 paths walked, with verdict + fix per path.
- Handoff doc:
  [`docs/handoff/2026-05-19-fleet-status-agent-handoff.md`](docs/handoff/2026-05-19-fleet-status-agent-handoff.md)
  for any agent picking up cold.

### Operational

- utah-us canary retired. Moves from `fix/drive-close-corestore-cascade`
  back to `main` (v0.8.15) as part of fleet rollout. Disarmed:
  `HIVERELAY_STORE_TRACE` env drop-in removed, `store-close-watcher`
  cron + log files cleaned up. The canary served its purpose
  (captured the root cause stack at 2026-05-18T09:38:53Z); leaving it
  in place created a fork against main.

### Compatibility

- **Backward-compatible.** No protocol changes. Public/non-blind
  drives behave identically.
- One semantic narrowing: any operator-side tooling that relied on
  `catalog()` returning unredacted data for blind entries (without
  passing `redactPrivate: true` or with `redactedCatalog: false` set)
  now sees redacted output. Switch to `appRegistry.get(appKey)` for
  direct internal access. The behavior was a leak; the fix is
  intentional.

## [0.8.14] — 2026-05-18

Root-cause fix for the silent corestore-close that wedged relays under
continuous operation. This is the actual fix for the bug class that
v0.8.13's LifecycleScope only *masked the faster half of*. Full
forensic writeup: `docs/repro/2026-05-17-v0.8.13-partial-recurrence.md`
and `.planning/debug/resolved/silent-corestore-close.md`.

### Fixed

- **`unseedApp()` no longer tears down the shared root corestore.**
  Every seeded drive was constructed `new Hyperdrive(node.store,
  appKey)` against the one shared root store. `hyperdrive@11.13.4`'s
  `_close()` unconditionally calls `this.corestore.close()`. So *any*
  unseed path — `_runCustodyExpiryPass` (temporary/atomic/blind entry
  past `retainUntil`), `_evictOldestApp`, version-supersede dedup,
  manual unseed — closed `node.store` for the **entire relay**. Every
  subsequent `new Hyperdrive(node.store, …)` in the seed path then
  threw `The corestore is closed` → relay-wide `POST /api/v1/seed`
  503 until systemd `Restart=always` reaped the crashed process.
  Mean-time-to-wedge (~57h pre-canary) tracked the time-to-first
  temporary-entry expiry, which is why it looked load-dependent and
  random.

  Fix: `new Hyperdrive(node.store.session(), appKey)`. A corestore
  session shares the same key-addressed hypercores (on-disk identity
  is byte-identical — the 300+ live entries on every production relay
  keep their storage, no re-replication) but its `_close()` only
  drops that session's refs. The root store stays open. One-line
  change in `app-lifecycle.js` `_seedAppInner`.

  This is the root cause of BOTH the original pre-v0.8.13 bug and the
  post-v0.8.13 recurrence. v0.8.13's `LifecycleScope` was orthogonal
  and still valuable — it eliminated the *restart-triggered* fire-
  and-forget vector that was wedging first (~6h) and masking this
  slower one (~57h).

### Added

- `test/unit/drive-close-cascade.test.js` — 7 tests / 17 assertions:
  seed 2 drives sharing the root store, unseed 1, assert
  `node.store.closed === false`, the other drive still resolves, a
  fresh `Hyperdrive` still opens, and the unseeded session's refs are
  released. Includes a regression test that documents + asserts the
  old broken pattern so it can't silently return.

### Fixed (build)

- **Dockerfile**: deps stage now also copies
  `packages/verifier/package.json`. `verifier` is in the root
  `workspaces` array + the lockfile, so `npm ci --workspaces` failed
  the image build without it (it was added to the workspace set after
  the Dockerfile's COPY list was last updated).

### Verified

- 7/7 unit regression tests pass; `npx standard` clean
- Canary (utah-us, `HIVERELAY_STORE_TRACE=1`): 5 rounds of
  seed-temporary-drive → `_runCustodyExpiryPass` unseed → **0**
  `[STORE-CLOSE-TRACE]` events; relay `active` + serving throughout.
  Independent re-verification: zero traces on the fixed process
  (last historical trace 0.7s *before* the fixed process started),
  plus a further forced-unseed round with zero traces and the relay
  still healthy.
- Before the fix the trace fired on the **first** unseed
  (2026-05-18T09:38:53Z captured stack).

### Operator note

`HIVERELAY_STORE_TRACE=1` is debug-only instrumentation on the
`debug/store-close-trace` branch — NOT in v0.8.14. Leave it off in
production. The `fix/drive-close-corestore-cascade` work is merged to
`main`; the instrumentation branch is kept until the fleet is
confirmed silent for 48h, then retired.

## [0.8.13] — 2026-05-15

Reliability v2 — closes the class of corestore-state-corruption bugs
that manifested as `Mutex has been destroyed`, `The corestore is
closed`, and `SESSION_CLOSED: Cannot make sessions on a closing core`
after hours/days of uptime on production relays.

Co-authored with **the contributor** (audit + design + fix). See full notes at
[`docs/RELEASE-NOTES-0.8.13.md`](docs/RELEASE-NOTES-0.8.13.md). Bug
class first reported in his 2026-05-15 09:56Z message; reproduction
captured in [`docs/repro/2026-05-15-corestore-closed-repro.md`](docs/repro/2026-05-15-corestore-closed-repro.md).

### Fixed

- **State corruption from fire-and-forget closures outliving stop()**.
  Several long-running async paths (eagerReplicate's 6-attempt retry
  loop, `_indexLog` from `localLog.on('append')`, repair pass,
  catalog-sync seedApp fan-out, cold-start primer, holesail auto-enable,
  replication/anchor/custody-expiry monitors, and the v0.8.12 re-pin
  retrigger) captured references to Hyperdrives / Hypercores / registry
  entries and continued running after `stop()` closed the corestore.
  The next `swarm.flush()` / `drive.update()` / `log.get(i)` would
  throw a stale-ref error. Over hours of uptime + self-heal restarts,
  these accumulated until `POST /api/v1/seed` started returning
  `503 The corestore is closed` and the relay was wedged until a
  full process restart.

### Added

- **`LifecycleScope`** (`packages/core/core/relay-node/lifecycle-scope.js`,
  174 lines). Single primitive: AbortSignal + tracked-promise Set with
  4 methods (`tracked()`, `race()`, `sleep()`, `drain()`,
  `throwIfAborted()`). Every fire-and-forget closure registers itself
  in the scope; every long `await` inside a participating loop is
  wrapped in `scope.race(promise)` so abort short-circuits the wait;
  every retry-delay uses `scope.sleep(ms)` so abort exits the backoff
  immediately. `RelayNode.stop()`'s first action is `await
  this._scope.drain()` — by the time it returns, no closure is still
  running against the corestore.
- 13 new unit tests for LifecycleScope (signal, drain, race, sleep,
  abort plumbing, regression guards).
- 4 new integration tests for Reliability v2 (testnet-backed):
  scope-created-on-start, stop()-blocks-on-tracked, 3-cycle
  start/stop with seeded apps (zero stale-ref errors), catch()-tails
  observed by drain.

### Verified (canary on Utah-US)

- 23/23 publishes succeeded under load
- 3/3 stop/start cycles clean — no wedge, no 503s
- Custody E2E (`scripts/custody-e2e.js`) passed in 12.5s with all 5
  relays consistent
- Zero `SESSION_CLOSED` / `corestore is closed` warnings on new pid
- `REQUEST_CANCELLED — recoverable rejection — continuing` warnings
  observed during restart cycles = abort signal cancelling in-flight
  requests gracefully, exactly as designed
- 80/80 existing lifecycle-adjacent unit tests still pass (per the contributor's
  audit run); 42/42 verified locally on validate-reliability-v2 branch

### Notes for operators

Behavior change is invisible during normal operation. The drain on
`stop()` is bounded by `config.shutdownTimeoutMs` × each participant's
own timeout, in practice ≤ 1s per scope drain. Self-heal `stop()`
+ `start()` cycles now produce clean transitions instead of
accumulating zombie refs in the new corestore.

## [0.8.12] — 2026-05-14

Structural follow-up to v0.8.11. Closes ask (6) from the
pearbrowser-desktop feedback — see
[`docs/RELEASE-NOTES-0.8.12.md`](docs/RELEASE-NOTES-0.8.12.md) for full
notes. Triggered by a maintainer-side bounce request from the
pearbrowser-desktop team after they discovered that their v0.8.10-era
partial-pinned drive couldn't be retriggered by a v0.8.11 re-pin
because `seedApp`'s `alreadySeeded` early-return swallowed the new opts.

### Fixed

- **`seedApp` no longer swallows new opts on re-pin**: when a publisher
  re-pins an already-seeded app with new `opts.maxStorage`, the relay
  now reconciles the change instead of returning early on the
  `alreadySeeded` branch. New `_reconcileSeedOptsOnRepin`:
  - cap raised (or newly declared) → entry's stored cap is updated and
    `_eagerReplicate` is retriggered to drain blocks the prior cap had
    blocked. Emits `seed-cap-raised` with `{ oldCap, newCap, anchored }`.
  - cap lowered → emits `seed-cap-warning` (`reason: 'cap-lowered-on-repin'`)
    and keeps the prior higher cap. Reducing accepted capacity mid-flight
    isn't honored; publisher must unseed first if they really want to
    shrink.
  - cap unchanged (or both null) → no-op.
  Concurrency-guarded via `entry._replicating` so rapid re-pins don't
  stack replication attempts. Applies on both the pre-mutex and
  post-mutex `alreadySeeded` checks in `seedApp` / `_seedAppInner`.

### Added

- **Per-app `maxStorage` persistence**: the publisher's declared cap is
  now tracked on each registry entry and persisted in
  `app-registry.json`. Older entries without the field load as
  `maxStorage: null` (no cap) — backward-compatible. On reseed at
  startup, `reseedFromRegistry` passes the persisted cap back through
  `seedApp`, so the v0.8.11 size-check now fires on startup too (it
  used to be skipped because the cap was forgotten between restarts).
- New `_eagerReplicate(appKeyHex, drive, opts, meta)` class method
  (extracted from the prior inline closure in `_seedAppInner`). Same
  retry-with-backoff + size-check + download + anchor flow, now
  callable from both the fresh-seed path and the re-pin retrigger
  path. Adds `source: 'fresh-seed' | 'repin-cap-raised'` to the
  emitted events (`seed-aborted`, `anchored`, `reseeded`,
  `reseed-error`) for observability.
- 12 unit tests in
  [`test/unit/repin-cap-reconcile.test.js`](test/unit/repin-cap-reconcile.test.js)
  covering: same-cap no-op, both-null no-op, cap raised, cap newly
  declared, cap lowered, in-flight retrigger guard, missing-drive
  guard, closed-drive guard, invalid-cap normalization, and the
  `AppRegistry` round-trip for the new `maxStorage` field.

### Notes

- Reseed-with-cap change is intentionally a behavior change: v0.8.11
  reseeded entries skipped the size-check (because the cap wasn't
  persisted), so an oversized drive accumulated silently after a
  restart. v0.8.12 now size-checks on reseed for entries written
  under v0.8.12+. Entries that predate cap persistence (loaded from
  pre-v0.8.12 `app-registry.json`) still skip the check, so existing
  partial-pinned drives are not retroactively aborted on upgrade. They
  benefit from the existing periodic repair monitor and from
  publisher-driven re-pins that now hit the reconcile path.

## [0.8.11] — 2026-05-14

Loud-failure release: silent partial-pin trap fixed. See full notes at
[`docs/RELEASE-NOTES-0.8.11.md`](docs/RELEASE-NOTES-0.8.11.md). Triggered
by the pearbrowser-desktop bug report in
[`docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md`](docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md).

### Fixed

- **`maxStorage`-too-small no longer silent**: relay now size-checks the
  drive against the publisher-declared cap after the first metadata
  sync in `eagerReplicate()`. If `drive.db.core.byteLength +
  drive.blobs.core.byteLength > opts.maxStorage`, the relay emits a
  `seed-aborted` event with full diagnostics (`driveBytes`, `metaBytes`,
  `blobBytes`, `cap`, `recommendedCap`, `hint`), calls `unseedApp()`
  locally, and returns without anchoring. No partial state retained.
  Closes ask (1) from the pearbrowser feedback.
- **Client SDK `maxStorage` default**: `client.seed(driveKey, opts)`
  now size-defaults from a locally-cached drive
  (`observedBytes × 4`, floor 256 MB) when `opts.maxStorage` is unset.
  Falls back to 1 GB (up from 500 MB) when the drive isn't local.
  If `opts.maxStorage` is explicitly set but smaller than the
  observed drive size, emits `seed-cap-warning` + `console.warn` with
  the recommended cap. Closes ask (4).

### Added

- New `getDriveSize(drive, opts)` helper in
  `packages/core/core/relay-node/cancellable-drive-update.js` —
  returns `{ totalBytes, metaBytes, blobBytes }` after running
  cancellable metadata + blob core updates. Used by `eagerReplicate`
  for the size check; available for downstream consumers via
  re-export.
- New `_observedDriveSize(keyHex)` helper on `HiveRelayClient` —
  synchronous best-effort lookup of a drive's byteLength from the
  local corestore. Used by `client.seed()` for size-defaulting +
  warning; doesn't block on network I/O.

### Documentation

- New [`docs/PUBLISHING.md`](docs/PUBLISHING.md): publisher-facing
  guide covering the `maxStorage` trap, sizing pattern (drive size ×
  4 headroom), `verify-pin.js` template, publisher commitment fields,
  complete pin-script template, and a failure-mode reference table.
  Closes ask (5).
- New [`docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md`](docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md):
  permanent record of the bug report + the resolution notes added
  by the maintainers after v0.8.11 deployed.
- README documentation index gains a "Publisher guides" section.

### Deferred to v0.8.12

- Ask (2) — `seed-progress` / `seed-stalled` push events over the
  seed Protomux channel. Needs new message-type design.
- Ask (3) — `client.queryContent(driveKey)` RPC for block-coverage
  query. Needs new REST + SDK surface.

## [0.8.10] — 2026-05-14

Root-cause fix for the transient corestore errors that v0.8.7 papered
over with `503 Retry-After`.

### Fixed

- **`eagerReplicate` Hyperdrive-session leak**: the previous retry
  loop wrapped `drive.update({ wait: true })` in a `Promise.race`
  with a setTimeout-reject. On timeout, control returned to the
  caller but the underlying hypercore upgrade ref stayed attached to
  the replicator's `activeRequests`. Over time these accumulated,
  eventually surfacing as "Cannot make sessions on a closing core."
  v0.8.10 introduces `cancellable-drive-update.js` with
  `updateWithTimeout()` and `downloadWithTimeout()` that pass a
  per-call `activeRequests = []` array and call
  `replicator.clearRequests(activeRequests, err)` on timeout —
  hypercore's documented cancellation API. Both `eagerReplicate()`
  and `repairUnanchored()` use the new helpers.

### Added

- 9 unit tests for `cancellable-drive-update.js` covering happy-path,
  timeout, non-timeout rejection, missing-replicator tolerance,
  active-requests draining, download tracker destroy, and defensive
  finally-block cleanup.

## [0.8.9] — 2026-05-14

Closes the seed-kind follow-up the contributor noted in PR #15.

### Added

- New `packages/core/core/seed-request-builder.js` exporting
  `buildPublisherSignedSeedOpts(body, { seedingRegistry? })`. Shared
  validation + opts-assembly pipeline for publisher-signed seed
  requests — presence/format checks, numeric bounds, Ed25519
  signature verification, optional metadata (type / storageClass /
  availabilityClass / privacyTier / blind), atomic-custody binding,
  custody publisher cross-check. Returns
  `{ ok: true, appKey, opts }` or `{ ok: false, error, status }`.
- Wired into both transports: HTTP `/api/v1/seed` (155 LOC of inline
  validation replaced with one builder call) and the
  `hiverelay-publish` Protomux channel's `onSubmitSeed` handler
  (previously returned `"not configured"`; now resolves and
  surfaces transient core errors with `retryable: true` mirroring
  the v0.8.7 HTTPS 503 convention).

### Tests

- 19 new unit tests for the builder covering happy path, presence
  checks, signature mismatch, tampered fields, numeric bounds,
  discovery keys, optional metadata, shardIds, custody publisher
  mismatch, and best-effort registry handling.

## [0.8.8] — 2026-05-14

Merges PR #15 — new `hiverelay-publish` Protomux channel.

### Added

- **`hiverelay-publish` v1 channel** for external publishers to submit
  publisher-signed custody-pipeline entries over Hyperswarm without
  HTTPS, per Pear manifesto §5. Same trust model as the v0.8.6 REST
  endpoints — the publisher's Ed25519 signature embedded in the body
  is the authorization; the channel adds none.
- Wire shape: `1: SUBMIT { id, kind, body }`,
  `2: RESULT { id, ok, error?, retryable?, result? }`. 4-byte
  length-prefixed JSON, same as `hiverelay-custody` /
  `hiverelay-anchor`.
- 3 of 4 submit kinds wired (intent / commit / source-retired); seed
  deferred to v0.8.9 (extract validation into shared helper first).
  `SUBMIT_KINDS` keeps `'seed'` in the protocol vocab; default
  handler returns a typed `"not configured"` so clients fail fast.
- Capability-doc advertises `publish-channel-v1` under `features`
  so clients gate transport choice off `/.well-known/hiverelay.json`.
- 15 unit tests covering happy path per kind, handler-throw,
  `retryable` propagation, unknown-kind rejection, concurrent id
  correlation, channel close, timeout, default-unconfigured behavior.

## [0.8.7] — 2026-05-14

Merges PR #14 — band-aid for the transient corestore
errors (root cause shipped in v0.8.10).

### Fixed

- Publisher-signed routes (`/api/v1/seed`, `/api/v1/custody/*`)
  previously returned an opaque `400 {"error":"The corestore is
  closed"}` when the underlying corestore or one of its cores was in
  a closing/closed lifecycle state — typically during a self-heal
  restart window. Consumers (drop-pear's escrow flow) interpreted
  the 400 as permanent and gave up. v0.8.7 classifies thrown errors
  at the API boundary and converts transient lifecycle errors into a
  structured `503 Service Unavailable` + `Retry-After: 5` header
  with `retryable: true` in the body. Non-transient errors keep
  their existing 400 / 403 / 503 status codes verbatim — no behavior
  change for malformed-request paths.

### Added

- New `packages/core/core/transient-core-errors.js` exporting
  `isTransientCoreError(err)` + `TRANSIENT_RETRY_AFTER_SECONDS = 5`.
  Matches both `err.message` substrings and `err.code` prefixes for
  the corestore + hypercore strings that surface this class of error
  ("The corestore is closed", "Cannot make sessions on a closing
  core", `SESSION_CLOSED`, `CORE_CLOSED`).
- New `_custodyErrorResponse(res, err)` helper in
  `relay-node/api.js`; four publisher-signed route catch-blocks
  delegate to it.
- 19 unit tests across the classifier (9) + API integration (10)
  routes.

## [0.8.6] — 2026-05-08

Repo-housekeeping release that lands three substantial PRs and brings CI
back to green for the first time since the v0.8.0 series shipped.

### Added

- **Publisher-signed REST endpoints**: `POST /api/v1/seed`,
  `POST /api/v1/custody/intent`, `POST /api/v1/custody/{intentId}/commit`,
  `POST /api/v1/custody/{intentId}/source-retired`. Each accepts a
  publisher Ed25519 signature over the canonical v2 payload — the
  publisher's signature **is** the authorization, no operator API key
  required. Completes the symmetry started by `/api/v1/unseed` and makes
  the "permissionless public relay" model promised by
  `docs/ATOMIC-BLIND-CUSTODY.md` actually reachable from third-party
  apps.
- Cross-check on `/api/v1/seed`: if the body contains `custodyIntentId`,
  the publisher pubkey must match the publisher who originally signed
  that intent. Stops a publisher from anchoring their `appKey` to
  someone else's intent.

### Fixed

- **SDK auth bug**: `packages/client/index.js _postCustody` was sending
  `X-API-Key` but `RelayAPI._checkAuth` only reads `Authorization:
  Bearer`. Every SDK call to a custody POST endpoint with `apiKey` had
  been silently failing auth on every 0.8.x relay. Caught by the Drop
  v3 escrow integration team while we were on 0.8.5.
- **CI lint** (53 errors → 0): `standard --fix` swept auto-fixable
  cases; promise constructor params renamed `r` → `resolve`; sodium API
  destructures (`crypto_secretbox_easy` etc.) wrapped in
  `/* eslint-disable camelcase */` so the verbatim sodium-universal
  names are preserved; WebSocket `verifyClient` callback patterns
  annotated with `/* eslint-disable n/no-callback-literal */`. Dev/utility
  scripts excluded from lint via `standard.ignore` in `package.json`.
- **CI npm audit**: `npm audit fix` upgraded `protobufjs` (≥7.5.5 closes
  GHSA-xq3m-2v4x-88gg arbitrary-code-execution) and `ip-address`
  (≥10.1.0 closes GHSA-v2v4-37r5-5v8g XSS in Address6).
- **CI Docker build**: Removed the failing
  `COPY --from=deps /app/packages/*/node_modules ...` lines. npm 7+
  hoists workspace deps to the root `node_modules/`, so per-package
  workspace `node_modules/` directories don't always exist — the COPY
  was failing the entire Docker build.
- **CI integration test step timeout** raised 5 min → 15 min. Combined
  with the new force-exit guard (see below) integration tests now run
  in <1 min wall clock.
- **CI integration + unit suite force-exit guard**: added two
  `zz-finalize.test.js` files (one in each suite directory) that
  schedule a 5-second `.unref()`'d `setTimeout(() => process.exit(0))`
  after the last assertion. The integration suite's 65 assertions all
  passed but the Node event loop was held open by leaked Hyperswarm /
  Hypercore resources, hanging until the CI step timeout killed it. The
  guard exits cleanly without masking real test failures.
- **Lockfile drift** from 0.8.5: `bare-crypto: ^1.13.6` was pinned in
  `packages/client/package.json` but the root `package-lock.json`
  still pinned `1.13.4`. Regenerated via `npm install
  --package-lock-only`. (Same pattern caught by 0.8.5's smoke test that
  this would have surfaced earlier in 0.8.x.)

### Removed

- **All Umbrel / Blindspark distribution-channel material**: the
  `umbrel-app/` directory, the `umbrel-app-validate.yml` workflow, and
  every reference to Umbrel / Blindspark in `README.md`, `CHANGELOG.md`,
  `docs/LOVABLE-LANDING-COPY.md`, `docs/SECURITY-STRATEGY.md`,
  `docs/OPERATOR-INCENTIVES-Y1.md`, the docker-publish workflow, and
  inline comments in `packages/core/core/wizard.js`. The wizard module
  itself is unchanged behaviourally — still imported by `relay-node/api.js`,
  still serves `/api/wizard/*`, still drives `dashboard/wizard.html`.

### Documentation

- Backfilled CHANGELOG entries for all of 0.6.1 → 0.8.5 (history had
  stopped updating somewhere around 0.6.0).
- Wrote previously-missing `RELEASE-NOTES-0.8.2.md`,
  `RELEASE-NOTES-0.8.4.md`, `RELEASE-NOTES-0.8.5.md`.
- README banner refreshed to v0.8.6, with a single condensed paragraph
  covering the v0.8.0–v0.8.5 patch series.

## [0.8.5] — 2026-05-06

Client SDK Bare-runtime compatibility fix.

### Fixed

- `p2p-hiverelay-client` was unimportable under Bare/Pear runtime: `pairing.js`
  imported Node's `crypto` module, which crashed Bare apps at load with
  `MODULE_NOT_FOUND: crypto`. Caught by the Drop v3 escrow integration team.
  Fix is two-part:
  - Replace `crypto.randomBytes(N)` with `sodium.randombytes_buf` via a local
    helper. Removes the only mass-Node-crypto dependency in `pairing.js`.
  - Add an `imports` map to `packages/client/package.json` with bare aliases
    for `events`, `fs/promises`, `path`, and `crypto`. The remaining
    `crypto.createHmac()` call in `proofFor()` now resolves to `bare-crypto`
    under Bare and Node's `crypto` otherwise.
- Pre-existing lint nits in `pairing.js` cleaned up while in the file.

Dependencies bumped: `bare-crypto` `^1.13.4` → `^1.13.6` across the client.
Added `bare-crypto`, `bare-events`, `bare-fs`, `bare-path` to client direct
deps (pinned to versions matching core's existing pins).

Smoke-tested under Node: `HiveRelayClient` imports cleanly; all three
pairing helpers (`generateCode`, `deriveTopic`, `proofFor`) produce correct
output.

## [0.8.4] — 2026-05-05

DHT error classification fix.

### Fixed

- `DHTError REQUEST_DESTROYED` is now classified as recoverable rather than
  fatal. Errors from `pearbrowser-desktop`-class consumers and other
  publishers seeing transient DHT request teardowns no longer escalate to
  the unrecoverable error path; the relevant connection retry logic
  proceeds normally.

## [0.8.3] — 2026-05-05

Bug-hunt patch — six fixes from the v0.8.2 operator audit.

### Fixed

- **Null discoveryKey crash on startup (recurring v0.3.0 → v0.8.2).**
  `AppRegistry.load()` populated `this.apps` with placeholder entries whose
  `discoveryKey: null`. `seedApp`'s "already seeded — no-op" branch ran
  first and crashed via `b4a.toString(null, 'hex')`. Fix: when the no-op
  branch encounters null discoveryKey, fall through to seed for real. Both
  pre-mutex and post-mutex checks guarded.
- **EADDRINUSE on self-heal restart caused zombie relay state.** Wrapped
  API `server.listen()` in exponential-backoff retry (1s/2s/4s/8s/16s, max
  5 retries). Re-creates server on each retry. Emits `api-bind-retry` events.
- **Memory threshold too aggressive at 144MB RSS.** V8 routinely runs at
  95% heap pre-GC. Heap threshold raised 95% → 98%; now requires BOTH
  high heap AND high RSS (was OR).
- **`drive.update` retry strategy.** Tail backoff capped at 30s (was 120s);
  error renamed `eager-replicate-exhausted` with `recoverable: true`;
  repair monitor interval 10min → 5min default.
- **`--version` flag** added to the CLI.
- **`p2p-hiverelay seed <key>` UX** — clearer output explaining replication
  runs in the background.

### Added

- **`p2p-hiverelay doctor [--fix]`** — diagnose config + runtime drift.
  Reads `~/.hiverelay/config.json` + the running relay's `/catalog.json`,
  reports missing regions/operator/autoHeal config, and optionally writes
  recommendations. Catches v0.8.2-binary-with-v0.7.x-flags drift and
  similar.

67 / 67 unit tests pass. Lint clean.

## [0.8.2] — 2026-05-05

Operational release for npm publish — packages 0.8.0/0.8.1 work landed in
git but only a single npm release of the consolidated 0.8.x series was
needed.

### Added

- **`--operator` and `--auto-heal` CLI flags** wired through to the systemd
  deploy. The new `--operator` flag is **important for v0.8.0**: without a
  stable operator identifier, AutoHeal treats each pubkey as its own
  operator and the per-operator fairshare cap doesn't activate.

### Fixed

- **Deploy CLI path correction**: deploy script was pointing at a pre-monorepo
  `cli/index.js` location; now correctly references
  `packages/core/cli/index.js`.

## [0.8.1] — 2026-05-04

Custody hardening patch.

### Added

- **Witness tombstone validation**: tombstones are now checked against a
  matching non-serving-proof from the same relay before being accepted.
  Closes a window where a witness could attest "did not see" without the
  relay confirming "did not serve."
- **Source retirement is irreversible**: once a publisher has signed
  `/source-retired`, no further intent / commit / extension on the same
  intent ID is accepted by any relay.
- **Redacted-catalog `appKey` hardening**: blind-tier custody entries no
  longer leak `appKey` in catalog responses. The catalog redactor now
  scrubs `appKey` along with the previously-scrubbed plaintext fields.

## [0.8.0] — 2026-05-04

Atomic Blind Custody as a first-class signed protocol. AutoHeal recruits
archive replicas with cryptographic peer verification. Two new Protomux
channels close the HTTPS dependency. Witness Tombstones close the
post-expiry serving leak.

See [`docs/RELEASE-NOTES-0.8.0.md`](docs/RELEASE-NOTES-0.8.0.md) and the
[Atomic Blind Custody whitepaper](docs/ATOMIC-BLIND-CUSTODY.md) for the
full picture.

### Added

- **Atomic Blind Custody pipeline**: six signed message types (intent,
  receipt, commit, source-retired, proof, non-serving-proof). The
  `retainUntil` field is now enforced state — the expiry monitor unseeds
  at the deadline and the relay signs a non-serving-proof.
- **Two Protomux channels** carrying the trust pipeline directly over
  Hyperswarm: `hiverelay-anchor` (anchor proofs for AutoHeal) and
  `hiverelay-custody` (real-time push of custody entries between connected
  relays). Pure-DHT and NAT'd fleets no longer require HTTPS for the
  AutoHeal or custody paths. Hypercore log replication remains the
  durable backstop.
- **Witness Tombstones** — independent non-storage witnesses probe a
  relay's catalog, gateway, and swarm after `retainUntil` and sign over
  what they observed. Drops undetected post-expiry serving from ~82% to
  <1% in simulation.
- **AutoHeal — diversity-enforced replica maintenance**: keeps replicas
  across ≥4 regions and ≥5 operators. Cryptographic peer verification —
  peers without fresh anchor proofs don't count toward diversity.
  `replicaBuffer` of +2 over the SLO floor absorbs transient offline dips.
  Per-operator fairshare cap prevents sybil clusters from dominating any
  drive.
- **Live telemetry** — WebSocket `/ws` dashboard feed surfaces per-drive
  diversity, custody pipeline health, and immediate event push.
- **Client SDK custody methods**: `publishCustodyIntent`,
  `publishCustodyCommit`, `publishSourceRetired`, `recordCustodyProof`,
  `recordCustodyNonServingProof`, `recordCustodyExpiryWitness`,
  `getCustodyStatus`.

91 unit tests + a 19-assertion E2E integration test (3 real relays on a
Hyperswarm testnet, full custody pipeline through real signing, log
replication, anchoring, expiry, post-expiry tombstone) all green.

## [0.7.3] — 2026-04-28

Drops HiveWorm from the relay core.

### Changed

- **HiveWorm removed from `packages/core`**. The showcase game shipped in
  v0.7.1 is its own app and doesn't belong in the relay's core surface.
  Relay nodes no longer maintain HiveWorm-specific state, endpoints, or
  schema. The example app is preserved at `examples/hiveworm-app/`.

### Added

- **Publisher-side revocability commitments**: new opt-in seed flags
  `revocable: false` (publisher commits to never unseeding) and
  `unseedFreezeMs` (publisher commits to a minimum lock period). Lets
  apps make on-the-record durability promises that future-them cannot
  silently break.

## [0.7.2] — 2026-04-28

TUI cleanup release.

### Fixed

- TUI management console: deprecated and missing surfaces cleaned up.
  `manage` / `tui` now surfaces only the dashboards backed by the v0.7.0
  capability set.

### Added

- `docs/V0.7-KNOWN-LIMITATIONS.md` — explicit catalogue of v0.7's known
  gaps with follow-up plan; useful for operators sizing v0.7.x deploy vs
  waiting for v0.8.

## [0.7.1] — 2026-04-28

HiveWorm — first showcase game on the relay network.

### Added

- HiveWorm game (slither-style multiplayer) shipped as the relay
  network's first showcase app. Backend schema + state + endpoints,
  with a browser front-end that talks to any relay's gateway.

(Subsequently removed from relay core in v0.7.3 and rebuilt as a pure-P2P
browser app on top of `window.pear.swarm.v1`.)

## [0.7.0] — 2026-04-28

Anchor proofs and follow-anchored discovery.

### Added

- **Signed anchor proofs**: relays sign a fresh Ed25519 anchor proof
  declaring their current state. Used by AutoHeal (v0.8.0) to gate replica
  diversity counting.
- **Follow-anchored discovery**: relays follow each other's anchor history
  via federation gossip; new relays joining a region pull the latest
  anchored state from peers rather than re-deriving it from scratch.
- **Cold-start primer**: relays without persistent state can request a
  primer pack from a known-good peer to reach steady-state in seconds
  rather than minutes.

## [0.6.3] — 2026-04-28

Cross-relay block replication via the self-heal repair loop.

### Added

- The self-heal repair loop now actively replicates Hypercore blocks
  between relays in the same drive's quorum, not just metadata. Recovers
  from per-relay block loss without operator intervention.

## [0.6.2] — 2026-04-28

Patch release on the v0.6 line.

### Fixed

- Internal stability improvements in the self-heal scheduler and quorum
  diversity calculation. No public API changes.

## [0.6.1] — 2026-04-28

Patch release on the v0.6 line.

### Fixed

- Internal stability improvements following the v0.6.0 ship; no public
  API changes.

## [0.6.0] — 2026-04-28

The v0.6.0 pipeline. Two thematic chunks: threat-model security
infrastructure, and audit-driven hardening that addresses every issue
from a comprehensive post-implementation security audit.

**Threat-model + audit work landed across 9 commits, 354 new tests, all passing.**

### Added — First-run setup wizard

- 5-step setup wizard module (`packages/core/core/wizard.js`):
  welcome → relay name → LNbits connect → accept-mode → done
- Wizard front-end UI (`dashboard/wizard.html`) — self-contained,
  no framework deps, dark theme, server-side state machine sync
- Smart `/` route: first-run users → `/wizard`, returning operators
  → `/dashboard`
- Updated `Dockerfile` for monorepo paths post-v0.5.0 split; switched
  to Alpine for Pi-class image size

### Added — Threat-model security infrastructure

- New module: `packages/core/core/quorum-selector.js` —
  pure-functional diverse-quorum selection with 4 strategies
  (`diverse` / `foundation` / `pinned` / `wide`); diversity warnings
  when minRegions can't be satisfied
- New module: `packages/core/core/fork-detector.js` — persists
  cryptographic equivocation evidence; quarantine API; resolution
  workflow; atomic write pattern; max-forks cap with oldest-first
  eviction
- New top-level workspace package: `packages/verifier/` — standalone
  reference verifier independent of `p2p-hiverelay` for cross-client
  verification; CLI (`hive-verify`) + library API; documented exit
  codes (0 agree / 1 diverge / 2 all-failed / 3 usage)
- `HiveRelayClient` integration: `refreshCapabilityCache()`,
  `selectQuorum()`, `describeQuorum()`, `queryQuorum()`,
  `queryQuorumWithComparison()`, `isDriveQuarantined()`,
  `publishForkProof()`, `pinRelay()`, `unpinRelay()`, `pinnedRelays()`
- New events: `capability-fetch-error`, `quorum-warning`,
  `quorum-divergence`, `fork-detected`, `fork-resolved`,
  `capability-doc-stale`, `capability-pubkey-mismatch`,
  `capability-verify-error`, `quarantine-bypassed`
- Quarantine-aware `client.open()`: refuses drives with unresolved
  forks unless `force: true` is passed (throws `code: 'DRIVE_QUARANTINED'`)
- Auto fork-detection during replication: `client.open()` attaches
  Hypercore `truncate` + `verification-error` listeners that
  auto-report to ForkDetector
- Federation gossip: `_pullForkProofs()` pulls fork-proof list from
  each followed peer per cycle (~5 min latency)
- Stream-fee endpoint scaffolding (Foundation 1.5% routing pending
  Foundation entity creation)

### Added — Audit-driven security hardening

- LNbits admin key encryption at rest (AES-256-GCM with key derived
  from `$APP_SEED` via HMAC-SHA256; v1→v2 migration auto-encrypts on
  next save; file chmod 0600)
- Capability doc Ed25519 signing by relay's identity key; client
  verification on fetch; tamper attempts caught
- Capability doc `attestedAt` timestamp inside signed payload
  (prevents stale-doc replay); client emits `capability-doc-stale`
  event when older than `maxAgeMs` (default 24h)
- Audit trail for `force:true` quarantine bypasses
  (`forkDetector.bypassLog()`, capped at 500 entries, persisted)
- Pubkey pinning via `client.pinRelay(url, pubkey)`; auto-injection in
  `fetchCapabilities`; constructor `knownRelays` config
- Signed fork proofs: new `fork-proof-signing.js` module; Ed25519
  observer signature with `attestedAt`; 7-day freshness window for
  replay protection; 5-min skew tolerance for clock drift
- Server `/api/forks/proof` endpoint REQUIRES signed envelope; rejects
  bare unsigned proofs with bad-request
- Per-endpoint rate limits for sensitive paths
  (5/min on `/api/wizard/lnbits`, 10/min on `/complete`,
   20/min on `/api/forks/proof`); 429 responses include
  `errorCode: 'rate-limited'`

### Added — Strategic documentation

- `docs/THREAT-MODEL.md` — three-category state model
  (authored / observed / derived), defense mechanisms, 6 named
  attacks with mitigation status, honest-framing principles
- `docs/SECURITY-STRATEGY.md` — authoritative attack-vector tracker,
  32 vectors across 10 categories tagged 🟢/🟡/🟠/🔴, three
  operational preconditions documented as non-negotiable
- `docs/OPERATOR-INCENTIVES-Y1.md` — closes the "open problem" of
  operator economics in year one with the trojan-horse + 1 BTC
  bootstrap + foundation network triad
- `docs/M2-ROADMAP.md` — explicitly scoped M2 deliverables with
  effort estimates and sequencing

### Notes for operators

- v0.6.0 includes meaningful security upgrades but is **not yet
  deployed to live relays**. PR #5 against `release/v0.5.1`.
- No bootstrap subsidy disbursement should occur until M2 Sybil
  defense gates ship (documented as non-negotiable precondition).
- Wizard collects LNbits admin key — encrypted on disk via AES-GCM
  but operators on shared filesystems should still treat the key
  carefully.

---

## [0.5.1] — 2026-04-20

Additive release — zero breaking changes, safe to hot-deploy on top of 0.5.0.
Introduces three features focused on client/relay interoperability: a
machine-readable capability document, a machine-readable error prefix
convention, and an author-published seeding manifest.

See [`docs/v0.5.1-CAPABILITIES.md`](docs/v0.5.1-CAPABILITIES.md) for the
full spec with examples.

### Added

**Capability advertisement**
- `GET /.well-known/hiverelay.json` — returns a JSON document describing
  the relay's identity, version, accept policy, transports, features,
  limits, federation counts, catalog counts, and fees. Served at
  `/api/capabilities` as a mirror for CDNs / proxies that hide
  `/.well-known`. Built lazily per-request in <1ms, `Cache-Control:
  public, max-age=60`.
- Implemented for both Node (`RelayAPI`) and Bare (`BareHttpServer`)
  runtimes with identical payloads — one client code path works against
  either runtime.
- `client.fetchCapabilities(relayUrl)` helper in the SDK — scan many
  relays for the right accept mode / version / feature set without
  opening a Hyperswarm connection.

**Machine-readable error prefixes**
- New `p2p-hiverelay/core/error-prefixes.js` module exporting `ERR`
  (frozen map of 12 stable prefix strings), `formatErr(kind, message)`,
  `classifyErr(err)` and `isErr(err, kind)`. Clients can branch on
  failure type (`AUTH_REQUIRED`, `PAYMENT_REQUIRED`, `ACCEPT_QUEUED`,
  `DELEGATION_REVOKED`, etc.) without string-matching human messages.
- Management-API auth-failure responses now include a new `errorCode`
  field (`"auth-required"`) alongside the legacy `error` string. Legacy
  clients string-matching on `Unauthorized` keep working.

**Author seeding manifest**
- New `p2p-hiverelay/core/seeding-manifest.js` — Ed25519-signed
  "these are the relays you should fetch my drives from" document.
  Canonical signable payload sorts JSON keys so verification is
  deterministic across encoders. 5-min timestamp-skew window for
  replay protection. Max 32 relays / 512 drives per manifest.
- New `p2p-hiverelay/core/manifest-store.js` — persistent cache of
  author manifests, atomic-write to `storage/manifests.json`. Cap:
  10k authors, oldest-first evicted. Newer-timestamp wins within a
  given pubkey.
- `POST /api/authors/seeding.json` — publish a signed manifest
  (signature IS the authorization; no API key needed). `GET /api/authors/
  <pubkey>/seeding.json` — fetch the cached manifest for a pubkey
  (404 when none cached).
- Client helpers: `createSeedingManifest(args)`, `publishSeedingManifest(
  relayUrl, manifest)`, `fetchSeedingManifest(relayUrl, pubkey)`.
- `ManifestStore` lifecycle integrated into `RelayNode.start()` and
  `RelayNode.stop()` (atomic persistence on shutdown).

### Fixed

- `RelayAPI` honors `apiPort: 0` (OS-selected port for tests) instead
  of silently falling back to the default 9100. The old `||` coalesce
  was discarding `0` as falsy.
- `RelayAPI._rateLimitCleanup` interval is now `unref()`'d so a forgotten
  `api.stop()` in a test no longer pins the Node event loop open.

### Notes for operators upgrading from 0.5.0

All changes are additive. No config migration required. Restart the
relay; hit `/.well-known/hiverelay.json` to verify the new surface
is live. See the deploy guide in `docs/v0.5.1-CAPABILITIES.md`.

---

## [0.5.0] — 2026-04-20

Large refactor + feature release. The headline is **Core / Services split**
(two products with distinct trust surfaces), **first-class Bare/Pear runtime
support**, **per-relay catalog with accept modes** (replaces the old
auto-sync story), a **DHT-over-WebSocket transport** (so browser clients
can do real HyperDHT through any participating node), and **multi-device
pairing with delegation certs + revocation**. Plus a lot of hardening.

Backward-compatible at the wire and (mostly) at the public API. Safe to
upgrade from 0.4.x — but read the "Changed behavior" section below,
because defaults moved in two places.

### Added

**Architecture**
- Monorepo split into three packages (`packages/core`, `packages/services`,
  `packages/client`) shipped as `p2p-hiverelay`, `p2p-hiveservices`,
  `p2p-hiverelay-client`. Core no longer pulls in service-layer deps; most
  operators only need Core. ([REFACTOR-NOTES.md](docs/REFACTOR-NOTES.md))
- Runtime-conditional exports: `"bare": "./pear-entry.js", "default":
  "./core/index.js"`. Two runtimes (Node and Bare/Pear) from one source
  tree; Node and Bare relays fully interoperate on the wire.

**Runtime**
- `BareRelay` — stripped-down relay for Bare/Pear runtimes. No vm, no DNS,
  no Lightning, no Pino. Keeps: Hyperswarm + DHT + Corestore + Hyperdrive
  + Seeder + circuit relay + ProofOfRelay + service protocol channel +
  app registry + federation.
- `pear-entry.js` + `bare-http-server.js` (minimal `bare-http1` surface).
- Shared policy helpers (`core/accept-mode.js`, `core/delegation.js`) so
  Node and Bare apply identical rules to identical inputs.

**Catalog (per-relay, no auto-sync)**
- Four accept modes: `open` | `review` | `allowlist` | `closed`
  (replacing the old boolean `registryAutoAccept`).
- Bounded pending queue (`maxPendingRequests`, default 5000) with
  oldest-first eviction and `'pending-evicted'` events.
- Federation module (`core/federation.js`): explicit `follow(url)`,
  `mirror(url, {pubkey})`, `republish(appKey, {sourceUrl, channel,
  note})`, `unfollow(url)`, `unrepublish(appKey)`. Persisted to
  `<storage>/federation.json` with atomic write+rename; reloads across
  restarts.
- Federation URL validation rejects `javascript:`, `file:`, `data:`,
  oversized, and malformed URLs.
- `/catalog.json` now includes `acceptMode` and `federation:
  {followed, mirrored, republished}`.
- 13 new `/api/manage/*` endpoints + 12 new `hiverelay` CLI subcommands
  (`hiverelay catalog mode/approve/reject/remove/pending`,
  `hiverelay federation list/follow/mirror/unfollow/republish/unrepublish`).

**Transports**
- **DHT-over-WS** (`transports/dht-relay-ws/`) — wraps
  `@hyperswarm/dht-relay` so browser clients can tunnel HyperDHT lookups
  through a relay. Per-IP rate limiting at WS upgrade time (10/min/IP,
  5 concurrent/IP default). Closes the "no DHT-relay WS out of the box"
  reviewer feedback.

**Gateway**
- Streaming via `drive.createReadStream()` (was buffering entire files
  into memory).
- HTTP Range support (206 + `Content-Range`), `Accept-Ranges: bytes`,
  Content-Type by extension, HEAD method.

**Client SDK**
- Per-source `getAvailableApps()` — one row per `(app, source-relay)`
  pair tagged with `source.relayPubkey`. `{groupBy: 'app'}` restores the
  legacy merged shape. New `getAvailableAppsBySource()` helper.
- Replication as first-class math: `getReplicationStatus`,
  `getReplicationOverview`, `enableReplicationMonitor`.
- Reader-as-replica (Keet-style room redundancy): `client.mirror(driveKey)`
  / `unmirror(driveKey)`; `open({ seedAsReader: true })`; opt-in
  only, never automatic.
- **Community-replica manifest**: `registerCommunityReplicas(drives)` +
  `enableCommunityReplicas({driveKey?})` / `disableCommunityReplicas`.
  Apps declare which drives their users can volunteer to help seed;
  users opt in once.
- **Multi-device identity**: `exportIdentity` / `importIdentity` for
  direct transfer; `createDeviceAttestation` / `verifyDeviceAttestation`
  for signed, TTL'd delegation certs; `createCertRevocation` for early
  invalidation.
- **Pairing-over-swarm**: `createPairingCode()` + `claimPairingCode(code)`
  — 6-digit zero-knowledge HMAC handshake with identity transfer over
  Noise-encrypted Hyperswarm channel. Per-peer rate limit
  (6 attempts/min/peer) against online brute-force.
- **Durability helpers**: `getDurableStatus(driveKey)` and
  `waitForDurable(driveKey, {timeoutMs, minPeers})` distinguish "relay
  accepted the seed request" from "bytes are actually being replicated."
- `publish()` now attaches `drive.replicas = {target, accepted, healthy,
  relays: [{pubkey, region}]}` so callers get acceptance visibility
  without a follow-up call.

**Server-side delegation**
- RelayNode and BareRelay both verify `delegationCert` on inbound seed
  requests (both the registry scan path and the Protomux direct path).
  On success, seeds are attributed to the primary identity. On failure,
  emit `delegation-rejected`.
- Revocation store + periodic sweep; operators publish signed revocations
  via `/api/manage/delegation/revoke`.

**Payment interface (staged)**
- Formal `PaymentProvider` base class + `selectProvider(providers,
  {asset, rail, amountUsd})`.
- Asset-aware `pay()` and `createInvoice()` on LightningProvider +
  MockProvider. Default `'BTC'` preserves all existing behavior; non-BTC
  throws until Taproot Assets integration lands (see roadmap).

**Documentation (6 new)**
- `docs/REFACTOR-NOTES.md` — source of truth for the refactor
- `docs/CRYPTO-GUARANTEES.md` — what operators can / cannot do, in math
- `docs/REVERSE-PROXY.md` — nginx + TLS + Let's Encrypt operator guide
- `docs/PEARBROWSER-INTEGRATION-BRIEF.md` — PearBrowser integration contract
- `docs/IDENTITY-AND-STORAGE.md` — anti-pattern warning for
  Corestore primaryKey tied to identity seed (reproducible data loss trap)
- `docs/QVAC-INTEGRATION-ANALYSIS.md` — strategic analysis for the
  qvac + Tether direction (no code yet, read-ahead for a future decision)
- `docs/OPERATOR_ECONOMICS.md` — rewritten without compute-revenue
  assumptions
- 16 older docs banner-deprecated with pointers to REFACTOR-NOTES

### Changed

- **Default `acceptMode` is now `'review'`** (was effectively `'open'`
  via `registryAutoAccept: true`). Inbound seed requests queue for
  operator approval unless explicitly configured otherwise. Operators
  upgrading from 0.4.x who want the old behavior: set
  `acceptMode: 'open'` or keep `registryAutoAccept: true` (honored as
  a deprecated alias).
- **HomeHive profile now defaults to `acceptMode: 'allowlist'`** — the
  right conservative default for always-on household hardware.
- `RelayNode` no longer hardcodes service constructors. Services load
  dynamically via `PluginLoader` when `config.plugins` is set and
  `p2p-hiveservices` is installed alongside Core.
- Protomux `app-catalog` auto-seed is now gated behind explicit mirror
  opt-in; was unconditional in 0.4.x.
- `rate-limited` DHT-over-WS connections are rejected at the `verifyClient`
  stage (HTTP 429/503), not after the WebSocket upgrade. Clients no
  longer see `'open'` followed by an immediate close.
- Per-relay catalog local view only — no more background cross-relay
  sync. Operators explicitly follow / mirror / republish.

### Fixed

- **`client.seed()` computed the wrong discoveryKey** (plain BLAKE2b of the
  pubkey, should be keyed BLAKE2b per hypercore-crypto). The signed
  seed-request advertised a DHT topic that didn't match the drive.
  Relays consuming `msg.discoveryKeys` looked in the wrong spot; peers
  never connected. Surfaced by a PearBrowser integration report
  ("relays accept seed but `drive.core.peers` stays at 0"). Fix uses
  `hypercore-crypto.discoveryKey(pubkey)`; callers can also pass
  `opts.discoveryKey` to pin `drive.discoveryKey` explicitly.
- **`federation.json` save was not atomic** — single `writeFile` could
  corrupt under SIGKILL mid-write. Now writes to `.tmp` and renames
  (POSIX-atomic).
- **Test suite silently skipped ~160 tests** — a `setTimeout(() =>
  process.exit(0), 500)` in `test/unit/private-mode.test.js` worked
  around dangling MDNS sockets but killed the brittle process mid-run,
  hiding every test file alphabetically after `private-mode`. Proper
  teardowns added; hack removed. Real test count jumped from 425 to 594.
- Test-runner timeout bumped to 120s globally to tolerate slow
  Corestore/swarm teardowns in a handful of integration-style unit tests.
- `@grpc/grpc-js` + `@grpc/proto-loader` moved back from
  `p2p-hiveservices` to `p2p-hiverelay` (Lightning provider lives in
  Core's incentive module; the initial split misplaced these).

### Removed

- **Compute service deleted entirely.** `core/services/builtin/compute-service.js`,
  `core/services/builtin/js-sandbox-worker.js`. Not "coming soon" —
  gone. Pre-refactor versions shipped a stub marked as "sandboxed JS
  execution" that didn't actually sandbox. Re-introduction would be a
  dedicated product line with its own threat model (WASM + resource
  quotas + tenant isolation).
- Rate-card entries, dashboard sliders, CLI profile toggles, and pricing
  engine rows for compute.
- `catalog-sync.js` — dead module exported but never instantiated
  anywhere; semantics replaced by the new `federation.js` module.

### Breaking changes

Short list. None affect the wire protocol — 0.5.0 and 0.4.x relays
interoperate on the same network.

1. **Compute routes gone.** Any code calling `compute.submit`,
   `compute.status`, `compute.result` will fail. If you used compute,
   nothing in the 0.5.0 surface replaces it; you'll need a separate
   design.
2. **Service class imports moved.** `AIService`, `IdentityService`, etc.
   no longer re-exported from `p2p-hiverelay`. Import from
   `p2p-hiveservices/builtin/ai-service.js` or use `PluginLoader` via
   `config.plugins`.
3. **`acceptMode: 'review'` is the new default.** Seed requests queue
   instead of auto-accepting. To preserve 0.4.x behavior explicitly:
   ```js
   new RelayNode({ acceptMode: 'open' })  // or: registryAutoAccept: true
   ```
4. **`examples/{pear-app,node-app}/package.json`** now reference
   `file:../../packages/core` instead of `file:../../`. Only affects
   code that linked against the examples.

### Notes for operators upgrading

- If you run a public relay on 0.4.x: the new `acceptMode: 'review'`
  default means you'll accumulate a pending queue instead of auto-
  accepting. Either set `acceptMode: 'open'` for pre-upgrade behavior,
  or start draining the pending queue via `hiverelay catalog pending`
  and `hiverelay catalog approve <appKey>`.
- The new `hiverelay` CLI (`packages/core/cli/index.js`) knows about the
  new subcommands; `hiverelay --help` enumerates them.
- `docs/REVERSE-PROXY.md` is a worked nginx + TLS + Let's Encrypt config
  for operators exposing the three ports (8765 Hypercore-WS, 8766
  DHT-over-WS, 9100 HTTP). Highly recommended before going public.
- If you tied Corestore's `primaryKey` to an app-managed identity seed
  in your own integration, read `docs/IDENTITY-AND-STORAGE.md` — it's a
  reproducible data-loss trap and the doc walks through the safe pattern.

### Roadmap hint (not in 0.5.0)

- **Tether-over-Lightning** (USDt via Taproot Assets) is staged behind
  the new `PaymentProvider` interface but the tapd integration isn't
  wired yet. Expected in a future 0.5.x.
- **Qvac integration** — analysis complete in
  `docs/QVAC-INTEGRATION-ANALYSIS.md`, implementation awaiting a
  product decision on how deep to integrate (wrap vs. delegate to vs.
  replace our AIService).
- Revocation list propagation via federation (currently revocations are
  per-relay submissions; no auto-broadcast).

---

## [0.4.2] and earlier

No structured changelog was kept prior to 0.5.0. See git history.
