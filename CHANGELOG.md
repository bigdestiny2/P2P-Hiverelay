# Changelog

All notable changes to `p2p-hiverelay`, `p2p-hiveservices`,
`p2p-hiverelay-client`, and (from v0.6.0) `p2p-hiverelay-verifier` are
documented here. Dates in YYYY-MM-DD.

The packages are versioned in lockstep.

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
