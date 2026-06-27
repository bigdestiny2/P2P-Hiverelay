> [!NOTE]
> **Living audit roadmap.** This file started as an April 2026 multi-agent
> audit, but the completed/current-state sections below are maintained against
> the current Core3/Blindspark code. For release-store publication status, treat
> the external proof gaps section as authoritative until real upstream evidence
> files exist.
>
> Current agent-facing snapshots: `docs/SHIP-HANDOFF-2026-06-26.md`,
> `docs/CURRENT_STATUS_AUDIT_2026-06-24.md`, and
> `docs/TEST-COMMAND-MATRIX-2026-06-24.md`.

# HiveRelay Audit Roadmap

**Generated:** April 2026 | **Based on:** 6-agent codebase audit (architecture, protocol, security, code quality, performance, alternatives)

---

## Completed (this session)

- [x] **S1** Management API auth — API key via `HIVERELAY_API_KEY` env var or localhost-only fallback
- [x] **S2** Unauthenticated `/unseed` — now requires API key
- [x] **S3** Unauthenticated `/seed` — now requires API key
- [x] **S4** HTTP dispatch `caller: 'api'` → `caller: 'remote'` — blocks `identity.sign` from HTTP
- [x] **S5** Service protocol OOM — 1MB max message size + try/catch on JSON.parse
- [x] **S6** Dashboard XSS — `escapeHtml()` on all user-supplied data in index.html, network.html, leaderboard.html
- [x] **Q1** `_proofOfRelay.destroy()` called on shutdown — prevents timer leak
- [x] **Q2** `chmod 0o600` on `relay-identity.json` — protects secret key
- [x] **Q3** Error message leak — catch-all returns generic "Internal server error"
- [x] **1.1** Unseed replay protection — signature-based dedup with 6-min eviction
- [x] **1.2** Legacy unseed rejection — NO_PUBLISHER_KEY error when no publisher recorded
- [x] **1.3** Catalog sync rate limiting — max 10 apps/event, 30s per-peer throttle
- [x] **1.4** Service RPC access control — RESTRICTED_METHODS blocks sensitive methods from P2P
- [x] **1.5** WebSocket dashboard auth — Origin validation + API key token
- [x] **1.6** Content-Type validation — POST must be application/json
- [x] **1.7** Config update bounds — per-field min/max validation
- [x] **2.1** Gateway shared Corestore — eliminates duplicate P2P stack (~30-50MB savings)
- [x] **2.2** Gateway file streaming — non-HTML files streamed instead of buffered
- [x] **2.3** DriveCache reduced — default 50 → 20
- [x] **2.4** Catalog broadcast debounce — 5s window prevents burst on startup
- [x] **2.6** AppRegistry save debounce — 5s timer with flush() for shutdown
- [x] **2.7** Circuit relay pending-connect bounds — rejects at capacity
- [x] **2.8** BandwidthReceipt nonce eviction — O(1) time-bucketed
- [x] **2.5** Delta app-catalog sync — full catalog on connect, signed added-entry deltas on live churn
- [x] **2.9** AutoHeal capacity fail-closed — archive recruitment now refuses to self-recruit when seeder accounting or a positive maxStorageBytes cap is unavailable
- [x] **3.4** Shared constants module — discovery topics, protocol names, hex validation, version compare, uint64 helper centralized
- [x] **3.5a** Shared JSON Protomux framing — service, anchor, custody, publish, and registry meta channels use one bounded JSON encoder with outbound, malformed-frame, and invalid-state guards
- [x] **3.5b** Client pairing compact-string JSON framing — pair setup frames reject oversized outbound messages before allocation and oversized/malformed/truncated/invalid inbound frames before JSON parse throws
- [x] **3.5c** Forward relay shared compact encodings — client and server use exported forward open/data/status/close encoders with data/status caps and malformed/truncated/invalid-state no-throw decode behavior
- [x] **3.5d** Circuit relay shared compact encodings — client and server use exported circuit connect/data/status/ready/close encoders with data/status caps and malformed/truncated/invalid-state no-throw decode behavior
- [x] **3.5e** Seed request compact encodings — seed request/accept/deny/unseed messages cap discovery-key arrays and variable strings, reject invalid outbound fields before allocation growth, and surface malformed inbound frames as protocol errors through relay/client handlers
- [x] **4.4** Unseed verification coverage — valid/stale/future/wrong-publisher/invalid-signature/malformed-timestamp cases
- [x] **4.5** Custody witness route body handling — management witness POSTs reuse the already parsed JSON body, validate intent ids at the HTTP boundary, and cannot hang on a second body read
- [x] **4.6** Durable live service disable — `/api/manage/services` persists configured plugin removal before unregistering live providers and rejects bundle dependency disables that would be re-added on restart
- [x] **4.7** Live-fleet package convergence proof — `fleet-rollout-evidence.json` now requires each relay's checked-out `package.json` version to match the promoted tag before status can be `verified`, and release/handoff verifiers reject missing or false package-version match fields
- [x] **4.8** Release image manifest platform proof — `release-image-manifest-evidence.json` now records and verifies the pinned GHCR digest's `linux/amd64` and `linux/arm64` platform manifests before release packages or reviewer handoff evidence can pass
- [x] **4.9** Handoff sidecar chronology — final handoff verification now enforces the release workflow's sidecar order: StartOS registry evidence must not be generated after `release-evidence.json`, official Umbrel PR evidence must not predate `release-evidence.json`, and optional real Umbrel runtime-review evidence must not predate either the release certificate or official PR handoff.
- [x] **4.10** Management JSON body shape — shared API body parsing now rejects top-level JSON arrays and primitives before route handlers run, returning a stable `JSON body must be an object` 400 without mutating service/config state.
- [x] **4.11** Review-ready Umbrel handoff gate — `release:verify-review-ready-handoff` now fails unless the real-device Umbrel setup/add-wallet/service-management runtime-review sidecar is present and valid, while the automated draft-PR release path can still stop at the pending-review marker.
- [x] **4.12** First-pass StartOS registry chronology — `release:verify-evidence` now requires the downloaded `startos-registry-evidence.json` to carry a valid `generatedAt` timestamp no later than `release-evidence.json`, matching the workflow order protected by the final handoff verifier.
- [x] **4.13** Fleet rollout identity proof — `fleet:check-rollout` now rejects duplicate selected relay names before probing or writing `fleet-rollout-evidence.json`, so public rollout sidecars cannot contain ambiguous per-relay identity evidence.
- [x] **4.14** Evidence-writer envelope proof — release, official Umbrel PR, StartOS registry, and Umbrel runtime-review evidence writers now validate their own top-level schema/version/status and ISO `generatedAt` fields before writing sidecars, keeping writer output aligned with downstream release and handoff verifiers.
- [x] **4.15** Image-manifest chronology — release and final handoff verifiers now reject `release-image-manifest-evidence.json` generated after `release-evidence.json`, matching the existing smoke-sidecar chronology gate for the pinned multi-arch image proof.
- [x] **4.16** Image-manifest platform uniqueness — the release image manifest checker plus release and handoff verifiers now reject duplicate platform rows before accepting multi-arch proof, so each required image platform maps to exactly one digest in public release evidence.
- [x] **4.17** Explicit StartOS evidence paths — `release:verify-evidence` now honors `--startos-registry` when validating the StartOS registry sidecar, so downloaded bundles and manual evidence checks can verify a caller-selected evidence file instead of silently falling back to the canonical relative path.
- [x] **4.18** Release evidence regular-file proof — release and handoff verifiers now reject symlinked or non-regular evidence sidecars before parsing or hashing, matching the existing gallery/image-manifest hardening for downloaded proof bundles and StartOS package artifacts.
- [x] **4.19** Bounded release evidence sidecars — release and handoff verifiers now cap public JSON evidence files at 2 MiB before hashing or parsing, while leaving the larger StartOS package artifact hash path uncapped for legitimate `.s9pk` sizes.
- [x] **4.20** Release writer sidecar preflight — `release:write-evidence` now checks any present public evidence sidecar before writing the release certificate, rejecting symlinked, non-regular, oversized, or hash-drifted JSON files at the source as well as in downstream bundle verification.
- [x] **4.21** Fleet channel hash fallback hardening — when `release:write-evidence` has to compute the fleet channel config hash itself, it now only reads the canonical `fleet/channels.json` from the release workspace and rejects symlinked, non-regular, or oversized metadata before hashing.
- [x] **4.22** StartOS package writer preflight — when `startos/blindspark.s9pk` is present during `release:write-evidence`, the writer now rejects symlinked/non-regular package artifacts and verifies the recorded SHA-256 before writing public release evidence, while keeping package hashing uncapped and streaming for legitimate `.s9pk` sizes.
- [x] **4.23** StartOS registry package preflight — `release:write-startos-registry-evidence` now applies the same present-package guard before writing `startos-registry-evidence.json`, rejecting symlinked/non-regular `.s9pk` artifacts and hash drift at the registry-publication evidence source. Present package hashing is streaming so large `.s9pk` artifacts do not have to be loaded into memory during evidence writing.
- [x] **4.24** Umbrel runtime-review evidence hygiene — `umbrel:write-runtime-review` and `umbrel:verify-runtime-review` now apply the same reserved-host/public-hostname checks used by release evidence URLs, rejecting placeholder or non-public URL values in manual real-device review evidence. The standalone verifier also rejects symlinked, non-regular, or oversized JSON evidence before parsing.
- [x] **4.25** Fleet rollout metadata preflight — `fleet:check-rollout` now rejects symlinked, non-regular, or oversized fleet inventory/channel metadata before selecting relays, hashing channel targets, probing SSH, or writing public rollout evidence.
- [x] **4.26** Pending catalog response schema — `/api/registry/pending` and `/api/manage/catalog/pending` now build responses through a catalog helper that preserves the canonical map key, converts byte publisher keys to hex, filters categories to strings, and omits raw/internal queue fields such as signatures or ad-hoc secrets.
- [x] **4.27** Federation pending queue bounds — federation catalog polling now queues review-mode discoveries through the RelayNode pending-request helper, so followed peers cannot bypass `maxPendingRequests`, duplicate suppression, or `pending-evicted` accounting.
- [x] **4.28** Federation JSON fetch bounds — followed-peer catalog and fork-proof pulls now use a shared bounded JSON fetcher with HTTPS support, `Content-Length` rejection, and a streaming 2 MiB body cap before `JSON.parse`.
- [x] **4.29** Standalone gateway seed hardening — `packages/core/gateway/server.js` now imports the Core3 constants from the correct package path and routes `POST /v1/seed` through bounded JSON parsing, strict `application/json` gating, and exact 64-hex drive-key validation before opening a Hyperdrive.
- [x] **4.30** Network discovery overview fetch bounds — relay discovery API probes now reject non-200 responses, oversized `Content-Length` values, streamed `/api/overview` bodies above 256 KiB, and non-object JSON before accepting live relay metadata.
- [x] **4.31** Network discovery Holesail metadata bounds — the `hiverelay-meta` channel now ignores oversized metadata frames, rejects malformed/non-object JSON and invalid Holesail keys, normalizes URL-prefixed z32 keys, and refuses invalid tunnel keys before constructing Holesail clients.
- [x] **4.32** Seed protocol handshake bounds — `hiverelay-seed` channel handshakes now cap version JSON at 256 bytes, reject malformed or non-object handshakes, close major-version mismatches, and avoid replaying pending seed requests to invalid peers.
- [x] **4.33** Proof response frame bounds — proof-of-relay challenge/response encodings now validate outbound fields before growing encode state, reject malformed/truncated frames without throwing, and cap inbound block/proof buffers before materialization.
- [x] **4.34** Signed directory wire bounds — `hiverelay-signed-directory` now caps record payloads, status strings, and list response counts at the wire decoder, rejects malformed frames without throwing, and slices outbound list responses to the bounded page size.
- [x] **4.35** Public catalog read helper — control-plane `/catalog.json`, legacy `/api/apps` and `/api/drives`, and the dedicated gateway catalog now share bounded query parsing, fail-closed content-type filters, one-pass page/count calculation, and valid-only `catalogBeeKey` advertisement.
- [x] **4.36** Delegation revocation management boundary — `/api/manage/delegation/revoke` now validates `certExpiresAt` before mutation, delegates through `api-delegation-management.js`, and `/api/manage/delegation/revocations` returns a capped, sanitized management payload.
- [x] **4.37** Alert management route boundary — `/api/alerts` and `/api/alerts/test` now delegate through `api-alert-management.js`, validate severity/type filters before log lookup, and bound manual test alert messages/details before dispatch.
- [x] **4.38** Unseed route boundary — `/unseed` and `/api/v1/unseed` now delegate through `api-unseed-actions.js`, validate app keys and signed-unseed timestamps before mutation/verifier calls, and preserve unseed-before-broadcast ordering with direct and HTTP coverage.
- [x] **4.39** Public peer list bounds — legacy `/peers`, Node `/api/peers`, and Bare `/api/peers` now share `api-peer-state.js` with a 1000-entry public cap, total/truncated metadata, malformed peer metadata redaction, and default salted peer-key digests for public metadata minimization.
- [x] **4.40** Registry status read boundary — `/api/registry` now delegates through `api-registry-status.js`, caps active request enrichment at 500 rows, caps per-request relay lists at 100 rows, and returns a shaped operator payload instead of spreading raw registry entries.
- [x] **4.41** README bounded read/status drift guard — the main README and workspace audit guard now explicitly preserve the current `/api/peers` public cap and `/api/registry` bounded, sanitized operator status contract.
- [x] **4.42** Fork-proof read boundary — public `/api/forks/proofs` now delegates through `api-fork-proofs.js`, caps records at 200, caps per-record evidence at 16 entries, caps evidence strings at 8192 bytes, and returns a shaped federation payload instead of raw ForkDetector records.
- [x] **4.43** Reputation read boundary — public `/api/reputation` and `/api/reputation/:pubkey` now delegate through `api-reputation-read.js`, cap leaderboard rows at 100, return shaped public records, and reuse the same sanitizer for `/api/peers` reputation decorations while keeping lookup keys internal when peer IDs are redacted.
- [x] **4.44** Gateway stats read boundary — public embedded `/api/gateway`, dashboard overview gateway summaries, and standalone gateway `/health` now shape gateway counters through `api-gateway-stats.js` instead of spreading raw gateway internals.
- [x] **4.45** Service catalog discovery boundary — public `/api/v1/services` now delegates through `api-service-read.js`, and P2P service catalog ingestion stores/emits entries shaped by `core/services/service-catalog.js` with bounded rows, capabilities, and strings instead of trusting raw peer/provider fields.
- [x] **4.46** Router discovery read boundary — public `/api/v1/router` now delegates through `api-router-read.js`, prefers `router.getStats()` for route counts, and exposes bounded/sanitized pubsub topic metadata instead of raw `routes()` or unbounded topic arrays.
- [x] **4.47** Public status read boundary — public `/status` now delegates through `api-status-read.js`, always calls `getStats({ includeSecrets: false })`, and exposes shaped liveness, transport, service, disk, storage, and accounting aggregates instead of raw node stats or auth-expanded transport/registry fields.
- [x] **4.48** Smoke evidence duplicate-check rejection — release and final handoff verifiers now reject duplicate release-image and Umbrel-package smoke check names instead of silently letting later rows overwrite earlier rows in the verifier map.
- [x] **4.49** Smoke evidence critical-detail validation — release and final handoff verifiers now require the release-image and Umbrel-package smoke sidecars to prove the UI details that matter for Blindspark handoff: in-band dashboard WebSocket auth, review-mode defaults, setup/dashboard token controls, wallet save, app-proxy-safe dashboard writes, bounded lease polling, setup dashboard-link behavior, first/second Umbrel boot review mode, stable identity, and wallet persistence.
- [x] **4.50** Usage telemetry smoke proof validation — release and final handoff verifiers now require the usage telemetry smoke row to carry boolean bandwidth/poker enabled flags and non-negative numeric bandwidth and Poker counters, so release evidence cannot satisfy the telemetry gate with an empty, stringified, or negative-counter row.
- [x] **4.51** Smoke runtime-version proof — release-image smoke now has its `/health.version` checked against the release semver, Umbrel package smoke records first/second boot health versions, and release/final handoff verifiers reject stale runtime-version proof rows before accepting package or reviewer evidence.
- [x] **4.52** Image-manifest-before-smoke chronology — release and final handoff verifiers now return the image-manifest proof timestamp and reject release-image or Umbrel-package smoke sidecars generated before that manifest proof, matching the workflow order where the pinned multi-arch digest is proven before any package smoke can count.
- [x] **4.53** Umbrel runtime-review future timestamp rejection — the standalone real-device Umbrel runtime-review verifier and final release-handoff verifier now reject `generatedAt` values more than five minutes in the future, so manual review sidecars cannot be predated to satisfy later handoff chronology.
- [x] **4.54** Dashboard route decision extraction — dashboard, wizard, root, and Blindspark simple-mode page routing now delegates through `api-dashboard-routes.js` with focused route-contract tests, preserving wizard locality/token-exposure semantics while reducing inline GET dispatcher branching.
- [x] **4.55** Operator telemetry read extraction — `/api/health-detail`, `/api/storage/top`, `/api/auto-heal`, and `/api/history` now delegate payload construction through `api-operator-telemetry.js` with direct coverage for self-heal actions, storage-top counts, AutoHeal disabled/running states, and malformed-safe metrics history.
- [x] **4.56** Wallet payout read extraction — `/api/subsidy` and `/api/subsidy/claim` now delegate through `api-subsidy.js`, preserving disabled/enabled wallet destination payloads while returning stable disabled/unavailable claim errors instead of crashing on malformed subsidy runtime state.
- [x] **4.57** Anchor proof read extraction — `/api/anchors/:appKey/proof` now delegates through `api-anchor-status.js`, rejecting malformed keys before proof generation and returning stable proof-generation errors with direct helper and HTTP-route coverage.
- [x] **4.58** StartOS package verifier streaming — `release:verify-evidence` and `release:verify-handoff-evidence` now stream the unbounded `.s9pk` package hash check while keeping JSON sidecar reads capped, so downloaded release bundles can verify large StartOS packages without whole-artifact memory spikes.
- [x] **4.59** Stable-release credential shape preflight — `release:check-distribution-env` now rejects placeholder or malformed GitHub tokens and private-key secrets before checkout, `gh`, SSH, or StartOS publish steps run, while still allowing multiline private-key blocks for fleet and StartOS credentials.
- [x] **4.60** Stable-release raw-secret validation — `release:check-distribution-env` now validates raw credential values rather than trim-normalized values, so whitespace-padded GitHub tokens, trailing-newline private keys, and newline-injection attempts fail the release gate before GitHub env writes or external distribution steps.
- [x] **4.61** Fleet rollout timeout preflight — full-release distribution preflight now rejects unsafe `FLEET_ROLLOUT_TIMEOUT_MS` values before SSH rollout checks, requiring an integer 10-minute to 4-hour budget without whitespace or control characters so a typo cannot instantly fail or indefinitely stall live fleet promotion.
- [x] **4.62** Fleet rollout probe timing proof — `release:verify-evidence` and `release:verify-handoff-evidence` now require the fleet rollout sidecar to include sane `timeoutMs`, `intervalMs`, and `sshTimeoutMs` probe budgets, so public release or reviewer handoff evidence cannot claim live fleet convergence from an instant or unbounded probe window.
- [x] **4.63** StartOS registry image-proof preflight — `release:write-startos-registry-evidence` now requires the release image manifest and image smoke sidecar paths and SHA-256 values from the release workflow, rejects symlinked/non-regular/oversized linked sidecars, parses them through the public-safety scanner, and hash-checks them before writing registry publication evidence.
- [x] **4.64** Release certificate sidecar hygiene — `release:write-evidence` now parses public JSON evidence sidecars through the same public-safety scanner before minting successful release evidence and hashes those sidecars through the streaming helper, so unsafe, malformed, stale, or oversized sidecars fail before the final release certificate is written.
- [x] **4.65** Umbrel runtime-review PR binding — `umbrel:write-runtime-review`, `umbrel:verify-runtime-review`, and final release-handoff verification now require `umbrel-runtime-review-evidence.json` to carry the upstream `getumbrel/umbrel-apps` PR URL, preventing an otherwise valid manual runtime sidecar from floating free of the reviewer handoff it is supposed to unblock.
- [x] **4.66** Official Umbrel fork preflight — stable-release distribution preflight now rejects `UMBREL_OFFICIAL_FORK=getumbrel/umbrel-apps` before checkout or `gh` calls, so automation cannot accidentally treat the upstream official repository as the writable fork used for draft PR branches.
- [x] **4.67** Official Umbrel evidence fork-owner proof — release evidence writing, official Umbrel PR evidence writing, release evidence verification, and final handoff verification now reject `getumbrel` as the PR head owner, preserving the upstream-vs-fork boundary in public proof bundles as well as in credential preflight.
- [x] **4.68** Service-management snapshot sanitization — authenticated `/api/manage/services` snapshots now cap service rows, method lists, provider stats objects, stats arrays, stats strings, and last-error strings while dropping control-character fields, non-finite numbers, and secret-looking stats keys before the appliance UI renders provider metadata.
- [x] **4.69** Device-management snapshot sanitization — `/api/manage/devices` list responses and authenticated device status snapshots now share a bounded device-list sanitizer that canonicalizes pubkeys, normalizes names, drops invalid rows and extra fields, and returns total/truncated metadata instead of exposing raw allowlist objects to the appliance UI.
- [x] **4.70** Federation-management snapshot sanitization — authenticated `/api/manage/federation` reads now route through a bounded federation snapshot payload builder that caps followed/mirrored relays, republished app rows, peer catalog rows, and per-peer app rows while dropping credential-bearing URLs, control-character labels/notes, invalid keys, and ad-hoc secret fields from remote catalog metadata.
- [x] **4.71** Detailed custody status sanitization — authenticated `?detailed=1` custody status reads now expose shaped operator diagnostics instead of the raw registry status object, preserving PVSS summaries, pending reasons, and public receipt diagnostics while omitting raw intents, commits, proofs, witness bodies, signatures, address keys, ciphertext roots, and share-bundle keys.
- [x] **4.72** Metrics history snapshot sanitization — authenticated `/api/history` still returns chart-friendly history rows, but now caps returned snapshots and emits only known timing, liveness, counter, relay, seeder, served, storage, registry-count, replication, reputation, DHT-over-WS, and disk metrics instead of handing raw in-memory node snapshots to operator clients.
- [x] **4.73** Operator diagnostics snapshot sanitization — authenticated `/api/health-detail`, `/api/storage/top`, and `/api/auto-heal` now cap self-heal action rows, measured storage rows, and AutoHeal drive rows while validating app keys, counters, status strings, regions, operators, thresholds, and backoff fields instead of spreading raw health, storage, or scheduler snapshots into dashboards.
- [x] **4.74** Dashboard WebSocket AutoHeal sanitization — the live dashboard feed now reuses the operator AutoHeal snapshot sanitizer before applying its smaller frame cap, so invalid app keys, control-character regions/operators, backoff details, and ad-hoc scheduler fields cannot leak through the authenticated WebSocket update stream.
- [x] **4.75** Dashboard WebSocket custody aggregate sanitization — the live dashboard feed now emits only bounded custody aggregate counters and a sane `commitRate`, dropping raw intent, receipt, proof, and witness collections even if a future registry snapshot grows beyond the current aggregate shape.
- [x] **4.76** Dashboard WebSocket transport redaction — the live dashboard feed now requests `getStats({ includeSecrets: false })` and shapes Tor/Holesail overview data down to status booleans/counters, so connection keys, onion addresses, local proxies, and API ports are not shipped in every operator WebSocket frame.
- [x] **4.77** Dashboard WebSocket payment/reputation telemetry shaping — payment, credit, metering, invoice, bandwidth, and reputation overview blocks now emit known bounded fields only, cap settlement account rows, sanitize provider labels, and reuse the public reputation leaderboard sanitizer instead of streaming raw manager objects to dashboard clients.
- [x] **4.78** Dashboard WebSocket relay/seeder counter shaping — relay and seeder overview blocks now emit only bounded counters plus the measured served-byte mirror used by dashboards, dropping raw circuit/core collections and malformed capacity values from live frames.
- [x] **4.79** Network discovery detailed-state shaping — `/api/network?detailed=1` and authenticated dashboard WebSocket network frames now share a capped detailed-state sanitizer that preserves operator host/API/Tor/Holesail fields while dropping raw relay internals, malformed counters, and excess relay rows.
- [x] **4.80** HTTP overview payload shaping — public `/api/overview` now emits known relay, seeder, storage, served, bandwidth, registry, and reputation fields only, clamps malformed counters, reuses the public reputation leaderboard sanitizer, and shapes authenticated Tor details so discovery/dashboard clients cannot inherit raw circuit/core/proxy manager internals.
- [x] **4.81** Public health disk-path redaction — `/health` now preserves the fleet rollout contract for version, running state, disk status, and disk-critical 503 responses while omitting storage mount paths and capping disk-monitor error strings so public liveness probes cannot disclose filesystem topology.
- [x] **4.82** Node/Bare anchor aggregate shaping — Node and Bare `/api/anchors` now share the bounded public anchor-status helper so malformed aggregate counts are clamped and future raw scheduler or registry fields cannot leak through either runtime's public anchor endpoint.
- [x] **4.83** Bare catalog pagination parity — Bare `/catalog.json` now reuses the shared relay catalog helper, preserving bounded page/type parsing, bucket/count calculation, relay identity, redacted registry reads, and fail-closed invalid content-type filters across both Node and Bare public catalog endpoints.
- [x] **4.84** Public Prometheus metrics redaction — metrics snapshots, summaries, and `/metrics` exports now request `getStats({ includeSecrets: false })`, clamp every emitted Prometheus sample to a finite non-negative value, route text output through no-sniff/no-store response headers, and unref the snapshot interval so metrics collection cannot leak transport secrets, poison exposition text, be cached by intermediaries, or keep a shutdown process alive by itself.
- [x] **4.85** Legacy catalog type-route bounds — legacy public `/api/apps` and `/api/drives` keep their array response shape for older clients but now pass through the shared catalog page/pageSize parser, cap default and oversized reads at the relay catalog page max, and filter by normalized content type before returning entries.
- [x] **4.86** Public catalog federation snapshot sanitization — public `/catalog.json` now reuses the bounded federation snapshot builder before embedding federation state, preserving followed/mirrored/republished/peer-catalog visibility while dropping credential URLs, raw peer catalog fields, invalid keys, control-character labels, and ad-hoc secret fields from the catalog response.
- [x] **4.87** Public catalog metadata sanitization — public `/catalog.json` now validates relay keys, trims and caps region/operator labels, rejects control-character metadata, and emits only known accept modes so malformed local config cannot poison catalog clients or app-store ingestion.
- [x] **4.88** Hyperdrive gateway error hygiene — public `/v1/hyper/:key/*` JSON responses now share hardened JSON headers, default error bodies to no-store, add no-sniff protection to gateway content, and redact unexpected drive/read/stream exception messages from browser responses while preserving internal diagnostic events.
- [x] **4.89** Standalone gateway seed response hygiene — standalone `/v1/seed` now uses shared hardened JSON responses, keeps validation/body errors public-safe, preserves connection-close behavior for rejected body-bearing media types, and collapses unexpected Corestore/Hyperdrive/swarm failures to a stable `Gateway seed failed` response.
- [x] **4.90** Data-plane gateway JSON response hygiene — the separate `GatewayServer` data-plane now uses the shared JSON writer for rate-limit, URL, health, catalog, 404, and internal-error responses, preserving explicit public caching only for successful catalog reads while giving other JSON responses no-store and no-sniff headers.
- [x] **4.91** Poker HTTP adapter response/body hygiene — public `/api/poker/*` table and move routes now use shared hardened JSON responses, strict `application/json` gating for body-bearing POSTs, bounded shared JSON body parsing, and explicit close hints for rejected media-type or oversized bodies.
- [x] **4.92** Poker HTTP adapter provider-error redaction — standalone-mounted public Poker list/state/log/create/move routes now catch provider exceptions inside the adapter, preserve only fixed client-actionable validation/capacity messages, and collapse unexpected service/storage failures to stable public-safe error bodies.
- [x] **4.93** Poker WebSocket provider-error redaction — public `/api/poker/:table/events` upgrades and post-auth attaches now wrap provider state/subscription lookups, return stable `503`, `state-unavailable`, or `subscribe-failed` signals to clients, and keep raw service/storage exception text only in internal adapter logs.
- [x] **4.94** Generic service RPC error redaction — peer-visible `hiverelay-services` RPC errors now preserve fixed control-plane codes such as `SERVICE_NOT_FOUND`, `ACCESS_DENIED`, and `RATE_LIMITED`, while unexpected provider/router exceptions collapse to `SERVICE_ERROR` and keep raw diagnostics on the internal `request-error` event.
- [x] **4.95** AI/QVAC management provider-error redaction — authenticated `/api/manage/ai/models` list/register/remove keeps fixed `AI_*` and `ACCESS_DENIED` operator errors actionable, but collapses unexpected SDK/provider/storage failures to stable UI-safe messages while retaining raw diagnostics on the internal `ai-model-error` event.
- [x] **4.96** Umbrel AI model add UX hardening — the Blindspark service manager now blocks duplicate in-flight `/api/manage/ai/models` writes, disables the model fields/button while adding, focuses missing required fields, and shows inline polite status/error feedback that survives service-section re-renders instead of relying only on transient toasts.
- [x] **4.97** Umbrel setup wizard action lock — the setup wizard now exposes a polite status region and a delegated action-level busy lock so slow relay-name, payout, skip, navigation, and completion requests cannot be double-submitted or appear as silent no-ops while the API is still working.
- [x] **4.98** Release smoke UI-hardening proof — release-image and Umbrel-package smoke now require packaged dashboard/setup HTML to carry wallet, service, restart, AI-model, and setup-wizard busy/status/action-lock contracts; release evidence verification rejects smoke sidecars that omit or falsify those UI-hardening booleans.
- [x] **4.99** Final handoff UI-hardening proof — `release:verify-handoff-evidence` now enforces the same release-image and Umbrel-package smoke UI-hardening fields as `release:verify-evidence`, so downloaded reviewer handoff bundles cannot pass with older dashboard/setup smoke schemas.
- [x] **4.100** Manual Umbrel runtime UI-hardening proof — `umbrel:write-runtime-review`, `umbrel:verify-runtime-review`, and final handoff verification now require real-device evidence for setup action locks, wallet busy state, service action state, restart pending state, and AI model add duplicate-submit prevention before the review-ready handoff gate can pass.
- [x] **4.101** Fleet rollout writer timing proof — `fleet:check-rollout` now refuses to write a `verified` public rollout sidecar when manual probe timing is outside the same sane `timeoutMs`, `intervalMs`, and `sshTimeoutMs` window enforced by release and final handoff verification, so unsafe one-shot timing cannot become public live-fleet proof at the source.
- [x] **4.102** Fleet rollout exact timing parser — `fleet:check-rollout` now accepts `timeoutMs`, `intervalMs`, and `sshTimeoutMs` inputs only as plain positive decimal integers, rejecting whitespace, control characters, fractions, and exponent notation before SSH probing or public evidence writing and without reflecting malformed timing values to stderr.
- [x] **4.103** Official Umbrel raw metadata proof — `release:write-official-umbrel-pr-evidence` now validates raw workflow and PR metadata without trim-normalizing env values, so whitespace-padded run ids, PR URLs, server URLs, head refs, or run attempts fail before the public handoff sidecar is written.
- [x] **4.104** StartOS registry raw metadata proof — `release:write-startos-registry-evidence` now validates raw workflow, registry, package, hash, and linked image-evidence metadata without trim-normalizing env values, so whitespace-padded registry URLs, package ids, package hashes, run ids, server URLs, or evidence paths fail before the public registry sidecar is written.
- [x] **4.105** Release certificate raw metadata proof — `release:write-evidence` now validates raw workflow, release, image, surface, and sidecar metadata without trim-normalizing env values, so whitespace-padded run ids, tag SHAs, server URLs, image digests, registry URLs, PR URLs, or evidence paths fail before the final public release certificate is written.
- [x] **4.106** Prerelease distribution-boundary proof — `release:verify-evidence` and `release:verify-handoff-evidence` now require `release.prerelease` to be a boolean and reject prerelease certificates that carry fleet rollout, official Umbrel PR, community-store, StartOS registry, package id, or registry-evidence facts, so preview releases cannot look partially promoted.
- [x] **4.107** Full-release whole-fleet default proof — `release:prepare`, `release-surfaces.yml`, and standalone `fleet:check-rollout` now default normal release evidence to `channel=both`; `test/unit/prepare-release.test.js` proves an implicit full release bumps both `canary` and `stable`, `test/unit/fleet-rollout-check.test.js` proves an implicit rollout check selects both channels, and `npm run audit:workspace` guards the regression tests plus the main README's high-fidelity Core3 graph.
- [x] **4.108** Validated GitHub secret rotation helper — `release:apply-github-secrets` validates a local env file with the same full-release preflight before writing values to GitHub Secrets through `gh` stdin, rejects prerelease validation mode, and the failed preflight repair path now points operators at helper dry-run/apply steps.
- [x] **4.109** GitHub secret apply failure redaction — `release:apply-github-secrets` now redacts exact stdin secrets, private-key blocks, and GitHub token-shaped values from `gh` failure output before printing, so the emergency release-secret repair path cannot leak credentials through wrapper or CLI error text.
- [x] **4.110** Hermetic release env-file validation — `release:check-distribution-env --env-file` now validates only the candidate file plus explicit CLI release flags, so ambient shell secrets cannot mask a missing env-file entry before operators apply release credentials to GitHub.
- [x] **4.111** Quorum ranking signal hardening — client quorum selection now treats `score` as valid only when it is finite and normalized to `[0, 1]`, and treats `latencyMs` as valid only when it is finite and non-negative. Malformed capability docs cannot win selector ranking with `Infinity`, huge scores, negative latency, or other out-of-contract ranking values.
- [x] **4.112** Router rate-limit bucket cap — service RPC per-route/per-peer token buckets now have a bounded map with stale-bucket pruning before new peer buckets are accepted. A rotating-peer flood cannot grow router memory without bound, and existing buckets remain observable through router stats.
- [x] **4.113** Data-plane gateway rate-limit bucket cap — the dedicated public `GatewayServer` now caps per-IP fixed-window buckets and prunes stale/malformed buckets before admitting a new IP bucket. Reverse-proxy or rotating-IP floods cannot turn the file-serving rate limiter into an unbounded memory sink.
- [x] **4.114** Current ship handoff evidence refresh — the 2026-06-26 handoff now reflects current `main` at the guarded npm-latest consumer commit, including fresh Test and Docker workflow IDs, ecosystem-consumer parity gates with source-marker coverage, the StartOS release-image blocker, and the newest current-main release-distribution preflight failure after the appliance release-readiness merge.
- [x] **4.115** Lease management API durability boundary — `/api/lease` and `/api/lease/config` now route through `api-lease.js`, which sanitizes paid-lease status payloads, counts only live lease-managed registry entries, and uses durable rate persistence before returning success. Persistence failures now roll the live rate back and return a stable `persist-failed` response instead of letting operator UI flows look successful when the write did not land.
- [x] **4.116** Usage telemetry route shadow cleanup — `/api/usage` now preserves payout-eligible `usageLedger` receipts while surfacing dashboard bandwidth telemetry when a bandwidth receipt tracker exists, and `/api/poker/usage` resolves either the running poker service provider or a direct `node.pokerApp` before returning the blind-safe append/seat tally. This removes stale duplicate-route behavior that could make authenticated operator telemetry look empty or unavailable.
- [x] **4.117** PearBrowser HTTPS relay transport alignment — PearBrowser desktop and mobile now declare `bare-https` directly and route relay GET/POST calls through scheme-aware HTTP/HTTPS transports, with mobile unit coverage for default `80`/`443` relay ports. This protects the default public `https://relay-*.p2phiverelay.xyz` gateway paths from silently using plain HTTP defaults.
- [x] **4.118** PearBrowser public ecosystem metadata sync — `pearbrowser.com` has been refreshed to the bundled desktop release metadata (`v0.5.0`, production length `33841`), and `npm run audit:workspace` now guards the public-site hero/spec/manifest values against the desktop README plus the browser relay-transport dependency contract.
- [x] **4.119** Release secret template hardening — `release:write-secret-template` now writes an owner-only local candidate env file outside the repo, refuses repo paths/symlink overwrites/accidental overwrites, and emits placeholders that fail validation until real GitHub, fleet, Umbrel, and StartOS values are pasted. The local validator, GitHub preflight summary, release docs, and ship handoff all point operators at this generated-template repair path before `release:apply-github-secrets`.
- [x] **4.120** Full-release npm latest proof — full `release-surfaces.yml` runs now require `NPM_TOKEN`, publish or confirm immutable tarballs for `p2p-hiverelay`, `p2p-hiverelay-client`, `p2p-hiverelay-verifier`, and `p2p-hiveservices`, verify every npm `latest` dist-tag equals the release semver, and record `surfaces.npmPackages` in release and handoff evidence. This prevents PearBrowser, PearPaste, anonGPT, and other app consumers from following a stale npm `latest` line.

---

## Current External Proof Gaps

These are not code-only tasks. They require evidence from live infrastructure or
external review-controlled stores before the full project goal can be marked
done.

Current masked-value preflight evidence: GitHub Actions run `28297002418` fails
on malformed `UMBREL_STORE_TOKEN`, `UMBREL_OFFICIAL_PR_TOKEN`,
`UMBREL_OFFICIAL_FORK`, missing `NPM_TOKEN`, and malformed
`STARTOS_REGISTRY_URL`. Secret names are present except `NPM_TOKEN`, but GitHub
does not expose values through `gh`; generate a local candidate with
`npm run release:write-secret-template`, validate it, rotate with
`npm run release:apply-github-secrets`, and rerun the preflight before cutting
a full release.

- **Official Umbrel App Store:** the workflow can export the `blindspark/`
  package and open/update a draft `getumbrel/umbrel-apps` PR, but a real
  upstream PR URL, PR state/head evidence, and reviewer handoff artifact must be
  captured before this surface is proven live. The final reviewer handoff should
  use `npm run release:verify-review-ready-handoff` once the real Umbrel
  lifecycle evidence exists.
- **StartOS registry/marketplace:** the workflow can build, verify, upload, and
  publish to a configured StartOS registry, but a real
  `startos-registry-evidence.json` with package URL/id/hash agreement is still
  required as proof of publication. Marketplace/community inclusion remains
  external review-controlled.
- **Live raw fleet convergence:** the code path is present for pull-based,
  health-gated fleet rollout and rollback, but the current release still needs
  authoritative `fleet-rollout-evidence.json` from `npm run fleet:check-rollout`
  or the release workflow before live-fleet convergence is proven. That sidecar
  must prove the target commit, remote package version, live `/health` runtime
  version, health state, inventory digest, and selected relay names.

## Current Remaining Engineering Gaps

- **RelayNode/API decomposition:** `RelayNode` and the management API are much
  better guarded than the original audit snapshot. Pure API auth,
  auth-failure label, validation, request-gate, CORS, dashboard HTML, config
  update, JSON
  body/object-shape, response, rate-limit, service-config, service-management, mode/transport,
  usage-telemetry, overview, anchor-status, network-state, and AI-model helpers have been split into
  `api-alert-management.js`, `api-auth-helpers.js`, `api-auth-failures.js`, `api-validation.js`,
  `api-request.js`, `api-cors.js`, `api-dashboard-html.js`, `api-body.js`,
  `api-config-update.js`, `api-response.js`, `api-rate-limit.js`,
  `api-health.js`, `api-eviction-purge.js`, `api-lifecycle-actions.js`,
  `api-management-snapshots.js`, `api-safe-config.js`,
  `api-service-config.js`, and
  `api-service-management.js`, `api-mode-transport.js`, `api-usage-telemetry.js`,
  `api-device-pairing.js`, `api-delegation-management.js`, `api-dispatch.js`, `api-signed-ingress.js`,
  `api-federation-management.js`, `api-overview.js`,
  `api-operator-telemetry.js`,
  `api-catalog-management.js`, `api-catalog-read.js`, `api-custody-management.js`,
  `api-custody-status.js`, `api-anchor-status.js`,
  `api-network-state.js`, `api-peer-state.js`, `api-fork-proofs.js`, `api-gateway-stats.js`, `api-registry-status.js`,
  `api-service-read.js`,
  `api-router-read.js`,
  `api-reputation-read.js`,
  `api-seed-publish.js`, `api-unseed-actions.js`, `api-ai-models.js`, `api-subsidy.js`, and `api-lease.js`, and
  `api-wizard-actions.js`, and `api-dashboard-routes.js`. The
  validation helper is shared by the management API plus dedicated gateway
  public catalog pagination, bucket/count calculation, content-type filter
  validation, and gateway catalogBeeKey advertisement; the config-update helper owns numeric/operator config
  mutation validation, strict boolean validation, regions/object-shape
  validation, and rollback; the
  service-config helper owns the service catalog,
  bundle expansion, and active-provider payloads; the service-management helper
  owns durable live service disable/restart orchestration and configured
  plugin persistence; the mode/transport helper owns mode override validation,
  strict boolean override validation, nested override object-shape validation,
  and transport toggle rollback; the
  device/pairing helper owns private-mode
  device API validation, known operator-error classification, persistence-error
  separation, and pairing timeout validation; the delegation-management helper
  owns revocation submit expiry validation and bounded sanitized revocation
  list payloads; the dispatch helper owns HTTP
  service dispatch route validation, local-only route denial, and caller role
  mapping; the signed-ingress helper owns author seeding manifest
  fetch/publish plus signed fork-proof publish signature gating, stale conflict
  mapping, and persistence rollback; the federation-management helper
  owns federation action validation, optional trusted metadata shape
  validation/canonicalization, durable save ordering, rollback, bounded
  federation status snapshot sanitization, and federation
  URL error classification; the catalog-management helper owns
  accept-mode, strict legacy auto-accept boolean validation, publisher
  allowlist, catalog approve/reject/remove, and registry-cancel validation
  plus persistence rollback; the custody-management helper owns operator
  custody writes, witness/non-serving proof validation, publisher-signed custody writes,
  null-signer enforcement, and transient-error delegation; the custody-status
  helper owns unauthenticated public custody status redaction, minimal
  receipt attestation fields, shaped authenticated detailed diagnostics, and
  raw proof/intent omission; the
  anchor-status helper owns public aggregate anchor stats, operator-only
  detailed custody-link diagnostics, malformed proof-key rejection, and stable
  unavailable-registry/proof-generation payloads;
  the network-state helper owns public redaction for DHT-discovered relay
  state, detailed host/API/Tor/Holesail metadata behind management auth, and
  dashboard public fallback shaping; the peer-state helper owns bounded public
  peer arrays, total/truncated metadata, and malformed connection metadata
  redaction across Node and Bare HTTP surfaces; the fork-proof helper owns
  bounded public fork-proof records, per-record evidence caps, evidence string
  byte caps, and omission of operator-only notes from federation payloads; the
  registry-status helper owns bounded active-request enrichment, per-request
  relay list caps, and shaped operator registry payloads;
  the seed-publish
  helper owns operator seed metadata/custody validation, immutable request opts,
  opts object-shape validation, publisher-signed seed validation/error
  delegation, registry publish request construction, policy-field validation,
  discovery-key caps, and publish-ready class defaults; the unseed-actions
  helper owns operator unseed validation, publisher-signed unseed HTTP boundary
  validation, verifier delegation, and unseed-before-broadcast ordering; the usage helper is
  shared by Blindspark/API telemetry
  routes; the overview helper owns the operator dashboard accounting payload;
  the operator-telemetry helper owns health-detail, storage-top, AutoHeal, and
  metrics-history payload shaping plus malformed metrics snapshot fallback;
  the AI-model helper owns QVAC registration normalization, nested option shape
  validation, source-id validation, and status decoration; the subsidy helper
  owns Umbrel wallet payout status/claim payload shaping, payout destination
  validation, and rollback orchestration;
  the wizard-actions helper owns first-run setup action dispatch plus
  config/wizard persistence rollback; the dashboard-routes helper owns
  dashboard/wizard/root/simple-mode page routing while preserving wizard
  localhost/token-exposure semantics; the
  health helper owns `/health` runtime version, uptime/running payload, disk
  summaries, and disk-critical drain status for fleet rollout probes; the
  eviction-purge helper owns authenticated operator purge request validation,
  50-key batch caps, per-key errors, and freed-byte aggregation while the
  lower-level eviction manager keeps archive/custody entries sacred; the
  lifecycle-actions helper owns restart/shutdown response payloads, deferred
  stop/start scheduling, restart error events, and clean/unclean
  shutdown-complete signaling; the management-snapshots helper owns service,
  transport, device, pairing, and mode-catalog read payloads while keeping
  pairing tokens out of operator status responses; the safe-config helper owns
  operator-safe persisted config payloads, secret-field omission, and wizard
  config rollback snapshots. The
  API and RelayNode still carry too many write-route responsibilities
  in large modules.
- **Service protocol v2:** service messages now use shared bounded JSON framing
  with malformed-frame guards. A compact-encoding service protocol remains a
  future wire-version change, not a silent in-place refactor.
- **Broader route/fault coverage:** critical API, Umbrel UI, protocol, release,
  and fleet tests now exist. The remaining test work is broadening route-module
  coverage and adding more integration/fault-injection cases, not filling a
  zero-coverage baseline.

---

## Phase 1: Remaining Security (completed)

### 1.1 Unseed replay protection
- **File:** `core/protocol/seed-request.js`
- **Issue:** 5-minute timestamp window has no nonce/dedup — intercepted unseed replayable within window
- **Fix:** Add random nonce to unseed message, maintain seen-nonces set (similar to BandwidthReceipt pattern at `bandwidth-receipt.js:80-82`)
- **Effort:** 2-3 hours

### 1.2 Legacy unseed accepts any signature
- **File:** `packages/core/core/relay-node/index.js:712-717`
- **Issue:** Apps with `publisherPubkey === null` accept any valid Ed25519 signature
- **Fix:** Reject unseed for apps with no recorded publisher. Log a warning suggesting operator backfill publisher keys
- **Effort:** 30 minutes

### 1.3 Catalog sync rate limiting
- **File:** `packages/core/core/relay-node/index.js:343-361`
- **Issue:** Malicious relay can broadcast catalog with thousands of bogus apps, forcing all connected relays to seed them
- **Fix:** Cap at 10 new apps per catalog event per peer. Throttle to max 1 catalog event per peer per 30 seconds
- **Effort:** 1 hour

### 1.4 Service RPC access control
- **File:** `core/services/protocol.js:236-268`
- **Issue:** Any connected peer can call any service method with arbitrary params
- **Fix:** Add per-service access level (public/authenticated/admin). Default sensitive methods (identity.sign, compute.submit) to authenticated
- **Effort:** 3-4 hours

### 1.5 WebSocket dashboard auth
- **File:** `packages/core/core/relay-node/ws-feed.js:32-41`
- **Issue:** No origin validation or auth on WebSocket feed — anyone can get real-time telemetry
- **Fix:** Validate Origin header, optionally require token parameter
- **Effort:** 1 hour

### 1.6 Content-Type validation on POST
- **File:** `packages/core/core/relay-node/api.js:738-762`
- **Issue:** Parses any POST body as JSON regardless of Content-Type — CSRF risk
- **Fix:** Reject requests without `Content-Type: application/json`
- **Effort:** 15 minutes

### 1.7 Config update bounds checking
- **File:** `packages/core/core/relay-node/api.js:770-809`
- **Issue:** `parseInt()` without validation — can set `maxConnections` to 0, negative, or NaN
- **Fix:** Validate all numeric config values are positive integers within sane ranges
- **Effort:** 30 minutes

---

## Phase 2: Performance & Stability (Priority: High — this month)

### 2.1 Gateway duplicate P2P stack
- **File:** `packages/core/gateway/hyper-gateway.js:156-167`
- **Issue:** Gateway creates its own Corestore + Hyperswarm, doubling memory on 512MB boxes
- **Fix:** Share relay's Corestore with a namespace. Pass store reference into HyperGateway constructor
- **Effort:** 3-4 hours
- **Impact:** ~30-50MB memory savings on Utah box
- **STATUS: Done** — `HyperGateway` can reuse the relay Corestore when
  `opts.store` is supplied and falls back to a dedicated store/swarm only for
  standalone compatibility.

### 2.2 Gateway file streaming
- **File:** `packages/core/gateway/hyper-gateway.js:258-290`
- **Issue:** `drive.get()` buffers entire file in memory before sending — 50MB file = 50MB spike
- **Fix:** Replace with `drive.createReadStream()` piped to response. Add Range request support
- **Effort:** 2-3 hours

### 2.3 Reduce DriveCache on small boxes
- **File:** `packages/core/gateway/hyper-gateway.js`
- **Issue:** Default 50 cached drives × ~5-10MB each can blow the memory budget
- **Fix:** Make configurable, default to 10. On boxes < 1GB RAM, auto-set to 5
- **Effort:** 30 minutes

### 2.4 Debounce catalog broadcasts
- **File:** `packages/core/core/relay-node/index.js:339-340`
- **Issue:** Every seed/unseed fires immediate full catalog broadcast to all peers
- **Fix:** 5-second debounce window — rapid changes during startup only trigger one broadcast
- **Effort:** 1 hour
- **STATUS: Done** — relay catalog-change events are debounced and shutdown
  clears the timer/peer throttle state before closing the store.

### 2.5 Delta catalog sync
- **File:** `core/services/protocol.js:159-167`
- **Issue:** Full JSON catalog sent on every exchange — breaks at ~500 apps
- **Fix:** Send diffs (added/removed) over service protocol. Full catalog on initial connect only
- **Effort:** 4-6 hours
- **STATUS: Done for P2P app-catalog broadcasts** — initial channel open still sends a full app catalog; later seed/unseed broadcasts send `MSG_APP_CATALOG_DELTA` with signed additions and remove hints. Relays only act on signed additions; removals update client caches and do not remotely unseed operator content.

### 2.6 AppRegistry save debouncing
- **File:** `core/app-registry.js:306`
- **Issue:** Every mutation (including bytesServed counter) triggers full JSON.stringify + disk write
- **Fix:** Separate hot counters (bytesServed) from cold state. Debounce saves to max once per 5 seconds
- **Effort:** 2 hours

### 2.7 Circuit relay pending-connect bounds
- **File:** `core/protocol/relay-circuit.js:165`
- **Issue:** No cap on pending connects — flood attack grows queue unboundedly
- **Fix:** Check `_maxPendingConnects` before enqueue, reject with error if full
- **Effort:** 30 minutes

### 2.8 BandwidthReceipt nonce eviction
- **File:** `core/protocol/bandwidth-receipt.js:118-130`
- **Issue:** O(n) iteration over 50K nonces during eviction
- **Fix:** Time-bucketed structure (Map of minute-buckets, drop entire old buckets)
- **Effort:** 1-2 hours

### 2.9 AutoHeal capacity fail-closed
- **File:** `packages/core/core/auto-heal.js`
- **Issue:** AutoHeal treated missing seeder accounting or a missing/invalid `maxStorageBytes` cap as unbounded capacity, so a misconfigured archive relay could self-recruit without reliable disk-pressure inputs.
- **Fix:** Replace the unbounded fallback with a fail-closed `storage-capacity-unavailable` skip reason. Archive recruitment still proceeds when production defaults expose positive capacity and seeder accounting, and still emits `storage-full` with capacity facts when the soft margin is reached.
- **STATUS: Done** — `test/unit/auto-heal.test.js` covers normal full-cap refusal, missing seeder accounting, and invalid/missing storage cap behavior.

---

## Phase 3: Architecture Refactoring (Priority: Medium — next month)

### 3.1 Extract RelayNode into composed managers
- **File:** `packages/core/core/relay-node/index.js` (1,233 lines)
- **Issue:** God class with ~30 responsibilities
- **Extract:**
  - `TransportManager` — WebSocket, Tor, Holesail lifecycle
  - `ProtocolManager` — SeedProtocol, CircuitRelay, ProofOfRelay, BandwidthReceipt wiring
  - `AppSeedingManager` — seedApp, unseedApp, eviction, eager replication, manifest indexing
  - `RegistryScanner` — _scanRegistry, approveRequest, rejectRequest
- **Target:** RelayNode under 400 lines, focused on lifecycle orchestration
- **Effort:** 2-3 days

### 3.2 Split API into route modules
- **File:** `packages/core/core/relay-node/api.js` (~3,800 lines before the
  first helper extraction)
- **Issue:** Single large route/lifecycle module with many direct node internals
  references
- **Fix:**
  - Route table: `{ path, method, handler, auth }` array
  - Route modules: `routes/manage.js`, `routes/apps.js`, `routes/registry.js`, `routes/services.js`
  - Node query interface: expose needed state through public getters instead of private field access
- **Effort:** 2-3 days
- **STATUS: Started** — pure bearer/loopback auth helpers, auth-failure route
  label sanitizers, query/numeric validation, POST media-type gating, CORS
  decisions, dashboard HTML token/header hardening, bounded JSON body reading,
  shared Node/Bare hardened JSON response writing, and fixed-window rate limiting have moved to
  `packages/core/core/relay-node/api-auth-helpers.js`,
  `packages/core/core/relay-node/api-auth-failures.js`,
  `packages/core/core/relay-node/api-alert-management.js`,
  `packages/core/core/relay-node/api-validation.js`,
  `packages/core/core/relay-node/api-request.js`,
  `packages/core/core/relay-node/api-cors.js`,
  `packages/core/core/relay-node/api-dashboard-html.js`,
  `packages/core/core/relay-node/api-body.js`,
  `packages/core/core/relay-node/api-config-update.js`,
  `packages/core/core/relay-node/api-response.js`,
  `packages/core/core/relay-node/api-rate-limit.js`, and
  `packages/core/core/relay-node/api-health.js`, and
  `packages/core/core/relay-node/api-eviction-purge.js`, and
  `packages/core/core/relay-node/api-lifecycle-actions.js`, and
  `packages/core/core/relay-node/api-management-snapshots.js`, and
  `packages/core/core/relay-node/api-safe-config.js`, and
  `packages/core/core/relay-node/api-service-config.js`, and
  `packages/core/core/relay-node/api-service-management.js`, and
  `packages/core/core/relay-node/api-mode-transport.js`, and
  `packages/core/core/relay-node/api-device-pairing.js`, and
  `packages/core/core/relay-node/api-delegation-management.js`, and
  `packages/core/core/relay-node/api-dispatch.js`, and
  `packages/core/core/relay-node/api-signed-ingress.js`, and
  `packages/core/core/relay-node/api-federation-management.js`, and
  `packages/core/core/relay-node/api-catalog-management.js`, and
  `packages/core/core/relay-node/api-catalog-read.js`, and
  `packages/core/core/relay-node/api-custody-management.js`, and
  `packages/core/core/relay-node/api-custody-status.js`, and
  `packages/core/core/relay-node/api-anchor-status.js`, and
  `packages/core/core/relay-node/api-network-state.js`, and
  `packages/core/core/relay-node/api-gateway-stats.js`, and
  `packages/core/core/relay-node/api-registry-status.js`, and
  `packages/core/core/relay-node/api-reputation-read.js`, and
  `packages/core/core/relay-node/api-seed-publish.js`, and
  `packages/core/core/relay-node/api-unseed-actions.js`, and
  `packages/core/core/relay-node/api-usage-telemetry.js`, and
  `packages/core/core/relay-node/api-overview.js`, and
  `packages/core/core/relay-node/api-ai-models.js`, and
  `packages/core/core/relay-node/api-subsidy.js`, and
  `packages/core/core/relay-node/api-lease.js`, and
  `packages/core/core/relay-node/api-wizard-actions.js` with direct unit coverage in
  `test/unit/api-auth-helpers.test.js`,
  `test/unit/api-auth-failures.test.js`, `test/unit/api-alert-management.test.js`,
  `test/unit/api-validation.test.js`,
  `test/unit/api-request.test.js`, `test/unit/api-cors.test.js`,
  `test/unit/api-dashboard-html.test.js`, `test/unit/api-body.test.js`,
  `test/unit/api-config-update.test.js`,
  `test/unit/api-response.test.js`, `test/unit/api-rate-limit.test.js`, and
  `test/unit/api-health.test.js`, and
  `test/unit/api-eviction-purge.test.js`, and
  `test/unit/api-lifecycle-actions.test.js`, and
  `test/unit/api-management-snapshots.test.js`, and
  `test/unit/api-safe-config.test.js`, and
  `test/unit/api-service-config-helpers.test.js`, and
  `test/unit/api-service-management.test.js`, and
  `test/unit/api-mode-transport.test.js`, and
  `test/unit/api-device-pairing.test.js`, and
  `test/unit/api-delegation-management.test.js`, and
  `test/unit/api-dispatch.test.js`, and
  `test/unit/api-signed-ingress.test.js`, and
  `test/unit/api-federation-management.test.js`, and
  `test/unit/api-catalog-management.test.js`, and
  `test/unit/api-catalog-read.test.js`, and
  `test/unit/api-custody-management.test.js`, and
  `test/unit/api-custody-status.test.js`, and
  `test/unit/api-anchor-status.test.js`, and
  `test/unit/api-network-state.test.js`, and
  `test/unit/api-gateway-stats.test.js`, and
  `test/unit/api-fork-proofs.test.js`, and
  `test/unit/api-registry-status.test.js`, and
  `test/unit/api-reputation-read.test.js`, and
  `test/unit/api-seed-publish.test.js`, and
  `test/unit/api-unseed-actions.test.js`, and
  `test/unit/api-usage-telemetry.test.js`, and
  `test/unit/api-overview.test.js`, and `test/unit/api-ai-models.test.js`,
  and `test/unit/api-subsidy.test.js`, and `test/unit/api-lease.test.js`, and
  `test/unit/api-wizard-actions.test.js`.
  The management API and dedicated gateway catalog wrappers share the same
  catalog-read and query-clamp helpers, while route behavior remains covered by `api-auth`,
  `api-service-config`, `capability-endpoints`, and `gateway-server` HTTP tests.

### 3.3 Plugin architecture for services
- **File:** `packages/core/core/relay-node/index.js:27-33` (hardcoded imports), `packages/core/core/relay-node/index.js:298-314` (registration)
- **Issue:** All 8 services loaded regardless of operating mode
- **Fix:**
  - New `core/plugin-loader.js` (~100 lines)
  - Config-driven: `config.plugins = ['@hiverelay/ai-service', './my-custom-service']`
  - Built-in services move to `plugins/builtin/` but remain bundled as defaults
  - Operating modes become preset plugin configurations
- **Foundation:** `ServiceProvider` base class already defines the interface — `manifest()`, `start()`, `stop()`
- **Effort:** 1-2 days
- **STATUS: Done** — `packages/core/core/plugin-loader.js` loads built-in and
  configured service providers on demand, expands the `poker` bundle, rejects
  unsafe plugin paths, and is covered by `test/unit/plugin-loader.test.js`.

### 3.4 Shared constants module
- **Issue:** Discovery topic, protocol names, hex validation duplicated 6+ times
- **Fix:** Create `core/constants.js` exporting:
  - `RELAY_DISCOVERY_TOPIC`
  - Protocol names (`'hiverelay-seed'`, `'hiverelay-circuit'`, `'hiverelay-services'`)
  - `isValidHexKey()`
  - `compareVersions()`
  - `uint64ToBuffer()`
- Replace all 6+ duplicate definitions with imports
- **Effort:** 2-3 hours
- **STATUS: Done for current Core3 surfaces** — `packages/core/core/constants.js` exports discovery topics, seed/circuit/forward/services Protomux protocol names, privacy/content/storage/availability normalizers, `isValidHexKey()`, `compareVersions()`, and `uint64ToBuffer()`. The client SDK, seed/circuit/forward/service protocol modules, main CLI, and catalog CLI now import the shared names/helpers instead of carrying local protocol-name or hex-regex definitions.

### 3.5 Share protocol code between client and server
- **File:** `client/index.js` (reimplements seed protocol channel setup)
- **Issue:** Client duplicates server protocol logic instead of importing `SeedProtocol`
- **Fix:** Make `SeedProtocol` usable from both sides, or extract shared `ProtocolChannels` class
- **Effort:** 1-2 days
- **STATUS: JSON framing helper done** — `core/protocol/json-message-encoding.js` now owns the shared bounded JSON encoder for length-prefixed Protomux channels. `ServiceProtocol` exports `serviceMessageEncoding` plus `MAX_SERVICE_MESSAGE_BYTES`, and the client SDK imports that encoding for the `hiverelay-services` channel instead of carrying a local decoder. Anchor proofs, custody push, publisher-submit, and registry meta channels also export named encodings from the same helper with their channel-specific byte caps. This gives service, anchor, custody, publish, and registry meta channels consistent outbound oversize rejection, oversized-frame rejection, and malformed, short-header, truncated JSON, or invalid decoder-state behavior without throwing.
- **STATUS: Forward relay shared encodings done** — `core/protocol/forward-relay.js` now exports forward open/data/status/close compact encodings, and the client SDK plus integration tests import them instead of carrying inline copies. Forward data/status frames are capped before outbound state growth and before inbound decode materializes declared payloads; malformed, truncated, and invalid-state frames decode to protocol error objects.
- **STATUS: Circuit relay shared encodings done** — `core/protocol/relay-circuit.js` now exports circuit connect/data/status/ready/close compact encodings, and the client SDK imports them instead of carrying inline copies. Circuit data/status frames are capped before outbound state growth and before inbound decode materializes declared payloads; malformed, truncated, and invalid-state frames decode to protocol error objects.
- **STATUS: Seed request compact encodings done** — `core/protocol/messages.js` now caps seed discovery-key arrays, seed geo-preference JSON, accept region strings, deny reason/detail strings, and unseed numeric fields before outbound allocation growth. Inbound malformed, oversized-declared, truncated, or invalid-state seed request/accept/deny/unseed frames decode to protocol error objects, and both `SeedProtocol` plus the client SDK ignore those decoded errors without throwing.

---

## Phase 4: Testing (Priority: Medium — ongoing)

### 4.1 HTTP API tests (highest priority gap)
- **Coverage:** Improved. Critical auth/config/wallet/service/publisher-signed
  routes are covered by `test/unit/api-auth.test.js`,
  `test/unit/api-validation.test.js`,
  `test/unit/api-service-config.test.js`, `test/unit/api-publisher-signed.test.js`,
  `test/unit/api-transient-errors.test.js`, `test/unit/api-trustproxy-auth.test.js`,
  `test/unit/api-ui-token.test.js`, and HTTP integration coverage in
  `test/integration/network.test.js`.
- **Remaining target:** keep broadening route coverage as the API is split into
  modules, especially negative-path persistence and rate-limit cases for less
  common management routes.
- **Effort:** ongoing

### 4.2 Protocol layer tests
- **Coverage:** Improved. Seed, circuit, forward, pairing, shared JSON framing,
  service subscriptions, and router behavior now have unit/integration tests
  including `test/unit/seed-protocol-encoding.test.js`,
  `test/unit/circuit-relay-encoding.test.js`,
  `test/unit/forward-relay-encoding.test.js`,
  `test/unit/pairing-protocol.test.js`,
  `test/unit/protocol-json-encoding.test.js`,
  `test/unit/client-service.test.js`, `test/unit/protocol-security.test.js`,
  and `test/integration/forward-relay.test.js`.
- **Remaining target:** expand protocol integration coverage around peer
  churn, mixed-version negotiation, and service protocol v2 migration.
- **Effort:** ongoing

### 4.3 Adversarial testing
- **Coverage:** Improved. Malformed, truncated, oversized, invalid-state,
  spoofed-signature, unsafe-public-value, and rate-limit paths now have coverage
  across protocol, API, release-evidence, fleet-shell, and Umbrel UI tests,
  including `test/unit/release-evidence.test.js`,
  `test/unit/fleet-shell-safety.test.js`, and
  `test/unit/umbrel-ui-controls.test.js`.
- **Remaining target:** add more multi-peer fault-injection tests for live fleet
  behaviors, service restarts, and mixed relay versions.
- **Effort:** ongoing

### 4.4 Unseed verification tests
- **STATUS: Done** — `test/unit/unseed-verify.test.js` covers valid signatures, invalid signatures, stale/future timestamps, wrong publishers, missing publisher keys, missing apps, malformed hex/key/signature inputs, and malformed timestamps.
- **Hardening added:** `verifyUnseedRequest()` now requires `Number.isSafeInteger(timestamp)` and rejects negative timestamps before building the signed payload, so fractional/unsafe timestamps return `MALFORMED_REQUEST` instead of reaching `BigInt()`.
- **Residual:** The signed unseed protocol still relies on replay dedup and freshness windows documented in Phase 1; keep future nonce/window changes covered by this test file.

### 4.5 Custody witness route body handling
- **STATUS: Done** — `POST /api/custody/:intentId/witness` now uses the JSON body already parsed by the generic POST dispatcher instead of trying to read the request stream a second time.
- **Hardening added:** the route rejects malformed non-hex intent ids before touching `seedingRegistry.recordCustodyExpiryWitness()`, matching the commit/source-retired/non-serving-proof custody routes.
- **Coverage:** `test/unit/api-service-config.test.js` includes a regression that proves invalid ids do not reach the registry and valid witness requests call the registry exactly once with the parsed payload plus `intentId`.

### 4.6 Durable live service disable
- **STATUS: Done** — `POST /api/manage/services` with `action: "disable"` now removes configured built-in service names from `config.plugins`, persists the config, and only then unregisters the live provider.
- **Hardening added:** persistence failures roll back the plugin list and do not unregister the live service. Bundle dependencies, such as disabling `vrf` while `poker` is configured, return `409` with guidance to use `/api/manage/services/config` so the dependency cannot silently reappear after restart.
- **Coverage:** `test/unit/api-service-config.test.js` covers durable disable success, persistence rollback before unregister, and configured bundle dependency rejection. `test/unit/api-service-config-helpers.test.js` directly covers built-in normalization, bundle expansion, active provider payloads, and bundle-parent dependency lookup.

---

## Phase 5: Future Architecture (Priority: Low — when needed)

### 5.1 Lightweight service supervision
- Replace `SelfHeal` with per-service restart capability
- Add `restart(serviceName)` to ServiceRegistry
- Wrap each `dispatch()` in try/catch that marks failed services and triggers restart
- **Depends on:** 3.3 (plugin architecture)

### 5.2 Federated reputation
- Shared Hypercore for relay reputation scores (gossip-based)
- Each relay appends proof-of-relay results to shared core
- Others replicate and merge scores
- **Foundation:** `SeedingRegistry` already uses shared Hypercore pattern

### 5.3 Fix proof-of-relay Merkle verification
- **File:** `core/protocol/proof-of-relay.js:367-399`
- **Issue:** Custom Merkle verifier incompatible with Hypercore's flat tree layout — never succeeds
- **Fix:** Integrate with Hypercore's `core.audit()` or remove the custom verifier
- **Depends on:** Hypercore API stability
- **STATUS: Resolved** — custom Merkle verification was removed. Proof-of-relay now verifies nonce, core/index, latency, data presence, bounded block size, and a nonce-keyed block hash when the challenger already has the block; Hypercore replication remains responsible for flat-tree integrity. Pending challenge state is capped by `proofMaxPendingChallenges`, and batches are capped by `proofMaxBatchSize`.

### 5.4 Service protocol migration to compact-encoding
- **File:** `core/services/protocol.js:62-78`
- **Issue:** JSON over Protomux with redundant length prefix — acknowledged in code comments
- **Fix:** Define proper compact-encoding message types
- **Effort:** 4-6 hours (breaking protocol change — needs version negotiation)

---

## Dependency Cleanup

| Item | Effort | Impact |
|------|--------|--------|
| Retain `@grpc/grpc-js` + `@grpc/proto-loader` for the optional LND `LightningProvider`; keep them dynamically imported so normal relay startup stays lazy | Audited | Avoids breaking Lightning payments while preserving lazy startup |
| Lazy-load `@inquirer/prompts` for interactive setup/manage TUI modules | Audited | Faster non-interactive CLI imports/startup |
| Keep `@noble/secp256k1` + `@noble/hashes` in core for PVSS blind custody; retain `@noble/curves` in core for Cashu NUT-00 BDHKE blind-mint secp256k1 field/point arithmetic; leave Ed25519 VRF/poker curve usage in `p2p-hiveservices` | Audited | Preserves PVSS, Cashu interop, and service-curve ownership without carrying unaccounted crypto dependencies |
| Read StartOS package build version from root `package.json` instead of hardcoding it in `startos/Makefile` | Audited | Fewer release-version drift surfaces |
| Copy a committed LF-pinned Docker entrypoint and honor `HIVERELAY_STORAGE=/data` by default | Audited | Prevents remote builders from dropping the entrypoint and keeps container stores on the mounted data volume |

---

## Architecture Decision Record

**Recommended long-term architecture:** Hybrid approach

1. **Plugin system** — convert hardcoded services to config-driven (lowest risk, highest value)
2. **Lightweight supervision** — per-service restart without full actor model
3. **Federated reputation** — shared Hypercore for scores (not credits)
4. **Selective isolation** — worker threads for AI inference only

**What NOT to change:**
- Protomux multiplexing over single connections
- DHT-based discovery (no central registry)
- Dual transport (P2P + HTTP) through unified Router
- Atomic disk persistence with write-coalescing
- Single-process deployment model (critical for home operators)
