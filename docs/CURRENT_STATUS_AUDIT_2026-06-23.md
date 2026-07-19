# Hiverelay Current Status Audit

Generated: 2026-06-23
Loop candidate: `hiverelay-status-audit`
Autonomy level: Level 1 status artifact
Source root: `~/pear-ecosystem/00-core/hiverelay`

## Executive Status

Hiverelay appears to be in a late hardening and external-proof phase, not an early architecture phase. The current source evidence says Core3 security and reliability hardening is substantially complete, the threat model is explicit, and the Umbrel package is close to official submission shape. The remaining highest-value work is mostly proof collection, release evidence, and a few named engineering cleanup tracks.

This note is the current source-backed status surface for the next agent loop.
Keep it aligned with live release evidence, proof artifacts, and the audit
roadmap.

## Latest Local Update

- The root README now explains the Core3/Blindspark/live-fleet architecture,
  schemas/contracts, API surfaces, SDK verification, use cases, release
  evidence, and store-review caveats. It intentionally stays version-managed by
  `npm run release:prepare`; do not publish an unsynchronized local status line
  over the live GitHub `main` `0.20.0` surface without a synchronized release
  prep.
- Dashboard/wizard/root/simple-mode page routing now delegates through
  `api-dashboard-routes.js`, with direct tests for the Blindspark simple-mode
  redirects, wizard localhost-or-token gate, and root redirect by wizard
  completion state. This trims another user-facing branch cluster out of
  `api.js` while keeping the Umbrel app-proxy setup path explicit.
- Operator diagnostics now delegate health-detail, storage-top, AutoHeal, and
  metrics-history payload shaping through `api-operator-telemetry.js`. Direct
  tests cover self-heal actions, storage-top count forwarding, AutoHeal disabled
  and running snapshots, and malformed-safe metrics history filtering.
- Wallet payout reads now delegate through `api-subsidy.js` as well as writes:
  `/api/subsidy` and `/api/subsidy/claim` have direct coverage for disabled and
  enabled payout payloads plus stable disabled/unavailable claim errors, keeping
  the Umbrel add-wallet/status path out of the central dispatcher.
- Anchor proof reads now delegate through `api-anchor-status.js` alongside
  anchor status shaping. `/api/anchors/:appKey/proof` rejects malformed keys
  before proof generation and returns stable proof-generation errors with direct
  helper and HTTP route coverage.
- Shared API JSON body parsing now rejects top-level arrays, null, and
  primitives before route modules see them. This keeps management and publisher
  mutations on the documented object-payload contract and returns a stable
  `JSON body must be an object` 400 without changing in-memory service/config
  state.
- Public catalog reads now share `api-catalog-read.js` across the control
  plane and dedicated gateway. `/catalog.json`, `/api/apps`, `/api/drives`, and
  the data-plane gateway catalog keep their existing response shapes while
  using one bounded query parser, fail-closed content-type filter handling,
  one-pass page/count calculation, and valid-only `catalogBeeKey`
  advertisement.
- Delegation revocation management now routes through
  `api-delegation-management.js`. The revoke write path rejects malformed
  `certExpiresAt` before calling `submitRevocation()`, and the revocation list
  path returns a bounded, sanitized management payload instead of raw store
  entries.
- Alert management now routes through `api-alert-management.js`. Alert log
  filters validate severity/type before lookup, and the manual test-alert route
  bounds message/details payloads before dispatching to configured channels.
- Unseed HTTP actions now route through `api-unseed-actions.js`. Operator
  unseed validates app keys before mutation, and publisher-signed unseed
  validates HTTP key/signature/timestamp shape before verifier calls while
  preserving unseed-before-broadcast ordering.
- Public peer list payloads now share `api-peer-state.js` across legacy
  `/peers`, Node `/api/peers`, and Bare `/api/peers`. The helper caps returned
  peer arrays at 1000 entries, reports total/truncated metadata, and redacts
  malformed public keys or connection types into JSON-safe nulls.
- Registry status reads now route through `api-registry-status.js`. `/api/registry`
  caps active request enrichment at 500 rows, caps per-request relay lists at 100
  rows, and returns shaped operator fields instead of spreading raw registry
  entries.
- Public fork-proof reads now route through `api-fork-proofs.js`. `/api/forks/proofs`
  caps records at 200, caps evidence entries at 16 per record, caps evidence
  strings at 8192 bytes, and omits operator-only notes or ad-hoc fields from
  the federation payload.
- Public reputation reads now route through `api-reputation-read.js`. `/api/reputation`
  caps leaderboard rows at 100 and returns shaped public rows, `/api/reputation/:pubkey`
  validates/canonicalizes 64-hex pubkeys and returns shaped records, and `/api/peers`
  reuses the same record sanitizer for reputation decorations.
- Public gateway stats now route through `api-gateway-stats.js`. Embedded
  `/api/gateway`, dashboard overview gateway summaries, and standalone gateway
  `/health` expose only shaped non-negative counters instead of spreading raw
  gateway internals.
- Service discovery catalogs now share `core/services/service-catalog.js`.
  Public `/api/v1/services` delegates through `api-service-read.js`, while P2P
  `hiverelay-services` catalog ingestion stores and emits bounded service rows
  with capped capabilities/descriptions instead of trusting raw peer fields.
- Public router discovery now routes through `api-router-read.js`. `/api/v1/router`
  prefers `router.getStats()` for route counts and returns bounded, sanitized
  pubsub topic metadata with total/truncated counts instead of materializing raw
  route keys or exposing an unbounded topic list.
- Public status reads now route through `api-status-read.js`. `/status` always
  requests `getStats({ includeSecrets: false })` and returns a shaped
  liveness/aggregate payload, so API-key callers cannot expand the public
  status response into raw transport, disk, registry, subsidy, or access-control
  internals.
- Release and final handoff verification now reject duplicate smoke-evidence
  check names for release-image and Umbrel-package smoke sidecars. This keeps a
  malformed bundle from hiding stale wallet/service proof rows behind later
  duplicate names in the verifier's check map.
- Release and final handoff verification now also require critical smoke-proof
  details, not only check names: dashboard WebSocket URL-token rejection plus
  in-band auth/update receipt, release-image dashboard/setup/token affordances,
  review-mode defaults, wallet save, Umbrel first/second boot review mode,
  stable identity, and wallet persistence are all enforced before release or
  reviewer handoff evidence can pass.
- Release and final handoff verification now require the usage telemetry smoke
  row to carry boolean bandwidth/poker enabled flags plus non-negative numeric
  bandwidth and Poker counters, so a release cannot claim telemetry smoke with
  an empty, stringified, or negative-counter proof row.
- Release-image smoke and Umbrel-package smoke now carry runtime-version proof:
  release-image `/health.version` and Umbrel first/second boot health versions
  must match the release semver before release or reviewer handoff evidence can
  pass.
- Release and final handoff verification now enforce
  image-manifest-before-smoke chronology: release-image and Umbrel-package
  smoke sidecars must not predate `release-image-manifest-evidence.json`,
  matching the workflow order where the pinned digest's multi-arch proof is
  established before smoke evidence counts.
- Bare/Pear read-only HTTP JSON now routes CORS and capability-doc cache policy
  through the shared `writeJson()` helper. The regression suite includes a
  minimal response object without `getHeader`, `hasHeader`, or `headers` so
  public capability-doc caching cannot be overwritten by the default
  `no-store` fallback on Bare-shaped responses.
- Security docs now separate shipped guardrails from M2/future work and scope
  confidentiality claims correctly: blind-mode apps and atomic custody payloads
  remain ciphertext to the relay, while public/non-blind app content may be
  readable by the operator and relies on signatures plus availability diversity
  for integrity/resilience.
- Release automation now includes a dedicated
  `release-image-manifest-evidence.json` sidecar. It verifies the exact
  `ghcr.io/bigdestiny2/p2p-hiverelay:<version>@sha256:<digest>` reference is an
  OCI/Docker image index with both `linux/amd64` and `linux/arm64` platform
  manifests before smoke, package, release-evidence, or final handoff evidence
  can pass.
- Official Umbrel handoff evidence now links the image-manifest proof as well
  as image smoke, Umbrel package smoke, fleet rollout, StartOS package, StartOS
  registry package, StartOS registry evidence, and workflow evidence. Final
  handoff verification now also rejects official Umbrel PR handoff sidecars
  whose `generatedAt` timestamp predates `release-evidence.json`.
- StartOS registry publication evidence now links the same image-manifest and
  image-smoke proof sidecars as the release certificate, so registry handoff
  evidence cannot drift away from the exact multi-arch image that was smoked and
  packaged. `release:verify-evidence` and final handoff verification now both
  require the StartOS registry sidecar to carry a valid `generatedAt` timestamp
  no later than the release evidence timestamp, matching the workflow order
  where the release certificate records the registry sidecar hash.
- Raw fleet rollout proof now fails before probing or writing
  `fleet-rollout-evidence.json` when the selected inventory contains duplicate
  relay names, keeping public per-relay convergence evidence unambiguous.
- Release, official Umbrel PR, StartOS registry, and real Umbrel runtime-review
  evidence writers now validate their own top-level schema/status/kind and ISO
  `generatedAt` envelope before writing sidecars, matching the stricter bundle
  verifiers instead of relying on later rejection.
- Release and final handoff verifiers now also require
  `release-image-manifest-evidence.json` to have been generated no later than
  `release-evidence.json`, so the multi-arch image proof has the same
  chronology guarantee as image-smoke and Umbrel-package-smoke sidecars.
- The release image manifest checker, release evidence verifier, and final
  handoff verifier now reject duplicate platform rows in
  `release-image-manifest-evidence.json`, keeping each required multi-arch
  platform bound to one digest instead of accepting ambiguous duplicate labels.
- The release image manifest checker now skips OCI attestation sidecars before
  duplicate-platform checks, matching GHCR's current `0.20.0` index shape where
  runnable `linux/amd64` and `linux/arm64` manifests are accompanied by
  `unknown/unknown` attestation manifests. See
  `docs/RELEASE_IMAGE_MANIFEST_EVIDENCE_2026-06-24.md` for the exact
  `0.20.0` digest proof.
- The published `0.20.0` release image still fails the Docker image smoke on
  dashboard WebSocket in-band auth with HTTP 403. The source tree now allows
  same-origin dashboard WebSockets while keeping cross-origin sockets denied,
  the smoke scripts now send browser-like `Origin` headers, and a rebuilt local
  Docker image passes `npm run release:smoke-image`. See
  `docs/RELEASE_IMAGE_SMOKE_2026-06-24.md`; a new public GHCR digest built from
  the fixed source is required before digest-pinned release smoke evidence can
  turn green.
- `release:verify-evidence` now passes the parsed `--startos-registry` sidecar
  path into StartOS registry verification, with regression coverage for a valid
  explicit sidecar outside the release file's directory.
- Release and final handoff evidence verification now reject symlinked or
  non-regular sidecars before parsing or hashing, keeping downloaded proof
  bundles anchored to real files rather than filesystem indirection.
- Public JSON evidence sidecars are now capped at 2 MiB in both release and
  final handoff verification before hashing or parsing; the StartOS `.s9pk`
  artifact hash path remains uncapped for legitimate package sizes.
- `release:write-evidence` now preflights any present public sidecar before
  writing `release-evidence.json`, rejecting symlinked, non-regular, oversized,
  or hash-drifted JSON evidence files before they can enter the public release
  certificate.
- Its fleet channel config hash fallback is now pinned to the canonical
  `fleet/channels.json` in the release workspace and rejects symlinked,
  non-regular, or oversized metadata before hashing.
- When `startos/blindspark.s9pk` is present, `release:write-evidence` also
  rejects symlinked or non-regular package artifacts and verifies the recorded
  StartOS package SHA-256 before writing public release evidence; the package
  hash path remains uncapped for legitimate `.s9pk` sizes.
- `release:write-startos-registry-evidence` applies the same present-package
  guard before writing registry-publication proof, so `startos-registry-evidence.json`
  cannot be produced over a local symlink, directory, or stale `.s9pk` hash when
  the package artifact is available in the release workspace. The registry
  evidence writer now streams `.s9pk` hashing instead of loading the whole
  package into memory.
- `umbrel:write-runtime-review` and `umbrel:verify-runtime-review` now reject
  placeholder or reserved URL hostnames in public manual review fields,
  aligning real-device Umbrel lifecycle evidence with the stricter public URL
  hygiene used by release and StartOS registry evidence. The standalone and
  final handoff verifiers also reject symlinked, non-regular, oversized, or
  future-dated JSON evidence before accepting the manual review proof.
- `fleet:check-rollout` now rejects symlinked, non-regular, or oversized fleet
  inventory/channel metadata before selecting relays, hashing channel targets,
  probing SSH, or writing public rollout evidence.
- The Umbrel/Blindspark service manager UI was flattened so service cards no
  longer sit inside a second card frame. The Poker preset now tells operators to
  save before applying, and mobile public-key/wallet chips now meet the same
  touch-target rule as the setup and service buttons.
- The Blindspark appliance dashboard now coalesces overview, wizard, and service
  polling, skips automatic refreshes while the tab is hidden, refreshes when the
  operator returns, and queues forced service refreshes behind an in-flight
  service poll so Save/Restart feedback is not swallowed on slow Umbrel boxes.
  Dashboard reads plus wallet/service writes also share a 10 second
  `AbortController` timeout so a hung app-proxy request releases busy UI state.
- The Umbrel gallery validator now rejects symlinked gallery directories and
  proves listed screenshot files resolve back inside that real directory before
  reading dimensions. The release runbook and official submission checklist now
  document the regular-file, non-symlink, bounded-asset expectation for future
  populated gallery handoffs.
- Real Umbrel UI lifecycle review now has a public-safe evidence writer:
  `npm run umbrel:write-runtime-review`, plus a verifier:
  `npm run umbrel:verify-runtime-review`. Together they record and validate the
  required install, app-proxy dashboard, in-band WebSocket auth, setup,
  add-wallet, management, review-mode, `/data`, and reinstall-preserves-key
  checks without publishing local URLs, LAN IPs, APP_SEED, bearer tokens, API
  keys, or raw public keys.
- The official Umbrel PR handoff sidecar now records
  `runtimeReview.status: pending-real-device-review` with the expected runtime
  review evidence filename and verifier command, and the final handoff verifier
  rejects drift. This keeps automated draft-PR proof separate from the later
  real Umbrel UI review proof.
- The final release handoff verifier now also validates
  `umbrel-runtime-review-evidence.json` when that sidecar is present in a
  downloaded bundle, cross-checking it against the release version and upstream
  PR URL, requiring the runtime-review timestamp to be no earlier than both the
  release evidence and official Umbrel PR handoff timestamps, while still
  allowing automated draft releases to pass before real Umbrel review has
  happened. A stricter `--require-umbrel-runtime-review` mode now turns that
  optional check into a final review-ready handoff gate, exposed as
  `npm run release:verify-review-ready-handoff`.
- HTTP API decomposition has started with
  `packages/core/core/relay-node/api-auth-helpers.js` for bearer/loopback auth
  helpers, `packages/core/core/relay-node/api-auth-failures.js` for sanitized
  auth-failure route and Prometheus labels,
  `packages/core/core/relay-node/api-alert-management.js` for bounded alert log
  filters and manual test-alert payload validation,
  `packages/core/core/relay-node/api-validation.js` for query/write validators,
  `packages/core/core/relay-node/api-request.js` for POST media-type gating,
  `packages/core/core/relay-node/api-cors.js` for origin allowlist and public
  Poker CORS decisions,
  `packages/core/core/relay-node/api-dashboard-html.js` for UI-token meta
  injection and dashboard browser-hardening headers,
  `packages/core/core/relay-node/api-dashboard-routes.js` for dashboard,
  wizard, root, and Blindspark simple-mode page routing,
  `packages/core/core/relay-node/api-body.js` for bounded object-only JSON body reads,
  `packages/core/core/relay-node/api-config-update.js` for management config
  write validation, strict boolean validation, regions/nested-object shape
  validation, progressive mutation rollback, and persistence failure rollback,
  `packages/core/core/relay-node/api-response.js` for CORS Vary plus hardened
  JSON response writing, and `packages/core/core/relay-node/api-rate-limit.js`
  for trusted-proxy client IP selection plus fixed-window global/endpoint
  request caps, plus `packages/core/core/relay-node/api-health.js` for fleet
  `/health` response payloads, runtime version, uptime/running fields, disk
  summaries, and disk-critical drain status, plus
  `packages/core/core/relay-node/api-eviction-purge.js` for authenticated
  operator purge request validation, 50-key batch caps, per-key error
  isolation, and freed-byte aggregation, plus
  `packages/core/core/relay-node/api-lifecycle-actions.js` for operator
  restart/shutdown response payloads, deferred stop/start scheduling, restart
  error events, and clean/unclean shutdown completion signals, plus
  `packages/core/core/relay-node/api-management-snapshots.js` for management
  read payloads covering service status, transport status, devices, pairing
  status, and mode catalog responses without leaking private pairing tokens,
  plus
  `packages/core/core/relay-node/api-safe-config.js` for operator-safe
  persisted config payloads, secret-field omission, default management config
  shaping, and wizard config snapshot/restore rollback semantics, plus
  `packages/core/core/relay-node/api-service-config.js` for
  built-in service catalog constants, service-selection normalization,
  service payload shaping, and bundle dependency checks, and
  `packages/core/core/relay-node/api-service-management.js` for durable live
  service disable/restart orchestration, configured plugin persistence, and
  bundle dependency protection, and
  `packages/core/core/relay-node/api-mode-transport.js` for mode override
  validation, strict boolean override validation, nested override object-shape
  validation, applied-mode persistence rollback, transport-name validation, and
  transport-toggle rollback, and
  `packages/core/core/relay-node/api-device-pairing.js` for private-mode device
  API validation, known operator-error classification, persistence-error
  separation, and pairing timeout validation, and
  `packages/core/core/relay-node/api-delegation-management.js` for device
  attestation revocation submit validation and capped/sanitized revocation
  list payloads, and
  `packages/core/core/relay-node/api-dispatch.js` for HTTP service dispatch
  route validation, params object-shape validation, local-only route denial,
  and caller role mapping, and
  `packages/core/core/relay-node/api-signed-ingress.js` for author seeding
  manifest fetch/publish plus signed fork-proof publish signature gating, stale
  conflict handling, and persistence rollback, and
  `packages/core/core/relay-node/api-federation-management.js` for federation
  action validation, optional trusted metadata shape validation/canonicalization,
  durable save ordering, rollback, and federation URL error classification, and
  `packages/core/core/relay-node/api-catalog-management.js` for catalog
  accept-mode, strict legacy auto-accept boolean validation, allowlist,
  approve/reject/remove, and registry-cancel validation plus persistence
  rollback, and
  `packages/core/core/relay-node/api-catalog-read.js` for public catalog
  filtering, bounded pagination, bucket/count calculation, legacy app/drive
  arrays, and gateway `catalogBeeKey` advertisement, and
  `packages/core/core/relay-node/api-service-read.js` plus
  `packages/core/core/services/service-catalog.js` for bounded public and P2P
  service discovery catalogs, service/capability string caps, and raw provider
  field omission, and
  `packages/core/core/relay-node/api-router-read.js` for bounded public router
  discovery, route count reads via stats, and pubsub topic count/truncation
  metadata, and
  `packages/core/core/relay-node/api-status-read.js` for bounded public status
  summaries, no auth-expanded raw stats, and transport/disk/registry field
  shaping, and
  `packages/core/core/relay-node/api-custody-management.js` for operator
  custody writes, custody witness/non-serving proof validation, publisher-signed
  custody writes, null-signer enforcement, and transient-error delegation, and
  `packages/core/core/relay-node/api-custody-status.js` for public custody
  status redaction, minimal receipt attestation fields, detailed-view auth
  separation, and stable redacted defaults, and
  `packages/core/core/relay-node/api-anchor-status.js` for public aggregate
  anchor stats, management-auth-gated detailed custody-link diagnostics, and
  stable unavailable-registry plus proof-generation payloads, and
  `packages/core/core/relay-node/api-network-state.js` for public redaction of
  DHT-discovered relay network state, detailed host/API/Tor/Holesail metadata
  behind management auth, and dashboard fallback shaping, and
  `packages/core/core/relay-node/api-gateway-stats.js` for public embedded and
  standalone gateway counter shaping without raw gateway internals, and
  `packages/core/core/relay-node/api-peer-state.js` for bounded public peer
  arrays, total/truncated metadata, and malformed peer metadata redaction across
  Node and Bare HTTP surfaces, and
  `packages/core/core/relay-node/api-fork-proofs.js` for bounded public
  fork-proof records, per-record evidence caps, evidence string byte caps, and
  omission of operator-only notes from federation payloads, and
  `packages/core/core/relay-node/api-registry-status.js` for bounded
  active-request enrichment, per-request relay list caps, and shaped operator
  registry status payloads, and
  `packages/core/core/relay-node/api-reputation-read.js` for bounded public
  reputation leaderboards, sanitized public reputation records, and shared
  peer-state reputation decoration shaping, and
  `packages/core/core/relay-node/api-seed-publish.js` for operator seed
  metadata/custody validation, request option normalization, immutable opts
  handling, opts object-shape validation, publisher-signed seed
  validation/error delegation, registry publish request construction, and
  registry policy-field validation, and
  `packages/core/core/relay-node/api-unseed-actions.js` for operator unseed
  validation, publisher-signed unseed HTTP boundary validation, verifier
  delegation, mutation, and P2P broadcast ordering, and
  `packages/core/core/relay-node/api-usage-telemetry.js` for verified receipt
  aggregation, measured served-byte payloads, and Poker usage rollups, and
  `packages/core/core/relay-node/api-overview.js` for operator overview uptime,
  honest storage/served-byte accounting, seeder mirroring, and optional
  reputation/bandwidth/registry summaries, and
  `packages/core/core/relay-node/api-operator-telemetry.js` for health-detail,
  storage-top, AutoHeal, and metrics-history payload shaping with malformed
  snapshot filtering, and
  `packages/core/core/relay-node/api-ai-models.js` for QVAC model registration
  normalization, nested option object-shape validation, source-id string
  validation, and model status decoration, and
  `packages/core/core/relay-node/api-subsidy.js` for Umbrel wallet payout
  status/claim payload shaping, destination validation, plus
  config/wizard/subsidy rollback semantics, and
  `packages/core/core/relay-node/api-wizard-actions.js` for first-run setup
  action dispatch, config apply, config persistence, wizard persistence, and
  rollback semantics. Dashboard route decisions are now covered by
  `test/unit/api-dashboard-routes.test.js`, and operator telemetry reads by
  `test/unit/api-operator-telemetry.test.js`. The management routes and
  dedicated gateway still delegate through their previous private names, sharing catalog/read-path clamp
  behavior while direct helper tests cover auth, auth-failure labels, validator,
  request-gate, CORS, dashboard HTML hardening, stream-body, config-update,
  response-header, rate-limit, health, eviction-purge, lifecycle-actions,
  management-snapshots, safe-config, service-config, service-management,
  service-read, router-read,
  mode/transport, device/pairing, dispatch params-shape, signed-ingress, federation-management, catalog-management,
  custody-management, custody-status, anchor-status, network-state, peer-state, registry-status, seed/publish, unseed, usage-telemetry, overview, AI/QVAC model, subsidy, and
  wallet/setup persistence semantics.
- Local verification for this slice passed:
  `./node_modules/.bin/brittle test/unit/release-evidence.test.js
  test/unit/release-evidence-verify.test.js
  test/unit/release-handoff-evidence-verify.test.js
  test/unit/release-image-manifest-check.test.js
  test/unit/official-umbrel-pr-evidence.test.js` (114 tests / 459 asserts),
  `./node_modules/.bin/brittle test/unit/startos-registry-evidence.test.js
  test/unit/release-evidence-verify.test.js
  test/unit/release-handoff-evidence-verify.test.js` (93 tests / 281 asserts),
  `./node_modules/.bin/brittle test/unit/umbrel-ui-controls.test.js` (17 tests
  / 123 asserts), `./node_modules/.bin/brittle
  test/unit/umbrel-gallery-check.test.js` (8 tests / 16 asserts),
  `./node_modules/.bin/brittle
  test/unit/umbrel-runtime-review-evidence.test.js` (5 tests / 24 asserts),
  `./node_modules/.bin/brittle
  test/unit/umbrel-runtime-review-verify.test.js` (5 tests / 20 asserts),
  `./node_modules/.bin/brittle test/unit/official-umbrel-pr-evidence.test.js
  test/unit/release-handoff-evidence-verify.test.js` (56 tests / 215 asserts),
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/release-handoff-evidence-verify.test.js
  test/unit/umbrel-runtime-review-verify.test.js
  test/unit/official-umbrel-pr-evidence.test.js` (65 tests / 256 asserts),
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/release-handoff-evidence-verify.test.js
  test/unit/startos-registry-evidence.test.js
  test/unit/official-umbrel-pr-evidence.test.js` (71 tests / 278 asserts),
  `node scripts/audit-workspace-alignment.mjs` with explicit sidecar
  chronology sentinels for official Umbrel PR, StartOS registry, and optional
  Umbrel runtime-review handoff evidence,
  `./node_modules/.bin/brittle
  test/unit/api-service-config-helpers.test.js
  test/unit/api-service-config.test.js test/unit/plugin-loader.test.js` (43
  tests / 308 asserts),
  `./node_modules/.bin/brittle test/unit/api-usage-telemetry.test.js
  test/unit/api-alert-management.test.js test/unit/api-auth.test.js
  test/unit/umbrel-ui-controls.test.js`,
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/api-peer-state.test.js test/unit/api-auth.test.js` (49 tests /
  271 asserts),
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/api-registry-status.test.js test/unit/api-auth.test.js` (48 tests /
  280 asserts),
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/api-fork-proofs.test.js test/unit/api-auth.test.js` (50 tests /
  287 asserts),
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/api-reputation-read.test.js test/unit/api-peer-state.test.js
  test/unit/api-auth.test.js` (58 tests / 327 asserts),
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/api-gateway-stats.test.js test/unit/api-auth.test.js
  test/unit/gateway-standalone-server.test.js test/unit/api-overview.test.js`
  (60 tests / 339 asserts),
  `./node_modules/.bin/brittle --timeout 120000
  test/unit/api-unseed-actions.test.js test/unit/api-auth.test.js` (46 tests /
  263 asserts),
  `./node_modules/.bin/brittle test/unit/api-overview.test.js
  test/unit/api-auth.test.js test/unit/status-secrets-redaction.test.js` (42
  tests / 194 asserts),
  `./node_modules/.bin/brittle test/unit/api-ai-models.test.js
  test/unit/api-qvac-models.test.js test/unit/umbrel-ui-controls.test.js` (25
  tests / 169 asserts),
  `./node_modules/.bin/brittle test/unit/api-subsidy.test.js
  test/unit/api-auth.test.js test/unit/umbrel-ui-controls.test.js
  test/unit/subsidy.test.js test/unit/wizard.test.js` (92 tests / 430
  asserts),
  `./node_modules/.bin/brittle test/unit/api-wizard-actions.test.js
  test/unit/api-auth.test.js test/unit/umbrel-ui-controls.test.js
  test/unit/dashboard-wizard-ui.test.js test/unit/wizard.test.js` (82 tests /
  432 asserts),
  `./node_modules/.bin/brittle test/unit/api-service-management.test.js
  test/unit/api-service-config.test.js
  test/unit/api-service-config-helpers.test.js
  test/unit/umbrel-ui-controls.test.js` (66 tests / 466 asserts),
  `./node_modules/.bin/brittle test/unit/api-mode-transport.test.js
  test/unit/api-service-config.test.js` (43 tests / 331 asserts),
  `./node_modules/.bin/brittle test/unit/api-config-update.test.js
  test/unit/api-service-config.test.js` (41 tests / 315 asserts),
  `./node_modules/.bin/brittle test/unit/api-device-pairing.test.js
  test/unit/api-delegation-management.test.js
  test/unit/api-service-config.test.js test/unit/private-mode.test.js`,
  `./node_modules/.bin/brittle test/unit/api-federation-management.test.js
  test/unit/api-service-config.test.js test/unit/federation-hardening.test.js
  test/unit/accept-mode.test.js`,
  `./node_modules/.bin/brittle test/unit/api-catalog-management.test.js
  test/unit/api-catalog-read.test.js test/unit/api-service-config.test.js`,
  `./node_modules/.bin/brittle test/unit/api-dispatch.test.js
  test/unit/api-auth.test.js test/unit/capability-endpoints.test.js
  test/unit/api-cors.test.js` (63 tests / 304 asserts),
  `./node_modules/.bin/brittle test/unit/api-signed-ingress.test.js
  test/unit/manifest-store.test.js test/unit/fork-proof-signing.test.js` (34
  tests / 123 asserts),
  `./node_modules/.bin/brittle test/unit/api-health.test.js
  test/unit/api-auth.test.js test/unit/fleet-rollout-check.test.js` (51 tests
  / 254 asserts),
  `./node_modules/.bin/brittle test/unit/api-eviction-purge.test.js
  test/unit/eviction.test.js test/unit/api-auth.test.js` (58 tests / 243
  asserts),
  `./node_modules/.bin/brittle test/unit/api-lifecycle-actions.test.js
  test/unit/api-auth.test.js test/unit/gateway-close.test.js` (44 tests / 194
  asserts),
  `./node_modules/.bin/brittle test/unit/api-management-snapshots.test.js
  test/unit/api-service-config.test.js test/unit/api-device-pairing.test.js
  test/unit/api-mode-transport.test.js` (52 tests / 388 asserts),
  `./node_modules/.bin/brittle test/unit/api-safe-config.test.js
  test/unit/api-config-update.test.js test/unit/api-service-config.test.js
  test/unit/api-subsidy.test.js test/unit/api-wizard-actions.test.js` (58 tests
  / 425 asserts),
  `./node_modules/.bin/brittle test/unit/api-custody-status.test.js
  test/unit/custody-status-redaction.test.js
  test/unit/api-custody-management.test.js` (13 tests / 85 asserts),
  `./node_modules/.bin/brittle test/unit/api-anchor-status.test.js
  test/unit/api-auth.test.js test/unit/manage-cli-client.test.js` (44 tests /
  197 asserts),
  `./node_modules/.bin/brittle test/unit/api-network-state.test.js
  test/unit/api-auth.test.js test/unit/ws-feed-payload.test.js
  test/unit/dashboard-network-ui.test.js` (60 tests / 289 asserts),
  `./node_modules/.bin/brittle test/unit/api-custody-management.test.js
  test/unit/api-publisher-signed.test.js test/unit/api-transient-errors.test.js
  test/unit/api-service-config.test.js` (69 tests / 393 asserts),
  `./node_modules/.bin/brittle test/unit/api-seed-publish.test.js
  test/unit/api-publisher-signed.test.js test/unit/api-transient-errors.test.js
  test/unit/api-service-config.test.js` (71 tests / 427 asserts),
  Browser mobile render check with no horizontal overflow and 34px public-key/wallet chips,
  `npm run lint`, `npm run audit:workspace`, and `git diff --check`.

## Strong Evidence Of Completed Work

- Core3 hardening is documented in `docs/AUDIT-2026-06-22.md`, including dependency audit fixes, auth hardening, API/router/gateway hardening, dashboard/auth/metrics/logging work, config persistence, service pub/sub, app-catalog delta handling, proof-of-relay accounting, and unseed verification.
- `docs/AUDIT-ROADMAP.md` marks multiple security and performance phases complete, including items in the S/Q/1/2/3/4 series.
- `docs/THREAT-MODEL.md` gives the security thesis: Hiverelay is a P2P substrate for timestamped claims and reputation over Hyperswarm and append-only logs, with N-of-M trust, replica diversity, cross-client verification, and explicit residual risks.
- `umbrel-app/OFFICIAL-SUBMISSION-PLAN.md` says the official Umbrel package is aligned for first submission with no icon URL field, empty first-submission release notes, app proxy usage, scoped data paths, and a digest-pinned image.
- `package.json` exposes the relevant release, proof, Umbrel, fleet, lint, and test commands needed to move from status to evidence.

## Current Open External Proof Gaps

- Official Umbrel App Store proof still needs a real upstream PR URL, PR state/head evidence, and reviewer handoff artifact.
- Umbrel first-submission `gallery: []` validation passes with
  `npm run umbrel:check-gallery`; real 1440x900 screenshots are still needed
  for reviewer handoff when the upstream PR asks for gallery assets.
- Real Umbrel install/start/dashboard/live-feed/wizard/management/devtools/data-writable/reinstall-preserves-key checks are still unchecked in `umbrel-app/SUBMISSION-CHECKLIST.md`; once run, they should be captured with `umbrel-runtime-review-evidence.json`.
- Multi-architecture image proof is automated for full releases through
  `release-image-manifest-evidence.json`; the Umbrel submission checklist still
  needs the current release's generated sidecar or a manual
  `npm run release:check-image-manifest` re-check before marking that
  submission item complete.
- StartOS registry or marketplace proof still needs real `startos-registry-evidence.json` with package URL/id/hash agreement.
- Live fleet convergence still needs authoritative `fleet-rollout-evidence.json` from `npm run fleet:check-rollout` or the release workflow.

## Current Open Engineering Gaps

- `docs/AUDIT-ROADMAP.md` still calls out RelayNode/API decomposition as too
  broad; multiple pure API helpers have now been split out, including
  Node/Bare public peer-state payload construction and shared JSON response
  hardening for Bare/Pear read-only HTTP. Pending catalog reads now use a
  stable public schema instead of raw queue entry spreading, and federation
  catalog polling now uses the bounded RelayNode pending-request helper and
  bounded JSON response reads instead of directly growing `_pendingRequests` or
  parsing uncapped followed-peer payloads. The standalone Hyper gateway now
  boots from the correct constants import and validates `/v1/seed` through the
  shared bounded JSON body gate. Network discovery relay overview probes now
  reject oversized or non-object `/api/overview` responses before accepting live
  metadata, and `hiverelay-meta` Holesail keys are bounded, parsed as object
  JSON, normalized to valid z32 keys, and rejected before tunnel creation when
  invalid. Seed protocol handshakes now reject oversized, malformed, or
  major-version-mismatched version JSON before replaying pending seed requests
  to peers. Proof-of-relay challenge/response frames now reject malformed or
  oversized proof buffers at decode/preencode time instead of relying only on
  later scoring checks. Signed-directory record payloads, status messages, and
  list responses now have hard wire caps before decode/encode allocation growth.
  Public catalog reads now share one bounded helper across the control-plane and
  data-plane gateway, and delegation revocation management now validates expiry
  metadata before mutation while returning capped sanitized list payloads. Alert
  log/test routes now validate filters and manual dispatch payloads before
  touching the alert manager. Operator and publisher-signed unseed routes now
  validate through `api-unseed-actions.js` before mutation/verifier calls while
  preserving broadcast ordering. Dashboard/wizard/root/simple-mode page routing
  now delegates through a directly tested resolver. Operator telemetry reads now
  delegate through a directly tested payload helper. Wallet payout status and
  claim reads now delegate through the subsidy helper. Public peer arrays are now bounded across
  legacy Node, current Node, and Bare HTTP surfaces. Public fork-proof reads now
  cap record/evidence payloads and omit operator-only notes. Registry status
  reads now cap request/relay enrichment and avoid raw entry spreading. Public
  reputation reads now cap leaderboard rows, validate direct-record pubkeys, and
  reuse one shaped record sanitizer for peer decorations. Public gateway stats
  now expose shaped counters across embedded, overview, and standalone gateway
  health surfaces. Route dispatch and mutation orchestration remain broad.
- Service protocol v2 compact encoding remains a future wire-version change.
- Broader route/fault integration coverage remains an open coverage track.
- `docs/LAUNCH_PLAN.md` should be treated as strategic/historical unless corroborated, because it declares itself partially out of date after Compute removal, Core/Services split, and Catalog auto-sync removal.

## Evidence Commands For Next Proof Pass

Run from `~/pear-ecosystem/00-core/hiverelay`:

```sh
npm run lint
npm run test:unit
npm run audit:workspace
npm run umbrel:smoke-package
npm run umbrel:check-gallery
npm run release:verify-evidence
npm run release:verify-handoff-evidence
npm run release:verify-review-ready-handoff
npm run release:check-image-manifest
npm run fleet:check-rollout
```

External or environment-dependent proof checks:

```sh
docker buildx imagetools inspect ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0
npm run release:check-image-manifest -- --image ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:<digest> --out release-image-manifest-evidence.json
grep -rn "^port: 9100" --include=umbrel-app.yml .
npm run release:write-official-umbrel-pr-evidence
npm run release:write-startos-registry-evidence
```

Do not claim these have passed until they are run in the correct environment and their output is captured.

## Recommended Next Level 1/2 Step

Run the focused evidence commands that do not require external credentials or GUI access, capture the outputs in source-backed evidence files, then refresh the brain. Finish with:

```sh
python3 outputs/agent-loop/loopctl.py recompile-brain
python3 outputs/agent-loop/loopctl.py score
```

## Source Evidence

- `~/pear-ecosystem/00-core/hiverelay/umbrel-app/OFFICIAL-SUBMISSION-PLAN.md`
- `~/pear-ecosystem/00-core/hiverelay/umbrel-app/SUBMISSION-CHECKLIST.md`
- `~/pear-ecosystem/00-core/hiverelay/docs/AUDIT-ROADMAP.md`
- `~/pear-ecosystem/00-core/hiverelay/docs/THREAT-MODEL.md`
- `~/pear-ecosystem/00-core/hiverelay/docs/LAUNCH_PLAN.md`
- `~/pear-ecosystem/00-core/hiverelay/docs/AUDIT-2026-06-22.md`
- `~/pear-ecosystem/00-core/hiverelay/docs/RELEASE_AUTOMATION.md`
- `~/pear-ecosystem/00-core/hiverelay/docs/README-MAIN-UPDATE-AUDIT.md`
- `~/pear-ecosystem/00-core/hiverelay/package.json`
