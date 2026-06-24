# Main README Update Audit - 2026-06-23

## Evidence Checked

- Published GitHub `main` README: `bigdestiny2/P2P-Hiverelay@main`, blob SHA
  `c38a1012ee4b4a7f031dd9c6e846b4f1380ad466`.
- Remote `origin/main` commit rechecked on 2026-06-24:
  `34f8415a1e4cbfd228ced5a2eb008b28992b5ef7`
  (`chore(startos): guard the s9pk image-digest pin (make digest + check-digest) (#113)`).
- Published GitHub `main` package version: `0.20.0`.
- Published GitHub `main` changelog through `0.20.0`.
- Local checkout: `main` at `0.16.3` with an uncommitted Core3/Blindspark/fleet
  README draft and release-surface audit work.

The earlier local README draft had the right structural direction, but it was
not enough to replace GitHub `main` as-is because GitHub `main` already includes
later `0.17.0` through `0.20.0` features. The current root README now folds
those surfaces into the Core3/Blindspark/fleet structure; the remaining
publication caveat is version synchronization through `npm run release:prepare`
before a tag is cut. Do not publish the local `0.16.3` status line over
GitHub `main`; apply the README structure on top of the current `0.20.0`
public surface or let `release:prepare` rewrite every versioned surface
together.

## Current Local State

- Root README now explains Core3 architecture, schemas/contracts, HTTP and P2P
  APIs, SDK verification surfaces, use cases, Blindspark packaging, and the
  live fleet/release model.
- The 2026-06-24 GitHub-main refresh confirms the published `README.md` blob is
  still `c38a1012ee4b4a7f031dd9c6e846b4f1380ad466`, while `origin/main`
  advanced to `34f8415a1e4cbfd228ced5a2eb008b28992b5ef7`; the README
  replacement plan still applies on top of the current `v0.20.0` public
  surface.
- The 2026-06-24 readability pass adds a concise public/signed-publisher/
  operator control-plane map and turns the release-evidence description into a
  sidecar table, so GitHub readers can understand the live fleet and store
  handoff model without digging through workflow YAML first.
- The 2026-06-24 bounded-status pass adds the newest public/status read
  boundary details to the README API map: `/status` is documented as a bounded
  public liveness/aggregate summary rather than raw node stats, `/api/peers` is
  documented as a bounded public peer list with total/truncated metadata, and
  `/api/registry` is documented as an authenticated, bounded, sanitized
  operator status view rather than raw registry record exposure. Umbrel
  runtime-review evidence remains the required real-device proof before a
  review-ready handoff.
- The 2026-06-24 operator-diagnostics pass adds the management-only diagnostic
  read cluster to the README API map: `/api/health-detail`, `/api/storage/top`,
  `/api/auto-heal`, and `/api/history` are documented as shaped operator
  payloads, with metrics history treated as bounded/malformed-safe dashboard
  data rather than raw internals.
- The release section now includes a **Live Vs Review-Gated Distribution** map
  so GitHub readers can see which surfaces move automatically on full releases
  and which still depend on Umbrel or Start9 review.
- The 2026-06-24 fleet-proof pass documents that `fleet-rollout-evidence.json`
  includes bounded `timeoutMs`, `intervalMs`, and `sshTimeoutMs` probe timing,
  and that release/handoff verifiers reject timing values that are missing,
  malformed, too short, or too long to prove live convergence.
- The 2026-06-24 publication-safety pass adds a **Current Publication Status**
  table near the top of the README, separating local Core3/Blindspark/source
  readiness from the external proof files still needed for official Umbrel,
  StartOS, and live raw-fleet claims. The release-evidence section now also
  calls out image-manifest-before-smoke chronology and runtime-version proof.
- The 2026-06-24 ship-readiness pass adds a GitHub-rendered Mermaid **Relay
  System Graph** covering clients/operators, network ingress, Core3 internals,
  Protomux protocol channels, opt-in services, public schemas/contracts,
  release/fleet/store distribution, and the security/runtime guardrails.
- Root README preserves the v0.17-v0.20 public-main features listed below,
  including `verifySeeded`, `proveSeeded`, `subscribeService`, `catalogBeeKey`,
  `indexRoom`, paid leases, durable bare-core pinning, and storage proofs.
- The status badge intentionally remains release-script managed. Do not
  hand-edit the badge or app-store package versions independently of
  `release:prepare`.

## Public README Goal

The front page should explain HiveRelay as:

1. Core3 blind relay infrastructure for Pear/Holepunch apps.
2. Blindspark as the home-server appliance packaging for Umbrel and StartOS.
3. A verifiable relay/network stack with schemas, APIs, SDKs, services,
   storage proofs, live catalog/index surfaces, and release/fleet automation.

It should avoid implying that official Umbrel App Store or StartOS marketplace
publication happens without the upstream human review gates. The automation can
prepare, smoke, evidence-link, publish configured registries, and open/update
draft PRs; official store inclusion remains review-controlled.

## Required Top-Level Shape

Use this section order for the GitHub `main` README:

1. Intro: HiveRelay, Blindspark, status, packages.
2. What changed recently.
3. Architecture.
4. Core concepts.
5. Schemas and contracts.
6. HTTP and P2P API surfaces.
7. Client SDK and verification.
8. Use cases.
9. Quick start.
10. Blindspark on Umbrel and StartOS.
11. Live fleet and release automation.
12. Security and privacy.
13. Test coverage.
14. Documentation and links.

## Must-Preserve v0.20 Features

Do not lose these current-main upgrades when replacing the old README:

- `verifySeeded(driveKey, { relay })` as Tier-1 trustless seed verification.
- `proveSeeded(driveKey, { relay, samples })` as Tier-2 signed proof-of-storage
  verification over the opt-in `storage-proof` service.
- `StorageProofService` privacy gate for blind/redacted drives, global proof-work
  rate cap, per-caller bucket, and phantom-core DoS guard.
- `subscribeService(service, event, onEvent, opts?)` for live P2P service event
  subscriptions.
- Poker live events on per-table topics via
  `client.subscribeService('poker', tableKey, ...)`.
- `catalogBeeKey` advertising for signed Hyperbee catalogs.
- `indexRoom` / schema-sheets sidecar as an optional signed, queryable index
  layer behind `/index/*` and `/api/index/room`.
- DHT-resolvable signed relay records for pubkey-to-gateway/index-room lookup.
- Paid pin-lease primitives and API, explicitly off by default.
- Durable bare-core pinning through `POST /seed-core`.
- Superseded app dedup/reclaim surfaces, with blind entries excluded.
- Measured storage fixes that use real disk usage, sparse-file block counts, and
  measured adoption guards.
- Browser ingress details from older public README/current code: streaming
  gateway reads with HTTP Range support, Hypercore-over-WS, optional
  DHT-over-WS, and `hiverelay-circuit` NAT fallback.
- Client SDK identity and reader-replica helpers: `exportIdentity`,
  `importIdentity`, device attestation verification/revocation,
  `createPairingCode`, `claimPairingCode`, `mirror`, `unmirror`, and community
  replica opt-in through `enableCommunityReplicas`.
- Optional `hiverelay-signed-directory` signed-record directory with TTL,
  signature, timestamp-skew, rate-limit, and single-hop replication semantics.

## Must-Preserve Core3/Fleet Draft Features

Merge these from the local Core3 README draft:

- Four-layer architecture: Core3 relay kernel, discovery/ingress layer,
  services layer, distribution layer.
- Blindspark appliance story: one-page dashboard, setup, wallet destination,
  service manager, restart/status, measured stored/served counters.
- Accept policy contract: `review`, `allowlist`, `open`, `closed`, with
  `HIVERELAY_ACCEPT_MODE=review` as the first-boot home-server default.
- Management API hardening: bearer auth, strict JSON content type, bounded
  object-only body handling, live `/api/manage/services` disable/restart
  actions, and durable service disable persistence before unregister;
  persistence failures return `persist-failed`.
- Service/accounting telemetry: `/api/usage` and `/api/poker/usage`.
- Authenticated dashboard live-feed smoke: release and package smokes should
  prove URL-token WebSockets are rejected, in-band auth succeeds, and an update
  frame is received.
- Release evidence model: `release-evidence.json`, smoke sidecars,
  `release-image-manifest-evidence.json`, `fleet-rollout-evidence.json`,
  `official-umbrel-pr-evidence.json`, `umbrel-runtime-review-evidence.json`,
  `startos-registry-evidence.json`, and final handoff verification.
- Raw fleet pull-update model: `fleet/channels.json`, `fleet/relays.json`,
  `hiverelay-updater`, health-gated restart, rollback, and rollout evidence.
- Clear distinction between in-repo/community-store automation and official
  Umbrel/StartOS review.

## Architecture Content To Add

The old README architecture section is too narrow. It should show:

- Pear/Bare apps and browsers entering through Hyperswarm and the HTTP gateway.
- Browser/mobile ingress through streaming Range reads, Hypercore-over-WS,
  optional DHT-over-WS, and circuit relay fallback.
- Core surfaces: AppRegistry, Seeder, Gateway, Dashboard/WS, AutoHeal, anchor
  proofs, custody registry, storage/served accounting, eviction, reputation.
- Services/index surfaces: identity, storage, schema, VRF, AI/QVAC, ZK, SLA,
  arbitration, poker/SignedLog, storage-proof, schema-sheets sidecar.
- Catalog/index/discovery: `/catalog.json`, `catalogBeeKey`, `indexRoom`, DHT
  relay record.
- Distribution: npm/Docker, Blindspark Umbrel, StartOS `.s9pk`, raw fleet,
  GHCR digest, release evidence.

## Schemas And Contracts To Cover

Keep the section brief and contract-oriented:

- App manifest: `name`, `version`, `description`, `author`, `entry`,
  `categories`, `icon`, `privacyTier`.
- Catalog entry: `contentType`, `privacyTier`, `storageClass`,
  `availabilityClass`, `catalogBeeKey`.
- Capability document: `schemaVersion: 1`, pubkey, runtime, version, region,
  transports, features, limits, federation, catalog counts, `indexRoom`,
  signed envelope.
- DHT relay record: relay pubkey resolves to signed gateway/index metadata.
- Accept policy: `acceptMode`, `acceptAllowlist`.
- Seeding manifest: signed author relay preferences.
- Custody envelope: signed message types and privacy invariant enforcement.
- Service manifest: `name`, `version`, `capabilities`.
- Signed-directory record: author pubkey, timestamp, payload, detached
  signature, TTL, newest-wins update, and rate-limit constraints.
- Storage proof: challenged core key/index/nonce plus signed proof response.
- Usage receipt: counterparty-signed metering receipt and aggregate usage view.
- Release evidence: release certificate and public-safe sidecars.

## API Surface To Cover

The old README lists only a subset. Add or retain these groups:

- Public liveness and telemetry: `/health`, `/status`, `/metrics`.
- Public catalog/gateway: `/catalog.json`, `/v1/hyper/:key/*path`.
- Browser transports: Hypercore-over-WS and DHT-over-WS, usually proxied as
  `/ws/replicate` and `/ws/dht`.
- Dashboard and appliance feed: `/dashboard`, `/wizard`, and `/ws`, with
  dashboard WebSocket tokens sent in-band rather than in the URL.
- Capabilities and discovery: `/.well-known/hiverelay.json`,
  `/api/capabilities`, DHT relay record helpers.
- Optional index sidecar: `/index/*`, `/api/index/room`,
  `/api/manage/index-room`.
- Seed and unseed: publisher-signed `/api/v1/seed`, `/api/v1/unseed`, operator
  `/seed`, `/unseed`, and `/seed-core`.
- Custody: `/api/v1/custody/*` plus management custody endpoints.
- Services: `/api/v1/services`, `/api/v1/router`, `/api/v1/dispatch`, P2P
  service RPC, P2P service subscriptions.
- Storage proof service: `storage-proof.prove`.
- Poker: `/api/poker/*`, `/api/poker/:table/events`, per-table P2P events.
- Paid leases: `/api/lease`, `/api/lease/config`.
- Dedup/reclaim: `/api/dedup/reclaim`.
- Usage telemetry: `/api/usage/receipt`, `/api/usage`,
  `/api/poker/usage`.
- Management: catalog, federation, delegation/devices, pairing, config,
  `/api/manage/services` live disable/restart, services, AI/QVAC models,
  mode/transport, restart/shutdown, operator diagnostics
  (`/api/health-detail`, `/api/storage/top`, `/api/auto-heal`, `/api/history`),
  eviction purge, subsidy destination.

## Use Cases To Make Explicit

- Keep a Pear app online after the publisher disconnects.
- Browser/mobile first load through HTTP while P2P catches up.
- PearBrowser/app-store catalog source via HTTP, catalogBee, or index room.
- Blind social recovery with PVSS shares.
- Encrypted handoff/dead drop with custody receipts and non-serving proofs.
- Home relay appliance on Umbrel/StartOS.
- Service operator for identity, storage, schema, VRF, AI/QVAC, ZK, SLA,
  arbitration, poker, and storage-proof.
- Card-blind games and sealed-action applications.
- Paid pin lease for publishers, off by default.
- Raw fleet relay with pull updates, health gates, rollback, and release
  evidence.
- Browser/mobile relay ingress and NAT fallback for clients that cannot speak
  UDP directly.

## Release And Store Wording

Use precise language:

- Full releases can build/push GHCR images, sync metadata, smoke the image and
  Umbrel package, prove the pinned GHCR digest has `linux/amd64` and
  `linux/arm64` manifests through `release-image-manifest-evidence.json`,
  build/verify StartOS `.s9pk`, update raw fleet channels, verify rollout,
  write evidence, publish configured StartOS registries, and open/update
  official Umbrel draft PRs when credentials are configured.
- Real Umbrel UI lifecycle review remains a separate manual proof surface:
  `umbrel-runtime-review-evidence.json` is generated after install, setup,
  add-wallet, service management, app-proxy dashboard, in-band WebSocket auth,
  `/data`, and reinstall-preserves-key checks pass on an actual Umbrel device.
- Official Umbrel App Store publication still requires the upstream
  `getumbrel/umbrel-apps` PR/review process.
- Official Start9 marketplace/community registry inclusion still requires
  Start9 review, even if a configured registry publish succeeds.
- Prereleases should stay isolated from fleet/store promotion unless explicitly
  staged by the workflow rules.

## Suggested Implementation Path

1. Start from the local README draft structure.
2. Apply it on top of current GitHub `main` before publishing, preserving the
   public `v0.20.0` status/version surface unless `release:prepare` is cutting
   a newer synchronized release.
3. Merge v0.17-v0.20 changelog features into the architecture, API, SDK, and
   use-case sections.
4. Keep proof/lease/index details short in README and link to deeper docs.
5. Add a README drift guard that checks for `verifySeeded`, `proveSeeded`,
   `subscribeService`, `storage-proof`, `indexRoom`, `catalogBeeKey`,
   `/api/lease`, `/seed-core`, `/api/peers`, `/api/registry`,
   `/api/health-detail`, `/api/storage/top`, `/api/auto-heal`, `/api/history`,
   DHT-over-WS,
   circuit relay, signed-directory, reader replica helpers, identity pairing
   helpers, release evidence, release-image manifest evidence, Umbrel
   runtime-review evidence, and fleet evidence terms.
6. Run the README guard, lint, and unit tests before landing.
