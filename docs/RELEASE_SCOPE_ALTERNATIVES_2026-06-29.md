# Release Scope Alternatives - 2026-06-29

## Source Basis

This note compares the current Core3/HiveRelay design against the stripped-back
direction implied by the alternative specs. I did not find literal
`GLM 5.2`, `glm`, or adversarial-review spec artifacts in the current checkout
or local `hiverelay`, `blindspark-umbrel-store`, or `pear-registry` refs. Treat
the "GLM alternatives" below as a source-backed reconstruction from the durable
specs and neighboring module apps available in this workspace:

- Current Core3 design: `README.md`, `docs/HIVERELAY-ARCHITECTURE-GRAPH.md`,
  `docs/RELEASE_AUTOMATION.md`, `docs/OPERATOR_ECONOMICS.md`,
  `docs/CURRENT_STATUS_AUDIT_2026-06-24.md`, and
  `docs/SHIP-HANDOFF-2026-06-26.md`.
- Privacy-tier alternative: `../hiverelay-spec/README.md`,
  `../hiverelay-spec/TECHNICAL_SPECIFICATION.md`,
  `../hiverelay-spec/IMPLEMENTATION_ROADMAP.md`, and its release/conformance
  checklist.
- Module-app alternative evidence: `../pear-registry/README.md`,
  `services/index-sidecar/README.md`, `docs/INDEX-LAYER.md`, and the
  `../blindspark-umbrel-store` Blindspark plus PearPaste package split.

## Bottom Line

The optimal release is not a rewrite and not a public promise that every Core3
module is product-ready. It should be a narrower **Blindspark Core Availability**
release:

- Ship HiveRelay as the verifiable always-on availability substrate for
  Pear/Holepunch apps.
- Keep the proven core surfaces: seed acceptance, catalog/capability reads,
  Hyperdrive gateway, DHT/WS/circuit ingress, review-mode appliance UI,
  storage caps, release evidence, and trustless seeded-content verification.
- Move the product story for package registries, privacy-tier app APIs,
  AI/QVAC providers, poker/SignedLog apps, payments, and rich search/index into
  separate apps or optional packages that consume the relay.
- Strip the release narrative and default appliance posture first. Do not rip
  working code out of the monorepo immediately before a release.

Both stripped specs are pointing at the same real risk: the relay is carrying
too many product identities at once. The fix is to make HiveRelay the small
trust root and distribution substrate, then let app-specific modules be apps.

## Current Design

The current design is a broad Core3 stack:

- `p2p-hiverelay`: core relay runtime, CLI, HTTP API, dashboard, gateway,
  seed/custody/anchor/circuit/forward protocols, release distribution surfaces.
- `p2p-hiverelay-client`: SDK, app publishing/opening, service RPC, custody
  helpers, `verifySeeded`, and `proveSeeded`.
- `p2p-hiverelay-verifier`: independent HTTP verifier.
- `p2p-hiveservices`: identity, storage, schema, VRF, AI, ZK, SLA,
  arbitration, `storage-proof`, and poker/SignedLog providers.
- Blindspark: Umbrel/StartOS appliance packaging of the core relay.
- Release automation: npm, GHCR, raw fleet, Umbrel, StartOS, package smokes,
  evidence sidecars, and ecosystem consumer sync.

This has one major advantage: it is real. It has code, tests, release tooling,
packaging, and live-consumer alignment. Its weakness is that the public story
sounds like one release is trying to be a relay, a service marketplace, a
payment network, an AI provider surface, a package registry, a privacy platform,
an app store, and a home-server appliance.

That bundle is too wide for the next release.

## Alternative A: Privacy-Tier Minimal Relay

The privacy architecture spec strips HiveRelay back to infrastructure
primitives:

- Public gateway and catalog for public app code and public content.
- P2P/direct transport for private flows.
- Local-first storage and key management as platform/app responsibilities.
- App manifests declare privacy needs; apps own encryption and data lifecycle.
- Relays stay simple, replaceable, and commodity.

### What It Gets Right

- Cleaner trust boundary: the relay moves and verifies bytes; apps own privacy.
- Better UX truthfulness: "relay can see public app code, not app-local private
  state" is more precise than implying the relay magically blinds everything.
- Easier review posture for Umbrel/StartOS: fewer services, fewer implied data
  processors, fewer unexplained monetization surfaces.
- Better app architecture: PearPaste, wallets, POS, and medical apps should not
  rely on the relay as their privacy boundary.

### What It Gives Up

- It is mostly a docs/spec artifact today. Platform APIs and reference app
  migrations are explicitly not started in `hiverelay-spec`.
- If followed too literally, it underplays the relay's strongest proven
  differentiator: availability with verifiable custody/seed proof.
- It can push hard problems into every app if the platform APIs are not shipped.

### Release Implication

Adopt the boundary, not the implementation timeline. The next HiveRelay release
should say:

> Blindspark keeps public or encrypted Pear app artifacts available. Sensitive
> user state belongs in the app, local storage, or encrypted P2P flows.

Do not make this release depend on unbuilt local-storage/key-management APIs.

## Alternative B: Module Apps Around The Relay

The module-app direction strips registries, indexes, and services out of the
core release and lets each become its own product:

- `pear-registry`: signed per-publisher package metadata, Hypercore logs,
  Hyperbee local views, future tarball/Hyperdrive byte proof.
- `index-sidecar`: queryable schema-sheets index derived from public relay
  surfaces, dependency-isolated from the relay.
- PearPaste: encrypted local-first application that uses HiveRelay availability
  but is not part of the relay.
- QVAC/AI, poker, arbitration, payment, and richer service modules: separate
  operator apps or optional service packages, not the core appliance promise.

### What It Gets Right

- Each module can have its own threat model, runtime, release cadence, and user.
- The core relay becomes easier to audit and explain.
- App-store review becomes cleaner: reviewers can approve Blindspark without
  needing to understand AI inference, poker logs, package registries, or
  payment rails.
- It matches the codebase direction already visible in `p2p-hiveservices`,
  `p2p-hiverelay-client`, `p2p-hiverelay-verifier`, `services/index-sidecar`,
  and the Blindspark/PearPaste community-store split.

### What It Gives Up

- More moving parts for home-server users if every module becomes a separate
  install with separate configuration.
- More contract discipline is required. A split module is useful only if the
  relay exposes stable, boring contracts.
- It can create "half-products" if a module has metadata but no byte proof,
  query surface but no deployment path, or service APIs without payment/access
  policy.

### Release Implication

Make modules independent products, but do not force operators to assemble a
maze by hand. The appliance can expose modules as optional integrations later;
the next release should not headline them as core features.

## Current Design Tradeoffs

| Dimension | Broad Core3 Release | Privacy-Tier Minimal Relay | Module-App Split |
| --- | --- | --- | --- |
| User clarity | High feature density, low simplicity | Clear privacy story | Clear product-by-product story |
| Engineering risk | Lowest immediate rewrite risk | Risk if it requires unbuilt APIs | Contract risk across apps |
| Review/store risk | High because many surfaces appear bundled | Low | Medium, depends on packaging |
| Operator UX | One install, one dashboard | One install, fewer knobs | Potentially many installs |
| Security boundary | Strong code hardening, broad surface | Smaller promise | Smaller per-module promises |
| Monetization story | Rich but premature | Weak for now | Strong later, per product |
| Evidence readiness | Strong local/release evidence, external gates remain | Docs-only evidence | Mixed: pear-registry has tests, sidecar built, apps vary |
| Long-term architecture | Powerful but can become monolithic | Clean substrate | Best fit if contracts stay stable |

The best release uses the current design's implementation maturity, the
privacy spec's boundary discipline, and the module split's product clarity.

## Recommended Release Shape

### Product Name And Promise

Release as:

> **Blindspark by HiveRelay: core availability for Pear apps.**

Primary promise:

> Keep Pear/Holepunch app artifacts reachable after publishers go offline,
> through a blind, operator-untrusted, verifiable relay appliance.

Do not headline "AI services", "poker", "payment network", "package registry",
or "global app store" in the release promise.

### Include In The Core Release

- Relay identity and durable storage.
- Review-mode seed acceptance and operator approval flow.
- Public read surfaces:
  - `GET /.well-known/hiverelay.json`
  - `GET /catalog.json`
  - `GET /v1/hyper/:driveKey/*path`
- Publisher/operator seed surfaces that already exist:
  - `POST /seed`
  - `POST /api/v1/seed`
- DHT/Hypercore replication, gateway Range reads, WS ingress, and circuit/forward
  relay where already proven.
- App registry, catalog provenance, storage accounting, served-byte accounting,
  storage cap, eviction/purge, and dashboard status.
- Verification:
  - `verifySeeded` as a core SDK path.
  - `proveSeeded` and `storage-proof` as optional verifiability, not as a broad
    services marketplace promise.
- Release evidence machinery:
  - npm package pack/latest proof.
  - GHCR multi-arch digest proof.
  - release image smoke.
  - Umbrel package smoke.
  - fleet rollout evidence where a live rollout is claimed.
  - StartOS/Umbrel official evidence only when those external facts exist.

### Exclude Or Mark Beta/Separate

- `pear-registry`: separate developer infrastructure app.
- Privacy-tier platform APIs (`platform.storage.local`, `platform.p2p.join`,
  `platform.keys.*`): separate platform/browser/app work until implemented.
- Rich query/index sidecar: optional Tier-2 discovery infrastructure until
  deployed and contract-smoked.
- AI/QVAC provider: separate `hiveservices` or operator-provider app.
- Poker/SignedLog: separate app/service module, not part of appliance review.
- Lightning/Tether/payment rails and lease economy: not a release-blocking
  promise until settlement is live and reviewed.
- Global catalog/search/naming claims: PearBrowser/pear-registry layer, not
  core relay.

## Versioning Call

If the next change is only release-secret repair, evidence refresh, and a
scope/narrative correction, use a patch release such as `v0.20.3`.

If the release intentionally changes the public product line from "Core3
everything stack" to "Blindspark Core Availability" with updated store copy,
docs, and default module posture, use `v0.21.0`. That is a user-visible product
boundary even if most code stays the same.

## Suggested Release Sequence

1. **Scope freeze**
   - Write the release notes around core availability and verification.
   - Keep services/index/payments in docs as optional future/module surfaces.
   - Do not start a large RelayNode or API refactor before this release.

2. **Evidence repair**
   - Resolve the issue #120 malformed GitHub-hosted release values.
   - Rerun the full-release distribution preflight with `channel=both`.
   - Prove npm latest for `p2p-hiverelay`, `p2p-hiverelay-client`,
     `p2p-hiverelay-verifier`, and `p2p-hiveservices` if those packages are
     published in lockstep.

3. **Core artifacts**
   - Cut the GHCR image and record the multi-arch digest.
   - Run release-image smoke against the digest.
   - Run Umbrel package smoke against the exact digest.
   - Verify package tarball README/LICENSE shape before npm publish.

4. **Distribution lanes**
   - Raw fleet: promote only after `fleet-rollout-evidence.json` proves target
     SHA, package version, `/health.version`, health, inventory digest, and
     selected relay names.
   - Community Umbrel store: publish after package smoke and anchor alignment.
   - Official Umbrel and StartOS: treat as reviewer/registry handoffs, not
     source-readiness claims. Attach only when real sidecars exist.

5. **Module follow-ons**
   - Pear Registry: next milestone is payload byte proof or npm-compatible read
     bridge, not inclusion in Blindspark.
   - PearPaste: publish as its own Umbrel app and use HiveRelay only as the
     availability substrate.
   - Index sidecar: deploy as optional discovery/index infrastructure after
     room lifecycle and deployment smoke are proven.
   - AI/QVAC/services: ship as operator service apps after access control,
     payment posture, and request-data trust boundaries are explicit.

## Release Acceptance Criteria

The release is ready when these statements are true and evidenced:

- A new user can install Blindspark, complete setup, and run review-mode relay
  operation without exposing a host management port.
- PearBrowser or a simple HTTP client can read capability and catalog surfaces
  from the installed relay.
- A real seeded drive can be fetched through the Hyperdrive gateway.
- The client SDK can verify that a relay is serving seeded content.
- The release image, package metadata, npm packages, and release docs agree on
  the same version and digest.
- Any official store, StartOS, or fleet availability claim has a matching
  public evidence sidecar.
- Service modules not included in that proof are described as optional/beta or
  separate apps, not as part of the core release guarantee.

## Decision

Adopt a **narrow release, broad ecosystem** strategy:

- Narrow the next release to the relay kernel and appliance distribution.
- Preserve the current package split and evidence automation.
- Move module ambition into separate apps with explicit contracts.
- Let the broader Core3 graph remain an architecture map, not the public
  release promise for this ship.

This keeps the strongest parts of the current design while taking the
adversarial-review critique seriously: the release should be boring, verifiable,
and easy to explain. The interesting modules can still exist; they should earn
their own release evidence instead of riding on the relay's core trust budget.
