# Release Notes — v0.8.6

**Release date**: 2026-05-08

Repo-housekeeping release. Lands three substantial PRs (#8, #9, #10) and
brings CI back to green for the first time since the v0.8.0 series shipped.

## Headline

| Change | Why it matters |
|---|---|
| **Publisher-signed REST endpoints** (`/api/v1/seed`, `/api/v1/custody/*`) | Third-party app developers can now drive the seed and atomic-custody pipelines against your public relays without holding the operator API key. The "permissionless public relay" model promised in `docs/ATOMIC-BLIND-CUSTODY.md` is actually reachable for the first time. |
| **SDK auth bug fix** | `_postCustody` was sending `X-API-Key` instead of `Authorization: Bearer`. Every SDK call to a custody POST endpoint with `apiKey` had been silently failing auth on every 0.8.x relay. |
| **CI green** | Lint, audit, docker, integration tests, unit tests all clean. First time since v0.8.0. |
| **Umbrel / Blindspark pulled** | Distribution channel paused. Repo now reflects what we actually ship today. |

## Added

### Publisher-signed REST endpoints

Four new HTTP endpoints, each authorized by a publisher Ed25519 signature
in the request body — no operator API key required. Same trust model as
the existing `POST /api/v1/unseed`.

| Endpoint | Body |
|---|---|
| `POST /api/v1/seed` | `{ appKey, publisherPubkey, publisherSignature, replicationFactor, ttlSeconds, blind, storageClass, availabilityClass, custodyIntentId, blindContentId, ciphertextRoot, ... }` |
| `POST /api/v1/custody/intent` | `{ ...intent, publisherPubkey, signature }` |
| `POST /api/v1/custody/{intentId}/commit` | `{ ...commit, publisherPubkey, signature }` |
| `POST /api/v1/custody/{intentId}/source-retired` | `{ ...retirement, publisherPubkey, signature }` |

The `/api/v1/seed` endpoint accepts the same custody-anchoring fields as
the operator `/seed` endpoint, including `custodyIntentId`,
`blindContentId`, `ciphertextRoot`. If `custodyIntentId` is present, the
server cross-checks that the publisher pubkey matches the publisher who
originally signed that intent — stops a publisher from anchoring their
appKey to someone else's intent.

The signature is verified against the canonical v2 seed-request payload
(`appKey || hash(discoveryKeys) || meta(40 bytes)`) — same scheme used
on the Protomux wire. v1 (28-byte) verification is supported as a
fallback for permissive-defaults requests, matching existing protocol
behavior.

All four endpoints are added to the per-endpoint rate limiter (30/min
per IP). Bounds DoS exposure from anonymous publishers spending relay
storage / CPU.

### Refactor (no behavioural change)

`_serializeForSigning` and `_verifyRequestSignature` factored out of the
`SeedProtocol` class into module-level exports
(`serializeSeedRequestForSigning`, `verifySeedRequestSignature`) so
`api.js` can verify without instantiating the protocol. Instance methods
on `SeedProtocol` delegate to the new module functions; on-wire behavior
is identical.

## Fixed

- **SDK `_postCustody` auth header**: was `X-API-Key`, server reads
  `Authorization: Bearer`. Real bug, silent failure on every 0.8.x relay.
  Caught by the Drop v3 escrow integration team.
- **CI lint** (53 errors → 0): `standard --fix` swept the auto-fixable
  cases; promise constructor `r` → `resolve` rename across ~15 callsites;
  unused-var deletions in test files; sodium snake_case + WebSocket
  `verifyClient` callback patterns covered by targeted `eslint-disable`
  comments. `scripts/test-*.js` and `examples/**` added to
  `standard.ignore` (utility/dev code, not part of the shipped library).
- **CI npm audit**: 2 vulnerabilities (1 critical, 1 moderate) fixed via
  `npm audit fix` — `protobufjs` ≥7.5.5 (GHSA-xq3m-2v4x-88gg) and
  `ip-address` ≥10.1.0 (GHSA-v2v4-37r5-5v8g).
- **CI Docker build**: removed failing per-package
  `COPY --from=deps /app/packages/*/node_modules` lines. npm 7+ hoists
  workspace deps to the root `node_modules/`.
- **CI integration test timeout**: bumped from 5 min to 15 min. Combined
  with the force-exit guard below, the suite now runs in <1 min.
- **Brittle process-hang workaround**: added `zz-finalize.test.js` to
  both `test/integration/` and `test/unit/`. The 65-assertion integration
  suite all passed but Node's event loop was held open by something —
  likely a Hyperswarm testnet, a Hypercore store, or a DHT node from
  earlier in the suite — that wasn't released cleanly. Brittle has no
  global afterAll hook. The guard schedules a 5-second `.unref()`'d
  `setTimeout(() => process.exit(0))` as the last assertion. `.unref()`
  ensures we don't artificially block clean natural exit.
- **Lockfile drift from 0.8.5**: `bare-crypto: ^1.13.6` pinned in
  `packages/client/package.json` but the root lockfile still resolved to
  `1.13.4`. Regenerated.

## Removed

- **`umbrel-app/` directory** (umbrel-app.yml, docker-compose.yml,
  SUBMISSION-CHECKLIST.md, README.md, icon.svg, gallery placeholder).
- **`.github/workflows/umbrel-app-validate.yml`** CI workflow.
- **All inline references to Umbrel and Blindspark** across README,
  CHANGELOG, docs, the docker-publish workflow, and `wizard.js`. The
  setup wizard module itself is unchanged — only its phrasing was
  Umbrel-specific. Still imported by `relay-node/api.js`, still serves
  `/api/wizard/*`, still drives `dashboard/wizard.html`.

The Blindspark consumer brand and Umbrel App Store distribution channel
are paused while the core relay protocol matures. They can be restored
later if/when the operational story is ready.

## Documentation

- Backfilled CHANGELOG entries for all 13 missed versions (0.6.1 → 0.8.5).
- Wrote previously-missing `RELEASE-NOTES-0.8.2.md`,
  `RELEASE-NOTES-0.8.4.md`, `RELEASE-NOTES-0.8.5.md`.
- README banner refreshed to v0.8.6.
- GitHub Releases page is now backfilled for every tag from `v0.6.0`
  to `v0.8.6` (was: only `v0.6.1` had a release entry; tags existed for
  the rest but no human-readable release pages).

## Upgrading

```bash
npm install -g p2p-hiverelay@^0.8.6
```

No config changes. No data migration. Restart your relay process to
pick up the new HTTP endpoints.

If you operate the public relays and want third-party publishers to be
able to use the new `/api/v1/*` endpoints, no further configuration is
needed — they're enabled by default. Rate-limited at 30/min per IP.

## Closed PRs

- **#5** — v0.6.0 pipeline. Closed as stale (0 ahead of main, all work
  already landed via direct commits).
- **#6** — HiveWorm pearbrowser rewrite. Closed as stale (HiveWorm was
  dropped from relay core in v0.7.3 already).
- **#7** — original publisher-signed REST PR. Closed; re-opened as #10
  with the same content rebased onto green main.

## What's next

- Live-relay deployment (Utah / Utah-US / Singapore) to v0.8.6 via the
  existing `scripts/deploy-vps.sh` flow.
- Ongoing: integration of v0.6 features (QuorumSelector, ForkDetector,
  verifier package) into `pearbrowser-desktop` consumers.
