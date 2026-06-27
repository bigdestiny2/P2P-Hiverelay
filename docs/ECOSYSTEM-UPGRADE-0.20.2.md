# HiveRelay 0.20.2 Ecosystem Upgrade Notes

This document tracks the direct non-bundled `p2p-hiverelay*` consumers found
from the Hiverelay source tree. It is intentionally separate from the
PearBrowser bundle notes: PearBrowser desktop is the release-critical bundled
consumer, while the customer-facing apps below are also treated as release
blocking direct consumers before we claim whole-ecosystem package parity.

Run this from the Hiverelay repo before and after each app upgrade:

```bash
npm run ecosystem:sync
npm run ecosystem:sync:release -- --check
npm run ecosystem:sync -- --check
npm run audit:ecosystem-consumers
npm run audit:ecosystem-consumers:release
npm run ecosystem:sync:local -- --check
npm run audit:ecosystem-consumers:local
```

`npm run ecosystem:sync` reads the current Hiverelay package version and updates
the known direct app consumers so their default `p2p-hiverelay*` package specs
pull the npm `latest` dist-tag. It refuses to edit app manifests unless every
relevant npm `latest` dist-tag already equals the expected Hiverelay version,
then delegates lockfile refreshes to `npm install --package-lock-only` in each
affected app root so lockfiles carry real registry tarball metadata. It also
rewrites versioned source markers such as the PearBrowser bundled catalog and
app handover notes. Use `--check` in a release review to fail if any app would
still need a default-version write.

Local workspace development uses the explicit local mode:

```bash
npm run ecosystem:sync:local
npm run audit:ecosystem-consumers:local
```

Local mode points the same consumers at this checkout's workspace packages,
refreshes linked package metadata in the nearest app lockfile, including
split-client `p2p-hiverelay` ranges such as `^0.20.2`, and preserves the same
source-marker checks. As of 2026-06-28, the default npm-latest guard is
important: npm `latest` is still `0.9.2` for the published packages, so
switching PearBrowser, PearPaste, anonGPT, or other customer apps to raw
`latest` before the release workflow publishes 0.20.2+ would downgrade installs.
Direct npm checks on 2026-06-28 returned `0.9.2` for `p2p-hiverelay`,
`p2p-hiverelay-client`, `p2p-hiverelay-verifier`, and `p2p-hiveservices`.
The full release workflow now publishes or promotes those npm packages before
running `release:prepare`, and `release:prepare` defaults sibling app consumer
sync to npm `latest` mode; use `--ecosystem-dependency-mode local` only for
checkout-to-checkout development.

Use the `:release` scripts for the remotely managed repos that CI can checkout
and push (`pearbrowser-desktop`, `pearpaste`, `p2pbuilders`, `Opengit`, and
`anongpt`). The default all-scope scripts still track Pear POS, Pear Tickets,
and `hiverelay-test` locally so their manifests and lockfiles can move to npm
`latest` immediately after the registry tag is correct.

If a release review environment cannot resolve the npm registry from inside
Node, feed the already-collected shell preflight evidence to the guard:

```bash
HIVERELAY_NPM_LATEST_JSON='{"p2p-hiverelay":"0.20.2","p2p-hiverelay-client":"0.20.2","p2p-hiverelay-verifier":"0.20.2"}' \
  npm run ecosystem:sync -- --check
```

The audit checks package manifests and lockfile metadata across the workspace
and requires every direct app consumer to point at the current published npm
`latest` dist-tag with a lockfile resolved to the same version. The explicit
local mode accepts current Hiverelay workspace package links for development.
PearBrowser desktop, PearPaste, pear-pos, pear-tickets, p2pbuilders, Opengit's
optional HiveRelay bridge, anonGPT, and the local smoke app are all tracked
consumers. New
`p2p-hiverelay*` pins fail the audit until they are classified. The same audit
renders PearBrowser's bundled
HiveRelay catalog entry plus customer-app source notes for PearPaste, anonGPT
relay/onion architecture, anonGPT's production HiveRelay forward-service client
contract, and Pear POS from the current Hiverelay version, so users and
operators do not see stale release guidance while the runtime pulls current
packages. The same audit also checks the local `00-core/hr-acct`,
`00-core/hr-fleet`, and `00-core/hr-release` snapshot manifests and root
lockfiles so their default package versions stay on the current Hiverelay line.

## Current Baseline

Authoritative Hiverelay package line:

- `p2p-hiverelay` `0.20.2`
- `p2p-hiverelay-client` `0.20.2`
- `p2p-hiverelay-verifier` `0.20.2`

The current package split is:

- App SDK: `import { HiveRelayClient } from 'p2p-hiverelay-client'`
- Core relay package: `p2p-hiverelay`
- Core deep services/protocols: `p2p-hiverelay/core/services/index.js` and
  `p2p-hiverelay/core/protocol/forward-relay.js`

The old `p2p-hiverelay/client` import path is not part of the 0.20.2 package
surface. Consumers using that path must move to `p2p-hiverelay-client`.

## Consumers

| Consumer | Current pin | Current usage | 0.20.2 action |
| --- | --- | --- | --- |
| `01-browser/pearbrowser-desktop` | published-app default `latest` for `p2p-hiverelay`, `p2p-hiverelay-client`, and `p2p-hiverelay-verifier`, guarded to resolve `0.20.2` | Release-critical bundled browser; publishing, seeding, relay checks, signed capability verification, DHT relay records, index-room hydration, and the built-in HiveRelay catalog entry | Ready for guarded latest sync after npm publish. Local mode still points at workspace packages; the built-in catalog and catalog seed advertise HiveRelay `0.20.2`; desktop CI checks out `bigdestiny2/P2P-Hiverelay@v0.20.2`. |
| `02-apps/pearpaste` | published-app default `latest` for `p2p-hiverelay` and `p2p-hiverelay-client`, guarded to resolve `0.20.2` | Encrypted availability layer in `backend/relay-service.js`, release pinning in `scripts/pin-on-hiverelay.js`, circuit/pairing helpers | Ready for guarded latest sync after npm publish. `test/unit/hiverelay-upgrade.test.js` guards the split-client import and prevents stale local-only guidance. |
| `02-apps/pear-pos` | published-app default `latest` for optional `p2p-hiverelay` and `p2p-hiverelay-client`, guarded to resolve `0.20.2` | Optional app relay integration for Pear POS availability/publish flows | Ready for guarded latest sync after npm publish. Local-mode lockfile checks keep old monorepo-root records from returning. |
| `02-apps/pear-tickets` | published-app default `latest` for `p2p-hiverelay` and `p2p-hiverelay-client`, guarded to resolve `0.20.2` | Event app publishing, catalog republish, and mobile bundle defer paths | Ready for guarded latest sync after npm publish; local mode remains available for checkout-to-checkout testing. |
| `03-sites/pearbrowser-publishers/src/p2pbuilders` | published-app default `latest` for `p2p-hiverelay` and `p2p-hiverelay-client`, guarded to resolve `0.20.2` | `src/terminal/main.js`, `scripts/publish.js`, `scripts/seed-pear.js`, and `scripts/probe-relays.mjs` import `p2p-hiverelay-client` | Ready for guarded latest sync after npm publish; `test/m12-hiverelay-client-migration.js` prevents the removed `p2p-hiverelay/client` subpath from returning. Still needs live publish/seed smoke before claiming public p2pbuilders release availability. |
| `04-experiments/Opengit/packages/opengit-relay` | published-app default `latest` for optional `p2p-hiverelay` and `p2p-hiverelay-client`, guarded to resolve `0.20.2` | Optional `--use-hiverelay` path in `lib/relay.js` dynamically imports the split client and calls `seed()`/`unseed()` | Ready for guarded latest sync after npm publish; `packages/opengit-relay/test/relay.test.js` guards the ESM optional bridge while preserving the default Apache-2.0 native relay path. Escalated Opengit relay tests and full Opengit `npm test` passed with local socket permissions. |
| `04-experiments/anongpt-native` | published-app default `latest` for `p2p-hiverelay`, guarded to resolve `0.20.2` | App entry and seller/test scripts import `p2p-hiverelay/core/services/index.js`; relay/onion and directory scripts import `ForwardRelay` and `SignedDirectory` through package subpaths | Ready for guarded latest sync after npm publish; `test/hiverelay-upgrade.test.cjs` guards service, forward-relay, signed-directory resolution and rejects absolute checkout imports. |
| `04-experiments/hiverelay-test` | published-app default `latest` for `p2p-hiverelay` and `p2p-hiverelay-client`, guarded to resolve `0.20.2` | Local smoke app for offline and live HiveRelay client checks | Ready for guarded latest sync after npm publish; local mode remains available for offline smoke loops. |

## Snapshot Defaults

| Snapshot | Required default | Guard |
| --- | --- | --- |
| `00-core/hr-acct` | root, core, client, services, verifier packages at `0.20.2`; client/services depend on `p2p-hiverelay` `^0.20.2` | `npm run audit:ecosystem-consumers` snapshot/default version checks |
| `00-core/hr-fleet` | root, core, client, services, verifier packages at `0.20.2`; client/services depend on `p2p-hiverelay` `^0.20.2` | `npm run audit:ecosystem-consumers` snapshot/default version checks |
| `00-core/hr-release` | root, core, client, services, verifier packages at `0.20.2`; client/services depend on `p2p-hiverelay` `^0.20.2` | `npm run audit:ecosystem-consumers` snapshot/default version checks |

## Verification Expectations

For every app migration:

1. Package manifest and lockfile point at npm `latest` resolved to the intended
   0.20.2 package line, or at local Hiverelay workspace links only in explicit
   local mode.
2. Import paths match the current split package surface.
3. The app still degrades cleanly when HiveRelay is optional or unavailable.
4. Seed/publish flows prove at least one relay acceptance in a local or live
   smoke test.
5. Security tests still prove that app plaintext is not exported to relays.
6. `npm run ecosystem:sync -- --check` is green after npm publish or blocked
   only by a clearly stale npm `latest` dist-tag.
7. `npm run ecosystem:sync:local -- --check` reports no pending local-mode app
   default writes during checkout-to-checkout testing.
8. `npm run audit:ecosystem-consumers` is updated in the same change when a new
   direct consumer is added or a package path legitimately moves.
9. Lockfiles do not retain stale monorepo-root HiveRelay records or old
   split-package ranges.

## Current Verification Snapshot

The latest local review verified the direct app consumers against the 0.20.2
package surface:

- Hiverelay: `npm test`, `npm run lint`, `npm audit --audit-level=high`,
  `npm run audit:workspace`, `npm run ecosystem:sync:local -- --check`, and
  `npm run audit:ecosystem-consumers:local` pass. The local ecosystem sync
  reports no pending app package, lockfile, or versioned source-marker writes.
  The default published-app `npm run ecosystem:sync -- --check` remains blocked
  until npm `latest` resolves to `0.20.2`; release automation now publishes npm
  before app-consumer metadata sync so a normal full release can clear that
  block without downgrading apps. The
  ecosystem audit reports lockfile migration checks as `ok` for all eight
  current direct consumers and source-level checks for PearBrowser catalog
  metadata, PearPaste customer docs/probes, anonGPT relay/onion architecture,
  anonGPT's production HiveRelay forward-service client contract, and Pear POS bridge docs/comments
  so package defaults cannot quietly drift back to old client guidance.
  It also reports snapshot/default version checks as `ok` for
  `hr-acct`, `hr-fleet`, and `hr-release`.
- PearPaste: `npm test`, `npm run lint`, `npm audit --audit-level=high`,
  `npm run preflight:linux`, `npm run preflight:mac`, `npm run preflight:win`,
  and `npm run package` pass. The app uses npm overrides for `tar` and `tmp` so
  Electron Forge / Pear Electron Forge maker build-tool chains resolve to
  patched package lines.
- Pear POS: `npm test`, `npm ls p2p-hiverelay p2p-hiverelay-client`, and
  `npm audit --audit-level=high` pass. The app uses an npm `overrides.ws` pin
  so WDK / `ethers` resolve to `ws@8.21.0`; npm still reports four low-severity
  `elliptic` findings through the BTC wallet path, and the npm registry reports
  `elliptic@6.6.1` as the latest available line.
- Pear Tickets: `npm test`, `npm ls p2p-hiverelay p2p-hiverelay-client`, and
  install/audit with the refreshed local links pass.
- `04-experiments/hiverelay-test`: `npm run smoke` and
  `npm ls p2p-hiverelay p2p-hiverelay-client` pass.
- anonGPT: `npm test`, `npm run check`, and `npm audit --audit-level=high` pass.
  The app uses an npm `overrides.ws` pin so WDK / `ethers` resolve to
  `ws@8.21.0` instead of vulnerable nested `ws@8.17.1` copies.

## Known Boundaries

- Snapshot relay worktrees under `00-core/hr-acct`, `00-core/hr-fleet`, and
  `00-core/hr-release` are not direct app consumers, but their package
  manifests and root lockfiles must stay on the current Hiverelay default line.
  Historical notes inside those trees may still mention older shipped tags when
  they are describing past releases.
- PearBrowser mobile is a wire-contract consumer, not a direct package
  consumer. Keep its HTTP/HTTPS gateway path, capability reads, catalog reads,
  and signed metadata behavior green separately.
