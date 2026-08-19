# Blindspark — Umbrel App Store submission checklist

Track pre-submission work here. Nothing below blocks running the app on
your own box; it all blocks the `getumbrel/umbrel-apps` PR.

## Assets

- [x] **Icon** — `icon.svg` is the yellow-spark mark (256×256, no rounded
  corners, no payment imagery). Optionally refine with a designer before
  submission, but it is shippable as-is.
- [x] **First-submission gallery manifest** — keep `gallery: []` in
  `umbrel-app.yml`; `npm run umbrel:check-gallery` accepts this empty list
  because the Umbrel team commits official gallery assets separately.
- [ ] **Reviewer handoff screenshots** — capture 3–5 real screenshots at
  1440×900 and attach them to the official PR/comment when requested. If the
  screenshots are ever listed in this repo, run `npm run umbrel:check-gallery`;
  listed files must be regular PNG/JPEG files, the gallery directory and listed
  files must not be symlinks, and assets must stay below the bounded
  asset-size gate.

## Image

- [x] **Digest pin shape** — `docker-compose.yml` uses an image tag plus
  sha256 digest instead of `latest`.
- [ ] **Release-aligned digest** — the compose pin must name the release
  actually under submission (`v0.26.0-rc.3` now; `v0.26.0` at GA). Run
  `npm run release:prepare -- v<version> --image-digest sha256:<digest>` after
  the multi-arch image is published so the tag and digest move together.
- [ ] **Multi-arch** — confirm the fixed published tag has both `linux/amd64`
  and `linux/arm64` manifests. Full releases run
  `npm run release:check-image-manifest` and publish
  `release-image-manifest-evidence.json`; for a manual re-check, pass the
  tag+digest image ref with `--out release-image-manifest-evidence.json`.
- [ ] **Release image smoke** — run `npm run release:smoke-image` against the
  exact fixed `ghcr.io/...:<semver>@sha256:<digest>` ref and publish
  `release-image-smoke-evidence.json`.

For a manual re-check of the pinned image, inspect the exact release tag
under submission:

  ```bash
  docker buildx imagetools inspect ghcr.io/bigdestiny2/p2p-hiverelay:<version>
  ```

## Verify on a real Umbrel box

- [ ] App installs and starts; the dashboard loads through the app proxy and
  the live status/feed updates without URL-token WebSocket auth.
- [ ] First-run wizard loads, names the relay, sets accept-mode, and
  completes — i.e. the `HIVERELAY_UI_EXPOSE_TOKEN` bearer path works end
  to end behind `app_proxy` (this is the mechanism this package adds).
- [ ] Wizard/setup actions show a visible in-flight/status state and cannot be
  double-submitted while a save is pending.
- [ ] Add-wallet shows a visible busy/status state, persists the destination,
  and does not look like a silent page refresh/no-op.
- [ ] Payout Add/Change/copy controls behave as buttons through the app proxy
  and do not trigger page navigation or refresh.
- [ ] Management actions from the dashboard (approve/reject a seed
  request, change accept-mode) succeed — confirms the bearer token is
  accepted on `/api/wizard/*` and the management routes.
- [ ] Service manager save/restart actions show visible in-flight or restart
  pending state until the selected providers are running.
- [ ] AI model add shows inline status, disables duplicate submits while
  pending, and preserves provider errors in the service manager UI.
- [ ] Browser/devtools check: dashboard WebSocket clients send an in-band
  auth frame and no `/ws?token=` or `/ws?api_key=` URL appears.
- [ ] Fresh install reports the Services layer disabled and starts none of the
  optional outbox, notification, shard-store, proof, VRF, or witness providers.
  Treat any service-provider test as a separate, explicit operator opt-in and
  return the package to its stock configuration afterwards.
- [ ] `/data` is writable by uid 999. If the relay logs storage/permission
  errors on first boot, the app data dir needs to be owned by 999 (or the
  service run with an init that chowns it) — resolve before submission.
- [ ] Reinstall test: uninstall + reinstall preserves the relay's public
  key (identity derived from `$APP_SEED`).
- [ ] Write the public-safe manual review artifact after the real-device pass:
  `npm run umbrel:write-runtime-review -- --out umbrel-runtime-review-evidence.json
  --release v<release-under-submission> --device "<public device label>" --umbrel-version <version>
  --tested-by <public reviewer> --public-key-before <hex> --public-key-after
  <hex> --checks installedThroughUmbrel,dashboardProxyLoads,liveFeedInBandAuth,noWebSocketUrlTokens,wizardCompletes,setupActionLockObserved,addWalletPersists,dynamicPayoutControlsObserved,walletBusyStateObserved,managementActionsPersist,serviceActionStateObserved,serviceRestartPendingObserved,aiModelAddStateObserved,reviewModeDefault,dataWritableUid999,reinstallPreservesPublicKey`.
  Then verify it with `npm run umbrel:verify-runtime-review -- --evidence
  umbrel-runtime-review-evidence.json --release v<release-under-submission>`.
  Do not include local URLs, LAN IPs, APP_SEED, bearer tokens, or API keys.

## Decisions to confirm before submission

- [x] **Default accept-mode.** Umbrel now sets `HIVERELAY_ACCEPT_MODE=review`
  at the package level, and the CLI honors it. Fresh installs queue seed
  requests for operator approval until the owner switches modes from setup or
  the dashboard, which avoids unattended disk fill on home boxes.
- [x] **Storage cap.** Core/VPS default stays 50 GB, but the Umbrel package sets
  `HIVERELAY_MAX_STORAGE=10GB` for a conservative home-box first install.
  Saved operator config wins on later restarts.
- [x] **Services default.** The stock package is an edge/community relay, not a
  service farm. `HIVERELAY_ENABLE_SERVICES` and every packaged utility-service
  flag are `"false"`; providers run only after the owner explicitly selects
  them and restarts.

## Open the PR

- [ ] Fork `getumbrel/umbrel-apps`, add this directory as `blindspark/`.
- [ ] Open the PR; paste its URL into `umbrel-app.yml` → `submission:`
  (replace the `PENDING` placeholder).
- [ ] Copy only `umbrel-app.yml`, `docker-compose.yml`, and `data/.gitkeep`
  into the official PR. Keep this README, checklist, icon, and gallery notes
  in the HiveRelay repo unless an Umbrel reviewer asks for them separately.
- [ ] Respond to reviewer feedback (gallery design help is offered by the
  Umbrel team if screenshots aren't pixel-perfect).
