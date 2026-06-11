# Blindspark — Umbrel App Store submission checklist

Track pre-submission work here. Nothing below blocks running the app on
your own box; it all blocks the `getumbrel/umbrel-apps` PR.

## Assets

- [ ] **Icon** — replace `icon.svg` (256×256, no rounded corners, no
  Lightning/payment imagery). The current file is a labelled placeholder.
- [ ] **Gallery** — add 3–5 screenshots to `gallery/` at 1440×900 and
  match the filenames in `umbrel-app.yml` (`1.png`, `2.png`, `3.png`).
  See `gallery/PLACEHOLDER.md` for suggested shots.

## Image

- [ ] **Digest pin** — in `docker-compose.yml`, replace
  `@sha256:__REPLACE_WITH_DIGEST_AFTER_CI__` with the real digest once CI
  has published the tag:
  ```bash
  docker buildx imagetools inspect ghcr.io/bigdestiny2/p2p-hiverelay:0.12.0
  ```
- [ ] **Multi-arch** — confirm the published tag has both `linux/amd64`
  and `linux/arm64` manifests (the `docker-publish.yml` workflow builds
  both; the inspect command above lists them).

## Verify on a real Umbrel box

- [ ] App installs and starts; the dashboard loads through the app proxy.
- [ ] First-run wizard loads, names the relay, sets accept-mode, and
  completes — i.e. the `HIVERELAY_UI_EXPOSE_TOKEN` bearer path works end
  to end behind `app_proxy` (this is the mechanism this package adds).
- [ ] Management actions from the dashboard (approve/reject a seed
  request, change accept-mode) succeed — confirms the bearer token is
  accepted on `/api/wizard/*` and the management routes.
- [ ] `/data` is writable by uid 999. If the relay logs storage/permission
  errors on first boot, the app data dir needs to be owned by 999 (or the
  service run with an init that chowns it) — resolve before submission.
- [ ] Reinstall test: uninstall + reinstall preserves the relay's public
  key (identity derived from `$APP_SEED`).

## Decisions to confirm before submission

- [ ] **Default accept-mode.** The relay's built-in default is
  auto-accept. For a home box, consider defaulting the wizard to "review"
  (operator approves each seed request) so a fresh install doesn't fill
  the disk unattended. If we want review-as-default at the package level
  (not just a wizard choice), wire it via config/env — currently the
  wizard is where the operator picks it.
- [ ] **Storage cap.** Image default is 50 GB. Decide whether to surface a
  smaller default for typical home boxes.

## Open the PR

- [ ] Fork `getumbrel/umbrel-apps`, add this directory as `blindspark/`.
- [ ] Open the PR; paste its URL into `umbrel-app.yml` → `submission:`
  (replace the `PENDING` placeholder).
- [ ] Respond to reviewer feedback (gallery design help is offered by the
  Umbrel team if screenshots aren't pixel-perfect).
