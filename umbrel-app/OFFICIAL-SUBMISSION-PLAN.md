# Blindspark — Official Umbrel App Store Submission Plan

Target repo: `getumbrel/umbrel-apps` (the **official** store, not a community store).
The repo's current `README.md` points package authors to `AGENTS.md`, which routes
new app packages through its repo-local `umbrel-package-app` and `umbrel-test-app`
skills. This plan mirrors those rules: useful web UI, multi-arch tag+digest image
pin, app data under `${APP_DATA_DIR}`, app_proxy auth by default, no broad host
access, and real Umbrel lifecycle testing before PR.

This is an ordered, do-this-then-that guide. Work top to bottom.

---

## 0. Pre-flight understanding (read once)

The official store differs from a community store in three ways that this package
currently gets wrong:

1. **No `icon:` URL field, and no icon/gallery files in the code PR.** The icon
   (`icon.svg`) and screenshots (`1.jpg`–`3.jpg`) live in a *separate* repo,
   `getumbrel/umbrel-apps-gallery/blindspark/`, and are committed by the **Umbrel
   team**, not the submitter. Your manifest carries `gallery: []` (empty) on first
   submission and **no** `icon:` field at all.
2. **`releaseNotes` must be empty (`""`) on first submission** — a non-empty value
   is a hard CI **error**.
3. **`submission:` must equal the exact URL of your PR** — a placeholder is a hard
   CI **error**.

The Docker image reference is structurally correct but not submission-ready:
`ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1`
is multi-arch (amd64 + arm64) and digest-pinned in `docker-compose.yml`.
However, `docs/RELEASE_IMAGE_SMOKE_2026-06-24.md` records that this published
digest is smoke-red because it predates the dashboard WebSocket same-origin fix.
Before opening the official PR, publish a fixed GHCR digest through the release
workflow (or an explicitly approved manual release path), rerun the manifest and
image-smoke evidence checks, and update the package pin.

---

## 1. Manifest state (`umbrel-app.yml`)

Already aligned for a first official submission:

- `manifestVersion: 1.1`
- `gallery: []` — Umbrel commits official gallery assets separately.
- `releaseNotes: ""` — first submissions leave release notes empty.
- no `icon:` field — official icons live outside the package repo.

Still required after opening the PR:

- Replace `submission: https://github.com/getumbrel/umbrel-apps/pull/PENDING`
  with the exact PR URL. The placeholder is expected in this repo, but it will
  fail official CI if copied unchanged into the final PR.

### Already-correct fields (do not change)
- `id: blindspark` — kebab-case, no `umbrel-app-store` prefix, not in its own deps. OK.
- `category: networking` — valid enum value. OK.
- `tagline: A blind relay that keeps peer-to-peer apps online` — no trailing period, ≤100 chars. OK.
- `name`, `developer`, `submitter: bigdestiny2` — within length limits. OK.
- `website` / `repo` / `support` — valid URLs. OK.
- `version: "0.20.0"` — matches the pinned image tag. OK.
- `port: 9100` — valid range. **Verify it is unused store-wide** (see Step 3).
- `path: ""`, `defaultUsername: ""`, `defaultPassword: ""`, `dependencies: []` — OK.
- No `icon:` field present — correct for the official store. Do **not** add one.

---

## 2. Version and image

The package currently pins
`ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0@sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1`,
and `umbrel-app.yml` uses `version: "0.20.0"`. Keep the manifest version, image
tag, and multi-arch manifest digest together, but do not submit this exact
digest until a fixed public image smoke is green.

For a newer release, let `release-surfaces.yml` publish the image, smoke the exact
digest, and run `npm run release:prepare -- vX.Y.Z --image-digest sha256:...`.
For a same-version repair, treat the tag overwrite as a release action requiring
explicit operator approval, then capture fresh `release-image-manifest-evidence`
and `release-image-smoke-evidence` for the new digest.

---

## 3. Pick / confirm a free UI port

`port: 9100` must be unique across the entire official store
(`duplicate_ui_port` is a CI **error**). Before opening the PR, search the store:
```bash
# From a clone of getumbrel/umbrel-apps:
grep -rn "^port: 9100" --include=umbrel-app.yml .
```
If anything matches, pick an unused port and update `umbrel-app.yml` → `port:`
(the in-container `APP_PORT` in `docker-compose.yml` stays 9100 — they are
independent; only the manifest `port` must be store-unique). Maintainers may
reassign anyway, but starting clean avoids a round-trip.

---

## 4. docker-compose.yml — structurally conformant; refresh image proof

Verified against the linter rules — structurally green:
- `app_proxy` present with `APP_HOST: blindspark_web_1` (= `<app-id>_<service>_1`)
  and `APP_PORT: 9100`. OK.
- Image is `name:tag@sha256:digest`, multi-arch, no `latest`. Shape OK; current
  digest is not runtime-green and must be replaced before official submission.
- `restart: on-failure`, `stop_grace_period: 1m`. OK.
- No `user:` pin — intentional. The image entrypoint starts as root only to fix
  bind-mounted `/data` ownership, then drops to uid 999 with `gosu`.
- No `ports:` host mappings, no `network_mode: host`, no docker socket. OK.
- Volume `${APP_DATA_DIR}/data:/data` — under a subdirectory, not the root. OK.
- Boolean `HIVERELAY_UI_EXPOSE_TOKEN: "true"` is quoted. OK.
- `HIVERELAY_ACCEPT_MODE: review` is set so a fresh home-server install queues
  new seed requests until the owner chooses otherwise. OK.
- `HIVERELAY_MAX_STORAGE: 10GB` gives the edge/community package a conservative
  first-boot relay-storage cap. OK.
- `HIVERELAY_CAPACITY_PROFILE: edge-community` declares the package's planning
  profile for capacity/status reporting; it does not claim physical per-pool
  enforcement. OK.
- `HIVERELAY_ENABLE_SERVICES` and every packaged utility-service flag are
  `"false"`. The stock package is a community edge, not a service farm;
  persistent service providers require an explicit owner selection in the
  dashboard followed by restart. OK.
- `${APP_SEED}` used for deterministic identity. OK.

`data/.gitkeep` is committed, matching the canonical clean package pattern
(`umbrel-app.yml`, `docker-compose.yml`, `data/.gitkeep`).

---

## 5. Decide what files go in the PR

The official PR should contain **only**:
```
blindspark/umbrel-app.yml
blindspark/docker-compose.yml
blindspark/data/.gitkeep        # optional but recommended
```
Do **NOT** include in the official PR:
- `icon.svg` — goes to the gallery repo (Step 7), handled by the team.
- `gallery/` (incl. `PLACEHOLDER.md`) — gallery is team-owned.
- `README.md` — this is your packaging doc, not part of the app entry.
- `SUBMISSION-CHECKLIST.md` / `OFFICIAL-SUBMISSION-PLAN.md` — internal docs.

Keep those internal docs in *your* `hiverelay` repo; just don't copy them into the
`blindspark/` folder inside the `umbrel-apps` fork.

---

## 6. Fork, branch, add the app, open the PR

```bash
# Fork via gh, then clone YOUR fork
gh repo fork getumbrel/umbrel-apps --clone
cd umbrel-apps
git checkout master
git pull upstream master 2>/dev/null || git pull origin master
git checkout -b add-blindspark

# Create the app directory with ONLY the allowed files
mkdir -p blindspark/data
cp ~/hiverelay/umbrel-app/umbrel-app.yml      blindspark/umbrel-app.yml
cp ~/hiverelay/umbrel-app/docker-compose.yml  blindspark/docker-compose.yml
touch blindspark/data/.gitkeep

git add blindspark
git commit -m "Add Blindspark — blind relay for the Pear/Holepunch P2P ecosystem"
git push -u origin add-blindspark
```

Open the PR against `getumbrel/umbrel-apps:master`. There is no PR template; write a
description containing:
- App name: **Blindspark** (HiveRelay).
- What it does: an always-on blind relay that seeds encrypted Hyperdrives for the
  Pear / Holepunch P2P ecosystem; stores ciphertext it cannot read.
- Device(s) tested on: e.g. Raspberry Pi 5 / Umbrel Home / Linux VM (state which).
- Confirmation that **data persists across restart/reinstall** (identity derived
  from `$APP_SEED`).
- Confirmation that the live dashboard feed works through Umbrel's `app_proxy`
  without `/ws?token=` or `/ws?api_key=` URL credentials.

```bash
gh pr create \
  --repo getumbrel/umbrel-apps \
  --base master \
  --head <your-gh-username>:add-blindspark \
  --title "Add Blindspark — blind relay for the Pear/Holepunch P2P ecosystem" \
  --body-file -  # paste the description above
```

### 6a. Set `submission:` to the real PR URL (closes the CI error)
```bash
# Copy the PR URL from the gh output, then:
# edit blindspark/umbrel-app.yml ->
#   submission: https://github.com/getumbrel/umbrel-apps/pull/<NUMBER>
git add blindspark/umbrel-app.yml
git commit -m "Set submission field to PR URL"
git push
```
This must match the PR exactly or `invalid_submission_field` keeps failing CI.

---

## 7. Gallery repo / icon — provide assets, let the team commit them

You do **not** open a PR to `getumbrel/umbrel-apps-gallery`; the Umbrel team
creates `umbrel-apps-gallery/blindspark/` with `icon.svg`, `1.jpg`, `2.jpg`,
`3.jpg`. Your job is to have real assets ready to hand over when asked.

- **Icon:** the existing `icon.svg` is adequate — 256×256 viewBox + width/height,
  a plain `<rect>` background with no `rx`/`ry` (no rounded corners), no payment
  imagery. Keep it ready to attach; the team will place it as `icon.svg`.
- **Gallery:** the gallery currently has only `PLACEHOLDER.md`. **You must capture
  3–5 real screenshots** at 1440×900 (16:10), PNG — dashboard, first-run wizard,
  seed-request review queue (see `gallery/PLACEHOLDER.md` for the shot list). The
  team optimizes them and commits as `1.jpg`–`3.jpg`. Attach them to the PR (or a
  comment) when the reviewer asks ("awaiting gallery assets").

After the team commits the assets, they set `gallery: [1.jpg, 2.jpg, 3.jpg]` in
your manifest and merge. Until then the listing renders blank — this is normal.

---

## 8. Pre-submission self-test (reviewer expects this)

On a real Umbrel box (or local sideload), confirm:
- App installs and the dashboard loads through `app_proxy`.
- The live dashboard feed updates through WebSocket after in-band auth, and no
  `/ws?token=` or `/ws?api_key=` URL appears in browser devtools.
- First-run wizard completes (names relay, picks accept-mode) — exercises the
  `HIVERELAY_UI_EXPOSE_TOKEN` bearer path behind the proxy.
- Management actions (approve/reject seed request, change accept-mode) work.
- Fresh install starts in review mode before the operator changes it.
- Fresh install reports the Services layer disabled and starts none of the
  optional outbox, notification, shard-store, proof, VRF, or witness providers.
  If service opt-in is tested separately, turn on only a deliberately selected
  provider, restart, record the result, and turn it off again before capturing
  the stock-package evidence.
- `/data` is writable by uid 999 (no permission errors on first boot).
- Uninstall + reinstall preserves the relay's public key (identity from `$APP_SEED`).

After the pass, write a public-safe evidence sidecar from the repo root:

```sh
npm run umbrel:write-runtime-review -- \
  --out umbrel-runtime-review-evidence.json \
  --release v0.20.0 \
  --device "<public device label>" \
  --umbrel-version <version> \
  --tested-by <public reviewer> \
  --public-key-before <hex> \
  --public-key-after <hex> \
  --checks installedThroughUmbrel,dashboardProxyLoads,liveFeedInBandAuth,noWebSocketUrlTokens,wizardCompletes,setupActionLockObserved,addWalletPersists,walletBusyStateObserved,managementActionsPersist,serviceActionStateObserved,serviceRestartPendingObserved,aiModelAddStateObserved,reviewModeDefault,dataWritableUid999,reinstallPreservesPublicKey
```

Then verify the artifact:

```sh
npm run umbrel:verify-runtime-review -- \
  --evidence umbrel-runtime-review-evidence.json \
  --release v0.20.0
```

The writer stores only public-safe facts and a SHA-256 of the relay public key.
The verifier catches release/PR drift, missing/duplicate/failed checks, raw
public-key fields, local URLs, LAN IP addresses, APP_SEED, bearer tokens, and
API keys. State the device you tested on in the PR description and attach the
evidence sidecar if the reviewer asks for runtime proof.

---

## 9. Respond to review

Single human reviewer (`nmfretz`); expect days-to-weeks. Likely asks:
- Provide real (non-placeholder) gallery screenshots.
- Possibly reassign `port` to avoid a conflict.
- Possibly minor description/tagline wording.

Updates after launch are trivial: a PR bumping `version`, the image digest, and
`releaseNotes` in `umbrel-app.yml`.

---

## Quick checklist

- [ ] `gallery: []` (Step 1a)
- [ ] `releaseNotes: ""` (Step 1b) — **CI error if not**
- [ ] `manifestVersion: 1.1` (Step 1c)
- [ ] No `icon:` field in manifest (already absent — keep it absent)
- [x] Package uses a digest-pinned `name:tag@sha256:digest` image ref (Step 2)
- [ ] Package points at a fixed public digest whose manifest and image smoke
  evidence are green (Step 2)
- [x] Fresh installs default to review-mode seed acceptance (Step 4)
- [ ] `port: 9100` confirmed unused store-wide (Step 3)
- [ ] `blindspark/data/.gitkeep` committed (Step 4)
- [ ] PR contains ONLY `umbrel-app.yml` + `docker-compose.yml` (+ `data/.gitkeep`) (Step 5)
- [ ] PR opened against `getumbrel/umbrel-apps:master` (Step 6)
- [ ] `submission:` set to the real PR URL (Step 6a) — **CI error if not**
- [ ] Real 1440×900 screenshots captured, ready for the team (Step 7)
- [ ] Self-tested on a real box; persistence-across-restart confirmed and
  `umbrel-runtime-review-evidence.json` written (Step 8)
