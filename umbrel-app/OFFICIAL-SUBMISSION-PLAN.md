# Blindspark — Official Umbrel App Store Submission Plan

Target repo: `getumbrel/umbrel-apps` (the **official** store, not a community store).
Single CI gate: the `Lint apps` GitHub Action (`sharknoon/umbrel-app-linter-action`).
`error`-severity rules block merge; `warning`/`info` do not block but maintainers
will request changes for them.

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

The Docker image is already correct: `ghcr.io/bigdestiny2/p2p-hiverelay:0.14.0`
is multi-arch (amd64 + arm64) and its `@sha256:` digest pin in `docker-compose.yml`
is verified correct. **Do not touch the image unless you choose to bump the version
(see Step 2, optional).**

---

## 1. Fix the manifest (`umbrel-app.yml`) — required before opening the PR

Apply these edits. Every one except `submission:` can be done now; `submission:`
is filled after the PR exists (Step 4).

### 1a. Empty the gallery (warning → fix now)
```yaml
# BEFORE
gallery:
  - 1.png
  - 2.png
  - 3.png
# AFTER
gallery: []
```
Reason: `filled_out_icon_or_gallery_on_first_submission` (warning). The team
creates the gallery in the gallery repo.

### 1b. Empty releaseNotes (ERROR → must fix)
```yaml
# BEFORE
releaseNotes: >-
  First App Store release of Blindspark ...
# AFTER
releaseNotes: ""
```
Reason: `filled_out_release_notes_on_first_submission` (**error**, blocks merge).
`releaseNotes` is only populated on later version-bump update PRs.

### 1c. Bump manifestVersion to 1.1 (polish)
```yaml
# BEFORE
manifestVersion: 1
# AFTER
manifestVersion: 1.1
```
Reason: schema accepts `1`, `1.1`, or `1.2`; all current real apps use `1.1` and
it is required for lifecycle hooks. `1` will not fail CI, but `1.1` is the norm.

### 1d. `submission:` — placeholder is an ERROR (fixed in Step 4)
Leave it as-is for now; you cannot know the PR URL until the PR exists. It will be
set to the real URL in Step 4. The current `.../pull/PENDING` value WILL fail CI if
left in, so do not forget Step 4.

### Already-correct fields (do not change)
- `id: blindspark` — kebab-case, no `umbrel-app-store` prefix, not in its own deps. OK.
- `category: networking` — valid enum value. OK.
- `tagline: A blind relay that keeps peer-to-peer apps online` — no trailing period, ≤100 chars. OK.
- `name`, `developer`, `submitter: bigdestiny2` — within length limits. OK.
- `website` / `repo` / `support` — valid URLs. OK.
- `version: "0.14.0"` — matches the pinned image tag. OK (unless you bump, Step 2).
- `port: 9100` — valid range. **Verify it is unused store-wide** (see Step 3).
- `path: ""`, `defaultUsername: ""`, `defaultPassword: ""`, `dependencies: []` — OK.
- No `icon:` field present — correct for the official store. Do **not** add one.

---

## 2. (Optional) Version decision — pin 0.14.0 or rebuild 0.15.6

The repo is at `0.15.6` but this package pins image `0.14.0`. Both are *valid*:
the linter only requires `name:tag@sha256:digest`, multi-arch, and that
`version:` is a non-empty string. It does NOT require the version to match the repo.

- **Acceptable as-is:** ship `version: "0.14.0"` + the verified `0.14.0` digest.
  The package is internally consistent and will pass CI.
- **Recommended:** publish a fresh `0.15.6` multi-arch image and pin that, so the
  store launches with current code (corruption-resilience + eviction fixes from
  `0.15.x`). Implication: shipping `0.14.0` means users install old code on day one,
  then you immediately need an update PR to reach parity — extra round-trip.

If you bump, do all of:
```bash
# Build + publish multi-arch 0.15.6 to ghcr (from the image repo, not this dir)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/bigdestiny2/p2p-hiverelay:0.15.6 \
  --output type=registry .

# Grab the MULTI-ARCH MANIFEST digest (the top-level one, not an arch-specific one)
docker buildx imagetools inspect ghcr.io/bigdestiny2/p2p-hiverelay:0.15.6
```
Then update `umbrel-app.yml` → `version: "0.15.6"` and `docker-compose.yml` →
`image: ghcr.io/bigdestiny2/p2p-hiverelay:0.15.6@sha256:<new-multiarch-digest>`.
Keep `version` and the image tag identical (the immich convention).

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

## 4. docker-compose.yml — already conformant; one optional add

Verified against the linter rules — all green:
- `app_proxy` present with `APP_HOST: blindspark_web_1` (= `<app-id>_<service>_1`)
  and `APP_PORT: 9100`. OK.
- Image is `name:tag@sha256:digest`, multi-arch, no `latest`. OK.
- `restart: on-failure`, `stop_grace_period: 1m`. OK.
- `user: "999:999"` — non-root. OK (linter only flags root/unset at info level).
- No `ports:` host mappings, no `network_mode: host`, no docker socket. OK.
- Volume `${APP_DATA_DIR}/data:/data` — under a subdirectory, not the root. OK.
- Boolean `HIVERELAY_UI_EXPOSE_TOKEN: "true"` is quoted. OK.
- `${APP_SEED}` used for deterministic identity. OK.

**Optional (silences an info-level `missing_file_or_directory`):** the bind-mount
target subdir should exist as a committed placeholder.
```bash
mkdir -p blindspark/data
touch blindspark/data/.gitkeep
```
This matches the canonical clean 3-file pattern (`umbrel-app.yml`,
`docker-compose.yml`, `data/.gitkeep`).

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
cp /Users/localllm/hiverelay/umbrel-app/umbrel-app.yml      blindspark/umbrel-app.yml
cp /Users/localllm/hiverelay/umbrel-app/docker-compose.yml  blindspark/docker-compose.yml
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
- First-run wizard completes (names relay, picks accept-mode) — exercises the
  `HIVERELAY_UI_EXPOSE_TOKEN` bearer path behind the proxy.
- Management actions (approve/reject seed request, change accept-mode) work.
- `/data` is writable by uid 999 (no permission errors on first boot).
- Uninstall + reinstall preserves the relay's public key (identity from `$APP_SEED`).

State the device you tested on in the PR description.

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
- [ ] (Optional) bump to `0.15.6` image + version (Step 2)
- [ ] `port: 9100` confirmed unused store-wide (Step 3)
- [ ] `blindspark/data/.gitkeep` committed (Step 4)
- [ ] PR contains ONLY `umbrel-app.yml` + `docker-compose.yml` (+ `data/.gitkeep`) (Step 5)
- [ ] PR opened against `getumbrel/umbrel-apps:master` (Step 6)
- [ ] `submission:` set to the real PR URL (Step 6a) — **CI error if not**
- [ ] Real 1440×900 screenshots captured, ready for the team (Step 7)
- [ ] Self-tested on a real box; persistence-across-restart confirmed (Step 8)
