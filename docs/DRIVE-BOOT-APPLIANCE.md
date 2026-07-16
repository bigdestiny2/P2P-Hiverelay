# Drive-Boot Appliances — self-updating Blindspark on Umbrel & StartOS

**Status:** design / execution map (not yet approved for build)
**Author:** drafted from a 6-agent codebase + platform-policy recon, 2026-07-07
**Scope:** make the Umbrel and StartOS packages self-update the *app code* peer-to-peer over a signed hyperdrive, keeping the Docker image thin and rarely-changing — so appliance operators stop falling behind releases.

---

## 1. Why

The appliance channels drift. As of this writing the Umbrel community store sat at **0.20.0 for ~2 weeks** while the fleet ran v0.24.2, and the StartOS s9pk was frozen at **v0.18.1** — because every appliance update requires a human to (a) rebuild/publish an image, (b) bump a store repo or registry, and (c) click "Update" on the device. The bare-metal fleet does **not** have this problem: `fleet/updater.sh` + `fleet/channels.json` give it channel-based, health-gated, auto-rollback updates. Umbrel/StartOS are explicitly *outside* that system (`fleet/README.md:4-6`). **Drive-boot closes that gap** by giving the appliances the same auto-update property the fleet already enjoys, over a P2P transport that Blindspark is uniquely suited to run (it seeds Hyperdrives for a living).

## 2. The core insight — two layers

Umbrel and StartOS **only install Docker images**. That cannot change: there is no "Pear app" or "Bare app" install type on either platform. But **what runs inside the container is our choice.** So:

- **Outer layer (Docker, thin, rare):** a Node 22 / glibc image containing the runtime, native addons, and a small **loader** as the entrypoint. Bumped only when the runtime or a native dependency changes.
- **Inner layer (code drive, P2P, frequent):** the JS app (`packages/`, 3.8 MB) ships on a **signed hyperdrive**. The loader fetches, verifies, checks out, runs, and self-updates it — health-gated, with rollback.

This is the fleet updater's model with `git fetch/checkout` replaced by `hyperdrive.update()/checkout()`.

## 3. What we learned (grounding facts)

### 3.1 The entrypoint is already the Node CLI on both platforms
- Umbrel: `tini → docker-entrypoint.sh` (root chowns `/data` to uid 999, `exec gosu hiverelay`) → `node /app/packages/core/cli/index.js start` (`Dockerfile:156,160`; `umbrel-app/docker-compose.yml`).
- StartOS: s9pk-shipped `startos/docker_entrypoint.sh` runs **as root** (no gosu drop) → same `node …/cli/index.js start` (`startos/docker_entrypoint.sh:38`).
- **Bare is not viable for v1.** `bare-relay.js` is an explicitly reduced relay — 8 read-only HTTP routes, no dashboard, no PluginLoader, no `services.json`; its header says dashboard/TUI operators "run the Node version." All appliance env wiring (`HIVERELAY_UI_EXPOSE_TOKEN`, `HIVERELAY_UI_SIMPLE`, subsidy, outboxlog namespace) lives only in the Node CLI `start()`. **v1 loader boots the existing Node CLI from a drive checkout.** Bare is a later, headless-mesh optimization.

### 3.2 Identity is on `/data`, not derived from APP_SEED
The relay keypair is a random ed25519 generated on first run and persisted `0600` at `/data/relay-identity.json` (`relay-node/index.js:2424-2452`). `APP_SEED` only derives the **UI management token** (`HMAC-SHA256('hiverelay/ui-token/v1', APP_SEED)`, `config/loader.js:30-35`). Corestore, config, and identity all live under `/data`. **The loader swaps `/app` only; `/data` is never touched** → identity and data survive every code update automatically.

### 3.3 The native/ABI boundary is precise
- 8 native packages: `sodium-native`, `udx-native`, `fs-native-extensions`, `quickbit-native`, `simdle-native`, `crc-native`, `rabin-native`, `bare-module-lexer`. All **Node-API** (ABI-stable across Node majors), all prebuildify prebuilds, **no `binding.gyp`, nothing compiles at install**.
- **No musl targets** → glibc Debian base is mandatory (`Dockerfile:38-51`, issue #21).
- Sizes: `packages/` = **3.8 MB**; `node_modules` = 414 MB (dev-inclusive), prebuilds alone = 258 MB.
- **v1 boundary: the drive ships `packages/` only; `node_modules` stays baked in the image.** A change to app logic (pure JS) ships over the drive for free. A change to the *dependency graph* still needs an image + store bump — which is rare and acceptable. (A later v2 could ship linux-x64/arm64 prebuilds on the drive too, but only if the mirror target isn't `noexec` — `dlopen` needs an on-disk, executable path.)

### 3.4 Publish/seed/verify machinery already exists
- `ship.mjs` / `HiveRelayClient.publish/seed` publish a drive and prove durability (metadata + **separate blob-core** durability gates, `publish.mjs:144-167,224-303`). Archive tier (`durability=1`) is publisher-signature-committed and opts into AutoHeal (≥7 replicas / ≥4 regions).
- Relays pin bare cores via authenticated `POST /seed-core` with restart-persistent pins + 15-min DHT re-announce (`api-seed-core.js`, `seeder.js`).
- **A second signature layer already exists:** an offline-key-signed release manifest over `{file hashes, driveKey, version}` (`js/release-verify.js`, `scripts/sign-release.mjs`) plus the signed relay-roster and signed catalog-bee patterns. This is the natural analogue of the SSH-signed git tag.
- `hyperdrive.checkout(version)` gives **atomic versioned snapshots**; `update()`, `truncate(version)`, `getBlobsLength(checkout)` exist → swap + rollback primitives are already there.
- **Gap:** current publishers are static-file-list based; shipping runnable app code is still small (289 files/3.8 MB) but no consumer yet verifies a signed release manifest read *over hyper://* — the loader would be the first.

### 3.5 The updater invariants the loader MUST preserve (from `fleet/updater.sh`)
1. **Channel resolution** — a local, data-parsed (never sourced) channel name → a signed pointer → a validated version. Default to a conservative channel.
2. **Health gate** — `GET :9100/health` must show `"running":true` **and** `"version"` == the expected version, within 120 s (5 s poll, 8 s curl cap). Bearer key read from env/file via a `0600` header file.
3. **Rollback** — snapshot the current version *before* mutating; on health failure or dep failure, restore the prior version, restart, re-health-check, exit non-zero so the failure is recorded. "Always try to leave the box on the version it started from."
4. **Signed-tag verification** — fail-closed: only an **annotated, signed** tag from a known key is ever checked out; exit code alone is not trusted (must see a GOODSIG line). Break-glass env exists but is never standing.
5. **Operational** — single-flight lock, dirty-tree skip, jittered timer, post-success-only plain `git gc`, `--dry-run`/`--verify-only` modes.
6. **Footgun guard** — tag-name-minus-`v` must equal `package.json` version or every box auto-rolls-back; `release.sh` refuses mismatched/unsigned tags at cut time.

### 3.6 Platform update policy — the governance reality
- **Umbrel:** apps **never auto-update**; `umbreld` polls *all* store repos (official + community, identically) every **5 min**; an installed app shows "update available" only when the manifest **version** changes; the user clicks Update. Packaging policy **requires** a pinned `…@sha256:` digest, no moving tags. Community stores are **entirely unreviewed**. No written ban on self-update, but it contradicts the enforced pinned-image model.
- **StartOS:** **no auto-update at all**; docs guarantee *"StartOS will NEVER update a service without your consent."* Updates surface in the Updates tab when the UI fetches registries and finds a higher `emver`; user clicks Update per service. 0.4.0's s9pk v2 adds built-in signature verification. Community-registry submission reviews **every version**.
- **Conclusion:** a silently self-updating app **subverts both platforms' core consent promise** and (for the official channels) their per-version review + pinned-digest model. Therefore drive-boot must be **operator opt-in, clearly disclosed, and shipped via our own community store / custom registry / sideload — not the official stores.**

---

## 4. Architecture

```
 Docker image (thin, rare bumps)                       Signed code drive (hyper://, frequent)
 ┌───────────────────────────────┐                     ┌──────────────────────────────────┐
 │ Node22 + glibc                │   hyperdrive.update  │ packages/  (app JS, 3.8MB)        │
 │ node_modules (native addons)  │ ◀───────P2P────────▶ │ release-manifest.json (offline-  │
 │ loader.mjs  ◀── ENTRYPOINT    │                     │   signed: {hashes, driveKey, ver})│
 └──────────────┬────────────────┘                     └──────────────────────────────────┘
                │ spawn (health-gated, swappable)
                ▼
   node <checkout>/packages/core/cli/index.js start     ── serves :9100/health, dashboard, relay
                │
                ▼   never swapped
        /data  (relay-identity.json, corestore, config.json)
```

### 4.1 The loader (`/app/boot/loader.mjs`, baked in the image)
Lifecycle, porting every `updater.sh` invariant:

1. **Answer `/health` immediately.** The loader binds `:9100` and serves `{"running":true,"version":"<current|starting>","phase":"sync|running|swapping"}` from the first second, proxying to the child once it's up. *Critical for StartOS, whose health check has only a 30 s grace* (`check-web.sh`) — a cold drive sync must not read as "app down."
2. **Resolve channel** → a **signed channel pointer** → a validated target drive version (see §4.4).
3. **Fetch + verify** the drive at that version: open the pinned drive key, `update()`, `checkout(version)`, **verify the offline-signed release manifest** (hashes + driveKey + version) before trusting a byte. Fail closed.
4. **Mirror** the checkout to `/data/app/<version>/` (an on-disk path; the drive FS is not directly `require`-able for `.node`, and v1 doesn't ship `.node` on the drive anyway).
5. **Spawn** `node /data/app/<version>/packages/core/cli/index.js start` with the appliance env; leave `/data` state in place.
6. **Health-gate** the child (`running:true` + `version`==target, 120 s). Green → cut over the `/health` proxy, mark `<version>` as last-good, keep `<version-1>` blobs for rollback, prune older.
7. **Watch** `drive.update()`; on a new signed target: spawn the new version alongside, health-gate it, cut over, keep the old for rollback (blue/green).
8. **Rollback** on any failure to the last-good checkout; restart; re-health-check; log the event to the dashboard.

### 4.2 Trust model
- **Anchor:** the drive **public key** (pinned in the image + the store manifest) — only the key-holder can append a new version.
- **Plus** an **offline-signed release manifest** inside each version (reuse `sign-release.mjs`), so a compromised *online* seeding key still cannot forge a release the loader will run. This is the drive-boot analogue of the SSH-signed annotated git tag; enforcement is fail-closed with a loud, never-standing break-glass env.

### 4.3 Health gate + rollback
Reuse the exact `updater.sh` semantics (§3.5). `hyperdrive.checkout(version)` provides the atomic snapshots; keep **N-1** on disk (~4-8 MB per version for `packages/`, cheap) so rollback is instant and local.

### 4.4 Channel pointer — **DECISION D3**
Two viable designs for mapping `channel → drive-version`:
- **(a) Reuse `channels.json` over HTTPS** (what the fleet uses). Simplest; already signed-tag-gated; but adds an HTTPS dependency to a P2P story.
- **(b) A signed Hyperbee pointer** (persistent keypair, signed meta, pinned via `/seed-core` — the catalog-bee pattern). Fully P2P, mutable without republishing the drive key. **Recommended** for the pure-pipe ethos, with (a) as a fallback bootstrap.

### 4.5 What stays in the image vs moves to the drive
| KEEP in image (thin, rare) | MOVE to drive (frequent) |
|---|---|
| Node 22 + glibc, tini/gosu/wget+curl/ca-certs | `packages/` (core, services, client, verifier, dashboard) |
| `node_modules` incl. 8 native addons | app version identity reported on `/health` |
| `loader.mjs` + the `/health` shim | (v2 only: linux-x64/arm64 prebuilds, if mirror ≠ noexec) |
| the frozen `/app/boot` entrypoint path | |
| env contract (`HOME=/data`, `HIVERELAY_STORAGE=/data`, token derivation) | |

---

## 5. Governance decision — **DECISION D1 + D4 (RATIFIED 2026-07-07)**

**Ratified:** pursue **all distribution channels including the official stores** (D1 = "Official too"), and ship auto-update **on by default with a prominent off-switch** (D4 = "On by default"). This is the widest-reach / most-hands-off end of the range; it is also the combination furthest from the platforms' *"never update without consent"* norm, so it carries **review risk on the official channels** and makes the disclosure/off-switch UX **load-bearing for acceptance**.

Concretely:
- **Default:** auto-update **on** out of the box (channel: stable), with a prominent dashboard off-switch and a per-version pin. First-run dashboard notice + store description + release notes disclose plainly that the app self-updates its code over a signed P2P channel and how to turn it off.
- **Distribution:** our Umbrel community store + StartOS custom registry + sideload **and** submission to the **official** Umbrel/Start9 stores. Because the official channels' pinned-digest + consent model may reject an on-by-default self-updating app, official submission is **gated on a policy read (M0)** with a **defined fallback**: ship an **opt-in (default-off) variant for the official channel only** if reviewers require it — the off-switch makes this a config flag, not a rebuild.
- **Version honesty:** the dashboard shows the *true running* drive-version + channel + last-update/rollback, so the (lagging) store-manifest version is never the source of truth.

> **Why validation-first:** recon found no *written* ban on self-update in either platform's guidelines, but no green light either, and both guarantee consent-gated updates. Building an official-store submission before confirming policy risks wasted official-specific work. The shared core (M1-M3) is distribution-agnostic and proceeds regardless.

---

## 6. Execution plan

### Track 0 — Design + decisions (this doc; gates the rest)
- **D1 Distribution:** ✅ RATIFIED "Official too" — all channels incl. official stores (§5), gated on M0 + opt-in fallback for the official channel.
- **D2 ABI/dep boundary:** ✅ v1 = `packages/`-only drive; dep changes ride image bumps.
- **D3 Channel pointer** (§4.4): signed Hyperbee (recommended) vs HTTPS `channels.json` — implementation choice, taken as signed-Hyperbee default.
- **D4 Auto-update default:** ✅ RATIFIED "On by default" + prominent off-switch + disclosure (§5).
- **Exit:** decisions ratified (done); this doc merged.

### Track 0.5 — Official-store policy validation (gates T2/T3 official submission ONLY; NOT the shared core)
- **M0 — Confirm the official-store stance.** Get an authoritative read from **Umbrel** (issue on `getumbrel/umbrel-apps` and/or Discord) and **Start9** (community forum / docs / Matrix) on whether a **disclosed, off-switchable, on-by-default self-updating** app is acceptable in their official store/registry, given their pinned-digest + consent guarantees. *Accept:* a documented yes / no / conditions from each platform. *On "no/conditions":* fall back to the opt-in (default-off) variant for that official channel; community + sideload proceed unchanged. **Runs in parallel with M1-M3; does not block them.**

### Track 1 — Shared drive-boot core
- **M1 — Code-drive publisher.** Extend the publish path to package `packages/` into a signed hyperdrive + an offline-signed release manifest (reuse `sign-release.mjs`); seed durably on the fleet (archive tier). Prove durability with the existing metadata+blob gates. *Accept:* a published drive version reconstructs byte-identical on a fresh peer and the manifest verifies.
- **M2 — The loader.** `boot/loader.mjs`: `/health` shim → channel resolve → verify → mirror → spawn Node CLI → health-gate → blue/green swap → rollback. Port the `updater.sh` invariants (§3.5). *Accept:* unit tests for each invariant + an integration test that hot-swaps v→v+1 and rolls back a deliberately-broken version, identity/data preserved.
- **M3 — Version identity plumbing.** Ensure the drive-shipped app reports its version on `/health` and the dashboard shows running-drive-version/channel/last-update (fixes the store-lag mismatch). *Accept:* dashboard + `/health` show the true running version after a swap.

### Track 2 — Umbrel appliance
- **M4 — Umbrel drive-boot image + compose.** Loader entrypoint (keep the uid-999 chown-drop); `umbrel-app.yml` disclosure copy + dashboard toggle. *Accept:* installs from our community store on a real/emulated Umbrel, self-updates a test release end-to-end, survives reinstall (identity intact).

### Track 3 — StartOS appliance
- **M5 — StartOS drive-boot s9pk.** `startos/docker_entrypoint.sh` → loader. Resolve the **root-vs-uid-999** difference (StartOS runs as root today — loader must be uid-agnostic or migrate ownership). Make the `/health` shim answer within the **30 s** grace during drive sync. Fix the `check-web.sh` **curl-vs-wget** gap (confirm curl in base image or switch to wget). *Accept:* sideload/registry install on StartOS 0.3.5.x, self-updates a test release, health survives a cold sync.

### Track 4 — Operations / release integration
- **M6 — Release-flow integration.** `release.sh` (or a sibling) also publishes the code drive + signs the release manifest + advances the channel pointer, canary→stable, mirroring `channels.json`. Rollback runbook + a `--verify-only` loader mode. *Accept:* one release command produces both a taggable fleet release *and* a drive-boot channel advance; a canary box self-updates before stable.

### Suggested sequencing
`Track 0 (decisions) → M1 → M2 → M3 → (M4 ∥ M5) → M6`. M4/M5 parallelize once the shared core (M1-M3) is proven. Ship behind the opt-in flag; dogfood on bern-as-appliance and one real device before enabling by default anywhere.

---

## 7. Risks & open decisions

| # | Risk / decision | Disposition |
|---|---|---|
| R1 | **On-by-default self-update + official-store submission conflicts with the platforms' consent model** (ratified D1/D4 = the highest-friction combo) | Validate first (**M0**) before official-specific work; disclosure + off-switch are load-bearing; **fallback = opt-in/default-off variant for the official channel only** (a config flag). Community + sideload proceed regardless. |
| R2 | **StartOS 30 s health grace vs drive-sync time** | Loader serves `/health` from second 0 (§4.1). Validate on-device. |
| R3 | **ABI/dep skew** if drive JS needs a dep the image lacks | v1 ships `packages/` only; dep changes ride image bumps (D2). CI check: drive version's `package-lock` == image's. |
| R4 | **`noexec` mirror target** breaks `.node` dlopen | v1 keeps addons in the image; mirror only pure JS. Revisit for v2. |
| R5 | **StartOS root vs Umbrel uid-999** ownership | Loader uid-agnostic; migration chown for existing StartOS installs (M5). |
| R6 | **Signed-manifest-over-hyper:// is a new consumer** | Reuse `release-verify.js`; fail-closed; offline signing key (M1/M2). |
| R7 | **Auto-heal for the code drive** must actually seed N replicas | Confirm the archive-tier AutoHeal path is live on the fleet before relying on it for update availability. |
| R8 | **`/health` `version` producer** must match what the loader gates on | Confirm the source of the `/health` version field and that the drive-shipped app reports it (M3). |

---

## 8. One-paragraph recommendation

Drive-boot is viable, on-brand (Blindspark already seeds signed drives and already runs a health-gated channel updater on the fleet), and it directly kills the appliance-staleness problem that motivated it. The engineering is mostly *reuse* — the Node CLI, `hyperdrive.checkout`, the signed-release-manifest pattern, and the `updater.sh` invariants already exist; the new code is a ~single loader plus a code-drive publisher. **The blocking decision is governance, not code:** self-update honors operator choice only if it is opt-in, disclosed, and kept off the official stores whose entire promise is "we never update without consent." Ratify D1-D4, then build M1→M3 as the shared core.
