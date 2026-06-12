# HiveRelay ↔ Pear/Bare Alignment Plan

> Status: synthesized 2026-06-12 from 5 dimension-mapping passes + 1 stack-research pass.
> Scope: alignment of the HiveRelay monorepo with the `hello-pear-bare` June-2026 conventions.
> Target posture: **maximally performant and wire-compatible with the live Holepunch stack**, with risk honestly gated.

---

## 1. Verdict

**HiveRelay is already structurally Pear/Bare-aligned — further along than the boilerplate baseline in shape, one major generation behind in dependencies, and missing exactly one real feature (OTA).**

What is already correct and idiomatic today:

- **Conditional exports** — `packages/core/package.json` `exports["."]` resolves `bare → ./pear-entry.js` and `default → ./core/index.js`. The Bare runtime loads the reduced `BareRelay`; Node loads the full stack. This is the boilerplate pattern, done right.
- **Imports map** — `events→bare-events`, `fs/promises→bare-fs/promises`, `path→bare-path`, `http→bare-http1` in core; the client adds `crypto→bare-crypto`. Verified by tracing the actual `BareRelay` import graph: **every Node builtin reached on the Bare path is remapped**, and Node-only modules (`worker_threads`, `child_process`, `net`, the full `RelayNode`) are correctly excluded from that graph, not under-mapped.
- **`bare-relay` core** — `BareRelay` (`packages/core/core/relay-node/bare-relay.js`) runs Corestore + Hyperswarm with `swarm.on('connection', conn => store.replicate(conn))` (lines 184/190), the exact shared-networking surface `pear-runtime` expects.
- **Pear app shape** — `pear: { name, type: 'terminal', bin }` block present; `pear-entry.js` already wires `Pear.teardown(() => relay.stop())` and `BareRelay.stop()` awaits `store.close()` + `appRegistry.save()` — the shutdown discipline OTA restart needs.
- **Bare-native randomness** — randomness is uniformly `sodium.randombytes_buf` everywhere; there is **no** `compat/random.js` shim to retire (it does not exist in this tree). The one `crypto.createHmac` use (client `pairing.js`) is already covered by the client `crypto→bare-crypto` map.
- **No cross-package version skew** — `packages/core` and `packages/client` pin corestore, hyperdrive, hyperswarm, bare-path, bare-fs, bare-events, sodium-universal, b4a to **identical** ranges; the lockfile resolves the whole stack consistently (corestore 6.18.4, hypercore 10.38.2, hyperdrive 11.13.4, hyperbee 2.27.3, hyperswarm 4.17.0).

### Highest-leverage gap

**OTA self-update is the headline boilerplate feature and it is entirely absent — but adopting it is not free, because `pear-runtime@1.1.4` transitively forces the corestore-6→7 / hypercore-10→11 storage-engine migration (RocksDB, on-disk format break).** The current "update" code in `pear-entry.js:49-56` is a dead stub: it dynamic-imports `pear-updates`, which is **not a declared dependency**, so the import always throws and is silently swallowed by `catch (_)`. The header comment ("auto-updates delivered via Pear's update mechanism") is aspirational. There is no `upgrade: pear://<key>` field, no apply/restart logic, and — critically — **production runs the Node CLI under systemd, not the Bare entry**, so today there is literally no code path that could receive a `pear-runtime` OTA.

So the strategic picture is: **the cheap structural work is essentially done; the remaining value is split between safe freshness bumps (do now) and one expensive, coupled OTA-plus-storage move (gate hard).**

---

## 2. The three tiers

Severity = how much it matters for correctness/alignment. Risk = blast radius if it goes wrong.

---

### TIER 1 — Safe high-value wins (low risk, adopt now)

These touch no on-disk format and no replication wire. They can ship independently, in any order.

#### 1.1 — Raise the `hyperswarm` floor pin → `^4.17.0`
- **Files:** `packages/core/package.json:88`, `packages/client/package.json` (both pin `^4.7.0`; lockfile already resolves 4.17.0).
- **Change:** bump the declared floor to `^4.17.0` in both packages (keep them matching).
- **Severity:** low · **Risk:** low.
- **Rationale:** the single genuinely-independent upgrade in the set — hyperswarm just produces an encrypted duplex stream and does not care whether the corestore behind it is v6 or v7; 4.x is API-stable (additive/bugfix via `hyperdht@^6.21`). Cheapest path to "current and performant" networking.

#### 1.2 — Adopt `which-runtime` and delete hand-rolled `global.Bare` sniffing
- **Files:** add `which-runtime@^1.4.0` to `packages/core` deps; edit `packages/core/core/capability-doc.js:52` (`typeof global !== 'undefined' && global.Bare ? 'bare' : 'node'`) and `packages/core/core/relay-node/bare-relay.js:~88` (`typeof globalThis.Bare !== 'undefined' && globalThis.Bare.env`).
- **Change:** `import { isBare } from 'which-runtime'`; in capability-doc use `opts.runtime || (isBare ? 'bare' : 'node')`. In bare-relay, keep the env fallback (`Bare.env` vs `process.env`) but gate it on `isBare`/`isNode` instead of `typeof globalThis.Bare`. `which-runtime` exposes `isBare/isNode/isPear/isWindows/isLinux/isMac/...`; **note there is no `isMobile`** — derive as `isIOS || isAndroid` if ever needed.
- **Severity:** medium · **Risk:** low.
- **Rationale:** behavior is identical (which-runtime reads `global.Bare` under the hood); it removes fragile global sniffing and is the ecosystem-standard detection primitive. Correctness/consistency win, and a prerequisite for a clean single-`bin.js` dispatch (see 1.4 / 2.x).

#### 1.3 — Refresh trivially-lagging floor pins (documentation/clarity)
- **Files:** `packages/core/package.json`, `packages/client/package.json`, `packages/services/package.json`.
- **Change:** raise declared floors to match what the lockfile already resolves — `hyperbee ^2.20.5→^2.27.3`, `hyperdht ^6.15.0→^6.29.x`, `protomux ^3.6.0→^3.10.x`, `b4a ^1.6.6→^1.8.x`, `compact-encoding ^2.15.0→^2.19.x`, `sodium-universal ^4.0.0` (already current), `bare-events ^2.2.0→^2.9.x`, `bare-http1 ^4.5.6→^4.5.7`, `bare-crypto ^1.13.6→^1.15.x`. Keep `b4a`/`sodium-universal` consistent across core/services/client.
- **Severity:** low · **Risk:** low.
- **Rationale:** all on their current major and auto-tracked by caret already; this is hygiene, not a functional change. **Caveat:** `hyperbee 2.27.3` only *functionally* matters once the cores underneath become hypercore-11 — it rides along with the storage move (Tier 3), so bumping the floor now is harmless but not load-bearing yet.

#### 1.4 — Make the Pear/Bare entry unambiguous (`pear.bin` currently shadows the Bare entry)
- **Files:** `packages/core/package.json:45-53` (`pear.bin: "p2p-hiverelay"` → `bin.p2p-hiverelay: "./cli/index.js"`), `packages/core/cli/index.js`, `packages/core/pear-entry.js`.
- **Change:** the `pear.bin` field resolves to the **Node-only** CLI (`cli/index.js`), which imports `http.createServer`, `os.homedir`, `worker_threads` (via router), `child_process` (via disk-monitor). The correct Bare entry (`pear-entry.js`) is reachable only via `exports["."].bare`. If `pear run` resolves `pear.bin`, it loads Node-only code under Bare and crashes on the first uncovered builtin. **Fix:** either (a) point `pear.bin` at a dedicated bin that maps to `./pear-entry.js`, or (b) adopt a single `bin.js` that does `import { isBare } from 'which-runtime'` and dispatches to the Bare relay vs the Node CLI. Verify with `pear run .` that `cli/index.js`'s Node-only imports are never evaluated.
- **Severity:** high · **Risk:** medium (it changes the resolved entry; must be verified under a real Bare run, not just Node).
- **Rationale:** this is the one place where a real `pear run` could load Node-only code under Bare. The conditional export is correct; the `pear.bin` field can override it. Low-cost fix, high correctness payoff, and unblocks OTA (which must attach to the Bare entry). *Promote to do-first within Tier 1.*

> **Deliberately NOT in Tier 1: `bare-build` standalone binaries.** See §4 "Do not adopt (yet)."

---

### TIER 2 — Valuable but needs care (medium risk, plan)

Coordinated within themselves, but independent of the storage move. Plan and test; don't piecemeal.

#### 2.1 — `bare-*` v3 generation move (bare-path 2→3, bare-os 2→3, bare-fs 2→4)
- **Files:** `packages/core/package.json` (bare-path `^2.1.0`, bare-fs `^2.1.0`), `packages/client/package.json` (same), add `bare-os ^3.9.x` and optionally `bare-storage ^1.1.x` where storage-dir resolution is wanted.
- **Change:** the path API (`join/resolve/basename/sep/win32/posix`) and the FS surface are unchanged; the break is **transitive `bare-os` 2→3** (platform-detection/native-addon changes), which `bare-fs 4` and `bare-path 3` both require. Bump **bare-path 3 + bare-os 3 + bare-fs 4 together**, in both core and client in lockstep. **Do not mix bare-os 2 and 3.** Verify `bare-fs/promises` (referenced in the imports map) still matches after skipping two majors (2→4).
- **Severity:** medium · **Risk:** medium.
- **Rationale:** keeps the Bare substrate on the current generation (better native perf, ongoing fixes) and is a prerequisite for `pear-runtime` (which depends on `bare-path@^3`). Independent of corestore/hypercore — a separate coordinated bump.

#### 2.2 — Migrate CLI arg parsing to `paparam`
- **Files:** `packages/core/cli/index.js` (currently `minimist`), `packages/core/pear-entry.js` (currently hand-rolled `indexOf` scanning in `parseRegions/parsePort/parseMaxStorage`).
- **Change:** declare flags/args as `paparam` specs (`flag('--region <r>')`, `flag('--port <n>')`, `flag('--max-storage <size>')`, `flag('--no-updates')`) and read `program.flags/program.args`. This unifies the two parsers (the `pear-entry.js` one is a fragile, duplicated `indexOf` scanner) and gives strict validation + auto `--help`.
- **Severity:** low · **Risk:** medium (mechanical but touches every CLI invocation path; minimist is lenient, paparam is strict — undeclared flags now error).
- **Rationale:** removes the brittle hand-rolled parser, aligns with boilerplate, and is the right substrate for adding `--no-updates` cleanly when OTA lands. Plan it alongside or just before OTA wiring.

#### 2.3 — Run tests **under Bare** + add a Bare CI job (`brittle-bare`)
- **Files:** `package.json` scripts (add `test:bare`), `test/unit/bare-relay-surface.test.js`, `.github/workflows/test.yml`, and promote `scripts/bare-production-verify.mjs` (real, but orphaned and Node-run) into a wired target.
- **Change:** **today nothing in CI ever loads `bare-fs`/`bare-http1`/`bare-path` under their real implementations** — all 121 brittle tests run under Node, and the imports map redirects `bare-*` to Node builtins under the `default` condition, so even `bare-relay-surface.test.js` exercises Node fallbacks, not Bare. Add `brittle-bare` to devDeps, add `test:bare` running a small Bare-only subset (bare-relay surface + a content round-trip), and add a `bare-tests` CI job that installs the Bare runtime. Either promote `bare-production-verify.mjs` to a `verify:bare-prod` script that boots a relay under `bare`, or fold its publish/seed/round-trip assertions into the brittle-bare suite (and document that it currently runs the *client* under Node against a Bare relay's HTTP endpoint — it proves protocol parity, not that the verifier runs under Bare).
- **Severity:** high (Bare correctness is unproven at runtime) · **Risk:** medium.
- **Rationale:** this is the verification gate the Tier-3 storage move depends on. You cannot safely land corestore 7 / hypercore 11 without a suite that actually executes under Bare. **Do this before Tier 3, not after.**

#### 2.4 — `pear-runtime` OTA integration into the long-running relay
- **Files:** `packages/core/pear-entry.js` (replace the dead `pear-updates` stub), `packages/core/package.json` (add `pear-runtime@^1.1.4`, add `upgrade: pear://<key>`), `packages/core/core/relay-node/bare-relay.js` (expose `relay.store` / `relay.swarm`).
- **Change:** run `pear touch` to mint an upgrade key; add `"upgrade": "pear://<KEY>"`. Construct `new PearRuntime({ dir/storage, name, version, upgrade, store: relay.store, swarm: relay.swarm })` — **passing the relay's existing Corestore + Hyperswarm** so the updater replicates the versioned updater drive over the live mesh instead of standing up a second corestore/swarm/DHT presence. `await pear.ready()`; subscribe to `updating → updating-delta → updated`. On `updated`, do **not** exit immediately: stop accepting new seed/circuit channels, let in-flight replication flush, run `BareRelay.stop()` (which awaits `store.close()` + `appRegistry.save()` — critical so corestore-7 atomic batches commit), call `pear.updater.applyUpdate()`, then re-exec or signal the supervisor. Wire `pear.close()` into the existing teardown so the updater swarm tears down cleanly (129..143 exit-code convention).
- **Severity:** critical (it's the missing headline feature) · **Risk:** high.
- **Rationale:** the only real functional gap, and the correct way to do P2P self-update. **BUT** — `pear-runtime@1.1.4` transitively pins `corestore@^7.9.1` + `hyperswarm@^4.17.0`. **You cannot run pear-runtime on a corestore-6 relay.** Adopting OTA *forces* the Tier-3 storage move. That coupling is why this item sits at the Tier-2/Tier-3 boundary: the *wiring* is Tier-2 work, but it is **gated behind** the Tier-3 storage migration completing first.

#### 2.5 — Lint/format convention switch (`standard` → `prettier` + `lunte`)
- **Files:** `package.json` (`lint: "standard"`, `lint:fix: "standard --fix"`, `standard.ignore` block).
- **Change:** boilerplate is `lint: "prettier . --check && lunte"`, `format: "prettier . --write"` with `prettier-config-holepunch`. Add those three devDeps, add a `format` script, reformat in one isolated commit.
- **Severity:** low · **Risk:** medium (a churny one-time reformat across 120+ files; noisy diff, zero functional benefit).
- **Rationale:** worth it **only** if HiveRelay intends to publish to `pear://` and align with Holepunch repos (matches reviewer expectations there). **Recommendation: defer** unless contributing upstream; this is the lowest-value item in Tier 2 and its diff noise can mask real review.

---

### TIER 3 — Risky / coordinated (high risk, gate behind verification)

**Do not attempt any of this until Tier 2.3 (Bare CI) is green and a replication-parity test exists.**

#### 3.1 — The coordinated storage-stack move (corestore 6→7, hypercore 10→11, hyperdrive 11→13, hyperbee floor →2.27.3)
- **Files:** `packages/core/package.json` (corestore `^6.18.0`, hypercore `^10.36.0`, hyperdrive `^11.8.0`, hyperbee `^2.20.5`), `packages/client/package.json` (corestore `^6.18.0`, hyperdrive `^11.8.0`) — **all in one change, both packages, to preserve their matching pins.**
- **Change targets (from research, June 2026 npm):** corestore `^7.10.1`, hypercore `^11.33.x`, hyperdrive `^13.3.x`, hyperbee `^2.27.3`.
- **Severity:** high · **Risk:** high.

**The research verdict — is corestore 7 safe with hypercore 10 / hyperdrive 11 / hyperbee 2?**

> **No. Corestore 7 is NOT a safe drop-in on a hypercore-10 / hyperdrive-11 stack. It forces a coordinated upgrade of the entire Holepunch storage stack.**

The hard blockers, verbatim from the stack research:

- **corestore@7.0.0 changed its dep from `hypercore@^10` to `hypercore@^11`** (7.10.1 pins `hypercore@^11.32.0`). Hypercore 11 **replaced the storage engine**: it dropped `random-access-storage` and now requires `hypercore-storage@^3` (RocksDB-backed, atomic batches). This is a **storage-format and storage-API break**, not an API rename.
- The boilerplate's own target list is **internally contradictory** — it lists `corestore ^7.9.2` alongside `hypercore 10.36.0`. Those two lines cannot coexist. HiveRelay's current pins (corestore 6 + hypercore 10) are coherent; the *boilerplate* is the stale/wrong one here.
- **hyperdrive 11.8.0 is two majors stale.** The corestore-7-compatible drive is **hyperdrive 13.3.2** (`hypercore@^11`). Constructor stays `new Hyperdrive(corestore, key?)` so call sites survive, but the corestore must be v7 and the drive v13.
- **hyperbee stayed on major 2** (no breaking major) — `2.27.3` works on hypercore-11 cores; the lockfile already resolves it. It rides along.
- **On-disk data must be migrated.** corestore-6 random-access files are **not readable** by corestore-7 (RocksDB). Holepunch ships `@andrewosh/corestore-migration` for this. **Every persisted store** (the 5 VPS nodes, StartOS/Umbrel users) needs a migration pass or a fresh store directory — a relay cannot just point corestore 7 at the old data dir.

**What survives unchanged:** the custody/replication call sites. `store.replicate(streamOrOpts)` and `swarm.on('connection', conn => store.replicate(conn))` (bare-relay.js:190/406) are stable; `store.get`, `store.namespace`, `store.session` are preserved; `new Hyperdrive(store.session(), key)` call shape is stable. **Only storage construction, the hypercore version, and the on-disk format break.**

- **Rationale:** moving to corestore 7 / hypercore 11 buys the RocksDB engine (atomic batches, better large-store performance) and is the only way to unlock `pear-runtime` OTA. But it is an **all-or-nothing** generation move with a mandatory data migration. Gate hard.
- **Cross-runtime interop note:** Bare and Node relays replicate the same Hyperdrives/corestores over the DHT. A v6-relay and a v7-relay must be tested to confirm they still replicate **before** any node ships v7 — otherwise a partial rollout splits the mesh. This is the single most important pre-ship verification.

#### 3.2 — Whole-stack coordinated upgrade as a single release (the safe sequencing of 3.1)
- **Change:** treat hypercore 11.33.x + corestore 7.10.x + hyperdrive 13.3.x + hyperbee 2.27.x + `@andrewosh/corestore-migration` + `pear-runtime` OTA wiring as **one coordinated milestone**, shipped together, gated behind: (a) Bare CI green (2.3), (b) a v6↔v7 replication-parity test, (c) a tested migration script run against a copy of a production store, (d) a staged rollout (one VPS node first), (e) a rollback plan (corestore-7 RocksDB lock semantics differ from random-access-file primary-key locks — the existing systemd `RestartSec=15` exists to prevent an ELOCKED crash loop, and that behavior may change).
- **Severity:** high · **Risk:** high.
- **Rationale:** the only safe way to get OTA is to land the whole generation at once. Piecemeal bumps here corrupt or split-brain the mesh.

---

## 3. Recommended execution sequence

**Phase A — ship now (Tier 1, low risk, no gate):**
1. **1.4** — fix the `pear.bin` shadowing first (verify `pear run .` loads the Bare path). This unblocks everything downstream and is the highest-correctness/lowest-cost item.
2. **1.2** — adopt `which-runtime`, delete `global.Bare` sniffing (prerequisite for a clean single-`bin.js`).
3. **1.1** — bump `hyperswarm` floor to `^4.17.0` (both packages).
4. **1.3** — refresh trivial floor pins (hygiene; batch into the same commit as 1.1).

**Phase B — plan and land (Tier 2, independent of storage):**
5. **2.3** — stand up `brittle-bare` `test:bare` + a `bare-tests` CI job. **This is the gate for Phase C** — do it before any storage work.
6. **2.1** — `bare-*` v3 move (bare-path 3 / bare-os 3 / bare-fs 4), both packages in lockstep. Prerequisite for `pear-runtime`.
7. **2.2** — `paparam` migration (unifies the two parsers; sets up `--no-updates`).

**Phase C — gated coordinated milestone (Tier 3 + the OTA wiring that depends on it):**
8. Write + test the v6↔v7 **replication-parity** test and run `@andrewosh/corestore-migration` against a *copy* of a production store. Do not proceed until both pass.
9. **3.1 / 3.2** — land hypercore 11 + corestore 7 + hyperdrive 13 + hyperbee 2.27 as **one release**, both packages together, with the migration baked into the upgrade path.
10. **2.4** — wire `pear-runtime` OTA (`pear touch` → `upgrade: pear://<key>`, shared `{ store, swarm }`, supervised drain+`applyUpdate()`+re-exec). This rides *on top of* the corestore-7 stack from step 9.
11. Staged rollout: one VPS node, observe, then the rest. Keep the systemd channel until OTA is proven (see §4).

**Skip / defer:**
- **2.5** (lint/format switch) — defer indefinitely unless contributing upstream to Holepunch.

---

## 4. Do NOT adopt (and why)

- **`bare-build` standalone single-file binaries — do not adopt as a distribution channel; it duplicates Docker.** HiveRelay already ships via Docker (`docker-publish.yml`) and systemd on the VPS fleet, plus StartOS/Umbrel packaging. `bare-build --standalone` produces per-OS binaries (darwin/linux/win/android/ios arm64/x64) — genuinely useful for a *client-side desktop* Pear app, but for an always-on server relay it adds a parallel build/release matrix with no operational benefit over the existing container image. **Adopt only if/when a standalone desktop relay binary becomes a real product goal**, not for parity's sake. (The `make:<os-arch>` scripts in the boilerplate exist for that desktop-distribution model HiveRelay doesn't use server-side.)

- **`corestore 7` alone (or any piecemeal storage bump) — never.** corestore 7 hard-requires hypercore 11 + RocksDB and cannot read v6 data. Bumping corestore (or hypercore, or hyperdrive) individually breaks the store and/or splits the mesh. It is all-or-nothing with a migration (§3.1).

- **`pear-runtime` OTA before the storage move — impossible, don't try.** `pear-runtime@1.1.4` transitively pins corestore `^7.9.1`; installing it on a corestore-6 relay is incoherent. OTA is gated behind Phase C, full stop.

- **OTA self-exec on the systemd/Node nodes — do not self-restart.** The 5 production VPS relays run the **Node CLI under systemd** (`Restart=always`, `RestartSec=15`, `KillSignal=SIGTERM`, `TimeoutStopSec=10`), which `pear-runtime` OTA (a Bare-runtime feature) cannot reach. Two non-overlapping update channels exist: systemd (git/SSH pull) for Node nodes, and pear-runtime OTA only if a node is migrated to `pear run pear://<key>` or a Bare binary. If a node ever runs OTA, `applyUpdate()` should **stage-and-exit cleanly** and let systemd's `Restart=always` bring up the new version — making systemd the supervisor and avoiding double-restart races. Do not bolt a self-exec loop on top of systemd.

- **Lint/format switch (`standard`→`prettier`+`lunte`) — skip unless going upstream.** Pure churn (120+ file reformat, noisy diff) with no functional or runtime benefit. The only payoff is matching Holepunch reviewer expectations on contributed PRs.

---

## Appendix — current vs. target pins (verified against lockfile)

| Package | Current pin | Lockfile resolves | Target | Tier |
|---|---|---|---|---|
| hyperswarm | `^4.7.0` | 4.17.0 | `^4.17.0` | 1 |
| hyperbee | `^2.20.5` | 2.27.3 | `^2.27.3` | 1 (floor) / rides 3 |
| which-runtime | absent | (transitive) | `^1.4.0` (direct) | 1 |
| bare-path | `^2.1.0` | 2.1.3 | `^3.0.x` | 2 (with bare-os/fs) |
| bare-fs | `^2.1.0` | 2.3.5 | `^4.7.x` | 2 |
| bare-os | absent | — | `^3.9.x` | 2 |
| paparam | absent | (transitive) | `^1.10.x` (direct) | 2 |
| brittle-bare | absent | — | devDep | 2 |
| pear-runtime | absent | — | `^1.1.4` | gated by 3 |
| corestore | `^6.18.0` | 6.18.4 | `^7.10.x` | **3 (gated)** |
| hypercore | `^10.36.0` | 10.38.2 | `^11.33.x` | **3 (gated)** |
| hyperdrive | `^11.8.0` | 11.13.4 | `^13.3.x` | **3 (gated)** |

Key local files: `packages/core/package.json`, `packages/client/package.json`, `packages/core/pear-entry.js` (dead OTA stub, lines 49-56), `packages/core/core/relay-node/bare-relay.js` (store/swarm/connection/stop at 157/184/190/342/406), `packages/core/core/capability-doc.js:52`, `packages/core/cli/index.js`, `.github/workflows/test.yml`, `scripts/bare-production-verify.mjs`, `scripts/deploy-vps.sh` + `hiverelay.service` (systemd update model).
