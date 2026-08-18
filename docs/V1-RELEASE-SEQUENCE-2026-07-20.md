# v1 Release Sequence — What's Next (2026-07-20)

> **Superseded (2026-08-18):** this is a dated planning snapshot. Outcomes
> since it was written: the Phase 2.4 version decision went to **0.26.0-rc.1 /
> GA v0.26.0** for the product line (the accidental `1.0.0-rc.1` numbering on
> `main` was renumbered; `1.0.0-rc.x` is reserved for the blind-* workspace
> packages only); npm `latest` was promoted to **0.24.4** for all four
> packages (no longer `0.20.2`); the 0.25.0-rc.1…rc.9 candidate train was
> superseded by 0.26.0-rc.1; and the TrueNAS/HexOS appliance lane (3.5) has
> merged to `main` as `truenas-app/` and `hexos-app/`.

**Where we are:** all four giga tracks (blind cells, Tor onion transport, HTTPS gateway, namespace) and the WAL spine are code-complete, tested (356/356 unit + 45/45 integration), and committed on branch `v1-integration` (worktree `00-core/v1-integration`). Nothing is pushed. This document is the ordered sequence from here to live on the fleet. Items are numbered in dependency order — do them top to bottom unless marked parallel.

---

## Phase 1 — Evidence runs (fleet/VPS, not a workstation)

| # | Item | How | Produces | Done when |
|---|---|---|---|---|
| 1.1 | **100 MB bulk-over-onion median** | Already running on this machine via schedule `122ef2c5` (fires :11/:56 hourly, logs to `/tmp/tor-gate-results.log`). Currently 4 valid full runs (0.75, 3.02, 1.17, 1.58 Mbps) — **one more valid run** for the 5-run median. If the local network stays degraded, move it to a canary with the calibrated knob: `HIVERELAY_TOR_TEST=1 HIVERELAY_TOR_BULK=1 HIVERELAY_TOR_ASSERT_GATE=1 HIVERELAY_TOR_BANDWIDTH_RATE=1250KB node_modules/.bin/brittle-node --timeout 2000000 test/integration/tor-bulk.test.js` | median Mbps + full attempt log | median recorded in `docs/GIGA-RELEASE-ARCHITECTURE.md` holdouts row; gate verdict stated (≥1.33 Mbps = pass; else documented ceiling) |
| 1.2 | **Linux Phase-0 WAL rerun** (last freeze-gate item) | `git bundle create wal-v1.bundle v1-integration` → ship to **bern** (canary, 484 GB) or a scratch VPS → `node 00-core/wal-phase0-evidence-2026-07-13/phase0-wal-bench.mjs <repo> <scratch>` + `bench-p2-atomic-put.mjs` + `bench-p3-pruning.mjs` (commands in `wal-phase0-evidence-2026-07-13/EVIDENCE.md`). Scratch dirs only — never `/var/lib/hiverelay`. | `bench-results-linux-<host>-*.json` next to the macOS ones | Linux datasync p99 inside the 250 ms PUT budget + group-commit signature holds → **freeze gate closed** |
| 1.3 | **Gateway G7–G13 operator evidence** (parallel with 1.2) | G7 two operators w/ distinct domains · G8 signed-tag manifest digests · G9 fleet-mode operator-contract digests · G12 Docker `nginx -T` capture · G13 real-host exclusive whole-root ceiling. Spec: `docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md` §16 gate table. | evidence JSONs per gate | all 13 gates have their evidence or an owner-waived Decision note |
| 1.4 | **PSL registration** for `*.<app-suffix>` (start now — months to propagate; parallel) | publicsuffix.org submission for the app-origin gateway domain | PSL PR filed | PSL entry merged (long-lead; not a hard gate for canary, IS a gate for app-origin stable) |

## Phase 2 — Owner decisions (record each as a Decision note in the vault)

| # | Decision | Options / current posture |
|---|---|---|
| 2.1 | **Freeze sign-off** | Protocol hashes + blind store-format authority can freeze (WAL P3 landed; D-6 K_partition dropped). Sign off via the remediation checker (`npm run vnext:check-protocol` — note its known `FORWARD_ROUTE_SCOPE_AUTHORITY_REGENERATION_PENDING` state; resolving that is part of the FORWARD decision). |
| 2.2 | **FORWARD wire family** | Excluded today (multi-hop has no enforceable route budget). Either: (a) pick the enforceable relay-carried route budget / signed acyclic route class (per the CR audit) and it enters a later train; or (b) formally exclude from v1.0 — the blockers stay documented. |
| 2.3 | **CORE.OPEN_REPLICATION** | Needs native descriptor topology + authenticated parent session + upstream signed-head proof authority. The stream service is built/unit-tested, no production surface until this is decided. Same train-vs-exclude call as FORWARD. |
| 2.4 | **Version** | v1.0.0 (the giga release at protocol freeze — recommended: the wire formats are all v1) or 0.25.x (roadmap reserved this for the unbuilt naming/IPFS train — reassign). |

## Phase 3 — Release mechanics (your signed flow)

| # | Step | Detail |
|---|---|---|
| 3.1 | **Push + PR** | Push `v1-integration`, `feat/tor-onion-transport`, `chore/holepunch-gen3-upgrade`; PRs per repo convention; review against `docs/HTTPS-GATEWAY-PRODUCTION-HANDOFF-2026-07-19.md` (evidence + merge-safety analysis are already in it). |
| 3.2 | **RC cut** | `scripts/release.sh cut <version>` (keyvault, SSH-signed tag). CI: npm ×4 → GHCR multi-arch + cosign → Umbrel/StartOS surfaces → release-evidence.json. |
| 3.3 | **npm `latest` promotion** | Was **0.20.2** on npm vs 0.24.3 in-repo (resolved: `0.24.4` took `latest` on 2026-08-06) — promote so downstream stops pinning 0.20.2 (includes the token rotation #120 if still open). |
| 3.4 | **Fleet rollout** | Edit `fleet/channels.json`: `canary` → the RC tag → `fleet:check-rollout` (health-gated, 120 s, auto-rollback) → `stable`. **Stagger relays**: first boot on the new stack does a one-time lazy block migration of the existing corestore (validated on a 52 GB copy — 3.2M blocks byte-identical; the 34 GB registry bee is real I/O). Prove the migration on one canary before fanning out. |
| 3.5 | **Surfaces** | Umbrel community store sync + official PR (full releases only), StartOS `.s9pk` + registry, TrueNAS/HexOS lane (merged to `main` as `truenas-app/` and `hexos-app/`). |

## Phase 4 — Post-release watch + next train

- **Watch**: pvss-custody-e2e intermittent harness race (documented, assertions pass); lazy-migration I/O on each relay's first boot; tor health machine's new negative probe in production (`restricted-discovery-fail-open` must not false-fire on real rosters).
- **Next train (post-v1)**: HIP-1 MLS over HiveRelay (P0 keypackage-directory is implementable on `wal.v2` today), R8 WebTransport v2 for `dhtRelayWs`, blind-cell repair/AutoHeal (M4), OHTTP split-ingress (D-3, needs an independent ingress operator), services productionization tiers (only `vrf` is production-ready), FORWARD/CORE-stream if 2.2/2.3 chose train.

---

### Quick-reference: state of every gate

| Gate | State |
|---|---|
| Code (4 tracks + WAL spine) | **done, green** |
| Linux WAL rerun | open (1.2) |
| 100 MB bulk median | **in progress — 4/5 valid runs, median 1.375 Mbps** |
| G1–G6 (gateway) | done (executed 2026-07-18) |
| G7–G13 (gateway) | open (1.3) |
| PSL | open (1.4) |
| Freeze sign-off | open (2.1) |
| FORWARD / CORE-stream | open (2.2 / 2.3) |
| Push/PR/RC/npm/fleet | open (3.x) |
