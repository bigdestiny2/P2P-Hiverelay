# Fleet plan — what we are doing, why, where, and how to improve

**Date:** 2026-07-28 · **Author:** rollout/audit session · **Status:** proposal, nothing executed

Written at an explicit stop-line: *"before we make any more changes to the fleet."*
Grounded in `docs/CAPABILITY-AUDIT-0.25.md` (77 agents, 64 verified findings, 6 refuted)
and in the live rollout state below.

---

## 0. The honest problem statement

Three times today a blocker was discovered **by hitting it in production** rather than by a gate:

| # | Blocker | Found by |
|---|---|---|
| 1 | rc.5 uninstallable — `patch-package` devDep vs `npm ci --omit=dev`, exit 127 | utah failing the update |
| 2 | utah's dirty tree refusing every update | the updater skipping, silently, for two days |
| 3 | utah-0.5gb crash-looping — `require-addon` resolving `/prebuilds/…` from filesystem root | the box going down |

None of these were exotic. All three were mechanically detectable **before** touching a relay.
The systemic fix is not "be more careful" — it is a pre-flight gate that runs the update on a
throwaway host and refuses the promotion if the relay does not come back green.

This plan is ordered by that principle: **make failure detectable before it is deployed.**

---

## 1. Where we actually are

### 1.1 Live fleet

| Box | RAM | Region | Channel | Version | State |
|---|---|---|---|---|---|
| utah | 12 GB | NA | canary | **0.25.0-rc.6** | healthy, converged |
| **utah-0.5gb** | 0.5 GB | NA | canary | rc.6 checked out | **DOWN — crash loop** |
| utah-8gb | 8 GB | NA | stable | rc.4 | healthy; declared-vs-actual drift (R-3) |
| utah-us, utah-2gb-a | 2 GB | NA | stable | 0.24.3 | healthy |
| miami | 0.5 GB | NA | stable | 0.24.3 | healthy |
| sing-1, sing-2 | 1 GB | APAC | stable | 0.24.3 | healthy |
| amsterdam | 2 GB | EU | stable | 0.24.3 | healthy |
| dubai | 4 GB | ME | stable | 0.24.3 | healthy |
| sydney | 2 GB | APAC | stable | 0.24.3 | healthy · Track B host · blind-edge crash-looping |
| dallas | 12 GB | NA | *(no updater)* | 0.24.3 | Track B host · excluded by construction |
| bern | 4 GB | EU | canary | — | provider outage, unreachable |

### 1.2 The two live incidents

**utah-0.5gb is down.** Not the outboxlog gate the audit predicted (B-1) — a different failure:

```
Error: Cannot find module '/prebuilds/linux-x64/sodium-native.node'
```

The path is **root-relative**: `require-addon` resolved the package root to `/`. The binary is
present and intact at
`node_modules/dht-rpc/node_modules/sodium-native/prebuilds/linux-x64/sodium-native.node` (919 KB).
**Corrected after a fleet-wide survey:** this is *not* a Node-version issue. `sing-1`, `sing-2`
and `dubai` all run the identical v22.22.2 and pass; the fleet spans v18.19.1 through v22.23.1
with 11 of 12 reachable boxes passing the runtime check. The cause is a **memory-starved
`npm ci`** on a 458 MB box with swap exhausted, which exited 0 while leaving `node_modules`
partially written — corroborated by a follow-up `npm rebuild` failing inside patch-package's own
dependency tree, and by the box having no compiler (only `python3`), so it depends entirely on
prebuilt binaries. The risk is therefore specific to memory-constrained boxes during dependency
reinstall, not to any Node version.

**`dashboard-admin-operator` is an unauthenticated fleet-root control plane.** Verified live on the
workstation: `node PID 51423 … TCP *:3458 (LISTEN)`. Zero auth references in `server.cjs`,
`server.listen(PORT)` with no host argument, wildcard CORS, and `exec()` of `ssh root@${ip}` with
shell interpolation of caller-supplied values, re-executed every 60 s. Unauthenticated side effects
include `systemctl restart`, `git pull && npm install`, `/etc/fstab` edits and `config.json`
rewrites — on all 13 relays. Its own README says "do not expose port 3458"; the sibling
`scripts/local-fleet-dashboard.mjs:121` correctly binds `127.0.0.1`.

### 1.3 What v0.25 actually enables

Per the audit's verdict: **G1 in code, G4-T in code.** It moves G2-S, G2-W, G3 and G4-I not at all,
and is **net-negative on G0** because of C-1 below.

At the audited RC6 baseline, both headline packaging claims were **inert**. All nine
`HIVERELAY_*` service and Tor variables had **zero readers** on the Node runtime
that Docker, systemd and Umbrel all launch — six were Bare-only and three were
read nowhere in the repo. "Tor on by default" and "a fresh appliance is no
longer an empty seeder" were true of the *expressed* configuration and false of
the *running* one.

> Post-RC7 repair (2026-07-29): the Node CLI now translates those variables as
> first-boot defaults with persisted config and `services.json` precedence;
> packaged OutboxLog is bounded and shard-store remains opt-in. Deployment and
> signed runtime evidence are still pending.

---

## 2. What we are doing, and why

**The goal:** a fleet that is strong (survives failure), diverse (many services, many failure
domains), and honest (claims match evidence).

**Why it is not just "enable more services":** the fleet currently cannot *express* diversity.
`config.regions` and `config.operator` are unset and the capability doc has no `operator` field, so
`quorum-selector.js:126` counts 13 relays as 13 independent operators. Seven of thirteen boxes are
NA and five of those are `utah-*` — one provider, one site. Adding services to NA boxes adds
capability and **zero** diversity, while the quorum math silently believes otherwise. Making
concentration visible is the prerequisite for honestly claiming G3, and it is a config change, not
a feature.

**Why the service story is stuck:** there is no supported way to enable a service on a systemd box.
No CLI flag, no TUI action, no dashboard tab. The management API writes `config.json`;
`setServicesConfig` — the only writer of `services.json` — has **zero production callers**. Every
service running on the fleet today is there because someone hand-wrote a file. Until that path
exists, every enablement is a manual, unrepeatable, undocumented act.

---

## 3. The plan

### Phase 0 — Stop the bleeding *(today, no fleet changes beyond recovery)*

| # | Action | Why |
|---|---|---|
| 0.1 | `kill 51423`; bind `127.0.0.1`, add a shared secret, replace `exec` with `execFile(argv)`, drop wildcard CORS | R-1 — remote root on 13 relays from any network the laptop joins |
| 0.2 | Recover **utah-0.5gb**: `npm rebuild` (or reinstall deps) and confirm the addon resolves; if it will not, revert it to `v0.24.3` | Box is down; it is a seed holder |
| 0.3 | Fix **C-1**: `config/default.js:205` `serviceDefaultPeerRole: 'authenticated-user'` → `'anonymous'` | Silently reverts commit `9125f3c`; opens `arbitration.submit` (uncapped Map) to any anonymous swarm peer on 10 boxes |
| 0.4 | Pin **utah-8gb** to `hold` before its timer is ever armed | R-3 — it runs rc.4 on `channel: stable` (pinned 0.24.3); arming converges it *backwards*, logged as success |

**Gate out of Phase 0:** utah-0.5gb green, admin operator on loopback with auth, C-1 shipped.

### Phase 1 — Build the gate that would have caught all three failures

| # | Action |
|---|---|
| 1.1 | **Canary-of-one throwaway host.** Provision a disposable VPS matching the fleet's OS and Node. Every promotion runs there first: fresh clone at the tag → `npm ci --omit=dev` → start → `/health` green → only then bump the channel |
| 1.2 | **~~Pin the Node version~~ — falsified, superseded by a runtime preflight.** The fleet spans v18.19.1–v22.23.1 and 11 of 12 pass; three boxes share utah-0.5gb's exact v22.22.2 and are fine. A version pin would have caught nothing. The gate that works is executing the runtime (`node -e 'require("hyperswarm")'`) after the deps install and before the restart — shipped in `updater.sh`. Separately: guard low-memory boxes against a partial `npm ci`, which is the actual cause |
| 1.3 | **Make the updater self-update.** It never reinstalls `/usr/local/bin/hiverelay-updater`, so the `--force` rollback fix in rc.6 is on *no* box. A fix to the update agent currently cannot reach the fleet except by hand |
| 1.4 | **Surface `storageAdmission.failClosed()`** on `/health` (R-8). Today it is invisible to every health surface *and* makes gateway reads 404 with "still replicating" — actively misleading |
| 1.5 | **Whitelist the disk-drain 503** in `health-watchdog.sh` (R-4). As written, `diskHealthGate` + watchdog is a 4-minute SIGKILL loop that frees no disk. Latent only because the gate defaults off — it arms the moment an operator follows `PRODUCTION.md` |

### Phase 2 — Make diversity measurable *(cheap, high leverage)*

| # | Action |
|---|---|
| 2.1 | Set `config.regions` and `config.operator` per box; add `operator` to the capability doc |
| 2.2 | Fix `quorum-selector.js` to count operators, not relays |
| 2.3 | Build the **runtime service prober**: read the unauthenticated `GET /api/v1/services` on all 13 boxes. Ten of twelve rows in the current fleet view are config-derived, which by this project's own dubai rule is not runtime truth |

### Phase 3 — Service enablement, in diversity order

Only after Phases 0–2. Sequencing from the audit: **large NA → non-NA → 2 GB NA → 0.5–1 GB last, and
mostly by *removal***. `docs/FLEET-STABILITY-2026-07-27.md:9` records `status=6/ABRT` every few hours
on miami, utah-0.5gb and sing-1 under the full suite.

The real win is **non-NA**: dubai (4 GB, ME), amsterdam (2 GB, EU), sing-1/2 (1 GB, APAC). Five of
fifteen builtins run nowhere — and `identity, storage, schema, vrf` is precisely the documented
**Service Operator profile** (`SERVICES.md:508`), which no box runs.

**Do not enable:** `forwardRelay` anywhere (no backpressure — bounded in bytes, not memory);
`shard-store` on any new box, and remove it from amsterdam (2 GB, violates `LADDER-SHIP-MAP.md:138`).

**Prerequisite:** a supported enable path (§2, "why the service story is stuck"). Enabling by
hand-editing `services.json` on twelve boxes is how we got here.

### Phase 4 — Honesty pass

19 claims need correcting (`CAPABILITY-AUDIT-0.25.md` §7), including three where the docs
**understate** — the HTTPS gateway *is* merged, and the split-transport wire layer *does* exist.
Under this project's stated discipline a known-wrong public sentence counts in either direction.
C-7 is the sharpest: commit `aae40ff` corrected three docs and skipped a fourth, so a sentence
already identified as wrong shipped inside a signed tag.

---

## 4. How we improve — the systemic changes

1. **Gate promotions on a real install, not a diff.** Every failure today would have been caught by
   one throwaway host running the actual update.
2. **Make the update agent updatable.** Otherwise every updater fix requires a manual sweep of every
   box, which is exactly the fragility the pull-based design was meant to remove.
3. **Give services a supported enable path** — CLI flag or API that writes `services.json`. Until
   then the fleet's configuration is unreproducible.
4. **Make silent failures loud.** `failClosed()` invisible to health; AppRegistry `'error'` with zero
   subscribers; cap-raise swallowing the durability error it explicitly asked for (R-5). The pattern
   repeats: the code knows something is wrong and no surface says so.
5. **Close the declared-vs-actual gap.** utah-8gb's channel says one thing and its version says
   another; `dallas` is in no committed inventory; `FLEET-STABILITY` records a plugin trim in the
   past tense that no artifact corroborates. Reconcile, then keep them reconciled by a prober.

---

## 5. What I am explicitly not proposing

- **No stable promotion.** `stable` stays on `v0.24.3` until Phases 0–1 clear.
- **No wider canary.** utah alone until the pre-flight gate exists.
- **No changes to sydney or dallas.** Track B hosts. sydney's `blind-edge` is crash-looping
  (`EdgeReadinessError: BLIND_READINESS_ACK`) — that is the Track B owner's call, and it means the
  Peerit bind is currently `bound_public_test_canary` against an unreachable DESCRIBE endpoint.
- **No `services.json` edits by hand.** That is the habit that made the fleet's configuration
  unreproducible.
