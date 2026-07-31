# Roadmap — August 2026

**Date:** 2026-07-31 · **Status:** forward plan · **Baseline:** canary `v0.25.0-rc.9` live · stable `v0.24.3` · **Related:** [LADDER-SHIP-MAP](./LADDER-SHIP-MAP.md) · [FLEET-PLAN-2026-07-31](./FLEET-PLAN-2026-07-31.md)

All gates are evidence-based; there are no calendar commitments. Each item lists its finish line and what blocks it.

## Phase A — Close the rc.9 cycle (early August)

| # | Item | Finish line | Blockers |
|---|------|-------------|----------|
| A1 | rc.9 release-evidence certificate | Full-green `Release surfaces` run; `release-evidence.json` attached to the GitHub prerelease and passing `release:verify-evidence -- --bundle-dir` | Only the tag's pre-flake-fix unit gate (rerun lottery); every structural blocker is fixed |
| A2 | Destroy-timeout flake (issue #217) | `swarm.destroy`/`relayDiscovery.destroy` timeouts no longer uncaught in unit teardown; #217 closed | Fix in progress |
| A3 | bern recovery | Box reachable, pulls rc.9, health green — canary cohort 3/3 | Host access |
| A4 | utah-8gb convergence | Runs a signed tag matching its pinned channel (no rc.4 drift) | Updater convergence or manual intervention |
| A5 | sing-1 disk | `maxStorageBytes` verified/set; below the 75% flag | Operator action |
| A6 | miami OutboxLog namespace | Production dual-registration write + restart under a fleet lease; crash loop ends | Fleet lease |

## Phase B — Prove the live claims (the stable gate)

The code for every v0.25 headline claim ships in rc.9. The runtime evidence does not exist yet. **No stable promotion until this table is green.**

| # | Claim | Evidence required | Current |
|---|-------|-------------------|---------|
| B1 | Wake notifications | Signed live push egress through an operator-configured provider; exact `notify-outbox-lane` wake on a running canary relay | 0/10 signed egress; 0/10 exact-lane |
| B2 | Restricted Tor readiness | The unauthenticated negative probe passes on a signed-advertised endpoint (readiness is suppressed until it does) | 0/10 ready |
| B3 | Mailbox | OutboxLog bounded journal initializes and persists across restart on a fresh bounded box (dubai-2gb, previously blocked under rc.7) | rc.9 unblocked; unobserved |
| B4 | Onion transfer | 100 MB transfer over the restricted route on canary | not run |
| B5 | Operator diversity | Per-box `config.regions`/`config.operator` rolled out; capability docs publish `operator`; quorum selector (#230) reports honest operator counts on live inventory | config not rolled out |

## Phase C — Promote v0.25.0 stable (decision)

Gate: Phase A complete, Phase B green, canary soak with zero watchdog restarts and zero fail-closed events. Then: bump `stable` in `fleet/channels.json`, publish npm `latest`, official Umbrel PR, StartOS registry — the full-release path the rc.9 repairs just proved end-to-end.

## Phase D — Track B acceptance (parallel, separate owner)

Blind public test (`1.0.0-rc.1.public-test.1`): sydney blind-edge out of its crash loop, TLS-on-443 liveness confirmed, dallas second failure domain live, Peerit bind completed. Track A does not block these; Phase C does not depend on them.

## Phase E — v0.26 line (late August, if B and D hold)

1. **v0.26.0-rc.1** — first monorepo tag containing the blind packages; opt-in blind-cell fleet profile (Track C activation).
2. **Ship 7** — gateway app-origin evidence.
3. **Ship 8** — Tor hardening RC.
4. **Ship 9** — split transport: the vnext worktree's wire layer merged behind the spec, transport descriptor, runtime — in that order. Spec first this time.
5. **Two-line convergence decision** — main (v1 tree) and the v0.25 release line are now two `ours`-merge lineage reconciliations deep (#209, #220). Before v0.26.0, decide which line is the product and how they merge for real. The reconciliations buy time; they are not the answer.

## Explicit non-goals for August

- **x402 payments** — default-off scaffold; hard gates X4-G1–G5 unmet (no stock-client evidence, no durable claim store, no reconciliation, legal review open).
- **`forwardRelay`** — do-not-enable anywhere (no backpressure).
- **`shard-store`** on new or <2 GB boxes — memory-starves; utah-0.5gb is the standing example.
- **G4-I** — research only; never a claim.

## Decision queue for the operator

1. Phase 1.1 throwaway pre-flight host — provision or drop?
2. Per-box `regions`/`operator` rollout — who writes the per-box configs?
3. Stable promotion timing once Phase B is green.
4. Two-line convergence approach (Phase E.5).
