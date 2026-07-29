# HTTPS Gateway Production Build-Out — Handoff (2026-07-19)

**Scope:** the HTTPS bridge gateway track of the giga release (Browser Bridge R1–R9 + app-origin gateway production surface) on branch `v1-integration` (worktree `00-core/v1-integration`). This document is the merge handoff: what is on the branch, the evidence, the merge-safety analysis, and what remains for the owner/fleet.

**Headline:** all gateway code items R1–R9 except R2 (PSL, registration) and R8 (WebTransport, Phase 3+) are implemented, tested, and committed. The branch merges current main (`fcd71163` opsec scrub) and current `feat/tor-onion-transport` (`2081fb7` fleet multi-node view) — verified ancestor of all three hub lines.

## 1. What is on the branch (gateway commits, oldest → newest)

| Commit | What |
|---|---|
| `ed50c54` + `7da9898` | **R1 verifiable retrieval mode** — `?verify=1` or `Accept: application/vnd.hiverelay.hc-block` returns a versioned bundle (block bytes + hypercore merkle proof + signed tree header) instead of raw bytes. `packages/core/gateway/verify-bundle.js` (builder, 305 lines), `packages/client/verify-block.js` (independent verifier, 287 lines). Clients verify content against the drive key's signed root without trusting the gateway. Public drives only; blind/custody stays hard-403 on the same admission. |
| `98bafe1` | **R4 federated signed denylist** — `packages/core/core/gateway-denylist.js` + `api-gateway-denylist.js`: versioned entries (hashed keys — the channel is not a content oracle; expiry; bounded reason codes) over the relay federation channel. Fail-closed before serving on both lanes; local add purges the LRU + stops in-flight streams; restart-persistent. |
| `070a791` | **R3/R5/R6/R7 edge header bundle** — `packages/core/gateway/edge-headers.js`: `Service-Worker-Allowed` structurally stripped on the shared-origin path lane (incl. `writeHead` object/array args; no content channel exists anyway); `ONION_READ_PLANE_CSP` (`default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; media-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`) on onion ingress (detected by `.onion` Host — spoofing only earns the stricter policy); COOP `same-origin`, CORP `cross-origin` (path) / `same-origin` (app-origin), Referrer-Policy `no-referrer` on every response class; `Link: <hive://key/path>; rel="canonical"` on both lanes. |
| `f1ea8c8` | **R9 conformance suite + real enforcement fixes** — `test/integration/gateway-conformance.test.js` (20 tests/154 asserts): frozen limits tuple (64 MiB legacy cap / 4 MiB cell class / 256 MiB egress per IP×app per 60 s / 15-min response lifetime) + edge discipline (421 unknown SNI, SNI==Host, single z32 label, GET-only, listing bounds, drive-op/empty-drive timeouts). Two real gaps closed in gateway code: lifetime-tripped stalled responses now release their admission slot; empty-drive wait abandons inside the frozen 20 s. |
| `b84f2b10` | merge: main @`fcd71163` (opsec scrub) — 1 comment-hunk conflict (kept the current v0.24.3 pin note) |
| `7b877642` | merge: feat/tor-onion-transport @`2081fb7` (fleet multi-node view + GIGA sync) — 2 small conflicts (took the opsec-scrubbed variants) |

Earlier spine these build on: `83d9fb5` gen-3 deps merge → `f0b4376` WAL P1 → `290bebd` WAL P2 → `76eff20` WAL P3 → `c05d84c` tor merge → `190b450` bytesPerDay → `4291100` journey matrix → `f0676b8` cs7 teardown fix.

## 2. Evidence (all on the committed tree)

- **45/45 gateway-focused test files pass** (unit + integration: verify-bundle, denylist + denylist-federation, edge-headers, conformance, streaming, journey-gateway-tor, public-hive-gateway-*, capability/catalog suites).
- R1: golden-drive round-trip + tamper cases (wrong bytes/index/stale header/wrong key all reject), both trigger surfaces, frozen-limits parity.
- R4: local add → immediate 451 + LRU purge; two-relay federation propagation proof; bad-sig/expired/wrong-key rejected; hashed keys only.
- Headers: full lane×ingress×header matrix (8 tests/112 asserts) + onion-ingress assertions through the real tor transport (journey-gateway-tor: 14/14, 124 asserts).
- R9: 20/20, 154/154.
- Post-merge suites for the fleet multi-node view files: api-overview, dashboard-fleet-ui, dashboard-index-ui, outboxlog — all PASS.
- Line-wide state before the gateway work: 340/345 unit files (4 pre-existing v1-tip failures — `blind-protocol-vectors`, `vnext-program-state`, `vnext-protocol-remediation`, `blind-client-late-app` — proven on the tip, not introduced here), integration 40/41 (pvss intermittent harness race only), 3-process cell qualification green.

## 3. Merge-safety analysis

- **Ancestry verified:** `hub/main` (`fcd71163`), `hub/feat/tor-onion-transport` (`2081fb7`), `hub/chore/holepunch-gen3-upgrade` all ancestors of `v1-integration` HEAD. The v1 line can merge into any of the hub lines without divergence from their side (only main-line commits land on it through the owner's flow).
- **All conflicts resolved and committed; working tree clean** (except untracked `.t/` test scratch and the pre-existing untracked PDFs in the hub repo — not in this worktree).
- **No rewrites:** every change is an additive commit; no amends, no force-push, nothing pushed.
- **Concurrent-session work respected:** the opsec scrub + fleet multi-node view (2081fb7) are merged in, not overwritten; their other live worktrees (hr-blind-review, tor-hardening-review, 10 shared-adoption lanes, pear-deploy, hub doc edits) untouched.
- **Cross-repo note:** the v1-integration worktree belongs to the `hiverelay-blind-vnext-integration` clone; the hub repo is linked as remote `hub` for the merges. Pushing this branch means pushing from that clone's origin (or adding it as a hub remote — owner's choice).
- **Frozen surfaces untouched:** wal.v2/HRWL frames, frozen limits tuple, exact-byte mode, byte-stable capability-doc signing (relays without Tor still produce byte-identical docs).

## 4. What is NOT done (owner/fleet only — no code left here)

- **G7–G13 gateway operator evidence:** two operators with distinct domains/keys, signed-tag manifest digests, operator-contract digests (fleet evidence), Docker `nginx -T` capture (G12), real-host exclusive whole-root ceiling (G13).
- **R2 — PSL registration** for `*.<app-suffix>` (public suffix list; months to propagate — start whenever).
- **R8 — WebTransport v2** for `dhtRelayWs` (Phase 3+).
- **Linux Phase-0 WAL rerun** (freeze gate; portable harness `00-core/wal-phase0-evidence-2026-07-13/`).
- **100 MB bulk-over-onion** measurement (live tor, env-gated `test/integration/tor-bulk.test.js`).
- **Negative-probe health gate** (adversarial gap recorded in `docs/GIGA-RELEASE-ARCHITECTURE.md` §7.3 — all-invalid roster silently fails open at the tor daemon; the gate needs a negative probe).
- Known follow-ups: P1×P2 atomic-staging lock narrowing (measured ~35 vs ~126 PUTs/s at 64-way), the 4 pre-existing v1-tip failures, INBOX/CORE/FORWARD assembly, HIP-1 MLS P0.

## 5. Suggested merge path (owner's flow)

1. Review this branch (`v1-integration`, tip at handoff commit) — diff per the table in §1.
2. Push + PR per repo conventions; run CI (the suite runner is brittle-4 compatible).
3. Cut the v1 RC via the signed release flow only after: Linux Phase-0 rerun + 100 MB bulk + G7–G13 evidence + freeze sign-off (protocol hashes + store-format authority).
4. Main-line release of `feat/tor-onion-transport` (tor + bytesPerDay + GIGA docs) can proceed independently on the v0.24.x line if desired — the v1 line already contains it.
