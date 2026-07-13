# HiveRelay Phase-0 Integration Plan — 2026-07-13

**Scope:** HiveRelay only (public HTTPS gateway + blind substrate).  
**Out of scope:** Peerit application work (owned by a parallel agent).  
**Authority:** does not authorize publish, deploy, fleet mutation, or GA.

## 1. Current truth (re-verified live)

| Surface | Location | Tip | Dirty | Role |
| --- | --- | --- | --- | --- |
| Canonical fleet main | `00-core/hiverelay` `main` | `999b0afd` v0.24.3 | yes (see salvage) | Production line; not blind |
| Public HTTPS gateway | `00-core/hr-https-gateway` `feat/public-https-hive-gateway` | `0ff54842` | 0 | Track A: `public-t1-gateway` |
| Blind integration | `00-core/hr-vnext-integration` `feat/vnext-integration` | `2ef12971` | programme docs only | Track B: `direct-blind-g2s` + programme ledger |
| Storage redesign salvage | `00-core/hr-main-salvage` `fix/vnext-inherited-baseline` | `e437d924` | 0 | Provenance-safe storage caps (related to gateway lineage) |
| Blind satellites | `hr-blind-*` worktrees | various | 0 | Earlier slice work; content largely re-landed on vnext under new hashes |

Gateway and vnext **diverge after** `999b0afd`. Path-name overlap is only ~4 files. They must be merged deliberately, not assumed equivalent.

Immutable main-dirty snapshot:  
`docs/vnext/salvage-bundles/2026-07-13-main-dirty/`  
(see `SHA256SUMS`, `tracked.patch`, `untracked-source.tgz`, `branch-graph.md`).

Prior salvage audit (still authoritative on P1s):  
`docs/vnext/hiverelay-main-salvage.json` (2026-07-12).

## 2. Main dirty classification (do not bulk-commit to release)

### Blocked until redesigned (P1)

1. **Credits API/auth** — financial views readable without management auth on main dirty.  
   - **Already fixed on vnext:** `ee4b1a6b fix(api): auth-gate credits financial views`.  
   - **Action:** do **not** cherry-pick main dirty credits; prefer vnext fix. Main dirty is evidence/history only.

2. **Storage-cap provenance** — main dirty treats numeric equality with 50 GiB default as “unset” and can enlarge caps / ignore free space.  
   - **Already redesigned on gateway + hr-main-salvage** (`resolveStorageCap` + provenance modules + tests).  
   - **Missing on vnext.**  
   - **Action:** bring gateway/salvage storage design into the integration train; discard main’s inline unsafe variant.

### Safe to preserve as independent commits (after split)

| Order | Group | Notes |
| --- | --- | --- |
| 1 | CLI `--help` dispatch safety | Hunk in `packages/core/cli/index.js` only |
| 2 | `pear-gracedown` migration | package/locks + cli/standalone; update leftover docs that still say `graceful-goodbye` |
| 3 | Compatibility aliases + examples + services README | `/api/status`, `/api/metrics`, defensive examples; **not** main’s old gateway spec draft |
| 4 | Fleet disk pressure display | `fleet/fleet-status.sh` — after storage policy is correct |

### Exclude from source commits

- `tmp-test-relay2/` runtime state  
- `startos-0.4/` scratch / node_modules  
- `HiveRelay-0.24.1-*.pdf` stale marketing artifacts  
- Main’s untracked `docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md` (686 lines) — **superseded** by gateway worktree (1052 lines)  
- `FEATURES.csv` until statuses are truthful and generation is deterministic  

## 3. Integration train (HiveRelay-only)

```text
999b0afd (v0.24.3 baseline)
    │
    ├─► feat/public-https-hive-gateway   (+10)  Track A gateway + storage enforcement
    │
    └─► feat/vnext-integration           (+42)  Track B blind packages + programme state
              │
              ▼
         integration merge (this plan)
              │
              ├─ public-t1-gateway canary (staging)
              └─ direct-blind-g2s package RC (fail-closed production start)
```

### Step A — close PG-0 for HiveRelay main dirty

1. Keep immutable bundle (done: `salvage-bundles/2026-07-13-main-dirty`).  
2. Optionally land **safe-only** commits on `salvage/main-dirty-safe-*` (cli-help, gracedown, aliases).  
3. Never promote main dirty P1 patches.  
4. Leave canonical `main` deployable only as released v0.24.3 until a deliberate RC.

### Step B — merge storage + gateway into integration base

Primary source of truth for gateway + storage: **`feat/public-https-hive-gateway`**.

On a **new** worktree from `feat/vnext-integration` tip (do not dirty the programme branch blindly):

1. Merge or rebase `0ff54842` onto vnext tip.  
2. Expect conflicts mainly in shared touchpoints (`package.json` / lock / `api.js`).  
3. Prefer:  
   - gateway storage provenance + public HTTPS runtime  
   - vnext blind packages + credits auth-gate + protocol docs  
4. Run gateway preflight/tests + blind package unit tests on the merge result.  
5. Record merge commit and evidence under `docs/vnext/`.

### Step C — Track A exit (`public-t1-gateway`)

Still required before live fleet canary:

- Frozen **non-transitional** T1/T2/T3 admission predicate (depends on blind role classifier).  
- Canonical gateway spec only (gateway worktree wins; generate mirrors).  
- V-GW1 budgets + full suite on the release commit.  
- Staging `--mode canary` evidence for **one** trusted public app.  
- Owner **D-5** (separate T1 product naming).  
- `--mode fleet` remains fail-closed until substrate gate passes.

### Step D — Track B exit (`direct-blind-g2s` draft → RC)

Current packages are `0.0.0-draft.1` with wire `releaseReady` for public WIRE only.

Still required:

- Owner **D-1, D-6, D-7** before `specHash` / Peerit migration sequence (D-1 can wait for Peerit agent; D-6/D-7 block freeze).  
- Finish CR/V gates (CR-1…CR-8, V-1…V-8) on **one** frozen ABI.  
- Daemon production assembler gates: store, signed topology, readiness, migration, soak.  
- Browser client evidence-bound `releaseReady` (static remains false until verifier).  
- Publish real versions only after gates; keep production listeners fail-closed until then.

### Step E — programme ledger updates after each step

Update:

- `docs/vnext/program-state.json` (profile status, gate evidence pointers)  
- focused JSON handoffs under `docs/vnext/`  
- never claim release/deploy from docs alone  

## 4. Explicit non-goals (this cycle)

- Peerit client migration, SW release sequence, capacity GA (other agent).  
- G3 / OHTTP promotion.  
- Fleet wipe or multi-node stable promotion.  
- npm/GHCR publish, Umbrel/StartOS marketplace submission.  
- Merging unsafe main dirty storage/credits as-is.

## 5. Immediate next actions (ordered)

1. **Done:** re-verify trees; write immutable main-dirty bundle; this plan.  
2. **Next:** create safe-only salvage commits from main (or leave dirty with bundle only).  
3. **Next:** open merge worktree `feat/vnext-integration` + `feat/public-https-hive-gateway`.  
4. **Next:** resolve conflicts; re-run blind + gateway test subsets.  
5. **Owner input:** D-5 (gateway positioning), D-6 (`K_partition`), D-7 (rollback wording).  
6. **Only then:** staging gateway canary rehearsal (no fleet).  

## 6. Stop rules

- Stop if merge would discard unknown dirty work without a hash-bound bundle.  
- Stop if any path would publish, deploy, rotate keys, or mutate production fleet.  
- Stop if gateway admission is still transitional and someone requests `--mode fleet` promotion.  
- Stop at Peerit surfaces; hand off notes only.
