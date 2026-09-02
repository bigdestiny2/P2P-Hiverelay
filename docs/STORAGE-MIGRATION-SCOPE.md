# Storage Migration Scope — new-Hypercore / RocksDB

> **Status (2026-09-01): HISTORICAL JUNE SPIKE — NOT CURRENT RELEASE AUTHORITY.**
> The accepted RC dependency lock is Hypercore **11.34.1**, Corestore **7.11.1**,
> Hyperdrive **13.3.3**, Hyperbee **2.27.3**, and hypercore-storage **3.2.0**
> with the tracked migration patch. The R5/R9 labels and target versions below
> record the June investigation only; they must not be cited as present RC gate
> status. Current closure comes from the accepted dependency lock, the RC
> storage-generation envelope/import/restore implementation, and its tests.

**Date:** 2026-06-16
**Historical spike target:** hypercore 10.38.2→**11.33.1** · corestore 6.18.4→**7.10.1** · hyperdrive 11.13.4→**13.3.2** · +**hypercore-storage ^3.1.1** (new, transitive `rocksdb-native ^3.11`)
**Why:** inode/dir pressure, the O(apps) `core.info({storage:true})` accounting sweep, eviction wedges, restart-reseed hangs — **not** throughput.

All version + API-existence facts verified against the live install at `~/hiverelay/node_modules` and against the new stack installed in a scratch dir on 2026-06-16. Every "behaviour-under-RocksDB" claim was empirically probed (see §5). Labels: **GROUNDED** = verified; **GATE** = unresolved, can block.

---

## 1. Verdict

**CONDITIONAL GO — but the original rationale was wrong, and there is one hard blocking prerequisite.**

Spike C (§5) **refuted the two pillars the research leaned on**:
- **fd exhaustion → REFUTED.** corestore 6 does *not* hold one fd/core — it caps at a bounded pool (~531 fds for 2650 bare cores; ~259 for 400 drive-cores). It never approaches the 245760 kern limit. fd pressure is not a real ceiling.
- **per-core memory → REFUTED.** RSS is flat between the two stacks (corestore 7 marginally *higher*).

But it surfaced a **different, real justification** that maps to the relay's actual documented pain:
- **inode/file collapse ~68×** — 1000+ files across 1200+ dirs per 500 cores on corestore 6, vs **9 files** on corestore 7. This is what the O(apps) accounting sweep `stat()`s.
- **accounting sweep correctness + speed** — see §2/R1: the sweep is both *broken* on naïve upgrade and, once fixed, structurally a fast DB read instead of thousands of `stat()`s.
- **~2× faster core open** → faster restart reseed (the milkyb-iad hang class).
- **~3× smaller on-disk** in the spike (caveat: 1-byte cores; real Hyperdrive content will narrow this — validate).

**Hard blocking prerequisite (R1):** under hypercore 11, `core.info({storage:true}).storage` is **`null`** → `storage-accounting.js` computes **0 bytes for every core** → the disk guard never trips → this reproduces the **2026-06-11 uncapped-adoption fleet-fill incident**. This must be fixed *before* any node migrates. It is provable today (§5), not a maybe.

**If the fd/inode/sweep wins don't justify the R1–R10 risk for your fleet size, the honest answer is: don't migrate.** The case rests on inode/sweep/restart, and those are real but not on-fire. Note: R1 is **migration-specific** — accounting is *correct on the current hc10 stack*, so there is nothing to "ship independently" there. The total-disk part of the R1 redesign (measure the store dir) *could* pre-land on hc10 as a more-accurate, backend-agnostic guard, which would de-risk the cutover; treat the full migration as opt-in once the GATEs clear.

---

## 2. What's de-risked (GROUNDED)

| Concern | Finding |
|---|---|
| RAS removal (hypercore 11 drops random-access-storage) | **Non-issue.** Relay passes a **path string** (`config.storage`, default `'./storage'`); zero `random-access-*` instances constructed in `packages/core`. corestore 7 accepts a path. |
| Call-site arg rewrites | **None expected.** All 12 construction sites take path-string / `store.session()`+key / corestore-core — unchanged shapes in 7/13. |
| `core.purge` / `drive.purge` / `core.clear` / `store.session` / `core.info` | **All present** in 11.33.1 / 13.3.2 (probed). |
| `core.replicator.clearRequests` (was flagged "likely broken") | **REFUTED — works.** Byte-identical v10↔v11 (`lib/replicator.js`), still guarded by `typeof === 'function'` at `cancellable-drive-update.js:413,427`. |
| Network identity across migration | **Survives.** `relay-identity.json` read outside corestore (`index.js:1816-1837`); migration folds `primary-key`→RocksDB `head.seed` with flush-before-`rm` ordering confirmed in `hypercore-storage/migrations/0/index.js`. |
| Fleet rollout | **Node-by-node.** hypercore 10 is LTS / forward-wire-compatible → mixed v10/v11 fleet replicates; migrate one box at a time. |

---

## 3. Blocking prerequisite + remaining GATEs

- **R1 (P0, CONFIRMED today) — redesign accounting for a single-store backend.** On hc11 `info.storage` is null *and* there is **no per-core on-disk size API** (verified: core exposes only `byteLength`/`contiguousByteLength` = logical content; corestore/hypercore-storage expose none). So `byteLength` is *not* a drop-in — it under-counts true on-disk bytes (hc10 example: 4096 logical vs 16384 on-disk). Two-part fix:
  - **Total disk guard** → measure the **store dir** itself (`du`/`statSync` of `config.storage`). On RocksDB that's ~9 files (cheap + accurate true-on-disk); it also works on hc10, so this half can pre-land as a backend-agnostic guard.
  - **Per-drive eviction ranking** → no on-disk per-core attribution exists under one RocksDB store; use `info.byteLength` (meta+blobs) as a **relative-size ranking proxy**, or track appended bytes in app metadata. Accept it's logical, not on-disk. Add a regression test (total ≈ `du` of store; ranking monotonic with content).
  This is migration **Step 0**, provable-needed today, and bigger than a one-line swap.
- **R7 (RESOLVED — non-blocker):** all production relays launch under **Node** (`hiverelay.service`: `/usr/bin/node .../cli/index.js`; Umbrel `Dockerfile` ENTRYPOINT `node ...`; StartOS `docker_entrypoint.sh` `exec node ...`), where rocksdb-native is proven (all of Spike C). Bare support (`pear-entry.js`, `test:bare`) is the Pear-desktop surface only. Probed anyway: **rocksdb-native + corestore 7 + hypercore 11 load and round-trip cleanly under Bare v1.28.7** (`new Corestore(path)` → append → read-back verified). Cleared for both runtimes.
- **R5 (GATE):** does `drive.close()` on a `store.session()` leave the root store + sibling drives serving on corestore 7? (Session/ref-count internals rewritten; regression = full-relay wedge, cf. CAPTURED-TRACE-2026-05-18.) Focused test required.
- **R9 (GATE):** does `drive.purge()` actually *shrink* the RocksDB store on disk, or only drop refs (compaction-deferred)? If it doesn't free space, the eviction motivation isn't relieved. Measure before/after.
- **R2 (CONFIRMED):** **no reverse v11→v10 export**; migration GC-destroys the legacy `cores/`+`primary-key` in place. → **full per-node storage-dir backup is mandatory** before cutover; canary + soak; never migrate a second node before the first validates.
- **R6 (GROUNDED):** `compact-encoding ^2→^3` + `sodium-universal ^4→^5` ride along (forced by hypercore 11's deps) — audit `protocol/*` codecs + framing separately.
- **R10 (GROUNDED):** upstream pins npm `latest` to corestore 6 ("not super deployed yet"); pin **exact** versions, long canary soak.

---

## 4. Ordered plan (once R1 done + GATEs clear)

0. **R1 accounting redesign + test** — total guard via store-dir `du` (can pre-land on hc10, backend-agnostic), per-drive ranking via `byteLength` proxy.
1. **Dep bump, lockstep**, one commit in `packages/core/package.json`: hypercore `^11.33.1`, corestore `^7.10.1`, hyperdrive `^13.3.2`, + `hypercore-storage ^3.1.1`; verify single deduped tree (`npm ls hypercore`). [S]
2. **Call-site verification** (12 sites / 5 files) — confirm contracts at runtime; expect zero arg edits. [S]
3. **Eviction re-validation** — purge present; confirm real disk shrink (R9); re-test DECODING_ERROR→meta-only path; `eviction.test`. [M]
4. **Replication smoke** — `clearRequests` works; re-verify `core.on('download'/'upload')` payloads at `seeder.js:62,68`. [S]
5. **Per-node migration**: stop unit → **back up storage dir** → swap binary → start (auto-migrate at corestore `ready()`; measure wall-time, watch the 8 s `READY_TIMEOUT_MS` on first reseed) → verify app count + accounting → return to rotation. [M]
6. **Canary soak**, then node-by-node with backup-restore rollback. [M]

**Mechanical effort is small (S);** the weight is re-validation (R1 rewrite, eviction) + rollout safety.

---

## 5. Spike C — empirical evidence (reproducible)

Harness: `bench/spike-c-core-density.mjs` (bare cores) + the statsweep/R1 probes below. Two scratch dirs with pinned stacks (`corestore@6.18.4 hypercore@10.38.2` vs `corestore@7.10.1 hypercore@11.33.1 hypercore-storage@3.1.1`), identical workload, measured `/dev/fd` count + `process.memoryUsage().rss` + on-disk `find`.

**Core density (bare cores, this run):**

| cores | corestore6 fds | corestore7 fds | cs6 RSS | cs7 RSS |
|--:|--:|--:|--:|--:|
| 500 | 531 | 21 | 76 MB | 80 MB |
| 1000 | 531 | 21 | 102 MB | 101 MB |
| 2650 | 531 | 21 | 148 MB | 155 MB |

On-disk @500 cores: **cs6 = 1001 files / 1219 dirs / 7.8 MB** vs **cs7 = 9 files / 2.5 MB**. Open-time @2650: **cs6 1497 ms vs cs7 799 ms (~2×)**. (Faithful Hyperdrive-pattern A/B, N=400 drive-cores, independently reproduced: fds 259→56, inodes 744→11, RSS flat.)

**Accounting sweep (what `storage-accounting.js` does), 2650 cores:** byteLength-based sweep **cs6 330 ms vs cs7 17 ms**.

**R1 (the blocker), per `storage-accounting.js:54-57` logic, populated core:**
```
corestore6/hc10: info.storage = {oplog:12288, tree:0, blocks:4096, bitfield:0} → 16384 bytes ✓
corestore7/hc11: info.storage = null                                          →     0 bytes ✗
```

**No per-core on-disk size API on hc11 (probed):** core exposes only `byteLength` / `contiguousByteLength` (logical content); corestore and hypercore-storage expose no per-core or store-level byte/size method. → the total guard must `du` the store dir; per-drive ranking has no precise on-disk source (use byteLength proxy). This is why R1 is a redesign, not a field swap.

**Spike C harness caveat (for re-runners):** a Hyperdrive opened on a *foreign key* is read-only — you can't `drive.put` to it (hangs), and opening two writable drives on separate `store.session()`s wedges on corestore 7. Use the **read-only-seed-from-producer** pattern (producer writes via `store.namespace()`, exports keys; seed arm opens read-only) — that's the real relay pattern (`app-lifecycle.js:298`).

---

## 6. Key files
- `packages/core/core/relay-node/storage-accounting.js:51-57` — **R1 break point** (the rewrite target)
- `packages/core/core/relay-node/eviction.js:84-108` — purge (R9)
- `packages/core/core/relay-node/app-lifecycle.js:290-298` — Hyperdrive hot path + session isolation (R5)
- `packages/core/core/relay-node/cancellable-drive-update.js:413-428` — clearRequests (works)
- `packages/core/package.json` — the dependency bump
