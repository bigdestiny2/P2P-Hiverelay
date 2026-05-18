# CAPTURED: silent-corestore-close root cause (2026-05-18T09:38:53Z)

The instrumented canary (utah-us, `HIVERELAY_STORE_TRACE=1`, branch
`debug/store-close-trace`) caught the wedge. Definitive stack:

```
[STORE-CLOSE-TRACE] 2026-05-18T09:38:53.663Z
Error: STORE-CLOSE-TRACE: store.close() called
    at _storeRef.close (file:///root/hiverelay/packages/core/core/relay-node/index.js:510:28)   ← instrumentation wrapper
    at Hyperdrive._close (/root/hiverelay/node_modules/hyperdrive/index.js:191:28)              ← THE CASCADE
    at async close (/root/hiverelay/node_modules/ready-resource/index.js:56:54)
    at async AppLifecycle.unseedApp (file:///root/hiverelay/packages/core/core/relay-node/app-lifecycle.js:953:11)
    at async RelayNode._runCustodyExpiryPass (file:///root/hiverelay/packages/core/core/relay-node/index.js:2580:9)

[STORE-CLOSE-TRACE] watchdog: store.closing/closed first detected at 2026-05-18T09:39:20.611Z closing=true closed=true
```

Status line confirms it: `Apps: 316` immediately before the trace,
`Apps: 315` immediately after — exactly one app unseeded, and the
root store went down with it.

## Root cause (confirmed by reading the code at every frame)

`app-lifecycle.js:257` constructs every drive against the SHARED root
corestore:

```js
const drive = new Hyperdrive(node.store, appKey)
```

`app-lifecycle.js:953` `unseedApp()` closes that drive:

```js
try { await entry.drive.close() } catch (_) {}
```

`hyperdrive@11.13.4 index.js:191` `_close()`:

```js
await this.db.close()
if (!this._checkout && !this._batching) {
  await this.corestore.close()        // ← closes the SHARED root store
}
```

Because each `Hyperdrive` is constructed with the **root** `node.store`
(not a per-drive namespace/session), `drive.close()` calls
`this.corestore.close()` on the one store the entire relay shares.
Closing any single drive tears down the root corestore → every
subsequent `new Hyperdrive(node.store, …)` in the seed path throws
`The corestore is closed` → `POST /api/v1/seed` 503 → relay wedged
until systemd `Restart=always` reaps the crashed process.

## Why this explains everything

- **Silent:** `unseedApp` + the hyperdrive/ready-resource close path
  emit no logs. Nothing in our code logs a root-store close because
  nothing in our code *intends* one.
- **Continuous-operation, no stop() needed:** any unseed triggers it —
  `_runCustodyExpiryPass` (temporary/atomic/blind entry past
  retainUntil), version-supersede dedup in `_indexAppManifest`,
  eviction (`_evictOldestApp`), manual unseed. The captured instance
  was the 60s custody-expiry pass.
- **v0.8.13 LifecycleScope didn't touch it:** that fix drained
  fire-and-forget loops on `stop()`. This is not a stop() path at all
  — it's a drive.close() cascade during normal runtime. v0.8.13's
  real ~10× improvement came from removing the *restart-triggered*
  vector that was wedging first; the unseed-cascade was always the
  slower second vector underneath.
- **~57h variable:** depends purely on when the first temporary /
  atomic-handoff / blind-with-retainUntil / superseded entry expires
  and gets unseeded. More short-TTL churn = faster wedge (explains
  bern + the canary wedging in <24h once test/custody churn rose).
- **Bounce "fixes" it:** restart reopens a fresh root store.

## Fix direction (for Phase 3)

Construct each app's Hyperdrive from an **isolated corestore
session/namespace** so `drive.close()` closes only that session, not
the shared root:

```js
// instead of:  new Hyperdrive(node.store, appKey)
// use a per-app namespace/session whose close() does NOT propagate
// to the root store. Verify the exact corestore@6.x / hyperdrive@11.13.4
// API: corestore.namespace(name) vs corestore.session({ ... }), and
// confirm the resulting drive.close() leaves node.store.closed === false.
```

Constraints Phase 3 must respect:
- Drives are looked up by key and reused across seed/repair/anchor/
  catalog paths — the session must be stable per appKey for the life
  of the entry, created at seed time, closed at unseed time.
- `_seedAppInner` (line 257) is the construction site. `unseedApp`
  (953) is the teardown. There may be other `new Hyperdrive(` sites —
  grep them all (repair, distributed-drive-bridge, gateway).
- The v0.8.13 LifecycleScope + cancellable-drive-update helpers must
  still work against the session-backed drives.
- After fix: `unseedApp()` of one entry must leave `node.store`
  open and every other seeded drive serviceable. Add a regression
  test that seeds 2 drives, unseeds 1, asserts the other still
  resolves + a fresh `new Hyperdrive(node.store, …)` still works.

## Operational state at capture time

- All 5 production relays self-recovered via systemd `Restart=always`
  and are healthy as of ~2026-05-18T09:45Z.
- Production impact per cycle: bounded 503 window between store-close
  and process restart, plus in-memory state loss (re-reseeds from
  registry on restart).
- The `debug/store-close-trace` instrumentation branch stays on
  utah-us until the fix is validated.

## IMPORTANT — blocked dependent work

The Tier-1 "make test scripts self-expiring" change (uncommitted,
local only — `scripts/publish-test-drive.js`, `scripts/custody-e2e.js`)
is currently a **wedge accelerator**: self-expiring temporary entries
→ more `_runCustodyExpiryPass` unseeds → more root-store closes. It
MUST NOT be committed/deployed until this root cause is fixed. After
the fix it becomes safe and desirable again. Same for the relay-janitor
(unseeds idle entries == triggers the same cascade pre-fix).
