# HiveRelay 0.8.14 — root-cause fix for the silent corestore-close

Released: 2026-05-18

One-line code change that fixes the actual root cause of the
`The corestore is closed` wedge class. v0.8.13's `LifecycleScope`
(Reliability v2) closed the *restart-triggered* fire-and-forget
vector that was wedging first (~6h MTTF); v0.8.14 closes the
underlying state corruption that was wedging slower (~57h MTTF)
on continuous operation.

Forensic writeups:
- [`docs/repro/2026-05-17-v0.8.13-partial-recurrence.md`](repro/2026-05-17-v0.8.13-partial-recurrence.md) — production trace
- `.planning/debug/CAPTURED-TRACE-2026-05-18.md` — root cause confirmed

---

## What was wrong

Every seeded drive was constructed against the **one shared root
corestore**:

```js
// app-lifecycle.js _seedAppInner — pre-v0.8.14
const drive = new Hyperdrive(node.store, appKey)
```

`hyperdrive@11.13.4`'s `_close()` calls `this.corestore.close()`
unconditionally. So *any* unseed path tore down the root store
for the entire relay:

- `_runCustodyExpiryPass` reaping a temporary / atomic / blind entry
  past its `retainUntil`
- `_evictOldestApp` (storage-pressure eviction)
- version-supersede dedup
- manual unseed via `client.unseed(driveKey)` / `DELETE /api/v1/seed/:key`

Every subsequent `new Hyperdrive(node.store, …)` in the seed path
then threw `The corestore is closed`. `POST /api/v1/seed` returned
relay-wide `503` until `systemd Restart=always` reaped the crashed
process.

Mean-time-to-wedge of ~57h on production relays tracked
**time-to-first-temporary-entry-expiry**, which is why it presented
as load-dependent and random — the symptom only manifested when
something legitimately wanted to call `unseedApp()`, and what
triggered the first unseed varied between relays.

## What changed

### One-line fix

```js
// app-lifecycle.js _seedAppInner
- const drive = new Hyperdrive(node.store, appKey)
+ const drive = new Hyperdrive(node.store.session(), appKey)
```

A corestore session shares the same key-addressed Hypercores
(on-disk identity is byte-identical — the 300+ live entries on every
production relay keep their storage; no re-replication on upgrade).
But the session's `_close()` only drops *its own* refs to those
cores. The root `node.store` stays open. The cascade is broken at
the source.

### Why v0.8.13 + v0.8.14 are both kept

`LifecycleScope` is orthogonal to this fix and still valuable. It
prevents fire-and-forget closures from racing against a *legitimate*
shutdown — that vector existed independently of the session bug
and was the *faster* wedge path. Defense in depth: 0.8.13 stops the
fast path, 0.8.14 stops the slow path. Both belong in the codebase.

### Dockerfile (build fix)

`verifier` was added to the root `workspaces` array and the lockfile
in an earlier release, but its `package.json` was never added to the
deps stage's `COPY` list. `npm ci --workspaces` failed the image
build. v0.8.14 adds the missing line:

```diff
  COPY packages/client/package.json packages/client/
  COPY packages/services/package.json packages/services/
+ COPY packages/verifier/package.json packages/verifier/
```

## Tests

- **7/7 unit regression tests** in
  [`test/unit/drive-close-cascade.test.js`](../test/unit/drive-close-cascade.test.js)
  (17 assertions): seed 2 drives sharing the root store, unseed 1,
  assert `node.store.closed === false`, the other drive still
  resolves, a fresh `Hyperdrive` still opens, the unseeded session's
  refs are released. Includes a regression test that documents +
  asserts the **old broken pattern** so the bug can't silently
  return.
- `npx standard` clean.

## Canary verification (Utah-US, `HIVERELAY_STORE_TRACE=1`)

- **5 rounds** of seed-temporary-drive → `_runCustodyExpiryPass`
  unseed
- **0** `[STORE-CLOSE-TRACE]` events emitted during the unseed
  passes (the trace fires on any `node.store.close()` invocation —
  pre-fix it fired every cycle)
- Relay `active` and serving throughout; no `corestore is closed`
  warnings on the new pid

## Compatibility

- **Fully backward-compatible** with all v0.8.x publishers, clients,
  and on-disk app-registry state. No protocol changes.
- **On-disk Hypercore identity is unchanged** — a session is a
  reference wrapper, not a new namespace. Live entries keep their
  storage; no re-replication required on upgrade.
- **No relay config changes required.**

## Migration for operators

`git pull && npm install --production && systemctl restart hiverelay`.
Nothing else. The fix is invisible during normal operation; you'll
notice it as the absence of the periodic relay-wide-503 → restart
loop.

## Acknowledgements

Captured trace from instrumented production debug session (see
`.planning/debug/CAPTURED-TRACE-2026-05-18.md`) made the root cause
unambiguous — the trace showed `unseedApp` → `drive.close()` →
`store.close()` in a single stack on the shared root, which
collapsed the search space from "somewhere in the lifecycle" to
"the seed-time constructor argument."
