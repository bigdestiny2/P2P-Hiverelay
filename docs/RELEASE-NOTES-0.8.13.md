# HiveRelay 0.8.13 — Reliability v2 (cancellation contract)

Released: 2026-05-15

Closes the class of corestore-state-corruption bugs that manifested
on production relays as `Mutex has been destroyed`, `The corestore
is closed`, and `SESSION_CLOSED: Cannot make sessions on a closing
core` after hours or days of uptime.

Co-authored with **the contributor** — he ran the audit, designed the
cancellation contract, and shipped the fix. The bug class was first
flagged in his 2026-05-15 09:56Z message; the production reproduction
was captured in
[`docs/repro/2026-05-15-corestore-closed-repro.md`](repro/2026-05-15-corestore-closed-repro.md)
when `scripts/publish-test-drive.js --roundrobin` caught two relays
wedged simultaneously.

---

## What was wrong

`RelayNode` has many long-running asynchronous paths that capture
closeable references — Hyperdrives, Hypercores, registry entries —
and continue running for tens of seconds to minutes:

- `_eagerReplicate` retry loop (~2 min, fire-and-forget from every
  `seedApp` and from `_reconcileSeedOptsOnRepin`)
- `_indexLog` triggered by `localLog.on('append')` and per-peer log
  `on('append')` listeners
- `_runRepairPass`, `_runAnchorCheck`, `_runCustodyExpiryPass`,
  `_checkReplicationHealth` periodic monitors
- `_reseedFromRegistry` cascading into a dozen seedApps on start
- Catalog-sync seedApp fan-out per remote catalog
- `_runColdStartPrimer`, `_autoEnableHolesail` setTimeouts

None of these were drained before `stop()` closed the swarm and the
corestore. The next `swarm.flush()` / `drive.update()` / `core.get(i)`
in the in-flight closure then hit the freshly-closed store and threw.
Symptoms accumulated because `drive.closed` (the flag the loops
checked) only reflects drive-level close, not the underlying store
state.

Self-heal restart cycles amplified the problem — every restart left
stale handlers from the previous incarnation in flight.

## What changed

### `LifecycleScope` (new file)

`packages/core/core/relay-node/lifecycle-scope.js` — 174 lines, single
class:

```js
const scope = new LifecycleScope()

// In a fire-and-forget loop:
for (;;) {
  if (scope.aborted) return
  try {
    await scope.race(node.swarm.flush())
    await scope.race(updateWithTimeout(drive, { timeoutMs: 30_000 }))
  } catch (err) {
    if (isAbortError(err)) return
    // ... other handling
  }
  try { await scope.sleep(5000) } catch (_) { return }
}

// At call sites:
scope.tracked(eagerReplicate(...).catch(() => {}))

// In stop():
const scope = this._scope
this._scope = null
if (scope) await scope.drain()
```

The primitive is small. `tracked(p)` registers a promise so drain
awaits it. `race(p)` short-circuits with AbortError if the signal
fires. `sleep(ms)` is an abort-aware setTimeout. `drain()` aborts
the signal, snapshots the in-flight set, awaits every promise via
`allSettled`. Idempotent.

### Wired into every participating loop

The PR modifies `app-lifecycle.js`, `relay-node/index.js`, and
`registry/index.js` to:

- Create a fresh scope at the top of `start()` (so stop+start
  cycles get a clean signal)
- Wrap every fire-and-forget that captures a closeable in
  `scope.tracked(...)`
- Replace every long `await` inside participating loops with
  `await scope.race(...)`
- Replace retry-delay sleeps with `await scope.sleep(...)`
- Add `if (scope.aborted) return` checks at iteration boundaries
- Drain the scope as the **first** action in `stop()`, before
  touching any subsystem
- Recognize `AbortError` in catch blocks via the `isAbortError()`
  helper and return silently (it's a normal exit path, not an error)

The same pattern in `registry/index.js`'s `_indexLog`: bail
synchronously before each `log.get(i)` if the scope is aborted, and
also bail if the log itself reports `closed/closing` as defense in
depth.

### Per-vector coverage

From the contributor's `STALE-REF-INVENTORY.md`:

| Vector | Site | Coverage |
| --- | --- | --- |
| A1 | `_eagerReplicate` retry loop | `scope.race` + `scope.sleep` + tracked via `_trackEagerReplicate` |
| A2 | self-heal stop/start cycle | scope recreated on each `start()`; drained on each `stop()` |
| A3 | `_indexLog` append listener | pre-iteration abort check + scope.tracked on the listener body |
| A4 | `_reconcileSeedOptsOnRepin` finally | covered by the unified `_trackEagerReplicate` wrapper |
| B1-B20 | repair pass, catalog-sync fan-out, monitors, primers, holesail auto-enable | wrapped via `_trackFireAndForget` helper on `RelayNode` |

## Tests

- **13/13 LifecycleScope unit tests** — signal/drain/race/sleep
  semantics, AbortError plumbing, retry-loop regression scenario
- **4/4 reliability-v2 integration tests** — scope-created-on-start,
  stop-blocks-on-tracked, 3-cycle start/stop with seeded apps
  (zero stale-ref errors), catch() tails observed by drain
- **80/80 existing lifecycle-adjacent unit tests still pass**
  (per the contributor's audit run; 42/42 verified locally on the validation
  branch)
- **standard** lint clean

## Canary verification (Utah-US)

Deployed the fix to Utah-US first as canary. Hammered with:

- **23/23 publishes succeeded** under back-to-back load
  (`node scripts/publish-test-drive.js --target utah-us` ×23)
- **3/3 stop/start cycles clean** — `systemctl restart hiverelay`
  followed by immediate publish all returned `200 OK`. Before this
  fix, this exact sequence would leave the relay returning 503 for
  hours.
- **Custody E2E passed** in 12.5s with Utah-US as source —
  all 5 relays converged to `committed: true, sourceRetired: true`
- **Zero `SESSION_CLOSED` / `corestore is closed` warnings** on the
  new pid
- **`REQUEST_CANCELLED — recoverable rejection — continuing`**
  warnings observed during the restart cycles — this IS the
  cancellation contract working: the abort signal cancels in-flight
  requests, the relay reports them as recoverable, no stale-ref
  errors follow

## Compatibility

- **Fully backward-compatible** with all v0.8.x publishers and
  clients. No protocol changes.
- **No relay config changes required.** Default `shutdownTimeoutMs`
  (5s) is enough for the scope drain.
- **No app-registry / data migration.** The fix is purely about
  process lifecycle.

## Migration for operators

`git pull && npm install --production && systemctl restart hiverelay`.
Nothing else.

## Acknowledgements

The contributor did the heavy lift here: he traced the symptom across multiple
production relays, mapped the call graph in the audit, designed the
LifecycleScope contract, wired it into every fire-and-forget site,
and wrote the tests. We pair-reviewed the design before the PR
landed; the validation harness (`scripts/publish-test-drive.js`,
`scripts/custody-e2e.js`, the observatory at `tools/observatory/`)
provided the canary that confirmed the fix.

His PRs #16 and #17 (client-side recovery) remain in the codebase
as defensive belt-and-suspenders, but with v0.8.13 deployed the
underlying state corruption that necessitated them shouldn't recur.
