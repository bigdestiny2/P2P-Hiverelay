# Handoff: `_scanRegistry` TOCTOU guard (defense-in-depth, apply AFTER root-cause)

**Author:** fleet-log-analysis pass, 2026-05-18
**Status:** ready, intentionally NOT applied
**Owner to coordinate with:** whoever holds Reliability v2 / the v0.8.13
corestore-closed debug session (see
`repro/2026-05-17-v0.8.13-partial-recurrence.md`)

## Why this is sitting in a handoff doc instead of committed

Fleet log analysis (5 relays, ~25k lines) found the
`"corestore is closed"` / `"Cannot read properties of null (reading
'getRelaysForApp')"` warnings concentrated on singapore-1 (403 in the
window) because it restarts frequently (8 starts), and every restart
that overlaps an in-flight `_scanRegistry()` hits a TOCTOU window:

```
_scanRegistry()
  guard: if (!this.seedingRegistry || !this.seeder) return   // passes
  await this.seedingRegistry.getActiveRequests(...)           // <-- stop() runs here
  ...                                                         //     nulls seedingRegistry
  for (const req of requests) {
    await this.seedingRegistry.getRelaysForApp(req.appKey)    // <-- null deref → warn
  }
```

A per-await re-check (`_scanAlive()`) closes this. **But applying it now
would suppress the exact symptom the planned instrumented debug session
needs to capture a stack on the silent `store.close()`.** The
recurrence repro depends on those warnings still firing. So this guard
must land **after** the root cause (who/what calls `store.close()`
mid-scan) is identified and fixed — at which point it's correct
defense-in-depth, because even a *legitimate* shutdown that overlaps an
in-flight scan still wants the scan to bail cleanly rather than
deref-null.

This is complementary to, not a replacement for, the Reliability v2
cancellation contract (`_trackFireAndForget` / drain-on-stop). The
cancellation contract prevents *new* scans starting during shutdown;
this guard makes an *already-running* scan that's parked on an `await`
bail at the next checkpoint instead of dereferencing a nulled dep.

## The change

Add a liveness helper and re-check it after every `await` in the two
registry-scan loops (`_scanRegistry`, `_checkReplicationHealth`).

Liveness signal is the **deps being non-null**, NOT `this.running`.
Rationale: `running === false` is also the legitimate pre-start state
(unit tests call these scans directly without `start()`), whereas
`stop()` nulls `seedingRegistry`/`seeder` — so their presence is the
precise "safe to keep dereferencing" condition.

```js
// add near _scanRegistry()
_scanAlive () {
  // TOCTOU signal = deps nulled by stop(), not the running flag
  // (false pre-start too, where direct scan calls are legitimate).
  return !!this.seedingRegistry && !!this.seeder
}
```

In `_scanRegistry()`:
- replace top guard `if (!this.seedingRegistry || !this.seeder) return`
  with `if (!this._scanAlive()) return`
- add `if (!this._scanAlive()) return` immediately after
  `await this.seedingRegistry.getActiveRequests(...)`
- add `if (!this._scanAlive()) return` as the first line inside
  `for (const req of requests) {`

In `_checkReplicationHealth()` (same shape, second loop):
- top guard → `if (!this._scanAlive()) return`
- after `await this.seedingRegistry.getActiveRequests()` →
  `if (!this._scanAlive()) return`
- first line inside `for (const req of requests) {` →
  `if (!this._scanAlive()) return`

## Verification done

- Re-applied locally, ran `test/unit/relay-node.test.js`: the
  replication-repair subtests (`replication health monitor attempts
  local repair`, `replication repair skips non-public tiers`) pass with
  the deps-only `_scanAlive()` (they FAIL if the guard also checks
  `this.running`, because the harness never calls `start()` — this is
  why the helper must not gate on `running`).
- Pre-existing unrelated failure in the same file: `applyMode updates
  mode profile config` — fails on clean checkout too, not caused by
  this change. Don't let it block the guard.
- Lint clean.

## Expected fleet impact once applied

singapore-1's ~400 `"corestore is closed"` / null-deref warns per
window → ~0. Other relays already near-zero (they restart rarely);
this mostly matters for memory-constrained / frequently-restarting
boxes. Pairs with the separate ops finding that singapore-1
(`ubuntu-Singapore-1gb`, 1 GB RAM, 96 seeded apps) is restarting every
12–50 min under memory pressure — that's the *frequency* driver; this
guard removes the *noise* each restart produces. Right-sizing
singapore-1 is the orthogonal ops fix.
