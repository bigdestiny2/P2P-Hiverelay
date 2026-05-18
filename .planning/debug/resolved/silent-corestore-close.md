---
status: resolved
trigger: "silent corestore close — relay wedges with 503s intermittently"
created: 2026-05-17T00:00:00Z
updated: 2026-05-18T10:20:00Z
---

## Current Focus

hypothesis: CONFIRMED + FIXED — drive.close() on root-store-backed Hyperdrive closes root corestore
test: canary validation on utah-us, 5x forced unseed via temporary drives
expecting: zero [STORE-CLOSE-TRACE] events, relay stays active after each unseed
next_action: DONE — fix shipped to fix/drive-close-corestore-cascade

## Symptoms

expected: relay serves requests indefinitely; unseeding expired/evicted apps does not affect other seeded drives
actual: relay serves 503 for all seed requests after an unseed event; process eventually crashes/restarts via systemd
errors: "The corestore is closed" on POST /api/v1/seed after first unseed; [STORE-CLOSE-TRACE] watchdog fires
reproduction: seed any storageClass:temporary drive with a short retainUntil; wait for _runCustodyExpiryPass to fire (60s interval)
started: has been present since initial builds; v0.8.13 LifecycleScope work fixed the restart-triggered vector that was masking this one

## Eliminated

- hypothesis: LifecycleScope fire-and-forget drain issue
  evidence: v0.8.13 added LifecycleScope which fixed the restart-path vector; problem recurred under continuous operation (no restart needed)
  timestamp: 2026-05-17

- hypothesis: race condition in swarm teardown during unseed
  evidence: stack trace shows drive.close() → corestore.close() directly, no swarm involvement
  timestamp: 2026-05-18T09:38:53Z

## Evidence

- timestamp: 2026-05-18T09:38:53Z
  checked: instrumented canary on utah-us (debug/store-close-trace branch, HIVERELAY_STORE_TRACE=1)
  found: |
    [STORE-CLOSE-TRACE] 2026-05-18T09:38:53.663Z
    Error: STORE-CLOSE-TRACE: store.close() called
        at _storeRef.close (index.js:510) ← instrumentation wrapper
        at Hyperdrive._close (hyperdrive/index.js:191) ← THE CASCADE
        at async AppLifecycle.unseedApp (app-lifecycle.js:953)
        at async RelayNode._runCustodyExpiryPass (index.js:2580)
    Apps: 316 before → 315 after (exactly one unseed, whole store down)
  implication: confirmed root cause — hyperdrive._close() calls corestore.close() on shared root store

- timestamp: 2026-05-18T09:45:00Z
  checked: hyperdrive@11.13.4 index.js:190-192
  found: |
    if (!this._checkout && !this._batching) {
      await this.corestore.close()
    }
    Every non-checkout non-batch drive unconditionally closes its corestore on drive.close()
  implication: the only safe pattern is to give each drive its own corestore session

- timestamp: 2026-05-18T10:00:00Z
  checked: corestore@6.18.4 session() API and _close() implementation
  found: |
    session() creates a Corestore with _root = this._root (shared cores map)
    session._close() removes from _rootStoreSessions + closes session._sessions
    session._close() does NOT call _closePrimaryNamespace() (checks this._root === this)
    corestore.get({ key }) looks up by discoveryKey — namespace-independent
    Same appKey → same hypercore regardless of session vs root store
  implication: store.session() is the safe wrapper — shares cores, isolated close()

- timestamp: 2026-05-18T10:05:00Z
  checked: all new Hyperdrive() sites in packages/core
  found: |
    app-lifecycle.js:257 — node.store (primary fix site)
    app-lifecycle.js:345 — same drive, same session (covered by fix)
    gateway/hyper-gateway.js:497 — uses gateway's own _store (not node.store, intentional)
    gateway/server.js:43,98 — standalone gateway process, owns its store (intentional)
  implication: only app-lifecycle.js needs the fix; gateway paths are standalone and own their stores

- timestamp: 2026-05-18T10:20:00Z
  checked: canary validation utah-us, 5x forced unseed rounds
  found: |
    Round 1: canary-fix-test-1 seeded, expired after 2min, unseeded — 0 STORE-CLOSE-TRACE
    Rounds 2-4: 3 drives seeded + expired batch — 0 STORE-CLOSE-TRACE  
    Round 5: canary-fix-test-5 seeded, expired — 0 STORE-CLOSE-TRACE
    relay status: active, running: True, connections: 8 throughout
    journalctl grep 'STORE-CLOSE-TRACE' in last 15min: 0 matches
  implication: fix confirmed by canary — no store-close cascade in 5+ unseed events

## Resolution

root_cause: |
  app-lifecycle.js:257 constructs every Hyperdrive with the shared root corestore:
    new Hyperdrive(node.store, appKey)
  Hyperdrive@11.13.4._close() calls this.corestore.close() unconditionally (unless
  _checkout or _batching). Any unseed path (custody expiry, eviction, manual unseed)
  therefore closes the root corestore → every subsequent new Hyperdrive(node.store, ...)
  throws "The corestore is closed" → relay-wide 503 until systemd Restart=always.

fix: |
  Replace new Hyperdrive(node.store, appKey) with new Hyperdrive(node.store.session(), appKey)
  in packages/core/core/relay-node/app-lifecycle.js:257.
  A corestore session shares the same key-addressed hypercore objects (_root.cores map,
  identical key derivation for explicit-key lookups) but its _close() only tears down
  its own session refs — the root store stays open for all other drives.
  The 300+ live on-disk entries are unaffected: key-based lookup is namespace-independent.

verification: |
  Unit tests: 7/7 pass including regression test proving old pattern breaks (drive-close-cascade.test.js)
  Canary: utah-us, 5x forced unseed via temporary drives with 2-min retainUntil
  Result: 0 [STORE-CLOSE-TRACE] events, relay active throughout, fresh seeds continue working
  Commit: 0573166 on branch fix/drive-close-corestore-cascade

files_changed:
  - packages/core/core/relay-node/app-lifecycle.js (line 257: node.store → node.store.session())
  - test/unit/drive-close-cascade.test.js (new — 7 tests, 17 assertions)
  - .planning/debug/CAPTURED-TRACE-2026-05-18.md (new — root cause confirmation + stack trace)
