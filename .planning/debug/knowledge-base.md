# GSD Debug Knowledge Base

Resolved debug sessions. Used by `gsd-debugger` to surface known-pattern hypotheses at the start of new investigations.

---

## silent-corestore-close — Hyperdrive.close() cascades to shared root corestore via unseed path
- **Date:** 2026-05-18
- **Error patterns:** corestore is closed, 503, store-close-trace, unseedApp, _runCustodyExpiryPass, custody expiry, relay wedge, drive close, hyperdrive _close
- **Root cause:** app-lifecycle.js constructed every Hyperdrive with the shared root `node.store` directly. Hyperdrive@11.13.4._close() unconditionally calls `this.corestore.close()` (unless _checkout/_batching). Any unseed — custody expiry, eviction, or manual — therefore closed the root corestore, making all subsequent seed requests throw "The corestore is closed" until systemd restarted the process.
- **Fix:** Replace `new Hyperdrive(node.store, appKey)` with `new Hyperdrive(node.store.session(), appKey)` in app-lifecycle.js:257. A corestore session shares the same key-addressed hypercore objects but its close() does not propagate to the root store.
- **Files changed:** packages/core/core/relay-node/app-lifecycle.js, test/unit/drive-close-cascade.test.js
---

