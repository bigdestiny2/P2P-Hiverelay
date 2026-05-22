# HiveRelay 0.8.15 — Audit hardening

Released: 2026-05-19

Pure hardening release. No protocol changes, no behavior change for
public/non-blind drives. Two audit-driven fixes close residual leaks
that v0.8.14 + the v0.8.13 cancellation contract left in place.

If you're upgrading from v0.8.14: `git pull && npm install --production
&& systemctl restart hiverelay`. No migration. Drop-in.

---

## What changed (5-line summary)

1. Every `new Hyperdrive(node.store, …)` site in the relay now uses
   `node.store.session()` — covers the 3 sites the v0.8.14 fix missed
   (gateway HTTP, storage service, standalone gateway entrypoint).
2. `_indexAppManifest` now skips drives with `blind: true` instead of
   opening their manifests.
3. `_shouldRedactEntry` now forces redaction for `blind: true`
   entries unconditionally — operator config cannot override the
   publisher's privacy commitment.
4. 7 new unit tests guarding the blind-path boundary.
5. utah-us canary retired (instrumentation + watcher cron removed;
   relay moves back to main).

---

## Hyperdrive-session audit follow-up

v0.8.14 wrapped `_seedAppInner`'s `new Hyperdrive(node.store, …)` with
`.session()` to break the close-cascade. The canary's `[STORE-CLOSE-
TRACE]` then captured 15 close-call events through OTHER unguarded
Hyperdrive sites — `gateway/hyper-gateway.js`, `gateway/server.js`,
`storage-service.js`. The fleet survived (v0.8.14's seed-path session
absorbed the cascade), but covering every site is the correct shape.

Sites fixed (one-line `.session()` wrap each):

| Site | Runtime exposure |
| --- | --- |
| `packages/core/gateway/hyper-gateway.js:497` | **In fleet runtime** — HyperGateway is constructed in `RelayNode` (`index.js:669`) with raw `node.store`. DriveCache evictions hit this path. |
| `packages/services/builtin/storage-service.js:65` | bare-relay (Pear runtime) — `bare-relay.js:223` passes raw `node.store`. Not in our CLI fleet but same pattern. |
| `packages/core/gateway/server.js:45, 101` | Standalone gateway entrypoint — owns its own Corestore. Defensive. |

Every other `new Hyperdrive(...)` call site (`app-lifecycle.js:265`
from v0.8.14) is now consistent.

---

## Blind-path airtight audit

Threat model: **operator-untrusted**. A relay operator with root on
the box must not be able to read blind drives' content or identifying
metadata through the relay's own machinery.

Walked 9 paths (full report at
[`docs/audit/2026-05-19-blind-path-audit.md`](audit/2026-05-19-blind-path-audit.md)).
Found **2 real leaks**, both with cascading fixes:

### Path 1 — `_indexAppManifest`

**Was:** Unconditionally opened `/manifest.json` on every anchored
drive, parsed it, persisted `appId`/`name`/`description`/`author`/
`categories`/`version` into `app-registry.json`. Operator with disk
access could read all of that for blind entries.

**Now:** Early-returns when `entry.blind === true`. Blind entries
keep their commitment-level fields (`appKey`, `blindContentId`,
`ciphertextRoot`, `durability`, `revocable`, `custodyIntentId`) —
signed publisher commitments, not inspected content. Manifest is
never opened.

**Cascade closure:** the `app-replaced` and `app-version-rejected`
events emitted from inside this method (with `appId` + `version` in
the payload, which flow to logs and ws-feed) now never fire for
blind entries.

### Path 3 — `_shouldRedactEntry`

**Was:**

```js
_shouldRedactEntry (entry, opts = {}) {
  if (opts.redactPrivate !== true) return false  // caller opt-in
  ...
  return entry.blind === true || privacyTier !== 'public' || ...
}
```

Blind redaction was caller-opt-in. A `redactedCatalog: false`
operator config exposed blind entries' full metadata via public
`/catalog.json`. And any internal `appRegistry.catalog()` call that
forgot `redactPrivate: true` (like `api.js:792`) skipped redaction.

**Now:**

```js
_shouldRedactEntry (entry, opts = {}) {
  if (entry.blind === true) return true   // unconditional
  if (opts.redactPrivate !== true) return false
  const privacyTier = String(entry.privacyTier || 'public').toLowerCase()
  return privacyTier !== 'public' || entry.metadataVisibility === 'redacted'
}
```

The blind flag is the publisher's commitment, not an operator
preference. The relay honors it independent of opts/config.
`opts.redactPrivate` now only controls non-blind privacy-tier
handling.

**Cascade closure:** every `catalog()` callsite (`/catalog.json`,
`/api/apps`, `/api/drives`, `api.js:792`, etc.) now redacts blind
entries even when no `redactPrivate` opt is passed.

### Paths NOT changed (already airtight or out-of-scope)

| # | Path | Status |
|---|---|---|
| 2 | HyperGateway HTTP | OK — `appEntry.blind` check at `:289` returns 403 before opening the drive |
| 4 | `catalogForBroadcast` (P2P gossip) | OK — hardcoded `redactPrivate: true` |
| 5, 9 | `app-replaced` / `app-version-rejected` logging | Cascade-fixed by Path 1 |
| 6 | `/api/manage/*` calling `catalog()` | Cascade-fixed by Path 3 |
| 7 | Federation catalog-sync | OK — `blind` flag propagates through `synthRequest` into `seedApp` |
| 8 | On-disk replication blocks | Architectural — relay can't cryptographically verify pushed blocks are ciphertext. Defaults already strict (`requireEncryptedPayload: true`, `allowTransparent: false`). Doc-level note in PUBLISHING.md (separate). |

---

## Tests

- 7 new tests in `test/unit/blind-path-airtight.test.js` fuzzing the
  blind-flag boundary:
  - `_shouldRedactEntry` returns true for blind regardless of opts
  - `catalog()` with no opts redacts blind
  - `catalog({ redactPrivate: false })` STILL redacts blind (the
    audit fix)
  - `catalogForBroadcast` regression guard
  - non-blind public entries follow opts (scope guard — public
    discovery still works)
- Existing `test/unit/app-registry.test.js: redacted catalog hides
  blind/private metadata` updated: its assertion that "raw internal
  catalog preserves operator metadata" was encoding the leak as a
  feature. Updated to assert the new contract; previously-leaky
  assertions flipped to assert redaction.
- 49/49 tests pass across the lifecycle/registry/blind test surface
  (168/168 assertions). `npx standard` clean.

---

## Canary retirement

utah-us was running on `fix/drive-close-corestore-cascade` (commit
`0573166`, the precursor to v0.8.14) with `HIVERELAY_STORE_TRACE=1`
and the hourly `store-close-watcher.sh` cron. Across 95.7 hours it:

- Captured 15 `close-call` stack events + 1 watchdog event showing the
  root corestore transitioning `closed=true` — confirmed the original
  failure path (`_runCustodyExpiryPass → unseedApp → drive.close() →
  Hyperdrive._close → store.close`) and surfaced the Hyperdrive-site
  audit
- Never wedged the relay despite the close events — validated v0.8.14's
  session boundary works
- Self-detected zero wedges via the synthetic publish watcher

The diagnostic apparatus is no longer needed:

- root cause known + fixed
- audit completed + further sites covered
- the canary's branch was drifting from main with every release

Retirement at v0.8.15 rollout: `git checkout main && git reset --hard
origin/main && rm /etc/systemd/system/hiverelay.service.d/store-trace.conf
&& crontab -l | grep -v store-close-watcher | crontab - && systemctl
restart hiverelay`.

---

## Compatibility

- **Backward-compatible.** Public/non-blind drives behave identically.
  All discovery features (`_indexAppManifest` for non-blind drives,
  `/catalog.json`, gateway HTTP for non-blind, federation catalog-sync)
  work as before.
- **One semantic narrowing for blind entries:** any operator-side
  tooling that relied on `appRegistry.catalog()` returning unredacted
  blind data (either by passing no opts, or by setting
  `custody.redactedCatalog: false`) now sees redacted output. The
  behavior was a leak; the audit fix is intentional. Internal code
  that needs unredacted access uses `appRegistry.get(appKey)`
  directly, not the `catalog()` projection.

## Migration

`git pull && npm install --production && systemctl restart hiverelay`.
Nothing else.

## Acknowledgements

The canary captured the trace that drove the Hyperdrive audit. The
audit-as-doc-first methodology (publish the report, get review on the
findings, then apply the fixes) turned the blindness work from "remove
all discovery features" into "two surgical guards." Path 1 + Path 3,
6 lines of code, 7 tests. The right scope was already in the codebase
— it just needed the guards finished.
