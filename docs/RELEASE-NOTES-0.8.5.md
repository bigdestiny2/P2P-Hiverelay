# Release Notes — v0.8.5

**Release date**: 2026-05-06

`p2p-hiverelay-client` Bare/Pear-runtime compatibility fix. Caught by an
external integrator (Drop v3 escrow team).

## The bug

Importing `HiveRelayClient` from a Bare or Pear app crashed at load with:

```
MODULE_NOT_FOUND: crypto
```

`pairing.js` (loaded transitively via `index.js`) imported Node's `crypto`
module, which doesn't exist in the Bare runtime. The crash happened
*before* any HiveRelay code ran — apps couldn't even reach their `await
client.start()` line.

## The fix

Two-part:

### 1. `pairing.js` — replace bulk `crypto.randomBytes` usage with sodium

`crypto.randomBytes(N)` was the only mass dependency on Node's `crypto`
in `pairing.js`. Three call sites updated to use a local `randomBytes`
helper that wraps `sodium.randombytes_buf`. Removes the load-time
crash trigger.

### 2. `imports` map in `packages/client/package.json`

Added a Bare-aware `imports` block that aliases Node built-ins to the
`bare-*` equivalents at the package level — same pattern `p2p-hiverelay`
core has been using since the 0.5.0 monorepo split:

```json
"imports": {
  "events": { "bare": "bare-events", "default": "events" },
  "fs/promises": { "bare": "bare-fs/promises", "default": "fs/promises" },
  "path": { "bare": "bare-path", "default": "path" },
  "crypto": { "bare": "bare-crypto", "default": "crypto" }
}
```

The remaining `crypto.createHmac()` call in `proofFor()` now resolves to
`bare-crypto` under Bare and Node's `crypto` otherwise.

### Dependencies

- `bare-crypto` `^1.13.4` → `^1.13.6` (across the client; lockfile
  regenerated)
- Added direct deps on `bare-crypto`, `bare-events`, `bare-fs`, `bare-path`
  (pinned to versions matching `core`'s existing pins)

## Verification

- Smoke-tested under Node: `HiveRelayClient` imports cleanly; all three
  pairing helpers (`generateCode`, `deriveTopic`, `proofFor`) produce
  correct output.
- Lint clean. Pre-existing unrelated nits in `pairing.js` cleaned up
  while in the file.

## Upgrading

```bash
npm install p2p-hiverelay-client@^0.8.5
```

If you're integrating from a Bare/Pear app, the import path changed in
v0.5.0 (the SDK split into its own package). Use:

```js
const { HiveRelayClient } = await import('p2p-hiverelay-client')
```

Dynamic import is required from CommonJS callers because the new package
is `"type": "module"`. ESM callers can use a regular `import` statement.
