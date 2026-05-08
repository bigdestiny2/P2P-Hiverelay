# Release Notes — v0.8.4

**Release date**: 2026-05-05

Targeted DHT error-classification fix. Single-line behavioural change.

## Fixed

### `DHTError REQUEST_DESTROYED` reclassified as recoverable

Background: when a Hyperswarm DHT lookup is torn down mid-request (because
the peer rotated, the network blipped, or the node went offline), the DHT
emits `REQUEST_DESTROYED`. Up through v0.8.3 the relay's connection-error
handler treated this as a fatal error and escalated it onto the
unrecoverable error path, which surfaced as user-visible failures in
`pearbrowser-desktop` and similar consumers.

`REQUEST_DESTROYED` is structurally a transient condition — the right
response is to retry the lookup. v0.8.4 reclassifies it accordingly:

```js
// packages/core/core/relay-node/...
if (err.code === 'REQUEST_DESTROYED') {
  // recoverable — caller will retry
  return { recoverable: true }
}
```

## Impact

- Publishers using the SDK will see fewer spurious "permanent failure"
  events on flaky networks.
- Auto-retry loops in HiveRelayClient now actually fire on
  REQUEST_DESTROYED rather than bailing out.
- No on-wire protocol change. Safe to run mixed-version (0.8.3 + 0.8.4)
  in the same network.

## Upgrading

```bash
npm install -g p2p-hiverelay@^0.8.4
```

No data migration. No config changes.
