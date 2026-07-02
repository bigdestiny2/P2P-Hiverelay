# Vendored `@hyperswarm/dht-relay@0.4.3` (HiveRelay fork)

Upstream: <https://github.com/holepunchto/dht-relay> — README says **"still
experimental. Do not use it in production."**

This is a **verbatim copy of 0.4.3** with a small number of clearly-marked
production-hardening patches, vendored into the source tree so the exact code
that proxies untrusted browser DHT operations against the operator's real
HyperDHT is auditable in-repo and cannot drift with an `npm install`. Its
transitive dependencies (`hyperdht`, `protomux`, `@hyperswarm/secret-stream`,
`streamx`, …) still resolve from `node_modules`.

The transport imports from here, not the npm package:
`packages/core/transports/dht-relay-ws/index.js` →
`./vendor/dht-relay/{index.js,ws.js}`. The npm dep is pinned to exact `0.4.3`
(`packages/core/package.json`) as the vendoring source of truth and to keep the
relay byte-compatible on the wire with the peerit browser bundle (also `0.4.3`).

## Patches (search the tree for `HIVERELAY PATCH`)

1. **Egress backpressure** — `lib/transport/ws.js` `_write`.
   Upstream did `socket.send(data); cb(null)` — an immediate synchronous ack, so
   streamx believed every write completed instantly and the DHT→browser pump
   never slowed for a slow reader; the ws socket's `bufferedAmount` grew without
   bound (server-side heap DoS). Now returns through the Node `ws` send callback
   (feature-detected via `socket._socket`) so write-backpressure is real. Browser
   WebSocket keeps the original synchronous ack.

2. **Per-connection crash containment** — `lib/node-proxy.js` constructor +
   `_onProxyError`. Every protocol handler runs against the shared real DHT with
   attacker-influenced args decoded from browser frames. A synchronous throw in
   any handler (e.g. `this._dht.lookup()` on a closed DHT, or invalid decoded
   args) propagated out through the protocol EventEmitter → `uncaughtException` →
   whole-relay crash-loop under systemd. Each handler is now wrapped in `guard`,
   which contains a throw to that one connection (destroys its proxy stream,
   firing the normal close cleanup) and never rethrows. Verified by
   `test/integration/dht-relay-ws.test.js` → "crash-safety: a proxied DHT op that
   throws tears down only its connection, never the process".

3. **Resource drain on close** — `lib/node-proxy.js` `onStreamClose`.
   Upstream destroyed `_connections` but left live query streams
   (lookup/announce running against the real DHT), pending handshakes, signature
   waiters, in-flight connects, and open servers alive after the browser WS
   dropped — a slow leak on a 24/7 pipe. All per-connection maps are now
   destroyed/closed and cleared.

## Deliberately NOT patched here

- **Ingress backpressure** is bounded at the transport layer, not in the Stream.
  Pausing the socket to backpressure the readable side also stalls ws control
  frames (ping/pong/close) and breaks clean teardown. Instead `DHTRelayWS` caps
  single frames (`maxPayload`), enforces an optional per-connection ingress
  byte-rate, and reaps sustained abusers — see the transport `index.js`.

## Re-syncing with upstream

0.4.3 is frozen (upstream is not tracking it for production), so we don't expect
to bump. If a future bump is needed: re-copy the package's own files, then
re-apply the three `HIVERELAY PATCH` blocks and re-run
`test/integration/dht-relay-ws*.test.js`.
