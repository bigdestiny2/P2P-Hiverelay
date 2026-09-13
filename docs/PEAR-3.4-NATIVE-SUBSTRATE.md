# Pear 3.4 native availability substrate

**Status:** local adoption candidate, 2026-09-13  
**Upstream anchor:** `holepunchto/pear` tag `v3.4.0`, commit
`06d118de02ff6c9be23345888d48903dbc2c7a9f`

## Decision

Pear 3.4 does not make HiveRelay redundant. It makes the raw availability and
hole-punch fallback layer a supported Pear primitive:

- `pear blind-relay start` forwards framed UDX streams for peers that cannot
  establish a direct path.
- global `pear --relay <key>` selects that fallback for Pear applications.
- `pear blind-peer start` and `pear seed --blind-peer <key>` provide raw
  Hypercore, Hyperdrive, and Autobase availability.

HiveRelay remains the operator and product layer: admission, storage budgets,
leases, receipts, retrievability proofs, encrypted custody, catalogues,
browser/HTTPS ingress, fleet policy, recovery, and deployment packaging. The
new native primitives should sit underneath those controls where they improve
interoperability.

## Bounded first adoption

This candidate adds an opt-in `pearBlindRelay` transport that speaks Pear
3.4's `blind-relay@1.6.1` protocol on HiveRelay's existing HyperDHT instance.
It is disabled by default, has a separate stable public key, enforces a finite
socket ceiling plus pending-pair and active-link budgets, uses framed raw
streams exactly like Pear 3.4, and advertises
itself only while listening.

The candidate also pins HyperDHT to `6.33.2` across the workspace, matching the
Pear 3.4 release. That upstream line fixes relayed keepalive/direct-upgrade
handoff, stale relay-socket cleanup, and LAN-shortcut fallback behavior.

The transport is a content-blind, in-memory connection pipe. Its aggregate
session/pairing/stream counters are operational telemetry, not HiveRelay
storage or bandwidth receipts. It does not grant seeding, custody, service, or
catalogue admission.

Enable it in configuration:

```js
transports: { pearBlindRelay: true },
pearBlindRelay: {
  maxSessions: 1024,
  keepAliveMs: 5000,
  maxPendingPairings: 1024,
  maxPendingPerSession: 16,
  maxActiveLinks: 2048,
  maxActiveLinksPerSession: 16,
  pairingTimeoutMs: 30000,
  idleTimeoutMs: 60000,
  maxLinkLifetimeMs: 3600000,
  stopTimeoutMs: 5000
}
```

Or at local startup with `--pear-blind-relay` /
`HIVERELAY_PEAR_BLIND_RELAY=1`. Clients read the running public key from the
signed capability document or operator status and pass it to Pear's global
`--relay` option.

## Admission and lifecycle bounds

Pair requests are checked before the native library allocates pairing records
or UDX streams. `maxActiveLinks` counts raw stream endpoints; each matched
pair uses two. Both participating sessions must have room under the per-session
link limit. The first request that exceeds a budget closes its control session
and socket. Self-pairing and reuse of an active token are refused because the
upstream session map cannot safely own both endpoints under the same key.

Unmatched tokens expire after `pairingTimeoutMs`; the owning control connection
closes so unmodified clients observe failure. Empty or never-opened channels
expire at the next `idleTimeoutMs` sweep. Active streams have a finite maximum
lifetime and close their counterpart on expiry or closure. Clients must reconnect
when the configured lifetime expires. Keepalive is separate from these limits.

A protocol-channel close destroys its owned Noise socket and both sides of its
active pairs. The session ceiling counts owned sockets until their actual close,
including channels already closing. Stop destroys owned sessions, sockets and raw
streams before waiting on listener closure; concurrent callers share completion.
A shutdown deadline rejects while retaining ownership and telemetry for a retry.
Counters remain visible after stop, and socket/stream gauges track actual owners.

The admission adapter uses the private message callbacks and pairing/link maps of
exact `blind-relay@1.6.1` and `protomux@3.11.0`. The lock is unchanged. Startup
checks their structural contract, and the real-library regression test binds both
resolved source files by SHA-256. Dependency changes require review of callback
ordering, pre-allocation behavior and cleanup, plus the same wire-level tests;
matching method names alone does not establish compatibility. The HyperDHT
integration tests use a private local testnet and preserve Pear's framed UDX
fallback. This is local evidence, not a public-fleet capacity or soak result.

## Blind-peer hold

Do not expose Pear's native `BlindPeer` server from HiveRelay yet. The reviewed
`blind-peer@3.12.6` defaults permit untrusted requesters to ask for cores and
carry a 100 GB default storage allowance. Its trusted-key controls do not
replace HiveRelay's per-publisher admission, byte accounting, expiry, lease,
receipt, or recovery contracts.

A later adoption may attach `blind-peering` to drives already admitted by
HiveRelay, or place native blind-peer workers behind an adapter that proves all
of the following before accepting bytes:

1. publisher/capability admission is resolved;
2. the exact core set is charged to the shared storage authority;
3. expiry, purge, recovery, and receipts remain consistent;
4. restart and rollback evidence passes with existing HiveRelay readers;
5. a native Pear client can seed and restore through the adapter on a local
   testnet.

Until then, Pear-native blind relay is adopted and native blind-peer storage is
held. Existing HiveRelay storage paths remain authoritative.

## Rollback

The new transport is additive and default-off. Disable
`transports.pearBlindRelay`, restart the node, and clients fall back to direct
hole punching or their previously configured relay. No storage or wire-format
migration is involved.
