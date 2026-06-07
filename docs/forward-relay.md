# Forward Relay (`hiverelay-forward`)

A demand-dialled relay **transport**: a client opens a forward channel, sends
`OPEN(targetPubkey)`, and the relay dials that target over the DHT and
byte-bridges the channel to/from the target stream. It turns a HiveRelay node
into a usable relay for apps behind **NAT / UDP-blocking**, and it composes
into **onion routing**.

It complements `CircuitRelay`:

| | CircuitRelay | ForwardRelay |
|---|---|---|
| Target setup | target must pre-`RESERVE` | **target needs nothing** (relay dials it) |
| Bridges | two *client* channels | one client channel ↔ a relay-dialled stream |
| Use | both peers are relay-aware | reach a normal DHT-listening peer (e.g. a seller) |

## Why

`relayThrough` (HyperDHT blind-relay) hides your IP but is still UDP — it
can't help when UDP is blocked, and it's single-hop. ForwardRelay is a
relay-served byte transport that:
- works for clients that can reach *a* relay (e.g. over the relay's WS DHT
  bridge) even when direct UDP holepunch fails;
- the seller needs **no changes** — it just sees an incoming DHT connection
  from the relay;
- **composes into onion routing**: reach `relay2` *through* `relay1`'s forward
  channel, then the seller through `relay2` — no single relay links you to the
  seller (entry sees you↔relay2, forwarder sees relay1↔seller).

## Trust model (read this)

The relay forwards **opaque bytes** but is an active **transport** hop: like a
Tor relay, it sees the transport-level traffic unless the peers encrypt
end-to-end on top. For confidentiality from the relay, run your own Noise /
use a **sealed payload** (a confidential tier) over the forward stream. The
relay byte-bridge gives **NAT traversal + IP-hiding from the target + (nested)
unlinkability** — not content secrecy by itself.

## Enabling it (opt-in)

OFF by default. Operators opt in per node:

```json
{
  "forwardRelay": {
    "enabled": true,
    "maxForwardsPerPeer": 5,
    "maxForwardBytes": 67108864
  }
}
```

**Abuse controls (built in):** only reaches **DHT pubkeys** (a 32-byte key,
never an arbitrary IP — *not* an internet open proxy); per-peer concurrency
cap (`maxForwardsPerPeer`, default 5); per-forward byte cap
(`maxForwardBytes`, default 64 MB); per-frame cap (64 KB); rejects
forward-to-self; honours the node's existing `SwarmFirewall`; optional
`allowTarget(targetHex, peerHex)` policy hook. Still — enabling it lets peers
reach other DHT peers through your node; enable deliberately.

## Client usage

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
const stream = await client.connectViaForward(targetPubkey, relayPubkey)
// `stream` is a Duplex of the relayed byte channel. Run a NoiseSecretStream +
// Protomux/ServiceProtocol over it, keyed by the RELAY's pubkey (your
// immediate peer). null if the relay has no forward channel / is busy / rejects.
```

Onion (2-hop): `connectViaForward(relay2, relay1)` → run a forward client over
that stream → `connectViaForward(seller, relay2)` over it.

## Status

Relay-side service + client `connectViaForward` shipped; relay-side proven
E2E (`test/integration/forward-relay.test.js`: byte round-trip + fail-closed
when disabled). v1 is one forward per relay connection (multiplexing multiple
concurrent forwards over one connection is a follow-up).
