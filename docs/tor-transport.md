# Tor v3 Onion Transport (`hiverelay.onion/1`)

Relay-side location anonymity: a persistent, access-gated, health-gated Tor v3
onion service. Clients reach the relay without learning its IP; with
restricted discovery enabled, only enrolled clients can even decrypt the
service descriptor.

OFF by default. Enable per node:

```json
{
  "transports": { "tor": true },
  "tor": {
    "keyFile": "./hiverelay-storage/tor/hs-key.blob",
    "minDaemonVersion": "0.4.9.5",
    "rosterFile": "./hiverelay-storage/tor/auth-roster.json",
    "endpointKeyId": "onion-2026-07-a",
    "exposure": "dual"
  }
}
```

Requires a local tor daemon (>= 0.4.9.5; **0.4.8 leaves the network
2026-09-01**) with `ControlPort` + `CookieAuthentication`. See the comments in
`packages/core/config/default.js` (`tor` section) for every option.

## Identity persistence

With `keyFile` set, the relay mints an `ED25519-V3` hidden-service key on
first start, stores it `chmod 0600`, and restores the **same onion address on
every restart**. Include `hs-key.blob` in the encrypted operator backup —
losing it means a new address (clients must re-read the capability doc).
A corrupt key file fails closed: the relay refuses to silently mint a new
identity.

Without `keyFile` the service is ephemeral (address changes every restart) —
fine for tests only.

## Restricted discovery (private relays)

With `rosterFile` set (or `clientAuthKeys` non-empty), the service requires
v3 client authorization: only enrolled clients can connect. Semantics
(M0-verified against tor 0.4.9.6):

- enrollment is **rebuild-in-place**: the roster change recreates the service
  with the same address (brief intro-point churn; there is no runtime
  roster add on the control port);
- the client device generates its own x25519 keypair and installs it into its
  own tor daemon (`ONION_CLIENT_AUTH_ADD ... Flags=Permanent`, survives
  restarts). The relay only ever holds **public** keys;
- the roster file is operator-private — it enumerates your clients. Never
  publish or log it.

Enrollment envelopes (`hiverelay.onion.authkey/1`) and signed acceptance
receipts are provided by `packages/core/transports/tor/auth-keys.js`
(`createEnrollment`/`verifyEnrollment`/`createReceipt`/`verifyReceipt`);
they ride the existing pairing channel: the device presents its envelope at
pair time and the relay completes the enrollment
(`packages/core/transports/tor/enrollment.js`, wired into
`RelayNode.pairDevice`) — verify, roster rebuild-in-place, rosterFile
persist, signed receipt back.

## Virtual ports

`vports` maps onion ports to local listeners; the capability doc advertises
roles (`readPlane`, `peer`) so clients can separate HTTP reads from the
peer/replication protocol. Default (legacy): vport 80 → the HTTP API port.

With the transport enabled, the peer protocol plane binds automatically: an
`OnionPeerListener` (loopback Noise XK endpoint, `tor.peer` config below)
accepts the peer vport's forwarded connections and runs the same
Noise/Protomux peer protocol as swarm connections (custody, replication,
RPC), re-validated by the relay's normal connection handler. The peer vport
is folded into the hidden-service mapping on start and on every roster
rebuild; an explicit `vports` entry for the same vport overrides it.

```json
"vports": [
  { "vport": 80, "targetHost": "127.0.0.1", "targetPort": 9100 },
  { "vport": 19737, "targetHost": "127.0.0.1", "targetPort": 19737 }
],
"peer": { "enabled": true, "vport": 19737, "host": "127.0.0.1", "port": 19737 }
```

`peer.host` must stay loopback — the onion service is the only ingress
(location hiding). Clients dial the onion peer vport as Noise XK initiators
with the relay's stable pubkey (from the signed capability doc) as
`remotePublicKey`.

## Health-gated advertisement

The onion endpoint appears in the signed capability doc
(`privacyTransports`) only while the transport reports `ready`
(descriptor uploads observed + optional SOCKS self-probe). Degraded health
removes the entry — clients never see a dead endpoint. Health states:
`tor-starting → key-loaded → descriptor-uploaded → ready`, plus `degraded`
and `disabled`.

## PoW defense — packaging decision

PoW requires a tor build **with the pow module** (the Homebrew build lacks
it) and a `HiddenServiceDir`-configured service; there are no per-service
control-port flags. `pow.enabled` attempts the daemon-wide `SETCONF` and
**fails closed with guidance** when the build/config can't support it. For
public, catalog-advertised relays, package a pow-enabled tor with a
filesystem hidden service (see the spec §6.3).

## Exposure modes

- `dual` (default): public DHT/HTTP surfaces + onion. Note: shared uptime and
  the shared stable identity link the two — clients are told.
- `hidden-only`: the relay's clearnet listeners/catalog publication are
  disabled; discovery flows only through the signed capability doc over
  protected channels. (Enforcement wiring lands with the exposure-mode
  follow-up; today this is an operator discipline + config flag.)

## Privacy guarantees and honest limits

- Clients and observers do not learn the relay IP from protocol data.
- The relay's stable identity remains a public pseudonym.
- **No timing-correlation resistance on this lane** — there is no cover
  traffic. UI must never label it `traffic-analysis-resistant`.
- Public status/metrics expose only coarse tor health (running, health,
  connection count) — no onion address, roster size, or descriptor counters
  (see `transports/tor/redaction.js` and its forbidden-field audit).

## Operator checklist (don't deanonymize yourself)

- Don't reuse payment rails, hosting accounts, or domains across the hidden
  identity and your real identity.
- Don't cross-sign the onion key and other identities.
- Keep the tor daemon updated religiously (currency is a security property).
- Back up `hs-key.blob` + roster file encrypted; test restore.
