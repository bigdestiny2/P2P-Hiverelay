# HiveRelay

**A versatile blind peer for Pear applications. Application-agnostic. Always-on. Cryptographically gated. Privacy-preserving by default.**

Drop a Hyperdrive key in front of a HiveRelay node and your Pear app comes online — discovered via the DHT, replicated across regions, reachable from browsers, mobile, and behind NATs. The relay is **blind to your application data**: encrypted drives stay encrypted on disk, plaintext fields are structurally rejected at the protocol boundary, and the operator never sees what you're hosting. **Application-agnostic at every layer** — anything built on Hypercore + Hyperswarm works, whether you're shipping a notes app, a marketplace, a chat client, a binary distribution, a P2P forum, or something nobody's built yet.

It's the substrate. You build the app; the network handles availability, NAT traversal, browser/mobile ingress, custody, and self-heal.

**Open source (Apache 2.0)** | **[GitHub](https://github.com/bigdestiny2/P2P-Hiverelay)** | **[npm](https://www.npmjs.com/package/p2p-hiverelay)** | **Status: v0.8.23**

### Recent releases

For full details on each see the [CHANGELOG](./CHANGELOG.md).

- **v0.8.23** — Partial-quorum custody-commit support + transient core error classification on Protomux publish channel + Drop's import-subpath exports pinned. Unblocks downstream T-of-N quorum workflows; brings Protomux retry semantics to parity with the HTTP API path.
- **v0.8.22** — Defensive timeouts on `drive.ready()` (8s) and `_isDriveFullyReplicated` (3s). One hung drive no longer deadlocks the reseed or anchor-check loops. Surfaced by milkyb-iad's disk-full investigation: 12-of-145 entries reseeded over 15h → all 145 in minutes post-fix.
- **v0.8.21** — Self-heal that actually heals. Hyperdrive 11.x Promise-shape `download()` API support + persistent download ranges (`core.download({ start: 0, end: -1 })`) registered on every per-app Hyperdrive's meta + blob cores. First cross-relay autonomous self-heal demonstrated on the milkyb fleet (syd anchored a drive in ~5s by pulling peer-to-peer from fra, no publisher in the loop).
- **v0.8.20** — Anchor honesty + custody auto-attestation. `anchored=true` now requires every blob block present locally, not just metadata length. Periodic `_runCustodyExpiryPass` auto-signs `custody-non-serving-proof` on every retainUntil expiry; cross-relay witness pass signs independent witnesses of peers' proofs.
- **v0.8.19** — Circuit-relay bridge data plane + auth-bypass closure. Reservation + connect handshake now actually completes a usable bridge over Protomux; identity binding can no longer be silently bypassed.
- **v0.8.18** — Catalog provenance (Phase A): `publisherPubkey`, `durability`, `revocable`, `retainUntil` surfaced on broadcasts so federation peers can distinguish published-with-commitment from pure-anonymous gossip.
- **v0.8.17** — Browser / WSS bridge enabled on 3 fleet relays via Caddy + Let's Encrypt. `wss://relay-us.p2phiverelay.xyz`, `wss://relay-sg.p2phiverelay.xyz`, `wss://relay-eu.p2phiverelay.xyz` now reachable for browser + Android WebView consumers.
- **v0.8.16** — `dht-relay-ws` transport privacy hardening: per-process salted IP hashing, error-message scrubbing, no raw client IPs in any emitted event or log.
- **v0.8.15** — Blind-path audit: `_indexAppManifest` skips `blind: true` drives, `_shouldRedactEntry` forces redaction unconditionally for blind entries (operator config can't override the publisher's privacy commitment). Plus extends the v0.8.14 `node.store.session()` pattern to all remaining `new Hyperdrive(...)` sites.
- **v0.8.14** — One-line root-cause fix for the silent `The corestore is closed` wedge. Each seeded drive now gets its own `node.store.session()` so unseeding never tears down the shared root store. Closes the failure class the v0.8.13 cancellation contract only masked half of.
- **v0.8.13** — `LifecycleScope` cancellation contract: every fire-and-forget closure is tracked and drained before `stop()` returns, eliminating the restart-triggered stale-ref class (co-authored with [@iainkek](https://github.com/iainkek)).
- **v0.8.0–v0.8.12** — Atomic Blind Custody as a first-class signed protocol; reliability series fixing the silent partial-pin trap and Hypercore session leaks; publisher-signed REST + Protomux submission paths; `--operator` / `--auto-heal` deploy flags.

---

## What HiveRelay does

P2P apps built on Hyperswarm work beautifully — until the developer closes their laptop. Users see "offline." Mobile users behind carrier NATs can't connect. Browser users can't use UDP. There is no durable availability layer and no shared discovery surface.

HiveRelay solves all of that, then keeps going.

A HiveRelay node is a Hyperswarm peer that joins the same DHT, speaks the same protocols, and replicates the same Hypercores — application-agnostic — plus five capabilities purpose-built for being a versatile blind substrate:

1. **Bootstrap any Pear application.** Hand the relay a Hyperdrive key + your accept-mode policy; the relay keeps the app online and discoverable from the DHT. No application-specific code; no opinionated metadata schema; no privileged knowledge of what you're hosting. The same relay can carry a binary mirror, a chat backend, an app store, and a notes app simultaneously.
2. **Blind by default for encrypted workloads.** The Atomic Blind Custody plane processes ciphertext only — the validator hard-blocks ten plaintext field names so leakage is structurally impossible. Operators can't see what you encrypted, and can prove they stopped storing it at expiry without ever decrypting.
3. **Cryptographically verified replica durability.** Peers count toward archive replication only when they produce a fresh signed Ed25519 anchor proof. AutoHeal recruits diverse replicas across regions and operators automatically. Self-heal pulls missing blocks peer-to-peer between relays once a publisher's been online once.
4. **Cross-NAT + browser/mobile ingress.** Circuit-relay protocol for hole-punching fallback (cellular ↔ home Wi-Fi). `dht-relay-ws` transport for browsers and WebView Android clients to participate in the DHT over WSS. No application code needs to change for any of it.
5. **Real-time P2P trust pipeline + live telemetry.** Custody, anchor, and publish messages flow over Protomux channels on the existing Hyperswarm connection — no HTTPS dependency. WebSocket dashboard feed surfaces per-drive diversity, custody pipeline health, and event push for every state change.

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'

const app = new HiveRelayClient('./my-app-storage')
await app.start()

const drive = await app.publish('./my-app')
// Close your laptop. Your app stays online via the relay network.
```

Works in **Pear/Bare runtime** natively. See [docs/PEAR-INTEGRATION.md](docs/PEAR-INTEGRATION.md) for full usage.

---

## The two storage planes

HiveRelay 0.8.0 distinguishes two storage classes with different semantics. A single relay can run both.

### Persistent Availability Plane

For Pear apps, public drives, package mirrors, routing services. Marked `durability: 1` (archive tier).

- **AutoHeal** background scheduler keeps replicas across ≥4 regions and ≥5 operators.
- Cryptographic peer verification — peers without fresh anchor proofs don't count toward diversity.
- `replicaBuffer` of +2 over the SLO floor absorbs transient offline dips.
- Per-operator fairshare cap prevents sybil clusters from dominating any drive.
- Catalogs are public; clients discover content via DHT plus the federation gossip layer.

### Atomic Blind Custody Plane

For encrypted file handoffs, blind dead drops, time-bounded transfers. Marked `storageClass: 'temporary'`.

- Relays process ciphertext only — never plaintext, never decryption keys.
- Validator hard-blocks ten plaintext field names so leakage is structurally impossible.
- Six signed message types: intent → receipt → commit → source-retired → proof → non-serving-proof, with witness tombstones layered on top.
- `retainUntil` is enforced state — the expiry monitor unseeds at the deadline and the relay signs a non-serving-proof.
- Independent witnesses probe relays after expiry and sign tombstones — drops undetected post-expiry serving from ~82% to <1%.

For the full protocol, see the [Atomic Blind Custody whitepaper](docs/ATOMIC-BLIND-CUSTODY.md).

---

## Five things you can build

### 1. Encrypted file handoff with a TTL that the network enforces

```js
const intent = await client.publishCustodyIntent(relayUrl, {
  blindContentId: hashHex(yourPayload),
  ciphertextRoot: yourCiphertextRoot,
  requiredReplicas: 3,
  deadline: Date.now() + 60_000,
  retainUntil: Date.now() + 24 * 60 * 60_000  // 24 hours
}, { apiKey })

// Wait for quorum, then commit + retire authority.
let status
while (!(status = await client.getCustodyStatus(relayUrl, intent.intentId)).quorumReached) {
  await sleep(2000)
}
await client.publishCustodyCommit(relayUrl, intent.intentId, {}, { apiKey })
await client.publishSourceRetired(relayUrl, intent.intentId, {}, { apiKey })

// 24h later, retainUntil elapses, relays unseed, witnesses sign tombstones.
```

### 2. Verifiable archive durability

```js
await client.seed(driveKey, { durability: 1, revocable: false })
// AutoHeal across the network ensures ≥7 replicas, ≥4 regions, ≥5 operators.
// Each replica's "I have it" claim is gated on a fresh Ed25519 anchor proof.
```

### 3. Cryptographic dead drops

Two parties, one signed handoff record, no trust in any single relay.

### 4. Multi-region read-replica distribution with provable freshness

```js
const peers = await client.getRelays()
const fresh = peers.filter(p => p.hasFreshAnchorProof)
// Read from any of them — they all cryptographically demonstrated current state.
```

### 5. Per-app SLA enforcement via live dashboard feed

Subscribe to `/ws` and drive UX off the actual durability state.

---

## Privacy model

Apps declare their own privacy tier. The relay enforces what it sees based on this:

| Tier | Relay sees | Where data lives | Example |
|---|---|---|---|
| `public` | Everything (drive content, metadata) | DHT-replicated, gateway-served | Open-source app, public dataset |
| `local-first` | Discovery key only; data exchanged peer-to-peer | Local + opportunistic relay cache | Personal notes, journal |
| `p2p-only` (blind) | Opaque ciphertext bytes | Encrypted on relay disk; gateway returns 403 | Wallets, medical, private messaging |

The `p2p-only` tier is the killer feature for production privacy-preserving apps. Combined with atomic blind custody, the relay can prove it stored your encrypted content and stopped storing it at expiry — without ever decrypting it.

---

## Client SDK

```bash
npm install p2p-hiverelay-client
```

### Content API

| Method | Description |
|---|---|
| `app.publish(dir, opts)` | Publish a directory to a Hyperdrive (`encryptionKey` for blind mode) |
| `app.open(key, opts)` | Open and replicate a remote drive |
| `app.get(key, path)` / `.put` / `.list` | Drive content access |
| `app.seed(driveKey, opts)` | Mark a drive for relay replication (`durability: 1` for archive tier) |
| `app.unseed(driveKey)` | Signed kill switch |
| `app.closeDrive(key)` | Close a drive |

### Custody API (v0.8.0)

| Method | Description |
|---|---|
| `app.publishCustodyIntent(url, intent, opts)` | Sign and publish a custody intent |
| `app.publishCustodyCommit(url, intentId, commit, opts)` | Sign commit when quorum reached |
| `app.publishSourceRetired(url, intentId, ret, opts)` | Retire source authority |
| `app.recordCustodyProof(url, proof, opts)` | Record a possession-challenge result |
| `app.recordCustodyNonServingProof(url, intentId, proof, opts)` | Relay's post-expiry attestation |
| `app.recordCustodyExpiryWitness(url, intentId, witness, opts)` | Independent witness tombstone |
| `app.getCustodyStatus(url, intentId)` | Read-only quorum + commit status |

### Quorum + verification API

| Method | Description |
|---|---|
| `app.refreshCapabilityCache(urls)` | Fetch + cache capability docs |
| `app.selectQuorum(opts)` | Pick diverse / pinned / wide quorum |
| `app.queryQuorumWithComparison(path, quorum, opts)` | Parallel query + auto fork detection |
| `app.fetchCapabilities(url, opts)` | Get a relay's signed capability doc |
| `app.publishSeedingManifest(url, manifest)` | Publish author's preferred-relay manifest |

---

## For Operators

You have hardware — a VPS, a Mac Mini, a Raspberry Pi. HiveRelay turns it into part of a verifiable trust network.

### Direct install

```bash
npm install -g p2p-hiverelay
p2p-hiverelay setup        # Interactive wizard
# or:
p2p-hiverelay start --region NA --operator your-org-name --max-storage 50GB
```

The new `--operator` flag is **important** for v0.8.0. Without a stable operator identifier, AutoHeal treats each pubkey as its own operator and the per-operator fairshare cap doesn't activate. Set it to your org / deployment name (`"acme-corp"`, `"foundation-prod"`, etc.).

### Live Management TUI

```bash
p2p-hiverelay tui
```

Interactive control of everything — accept-mode, federation, custody settings, AutoHeal thresholds, network discovery.

### Operating Modes

| Mode | Description |
|---|---|
| **Relay Core** | Default focused kernel: availability + atomic custody, no service plugins |
| **Custody Relay** | Atomic blind custody profile for encrypted temporary handoff |
| **Service Operator** | Service plugin host on top of relay core |
| **Witness** | Lightweight expiry-witness role — no storage, just attestation |
| **HomeHive** | Home/personal relay — 32 connections, 25 Mbps, LAN-priority |
| **Seed Only** | App seeding only — no circuit relay |
| **Relay Only** | Circuit relay only — no seeding |
| **Stealth** | Minimal footprint, designed for Tor-only |
| **Gateway** | HTTP gateway focus — high connection limits |

### Accept-Mode

| Mode | Behavior |
|---|---|
| `review` (default) | Operator approves every inbound seed request |
| `allowlist` | Auto-accept publishers in the trusted list |
| `open` | Auto-accept everything signed (pair with payment-required) |
| `closed` | Relay-only mode, no inbound seed requests |

### Federation

```bash
hiverelay federation follow https://relay.example.com
hiverelay federation mirror https://my-other-relay.example.com
```

Followed catalogs go through your accept-mode gate. Mirrored peers bypass the gate (use sparingly — only for "your own other node" or trusted partners).

### Live Dashboard

Every relay exposes a WebSocket feed at `/ws` that broadcasts:
- Per-drive AutoHeal diversity scorecard (replicas, regions, operators, threshold status)
- Aggregate custody snapshot (intents, quorums met, commits, witness tombstones, commit rate)
- Real-time event push on recruit, proof-fail, throttle, and every custody pipeline transition

Dashboards subscribe and reflect actual state, not polled state.

---

## Architecture

```
                Pear App / Client SDK
                         |
                Hyperswarm DHT (discovery)
                         |
              +----------+----------+
              |                     |
         Relay A                Relay B
              |                     |
         +----+----+           +----+----+
         | Seeder  |           | Seeder  |
         | Circuit |           | Circuit |
         | Custody |           | Custody |
         | Witness |           | Witness |
         | AutoHeal|           | AutoHeal|
         +----+----+           +----+----+
              |                     |
              +- mutual federation -+
                         |
              +----------+----------+
              |                     |
        Hyperdrive             Registry log
        replication            (custody entries)
                         |
              +----------+----------+
              |                     |
        Persistent             Atomic Blind
        Availability           Custody
        Plane                  Plane
```

Seven Protomux channels run over each Hyperswarm connection: `hiverelay-seed`, `hiverelay-proof`, `hiverelay-circuit`, `hiverelay-services`, `hiverelay-registry-meta`, `hiverelay-anchor` (new in 0.8.0), `hiverelay-custody` (new in 0.8.0). Plus Hypercore replication for the registry log itself.

---

## Quick start

> **Requirements**: Node.js 20+

### For developers

```bash
npm install p2p-hiverelay-client
```

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
const app = new HiveRelayClient('./my-storage')
await app.start()

const drive = await app.publish('./my-app')
await app.seed(drive.key, { durability: 1, revocable: false })
```

### For operators

```bash
npm install -g p2p-hiverelay
p2p-hiverelay setup
```

Or via Docker:

```bash
docker run -d --name hiverelay \
  -v hiverelay-data:/data \
  -v hiverelay-config:/config \
  -e HIVERELAY_OPERATOR=your-org-name \
  -p 9100:9100 \
  ghcr.io/bigdestiny2/p2p-hiverelay:latest
```

### Local testnet

```bash
npx p2p-hiverelay testnet --nodes 5
```

---

## Test coverage

The v0.8.0 trust-stack bundle (custody-signing, registry-custody, anchor-channel, custody-channel, auto-heal, ws-feed-payload, client-custody, seed-revocability, seeding-registry-hardening) was the foundation. Eight subsequent releases added regression coverage for each shipped fix: anchor honesty (PR #19), circuit-relay bridge (v0.8.19), catalog provenance (v0.8.18), blind-path airtight (v0.8.15), `dht-relay-ws` privacy (v0.8.16), partial-pin self-heal integration (v0.8.21), defensive timeouts (v0.8.22), partial-quorum custody-commit (v0.8.23), and more. Current core smoke battery is 15 suites / hundreds of assertions, 5.3s wall time on a clean checkout, all green on each release.

Two simulation harnesses cover behaviors unit tests can't reach:
- `scripts/simulate-blind-atomic-custody.js` — Monte Carlo across 7 protocol scenarios, 5,000 trials each. Surfaced the witness tombstone primitive as the highest-leverage post-expiry attestation.
- `scripts/simulate-auto-heal-bridge.js` — drives real AutoHeal against an in-memory simulated network with 7 deterministic scenarios (cold-start, sybil, liar, churn at 4 rates, stampede, partition heal, scaling).

---

## Documentation

### Start here
- **[HIVERELAY_OVERVIEW.md](docs/HIVERELAY_OVERVIEW.md)** — single-page mental model
- **[PEAR-INTEGRATION.md](docs/PEAR-INTEGRATION.md)** — Pear / Bare usage guide
- **[CHANGELOG.md](./CHANGELOG.md)** — release-by-release notes for every version

### Atomic Blind Custody
- **[ATOMIC-BLIND-CUSTODY.md](docs/ATOMIC-BLIND-CUSTODY.md)** — full protocol whitepaper (threat model, state machine, security analysis, simulation evidence, comparison to Filecoin/Sia/Storj/IPFS)
- **[WHATS-IN-THE-RELAY.md](docs/WHATS-IN-THE-RELAY.md)** — guided tour of every component
- **[TUTORIAL-CUSTODY-QUICKSTART.md](docs/TUTORIAL-CUSTODY-QUICKSTART.md)** — build an encrypted custody handoff in 10 minutes
- **[atomic-network-design.md](docs/atomic-network-design.md)** — extended design doc with rollout matrix and protocol shape
- **[ATOMIC-CUSTODY-SIMULATION.md](docs/ATOMIC-CUSTODY-SIMULATION.md)** — simulation methodology and findings

### Publisher guides
- **[PUBLISHING.md](docs/PUBLISHING.md)** — what to know before you pin a Hyperdrive (the `maxStorage` trap, `verify-pin` pattern, publisher commitments)

### Security & threat model
- **[THREAT-MODEL.md](docs/THREAT-MODEL.md)** — security thesis
- **[SECURITY-STRATEGY.md](docs/SECURITY-STRATEGY.md)** — attack-vector mitigation tracker
- **[CRYPTO-GUARANTEES.md](docs/CRYPTO-GUARANTEES.md)** — cryptographic primitives audit
- **[AUTO-HEAL-ROOT-CAUSE-2026-05-22.md](docs/AUTO-HEAL-ROOT-CAUSE-2026-05-22.md)** — v0.8.20 partial-pin root-cause investigation (the "anchor honesty" backstory)

### Operator
- **[v0.5.1-CAPABILITIES.md](docs/v0.5.1-CAPABILITIES.md)** — capability doc + error prefixes + manifests spec
- **[HOMEHIVE.md](docs/HOMEHIVE.md)** — private mode for home / family
- **[ECONOMICS.md](docs/ECONOMICS.md)** — economics design
- **[OPERATOR-INCENTIVES-Y1.md](docs/OPERATOR-INCENTIVES-Y1.md)** — operator-side incentive design

### Roadmap
- **[M2-ROADMAP.md](docs/M2-ROADMAP.md)** — what's next (post-v0.8.0 milestone)
- **[AUDIT-ROADMAP.md](docs/AUDIT-ROADMAP.md)** — outstanding audit items + tracking

---

## Links

- **GitHub**: [github.com/bigdestiny2/P2P-Hiverelay](https://github.com/bigdestiny2/P2P-Hiverelay)
- **npm (core)**: [p2p-hiverelay](https://www.npmjs.com/package/p2p-hiverelay)
- **npm (client)**: [p2p-hiverelay-client](https://www.npmjs.com/package/p2p-hiverelay-client)
- **npm (verifier)**: [p2p-hiverelay-verifier](https://www.npmjs.com/package/p2p-hiverelay-verifier)
- **Docker image**: `ghcr.io/bigdestiny2/p2p-hiverelay:latest`
- **Live Dashboard**: `http://{relay}:9100/dashboard`
- **Catalog**: `http://{relay}:9100/catalog.json`

---

## License

Apache 2.0 — full text in [LICENSE](LICENSE).

The protocol, SDK, and reference implementation are open. Alternative implementations are welcome and encouraged — the protocol is independent of any specific implementation.
