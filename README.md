# HiveRelay

**Verifiable trust infrastructure for P2P apps. Always-on. Cryptographically gated. Privacy-preserving.**

A relay network where availability is provable, not promised. Your P2P app stays online forever; your encrypted handoffs come with quorum receipts; expiry is enforced by the network and witnessed by independent attesters; and no relay ever sees your plaintext.

**Open source (Apache 2.0)** | **[GitHub](https://github.com/bigdestiny2/P2P-Hiverelay)** | **[npm](https://www.npmjs.com/package/p2p-hiverelay)** | **Status: v0.8.6**

> **v0.8.6** — Repo housekeeping + publisher-signed REST endpoints (`/api/v1/seed`, `/api/v1/custody/intent` and friends). Third-party publishers can now drive the seed and atomic-custody pipelines against a public relay without holding the operator's API key. Plus the SDK auth bug in `_postCustody` (silent failure on every 0.8.x relay) is fixed. CI is green for the first time since the v0.8.0 series shipped — lint, audit, docker, and integration tests all clean.
>
> **v0.8.0–v0.8.5** — Atomic Blind Custody as a first-class signed protocol. AutoHeal recruits archive replicas with cryptographic peer verification. Two new Protomux channels (`hiverelay-anchor`, `hiverelay-custody`) close the HTTPS dependency. Witness Tombstones close the post-expiry serving leak. Patch series: custody hardening (0.8.1), `--operator`/`--auto-heal` deploy flags (0.8.2), bug-hunt + `doctor` command (0.8.3), DHT recoverable-error fix (0.8.4), client SDK Bare-runtime compatibility (0.8.5). Read the [whitepaper](./docs/ATOMIC-BLIND-CUSTODY.md), the [components tour](./docs/WHATS-IN-THE-RELAY.md), or the [v0.8.0 release notes](./docs/RELEASE-NOTES-0.8.0.md).

> The relay layer of the Hive substrate.

---

## What HiveRelay does

P2P apps built on Hyperswarm work beautifully — until the developer closes their laptop. Users see "offline." Mobile users behind carrier NATs can't connect. Browser users can't use UDP. There is no durable availability layer and no shared discovery surface.

HiveRelay solves all of that, then keeps going.

A relay node is a Hyperswarm peer that joins the same DHT, speaks the same protocols, and replicates the same Hypercores — plus four things no other relay does:

1. **Cryptographically verified replica durability** — peers count toward archive replication only when they produce a fresh signed Ed25519 anchor proof. AutoHeal recruits diverse replicas across regions and operators automatically.
2. **Atomic Blind Custody** — encrypted content handoff with quorum receipts, source-authority retirement, possession proofs, and witness tombstones for post-expiry attestation. Relays never see plaintext or decryption keys.
3. **Real-time P2P trust pipeline** — custody and proof traffic flow over Protomux channels on the existing Hyperswarm connection. Works on pure-DHT and NAT'd fleets without HTTPS.
4. **Live telemetry** — WebSocket dashboard feed surfaces per-drive diversity, custody pipeline health, and immediate event push for every state change.

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

The v0.8.0 trust-stack bundle (custody-signing, registry-custody, anchor-channel, custody-channel, auto-heal, ws-feed-payload, client-custody, seed-revocability, seeding-registry-hardening) runs **91 unit tests** plus a 19-assertion **end-to-end integration test** that spins up three real relays on a Hyperswarm testnet and runs the full custody pipeline.

Two simulation harnesses cover behaviors unit tests can't reach:
- `scripts/simulate-blind-atomic-custody.js` — Monte Carlo across 7 protocol scenarios, 5,000 trials each. Surfaced the witness tombstone primitive as the highest-leverage post-expiry attestation.
- `scripts/simulate-auto-heal-bridge.js` — drives real AutoHeal against an in-memory simulated network with 7 deterministic scenarios (cold-start, sybil, liar, churn at 4 rates, stampede, partition heal, scaling).

---

## Documentation

### v0.8.0 release
- **[ATOMIC-BLIND-CUSTODY.md](docs/ATOMIC-BLIND-CUSTODY.md)** — full protocol whitepaper (threat model, state machine, security analysis, simulation evidence, comparison to Filecoin/Sia/Storj/IPFS)
- **[WHATS-IN-THE-RELAY.md](docs/WHATS-IN-THE-RELAY.md)** — guided tour of every component the relay picks up at v0.8.0
- **[TUTORIAL-CUSTODY-QUICKSTART.md](docs/TUTORIAL-CUSTODY-QUICKSTART.md)** — build an encrypted custody handoff in 10 minutes
- **[RELEASE-NOTES-0.8.1.md](docs/RELEASE-NOTES-0.8.1.md)** — custody hardening patch (witness validation, source retirement immutability, appKey redaction)
- **[RELEASE-NOTES-0.8.0.md](docs/RELEASE-NOTES-0.8.0.md)** — what's new + migration guide for operators upgrading from 0.7.x
- **[HIVERELAY_OVERVIEW.md](docs/HIVERELAY_OVERVIEW.md)** — single-page mental model
- **[atomic-network-design.md](docs/atomic-network-design.md)** — extended design doc with rollout matrix and protocol shape
- **[ATOMIC-CUSTODY-SIMULATION.md](docs/ATOMIC-CUSTODY-SIMULATION.md)** — simulation methodology and findings
- **[M2-ROADMAP.md](docs/M2-ROADMAP.md)** — what's next (post-v0.8.0)

### Strategic & security
- **[MANIFESTO.md](docs/MANIFESTO.md)** — non-negotiable architectural values
- **[Hive_Engineering_Brief.md](docs/Hive_Engineering_Brief.md)** — architecture + business decisions
- **[THREAT-MODEL.md](docs/THREAT-MODEL.md)** — security thesis
- **[SECURITY-STRATEGY.md](docs/SECURITY-STRATEGY.md)** — attack-vector mitigation tracker
- **[CRYPTO-GUARANTEES.md](docs/CRYPTO-GUARANTEES.md)** — cryptographic primitives audit

### Operator & developer
- **[v0.5.1-CAPABILITIES.md](docs/v0.5.1-CAPABILITIES.md)** — capability doc + error prefixes + manifests spec
- **[PEAR-INTEGRATION.md](docs/PEAR-INTEGRATION.md)** — Pear/Bare usage guide
- **[HOMEHIVE.md](docs/HOMEHIVE.md)** — private mode for home/family
- **[ECONOMICS.md](docs/ECONOMICS.md)** — economics design

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
