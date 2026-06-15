# HiveRelay

**A versatile blind peer for Pear applications. Application-agnostic. Always-on. Cryptographically gated. Privacy-preserving by default.**

Drop a Hyperdrive key in front of a HiveRelay node and your Pear app comes online — discovered via the DHT, replicated across regions, reachable from browsers, mobile, and behind NATs. The relay is **blind to your application data**: encrypted drives stay encrypted on disk, plaintext fields are structurally rejected at the protocol boundary, and the operator never sees what you're hosting. **Application-agnostic at every layer** — anything built on Hypercore + Hyperswarm works, whether you're shipping a notes app, a marketplace, a chat client, a binary distribution, a P2P forum, or something nobody's built yet.

It's the substrate. You build the app; the network handles availability, NAT traversal, browser/mobile ingress, custody, and self-heal.

**Open source (Apache 2.0)** | **[GitHub](https://github.com/bigdestiny2/P2P-Hiverelay)** | **[npm](https://www.npmjs.com/package/p2p-hiverelay)** | **Status: v0.16.0**

The four packages — `p2p-hiverelay` (core), `p2p-hiveservices` (services), `p2p-hiverelay-client` (SDK), `p2p-hiverelay-verifier` — are versioned in lockstep. Release-by-release notes live in the [CHANGELOG](./CHANGELOG.md).

---

## What HiveRelay does

P2P apps built on Hyperswarm work beautifully — until the developer closes their laptop. Users see "offline." Mobile users behind carrier NATs can't connect. Browser users can't use UDP. There is no durable availability layer and no shared discovery surface.

HiveRelay solves all of that, then keeps going. A HiveRelay node is a Hyperswarm peer that joins the same DHT, speaks the same protocols, and replicates the same Hypercores — application-agnostic — plus five capabilities purpose-built for being a versatile blind substrate:

1. **Bootstrap any Pear application.** Hand the relay a Hyperdrive key + your accept-mode policy; it keeps the app online and discoverable from the DHT. No application-specific code, no opinionated metadata schema, no privileged knowledge of what you're hosting. One relay can carry a binary mirror, a chat backend, an app store, and a notes app simultaneously.
2. **Blind by default for encrypted workloads.** The Atomic Blind Custody plane processes ciphertext only — the validator hard-blocks ten plaintext field names so leakage is structurally impossible. Operators can't see what you encrypted, and can prove they stopped storing it at expiry without ever decrypting.
3. **Cryptographically verified replica durability.** Peers count toward archive replication only when they produce a fresh signed Ed25519 anchor proof. AutoHeal recruits diverse replicas across regions and operators automatically; self-heal pulls missing blocks peer-to-peer between relays once a publisher has been online once.
4. **Cross-NAT + browser/mobile ingress.** Circuit-relay protocol for hole-punching fallback (cellular ↔ home Wi-Fi). `dht-relay-ws` transport lets browsers and Android WebView clients participate in the DHT over WSS. No application code changes for any of it.
5. **Real-time P2P trust pipeline + live telemetry.** Custody, anchor, and publish messages flow over Protomux channels on the existing Hyperswarm connection — no HTTPS dependency. A WebSocket dashboard feed surfaces per-drive diversity, custody pipeline health, and event push for every state change.

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'

const app = new HiveRelayClient('./my-app-storage')
await app.start()

const drive = await app.publish('./my-app')
// Close your laptop. Your app stays online via the relay network.
```

Runs natively in the **Pear / Bare runtime** — `pear run pear://<key>` boots the same relay as a Bare app that peers with the Node fleet on the DHT. It tracks current Holepunch conventions: `which-runtime` detection, hyperswarm `^4.17`, the current `bare-*` generation (`bare-fs 4` / `bare-path 3`), `paparam` arg parsing on the Pear entry, and a CI job that runs the suite **under the real Bare runtime** (`npm run test:bare`), not just Node. See [docs/PEAR-INTEGRATION.md](docs/PEAR-INTEGRATION.md) for full usage and [docs/PEAR-ALIGNMENT.md](docs/PEAR-ALIGNMENT.md) for the conventions roadmap.

---

## The two storage planes

HiveRelay distinguishes two storage classes with different semantics. A single relay can run both.

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
- The signed custody log is schema-constrained: a per-type field **allowlist** rejects any unknown field, and a denylist hard-blocks known plaintext/key names (`plaintext`, `dataKey`, `fileName`, `path`, PVSS share scalars, …). Custody metadata therefore can't carry cleartext content or key material.
- Six signed message types: intent → receipt → commit → source-retired → proof → non-serving-proof, with witness tombstones layered on top.
- `retainUntil` is enforced state — the expiry monitor unseeds at the deadline and the relay signs a non-serving-proof; independent witnesses probe after expiry and sign tombstones.

See the [Atomic Blind Custody whitepaper](docs/ATOMIC-BLIND-CUSTODY.md) for the full content-custody protocol.

---

## Blind social recovery — the threshold-custody primitive

The headline feature on top of the custody plane. **A relay holds an opaque, guardian-encrypted share of a secret — publicly verifies it's well-formed without ever decrypting it — and any *t-of-n* guardians later reconstruct the secret entirely client-side.** No single party can reconstruct alone: not the relay (it never has a guardian private key), and not any single guardian (it has one share of `t`).

This is the primitive behind:

- **Social recovery** for self-custodial wallets, identity, and crypto keys (lose your phone → 2 of 3 friends help you recover)
- **Team break-glass** for shared org secrets (admin departs → board majority recovers)
- **Inheritance** for serverless / Pear apps (executor's t-of-n release is timestamp-bounded by retainUntil; relays sign non-serving proofs at expiry)
- **Threshold signing setup** that survives operator churn — guardians can be added or rotated independently of the relays storing the shares

**What makes it work without a trusted server:** the relay verifies each share against published commitments using only the share's public components, never the dealer's private witness. The fleet-wide replication mesh (5 relays) means losing any one relay doesn't lose the share; the cross-relay non-serving-proof + witness tombstone primitives mean recipients get cryptographic confirmation when shares are destroyed.

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { keygen } from 'p2p-hiverelay-client/secret-sharing.js'

// Dealer splits a secret into 3 shares across 3 relays, requiring any 2 guardians to recover.
const g1 = await keygen(); const g2 = await keygen(); const g3 = await keygen()
const res = await app.splitForCustody({
  guardians: [g1.publicKey, g2.publicKey, g3.publicKey],
  threshold: 2,
  relays: [r1, r2, r3],
  appKey,
  opts: { apiKey }
})
// res.key is dealer-private. Each relay holds an opaque, publicly-verifiable share.

// Later — only the guardians can recover. No relay can; no single guardian can.
const out = await app.reconstructFromCustody({
  intentId: res.intentId,
  guardianSecretKeys: [g1.secretKey, g3.secretKey],
  shareBundleKey: res.shareBundleKey,
  threshold: 2
})
// out.key === res.key
```

The scheme is **`pvss-secp256k1-v1`** — Schoenmakers Publicly Verifiable Secret Sharing over secp256k1, with Chaum-Pedersen non-interactive zero-knowledge equality proofs binding each share to the dealer's commitment. Crypto + signing are Bare-safe and self-contained (no dependency on the relay package).

See the [PVSS blind key custody whitepaper](docs/PVSS-BLIND-CUSTODY.md) for the scheme, threat model, and trust analysis.

---

## Services module

Beyond the relay kernel, optional services live under `packages/services/builtin/` (`p2p-hiveservices`) and each own an HTTP/WS or Protomux surface on top of relay core: `ai-service`, `schema-service`, `zk-service`, `arbitration-service`, `sla-service`, `storage-service`, `identity-service`, plus the v0.10.2 `signed-directory` registry primitive. A relay that never instantiates a service is byte-zero affected by it.

### SignedDirectory — relay-hosted openly-writable registry (v0.10.2)

Opt-in registry of signed records keyed by author pubkey. Sellers publish, buyers list + verify locally. Trust model identical to a topic-swarm announce: the relay can omit or reorder records but cannot forge them — every record carries a detached Ed25519 signature over `SHA256(authorPubkey || timestamp || payload)`. Generic enough for any "signed record set by author" use case (marketplaces, job boards, file-share directories, signed gossip feeds).

- 8 KB per-record cap, 24h TTL, newest-timestamp-wins, ±60s clock-skew tolerance (prevents pubkey squatting)
- Single-hop NOTIFY replication across the fleet — publish at any relay, the record appears at all enabled peers within milliseconds
- Per-peer publish rate-limit + global entry cap + TTL-oldest-first eviction
- Default off; enable with `config.signedDirectory.enabled`

See the [SignedDirectory operator section in PRODUCTION.md](./PRODUCTION.md).

### Card-blind signed-log substrate (v0.10.0)

`packages/services/builtin/poker/` was the first consumer of the services-module pattern: a generic primitive for turn-based games with hidden information. The relay enforces signatures, monotonic ordering, clock-skew bounds, and a byte budget; payloads stay opaque and game rules live in the Pear client. The same substrate composes for liar's dice, mafia, sealed-bid auctions, and other "everyone sees the moves, nobody sees the hidden state" patterns. Includes a HypercorePersistence adapter for restart-replay and an arbitration seam for pluggable evidence verification.

See [docs/SERVICES.md](docs/SERVICES.md) and the [poker substrate README](packages/services/builtin/poker/README.md).

---

## Privacy model

Apps declare their own privacy tier. The relay enforces what it sees based on this:

| Tier | Relay sees | Where data lives | Example |
|---|---|---|---|
| `public` | Everything (drive content, metadata) | DHT-replicated, gateway-served | Open-source app, public dataset |
| `local-first` | Discovery key only; data exchanged peer-to-peer | Local + opportunistic relay cache | Personal notes, journal |
| `p2p-only` (blind) | Opaque ciphertext bytes | Encrypted on relay disk; gateway returns 403 | Wallets, medical, private messaging |

The `p2p-only` tier is the key feature for production privacy-preserving apps. Combined with atomic blind custody, the relay attests it stored your encrypted content and signs a non-serving proof at expiry — corroborated by independent witness tombstones — without ever decrypting it.

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

### Custody API

| Method | Description |
|---|---|
| `app.publishCustodyIntent(url, intent, opts)` | Sign and publish a custody intent |
| `app.publishCustodyCommit(url, intentId, commit, opts)` | Sign commit when quorum reached |
| `app.publishSourceRetired(url, intentId, ret, opts)` | Retire source authority |
| `app.recordCustodyProof(url, proof, opts)` | Record a possession-challenge result |
| `app.recordCustodyNonServingProof(url, intentId, proof, opts)` | Relay's post-expiry attestation |
| `app.recordCustodyExpiryWitness(url, intentId, witness, opts)` | Independent witness tombstone |
| `app.getCustodyStatus(url, intentId)` | Read-only quorum + commit status |

### Blind social recovery — PVSS (v0.9.0)

The full primitive, code-example, and trust analysis live in the [Blind social recovery section](#blind-social-recovery--the-threshold-custody-primitive) at the top of this README. SDK surface:

| Method | Description |
|---|---|
| `app.splitForCustody({ secret?, guardians, threshold, relays, appKey, opts? })` | PVSS-split a secret to the guardians' pubkeys, publish the public share bundle, sign the v2 intent, collect a share-verified receipt from every relay, then sign + publish the quorum commit |
| `app.reconstructFromCustody({ intentId, guardianSecretKeys, relays?, shareBundleKey?, threshold? })` | Recover the secret from any `t` guardian secret keys, entirely client-side |

### Quorum + verification API

| Method | Description |
|---|---|
| `app.refreshCapabilityCache(urls)` | Fetch + cache capability docs |
| `app.selectQuorum(opts)` | Pick diverse / pinned / wide quorum |
| `app.queryQuorumWithComparison(path, quorum, opts)` | Parallel query + auto fork detection |
| `app.fetchCapabilities(url, opts)` | Get a relay's signed capability doc |
| `app.publishSeedingManifest(url, manifest)` | Publish author's preferred-relay manifest |

---

## For operators

You have hardware — a VPS, a Mac Mini, a Raspberry Pi. HiveRelay turns it into part of a verifiable trust network.

### Direct install

```bash
npm install -g p2p-hiverelay
p2p-hiverelay setup        # interactive wizard
# or:
p2p-hiverelay start --region NA --operator your-org-name --max-storage 50GB
```

Set `--operator` to a stable identifier (your org / deployment name). Without it, AutoHeal treats each pubkey as its own operator and the per-operator fairshare cap doesn't activate.

### Live management TUI

```bash
p2p-hiverelay tui
```

Interactive control of accept-mode, federation, custody settings, AutoHeal thresholds, and network discovery.

### Operating modes

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

### Accept-mode

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

Followed catalogs go through your accept-mode gate. Mirrored peers bypass the gate — use sparingly, only for "your own other node" or trusted partners.

### Live dashboard

Every relay exposes a WebSocket feed at `/ws` broadcasting per-drive AutoHeal diversity (replicas, regions, operators, threshold status), an aggregate custody snapshot (intents, quorums met, commits, witness tombstones, commit rate), and real-time event push on recruit, proof-fail, throttle, and every custody pipeline transition.

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

Seven Protomux channels run over each Hyperswarm connection: `hiverelay-seed`, `hiverelay-proof`, `hiverelay-circuit`, `hiverelay-services`, `hiverelay-registry-meta`, `hiverelay-anchor`, `hiverelay-custody`. Plus Hypercore replication for the registry log itself.

---

## Quick start

> **Requirements:** Node.js 20+

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

Or as a Pear/Bare app (always-on, mobile-capable hardware; same wire protocol as the Node fleet):

```bash
pear run pear://<key>            # or `pear run .` from a checkout
pear run pear://<key> -- --region EU --port 9200 --no-updates
```

### Local testnet

```bash
npx p2p-hiverelay testnet --nodes 5
```

---

## Test coverage

The core trust stack — custody-signing, registry-custody, anchor- and custody-channel, auto-heal, ws-feed payload, client-custody, seed-revocability, seeding-registry hardening, PVSS blind key custody (split, verify-without-decrypt, reconstruct, dealer-private witness), SignedDirectory (signature, timestamp, rate-limit, eviction, replication) — is covered by a smoke battery that runs in seconds on a clean checkout. The services-module work adds suites covering arbitration evidence verification and the card-blind signed-log substrate end-to-end.

A dedicated `bare-tests` CI job runs the suite under the **real Bare runtime** (`npm run test:bare`), so the imports-map `bare` condition resolves to the actual `bare-events` / `bare-fs` / `bare-http1` / `bare-path` implementations rather than the Node fallback — the runtime gate any storage-stack upgrade depends on.

Two simulation harnesses cover behaviors unit tests can't reach:
- `scripts/simulate-blind-atomic-custody.js` — Monte Carlo across 7 protocol scenarios, 5,000 trials each. Surfaced the witness tombstone primitive as the highest-leverage post-expiry attestation.
- `scripts/simulate-auto-heal-bridge.js` — drives real AutoHeal against an in-memory simulated network across 7 deterministic scenarios (cold-start, sybil, liar, churn at 4 rates, stampede, partition heal, scaling).

---

## Documentation

### Start here
- **[HIVERELAY_OVERVIEW.md](docs/HIVERELAY_OVERVIEW.md)** — single-page mental model
- **[PEAR-INTEGRATION.md](docs/PEAR-INTEGRATION.md)** — Pear / Bare usage guide
- **[DEVELOPER.md](docs/DEVELOPER.md)** — full developer reference
- **[TUTORIAL-QUICKSTART.md](docs/TUTORIAL-QUICKSTART.md)** — build and publish your first app
- **[CHANGELOG.md](./CHANGELOG.md)** — release-by-release notes for every version

### Protocol & services
- **[PROTOCOL-SPEC.md](docs/PROTOCOL-SPEC.md)** — wire protocol, channels, message encodings
- **[SERVICES.md](docs/SERVICES.md)** — the services module and how to build one
- **[WHATS-IN-THE-RELAY.md](docs/WHATS-IN-THE-RELAY.md)** — guided tour of every component

### Atomic blind custody
- **[ATOMIC-BLIND-CUSTODY.md](docs/ATOMIC-BLIND-CUSTODY.md)** — full protocol whitepaper (threat model, state machine, security analysis, comparison to Filecoin/Sia/Storj/IPFS)
- **[PVSS-BLIND-CUSTODY.md](docs/PVSS-BLIND-CUSTODY.md)** — publicly verifiable threshold *key* custody (PVSS over secp256k1)
- **[TUTORIAL-CUSTODY-QUICKSTART.md](docs/TUTORIAL-CUSTODY-QUICKSTART.md)** — build an encrypted custody handoff in 10 minutes
- **[atomic-network-design.md](docs/atomic-network-design.md)** — extended design doc
- **[ATOMIC-CUSTODY-SIMULATION.md](docs/ATOMIC-CUSTODY-SIMULATION.md)** — simulation methodology and findings

### Security & threat model
- **[THREAT-MODEL.md](docs/THREAT-MODEL.md)** — security thesis
- **[SECURITY-STRATEGY.md](docs/SECURITY-STRATEGY.md)** — attack-vector mitigation tracker
- **[CRYPTO-GUARANTEES.md](docs/CRYPTO-GUARANTEES.md)** — cryptographic primitives audit
- **[AUDIT-ROADMAP.md](docs/AUDIT-ROADMAP.md)** — outstanding audit items + tracking

### Publisher & operator
- **[PUBLISHING.md](docs/PUBLISHING.md)** — what to know before you pin a Hyperdrive
- **[PRODUCTION.md](./PRODUCTION.md)** — production deployment guide
- **[HOMEHIVE.md](docs/HOMEHIVE.md)** — private mode for home / family
- **[ECONOMICS.md](docs/ECONOMICS.md)** / **[OPERATOR-INCENTIVES-Y1.md](docs/OPERATOR-INCENTIVES-Y1.md)** — economics + operator incentive design

### Roadmap
- **[M2-ROADMAP.md](docs/M2-ROADMAP.md)** — what's next

---

## Links

- **GitHub**: [github.com/bigdestiny2/P2P-Hiverelay](https://github.com/bigdestiny2/P2P-Hiverelay)
- **npm (core)**: [p2p-hiverelay](https://www.npmjs.com/package/p2p-hiverelay)
- **npm (client)**: [p2p-hiverelay-client](https://www.npmjs.com/package/p2p-hiverelay-client)
- **npm (verifier)**: [p2p-hiverelay-verifier](https://www.npmjs.com/package/p2p-hiverelay-verifier)
- **Docker image**: `ghcr.io/bigdestiny2/p2p-hiverelay:latest`
- **Live dashboard**: `http://{relay}:9100/dashboard`
- **Catalog**: `http://{relay}:9100/catalog.json`

---

## License

Apache 2.0 — full text in [LICENSE](LICENSE).

The protocol, SDK, and reference implementation are open. Alternative implementations are welcome and encouraged — the protocol is independent of any specific implementation.
