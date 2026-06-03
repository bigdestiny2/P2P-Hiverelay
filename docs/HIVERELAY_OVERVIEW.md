# HiveRelay Overview

**A versatile blind peer for Pear applications. Application-agnostic. Always-on. Cryptographically gated. Privacy-preserving by default.**

HiveRelay is the substrate any Pear application can plug into. Hand
the relay a Hyperdrive key and your app comes online — discovered
via the DHT, replicated across regions, reachable from browsers,
mobile, and behind NATs. The relay is **blind to your application
data** (encrypted drives stay encrypted on disk; plaintext fields
are structurally rejected at the protocol boundary). And it's
**application-agnostic** — the same relay simultaneously carries a
binary mirror, a chat backend, an app store, a notes app, and
anything else built on Hypercore + Hyperswarm.

This document is the single-page mental model. If you have 10 minutes,
read this. If you have an hour, read the
[Atomic Blind Custody whitepaper](./ATOMIC-BLIND-CUSTODY.md) and the
[components tour](./WHATS-IN-THE-RELAY.md).

---

## The Problem

Peer-to-peer apps disappear when the developer closes their laptop.
End users see "offline." Mobile users behind carrier NATs can't
connect. Browser users can't use UDP. There is no durable availability
layer and no shared discovery surface.

But that's the *easy* problem. The harder problem is trust:

- Did the relay you handed your encrypted file to actually take custody?
- Will it still be serving in 24 hours?
- Will it stop serving when you said it should?
- Can the operator read your data?

Existing relay infrastructure offers availability without provable
custody. A relay that says "I have your content" cannot be
distinguished, by an observer, from one that says it but doesn't.
Encryption-aware relays solve confidentiality but leave the custody
question unanswered. And no other Hyperswarm-compatible relay tries
to be *application-agnostic* — most are built around a specific app
or workload, baking assumptions into the substrate that limit reuse.

## The Fix

HiveRelay is a Hyperswarm peer that joins the same DHT, speaks the
same protocols, and replicates the same Hypercores —
application-agnostic — plus five capabilities purpose-built for
being a versatile blind substrate:

1. **Bootstrap any Pear application.** Hand the relay a Hyperdrive
   key plus your accept-mode policy; the relay keeps it online and
   discoverable. No application-specific code, no opinionated
   metadata schema, no privileged knowledge of what's being hosted.

2. **Cryptographically verified replica durability.** Peers count
   toward archive replication only when they produce a fresh signed
   Ed25519 anchor proof. The AutoHeal scheduler recruits diverse
   replicas across regions and operators automatically. Self-heal
   (since v0.8.21) now pulls missing blocks peer-to-peer between
   relays once a publisher's been online once.

3. **Atomic Blind Custody.** Encrypted content handoff with quorum
   receipts, source-authority retirement, possession proofs, and
   independent witness tombstones for post-expiry attestation. Relays
   never see plaintext or decryption keys; the validator
   hard-blocks ten plaintext field names so leakage is structurally
   impossible.

4. **Cross-NAT + browser/mobile ingress.** Circuit-relay protocol
   for hole-punching fallback (cellular ↔ home Wi-Fi). `dht-relay-ws`
   transport (WSS) for browsers and WebView Android clients to
   participate in the DHT. No application code changes for any of it.

5. **Real-time P2P trust pipeline + live telemetry.** Custody,
   anchor, and publish messages flow over Protomux channels on the
   existing Hyperswarm connection — no HTTPS dependency. WebSocket
   dashboard feed surfaces per-drive diversity, custody pipeline
   health, and event push for every state change.

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
const app = new HiveRelayClient('./storage')
await app.start()
const drive = await app.publish([{ path: '/index.html', content: '<h1>Always On</h1>' }])
// Your app is now available 24/7 from relay nodes. Close your laptop.
```

No servers. No accounts. No cloud vendor. Just more peers that happen
to be always online — and provably so.

---

## What HiveRelay Is

A relay node has five role-functions:

1. **Seeder.** Accepts and replicates Hyperdrives so app data stays
   available when the original publisher is offline. AutoHeal manages
   archive durability across the network.

2. **Custody Peer.** Stores encrypted ciphertext, signs receipts when
   anchoring, signs non-serving-proofs at expiry. Validator-level
   privacy invariants prevent plaintext leakage.

3. **Witness.** Probes other relays' state at expiry and signs
   tombstones over what it observed. Does not store content. New
   third-role addition that closes the post-expiry serving leak.

4. **Circuit-relay.** NAT-blocked peers forward encrypted bytes
   through relay nodes when direct hole-punching fails. The relay
   sees only opaque ciphertext.

5. **Service host (optional plugin layer).** Plugin-based dispatch
   for AI inference, identity, schemas, SLAs, storage CRUD. Disabled
   by default — the core product is availability + custody.

A single relay can run multiple roles simultaneously. Operators
choose which roles via config or operating mode.

---

## The Two Storage Planes

HiveRelay 0.8.0 distinguishes two storage classes with different
lifecycle semantics. A relay can run both simultaneously; they share
the same Hyperswarm connection, registry log, and channel inventory.

| Plane | Storage Class | Best For | Lifecycle |
|---|---|---|---|
| **Persistent Availability** | `persistent` / `always-on` | Pear apps, public drives, package mirrors, routing services | Cataloged, repaired, kept online by AutoHeal |
| **Atomic Blind Custody** | `temporary` / `atomic-handoff` | Encrypted file/data handoff, blind dead drops, time-bounded transfers | Redacted catalog, TTL-bounded, proofed, removed from active serving at `retainUntil` |

This split is the architectural insight. Apps and services want
durable relay availability. Atomic blind file movement wants
temporary custody, privacy, and auditable removal.

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
         | Custody |           | Custody |
         | Witness |           | Witness |
         | Circuit |           | Circuit |
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

### Discovery

All relays announce on a well-known DHT topic
(`hiverelay-discovery-v1`). Client SDKs join this topic and the DHT
connects them to relays within 2-5 seconds. No central registry, no
hardcoded URLs, no accounts.

### Wire protocols

Seven Protomux channels run over each Hyperswarm connection:

| Channel | Purpose |
|---|---|
| `hiverelay-seed` | Publisher → relay seed requests |
| `hiverelay-proof` | Relay-to-relay liveness proofs |
| `hiverelay-circuit` | Circuit relay tunnels |
| `hiverelay-services` | Service plugin RPC (when enabled) |
| `hiverelay-registry-meta` | Registry log key exchange |
| `hiverelay-anchor` | **New in 0.8.0** — anchor proof requests over swarm |
| `hiverelay-custody` | **New in 0.8.0** — real-time custody entry push |

The two new channels are what makes the trust pipeline fully P2P at
the protocol layer. AutoHeal can verify peers without HTTPS reachability.
Custody quorum convergence happens in milliseconds for connected peers
instead of being bound by log replication latency.

### Data flow (persistent availability)

1. Developer publishes content via the SDK — creates a Hyperdrive,
   writes files, announces on DHT.
2. SDK broadcasts a signed seed request over Protomux to connected
   relays.
3. Relays with capacity accept and begin replicating.
4. Developer goes offline — data remains available from relay nodes.
5. End users open the app by key — the DHT finds peers (relays and
   other users) and replicates.

If the drive is `durability: 1` (archive tier), AutoHeal recruits
diverse replicas across regions and operators automatically.

### Data flow (atomic blind custody)

1. Publisher signs a `custody-intent` declaring the encrypted
   ciphertext root, replication target, and retention window.
2. Each anchoring relay auto-emits a signed `custody-receipt`.
3. When `requiredReplicas` receipts accumulate, the publisher signs
   a `custody-commit` with a deterministic order-invariant
   `receiptRoot` over the relay quorum's receipts.
4. The publisher signs `source-retired`, relinquishing authority over
   future state. Clients refuse further state-change signatures from
   the retired key.
5. During the retention window, observers can issue possession
   challenges and sign `custody-proof` entries.
6. At `retainUntil`, the expiry monitor unseeds the entry and signs
   a `custody-non-serving-proof`. Independent witnesses probe and
   sign `custody-expiry-witness` tombstones.

For the full state machine, message schemas, security analysis, and
simulation evidence, read the
[Atomic Blind Custody whitepaper](./ATOMIC-BLIND-CUSTODY.md).

---

## Privacy Model

Apps declare their own privacy tier. The relay enforces what it sees
based on this declaration:

| Tier | What the Relay Sees | Where Data Lives | Example Use |
|---|---|---|---|
| `public` | Drive content + metadata | DHT-replicated, gateway-served | Open-source app, public dataset |
| `local-first` | Discovery key only | Local + opportunistic relay cache | Personal notes, journal |
| `p2p-only` (blind) | Opaque ciphertext bytes | Encrypted on relay disk; gateway returns 403 | Wallets, medical records, private messaging |

The `p2p-only` (blind) tier combined with atomic blind custody is the
architectural primitive that production privacy-preserving apps need.
The relay can prove it stored your encrypted content and stopped
storing it at expiry — without ever decrypting it.

### Blind privacy invariants (enforced as code)

The validator hard-blocks ten plaintext field names from ever
appearing in a signed custody entry: `dataKey`, `decryptionKey`,
`plaintext`, `fileName`, `filename`, `path`, `name`, `description`,
`author`, `categories`. The signing function throws before producing
a signature if any are present. This is the privacy floor as code,
not as policy.

### The four-key model

| Key | Function | Visible to relays? |
|---|---|---|
| `addressKey` | Public lookup (Hyperdrive key, content address) | Usually yes |
| `dataKey` | Symmetric key that decrypts the payload | **Never** |
| `authorityKey` | Signing key controlling future lifecycle state | Public yes, secret never |
| `blindSalt` | Random hiding content identity in public registries | No (unless content is public) |

Existing implementations may use `contentKey` as a backward-compat
alias for `addressKey`; new code uses `addressKey` to avoid
conflation with the data key.

---

## Diversity-Enforced Durability

For archive-tier drives (`durability: 1`), AutoHeal runs every 30
minutes by default. The recruit gate has three valid paths:

- The relay closes a region gap (its region isn't in the existing
  replica set).
- The relay closes an operator gap (its operator isn't in the
  existing replica set).
- Both diversity dimensions are at threshold but replica count is
  below target — fill a buffer slot, requiring `meetsOperatorThreshold`
  and that the operator isn't at the per-operator fairshare cap.

This produces a network where:
- Replicas spread across regions and operators by construction.
- Sybil clusters with one operator are bounded to fairshare slots.
- Transient offline dips don't violate SLO (the +2 buffer absorbs them).
- Liars who claim `anchored: true` without producing valid proofs
  don't count.

Simulation results: at 2% per-tick churn, the SLO floor held 100% of
ticks. At 20% churn, 72%. The 50-sybil attack is bounded to 2
host-slots = the fairshare cap. Liars are detected at 100% rate.

---

## Three Roles in the Trust Network

The protocol-level architecture has three distinct roles. A relay
operator can run any combination.

| Role | Stores Content? | Signs |
|---|---|---|
| **Publisher** | Yes initially | intent, commit, source-retired |
| **Custody Relay** | Yes (encrypted only) | receipt, proof, non-serving-proof |
| **Witness** | **No** | expiry-witness tombstone |

The Witness role is what makes post-expiry detection work. Storage
replication alone leaves continued post-expiry serving undetected at
27%-82% rates across configurations. A 5-of-7 witness quorum drops
this to <1% with no availability cost. Witnesses do not store content
and so are operationally inexpensive.

This broadens operator participation: lightweight nodes that don't
want storage responsibility can still participate in the trust
network.

---

## What HiveRelay Cannot Prove

The whitepaper is honest about this boundary. On commodity hardware,
cryptography cannot prove:

- A remote peer physically deleted bytes from disk.
- A source machine no longer holds copies of `dataKey` or
  `authorityKey`.
- A relay did not retain a snapshot before deletion.

So the protocol delivers **logical source retirement** and
**observed non-serving state**, not forensic erasure. The product
language uses "logical retirement" and "post-expiry attestation,"
not "provable deletion." TEE/HSM attestation for actual deletion is
enumerated as an optional future extension, not a current claim.

The strong claim:

> After handoff, clients can cryptographically verify that the old
> source authority key is no longer authoritative for the encrypted
> content's live custody state, and that a quorum of independent
> relays signed receipts for the exact ciphertext root, and that
> independent witnesses observed the relay's non-serving state after
> expiry.

That is a real primitive.

---

## What Apps Get

Five concrete patterns the protocol enables:

### 1. Encrypted file handoff with a TTL the network enforces

Recipients can prove the relay quorum took custody before unsealing.
The TTL is enforced + provable, not just a config option. If a relay
misbehaves and keeps serving past expiry, witness tombstones surface
it.

### 2. Verifiable archive durability

Mark a drive `durability: 1` and AutoHeal recruits diverse replicas
automatically. Each replica's "I have it" claim is gated on a fresh
Ed25519 anchor proof. Diversity is enforced, not requested.

### 3. Cryptographic dead drops

Two parties, one signed handoff record, no trust in any single
intermediary. Both can prove the handoff later. Relays never see
plaintext. Neither party can repudiate.

### 4. Multi-region read distribution with provable freshness

Clients pick the closest verified-anchored peer and read from there.
Every peer in the read set has cryptographically demonstrated current
state.

### 5. Per-app SLA enforcement

Subscribe to the dashboard `/ws` feed. Drive UX off the actual
durability state, not the polled state.

---

## Operator Roles & Modes

| Mode | What it runs |
|---|---|
| **Relay Core** | Default focused kernel: availability + custody |
| **Custody Relay** | Atomic blind custody profile only |
| **Service Operator** | Service plugin host on top of relay core |
| **Witness** | Lightweight expiry-witness role — no storage |
| **HomeHive** | Home/personal relay |
| **Seed Only** | App seeding only |
| **Relay Only** | Circuit relay only |
| **Stealth** | Minimal footprint, designed for Tor-only |
| **Gateway** | HTTP gateway focus |

Each mode picks defaults for AutoHeal thresholds, accept-mode,
custody profile, network discovery, and connection limits. Operators
can override any individual setting.

---

## Federation

Relays can follow each other's catalogs:

```bash
hiverelay federation follow https://relay.example.com
hiverelay federation mirror https://my-other-relay.example.com
```

Followed catalogs go through the receiving relay's accept-mode gate.
Mirrored peers bypass the gate (used for "your own other node" or
trusted partners only).

Federation gossip is what propagates fork proofs, custody intents
that haven't been pushed yet, and operator/region metadata that
AutoHeal uses for diversity scoring.

---

## Documentation Index

For the complete documentation map, see the
[README documentation section](../README.md#documentation).

Key entry points:

- **[Atomic Blind Custody whitepaper](./ATOMIC-BLIND-CUSTODY.md)** — formal protocol specification
- **[What's in the Relay](./WHATS-IN-THE-RELAY.md)** — guided tour of every v0.8.0 component
- **[CHANGELOG](../CHANGELOG.md)** — release-by-release notes for every version
- **[Atomic Network Design](./atomic-network-design.md)** — extended design doc
- **[Atomic Custody Simulation](./ATOMIC-CUSTODY-SIMULATION.md)** — methodology and findings
- **[Threat Model](./THREAT-MODEL.md)** — security thesis
- **[Pear Integration](./PEAR-INTEGRATION.md)** — Pear/Bare runtime usage

---

*HiveRelay 0.8.0. The protocol is independent of any specific
implementation; alternative implementations are welcome.*
