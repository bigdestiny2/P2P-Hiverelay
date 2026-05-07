# Lovable Landing Page Copy — HiveRelay

This is the copy for the public-facing site on Lovable. Each section
maps to a typical landing-page block. Hand it to whoever's building
the page; they can lift sections as components.

The voice is direct and technical without being jargon-soaked.
Headlines are claims, not slogans. Concrete examples are concrete,
not aspirational. No "revolutionary," no "powered by AI," no rocket
emojis.

---

## Hero block

### Headline (H1)
**Make your P2P app prove it.**

### Subhead (H2)
HiveRelay is verifiable trust infrastructure for peer-to-peer apps.
Always-on availability. Cryptographic custody handoff. Privacy by
construction. No vendor lock-in.

### Body
Build on Hyperswarm and your app works beautifully — until you close
your laptop. HiveRelay keeps it online. But "online" isn't enough for
encrypted file transfers, archived data, or anything that needs to
*prove* it happened. v0.8.0 closes that gap.

Replicas are cryptographically verified. Custody handoffs come with
quorum receipts. Expiry is enforced by the network and witnessed by
independent attesters. Relays never see your plaintext.

### Primary CTA
**Read the whitepaper** → /docs/atomic-blind-custody

### Secondary CTAs
- **View on GitHub** → github.com/bigdestiny2/P2P-Hiverelay
- **Get started in 10 minutes** → /docs/tutorial-custody-quickstart

---

## Three pillars block

Three side-by-side cards or columns.

### Pillar 1 — Verifiable durability

**Title:** Replicas you can trust without trusting anyone.

**Body:** AutoHeal recruits diverse replicas across regions and
operators automatically. A peer counts as live only when it produces
a fresh Ed25519 anchor proof. Sybil clusters are bounded by an
operator-fairshare cap. Buffer slots absorb churn. Diversity is
enforced, not requested.

### Pillar 2 — Atomic blind custody

**Title:** Encrypted handoff with cryptographic receipts.

**Body:** Six signed message types — intent, receipt, commit,
source-retired, proof, non-serving-proof — plus witness tombstones
for post-expiry attestation. Ten plaintext field names hard-blocked
at the validator. Relays process ciphertext only, never plaintext or
keys. The privacy floor is code, not policy.

### Pillar 3 — Real-time P2P trust

**Title:** No HTTPS required.

**Body:** Two new Protomux channels (anchor + custody) carry the
trust pipeline directly over Hyperswarm. Works on pure-DHT and NAT'd
fleets where HTTPS isn't reachable. Custody quorum convergence
measured in milliseconds for connected peers, not log-replication
seconds. Live dashboard `/ws` feed for every state change.

---

## Use cases block

A grid or vertical list. Each is a concrete pattern, not a generic
"can be used for."

### 1. Encrypted file handoff with a TTL the network enforces

Send an encrypted blob to a quorum of relays. Recipients can prove
the relay quorum took custody before unsealing. The TTL is enforced
state, not a config option. If a relay misbehaves and keeps serving
past expiry, witness tombstones surface it.

**Best for:** Document escrow, time-bounded access grants, ephemeral
sharing, key escrow with auditable expiry.

### 2. Archive-tier replica durability

Mark your drive `durability: 1` and AutoHeal recruits replicas across
≥4 regions and ≥5 operators. Each replica's "I have it" claim is
cryptographically verified. Buffer of +2 over SLO floor absorbs
transient outages without violating threshold.

**Best for:** Long-term content preservation, package mirrors,
multi-region read replicas, public datasets that must stay available.

### 3. Cryptographic dead drops

Two parties, one signed handoff record, zero trust in any single
relay. Both sides can prove the handoff later. Relays never see
plaintext. Neither party can repudiate.

**Best for:** Whistleblower drops, contractual delivery, court-
admissible custody chains, secure team handoffs.

### 4. Privacy-preserving messaging and storage

Apps declare `privacyTier: 'p2p-only'` and the relay processes only
opaque ciphertext. Catalogs are redacted. Gateway returns 403. Peers
connect P2P with the data key out-of-band. The relay can prove
storage without ever decrypting.

**Best for:** Wallets, medical apps, encrypted messaging, identity
storage, anything the user wouldn't want a relay operator reading.

### 5. Per-app SLA enforcement

Subscribe to the dashboard `/ws` feed. Get real-time per-drive
diversity scorecard, custody pipeline health, and immediate event push.
Drive your app's UX off actual durability state.

**Best for:** Customer-facing reliability dashboards, contractual
SLA verification, capacity planning.

---

## What's different block

A two-column comparison.

### What other relays say

- "Trust me, I have your content."
- Encryption is your problem.
- Expiry is a config option.
- Diversity is a recommendation.
- Sybils are an unsolved problem.
- HTTPS required.

### What HiveRelay does

- Cryptographic anchor proof on demand.
- Validator-enforced privacy invariants.
- Expiry is enforced state with non-serving-proofs.
- Diversity is enforced by per-operator fairshare cap.
- Sybils bounded by construction; witnesses catch violators.
- Two new Protomux channels — pure P2P trust pipeline.

---

## For developers block

### Headline
**5 lines of code, your app stays online forever.**

### Code block
```js
import { HiveRelayClient } from 'p2p-hiverelay-client'

const app = new HiveRelayClient('./storage')
await app.start()
const drive = await app.publish('./my-app')
// Close your laptop. Your app stays online via the relay network.
```

### For atomic custody
```js
const intent = await app.publishCustodyIntent(relayUrl, {
  blindContentId: hashHex(payload),
  ciphertextRoot: yourCiphertextRoot,
  requiredReplicas: 3,
  retainUntil: Date.now() + 24 * 60 * 60_000
}, { apiKey })

// Wait for quorum, sign commit, retire authority.
// Recipients can verify the chain later, without trusting you.
```

### CTAs
- **Quickstart tutorial** → /docs/tutorial-custody-quickstart
- **SDK reference** → /docs/developer
- **Pear/Bare integration** → /docs/pear-integration

---

## For operators block

### Headline
**Run a relay. Earn or contribute. Choose your role.**

### Body
Three roles, mix and match. Run all three, run one, run a witness-
only node.

| Role | What you do | What you need |
|---|---|---|
| **Custody Relay** | Store encrypted ciphertext, sign receipts and proofs | Storage |
| **Witness** | Probe other relays at expiry, sign tombstones | Just a small VPS — no storage |
| **Persistent Seeder** | Host archive replicas, AutoHeal manages diversity | Storage + uptime |

### Install
```bash
npm install -g p2p-hiverelay
p2p-hiverelay setup
```

### CTAs
- **Operator guide** → /docs/operator
- **Live dashboard preview** → /screenshots

---

## Trust block

### Headline
**Tested. Audited. Open.**

### Body grid

**91 tests + E2E integration.** The v0.8.0 trust-stack runs 91 unit
tests plus a 19-assertion end-to-end integration test that spins up
three real relays on a Hyperswarm testnet and exercises the full
custody pipeline. All passing.

**Two simulation harnesses.** A Monte Carlo analytic model runs 5,000
trials per scenario across a 72-relay simulated network. A behavioral
simulator drives the real AutoHeal class against an in-memory network
with deterministic scenarios. Both rerun on every behavioral change.

**Apache 2.0 open source.** The protocol, SDK, and reference
implementation are open. Alternative implementations are welcome —
the protocol is independent of any specific implementation.

**Honest about what we can't do.** The whitepaper is explicit: on
commodity hardware, cryptography cannot prove a relay erased bytes.
The protocol delivers logical source retirement and observed
non-serving state, not forensic erasure. That boundary is documented,
not hidden.

---

## Dashboard preview block

A screenshot or animation of the live dashboard, with caption:

**Live state, not polled state.**

Per-drive AutoHeal diversity scorecard, aggregate custody pipeline
health, immediate event push for every recruit, every receipt, every
witness tombstone. Dashboards reflect what's actually happening
across the network in near-real-time.

---

## Footer block

### Three columns

**Documentation**
- Atomic Blind Custody (whitepaper)
- What's in the Relay
- Release notes 0.8.0
- Threat model
- Tutorial quickstart

**Community**
- GitHub
- npm packages
- Issue tracker
- Discussions

**About**
- Hive Foundation
- License (Apache 2.0)
- Status: v0.8.0
- Built on Hyperswarm + Hypercore

### Closing line
*Verifiable trust infrastructure for the peer-to-peer internet.*

---

## SEO + meta

### Page title
**HiveRelay — Verifiable trust infrastructure for P2P apps**

### Meta description
Always-on relay network for Hyperswarm-based apps. Atomic blind
custody with cryptographic quorum receipts. AutoHeal-managed archive
durability with verified replicas. Apache 2.0 open source.

### Keywords (for whatever Lovable does with these)
P2P, Hyperswarm, Hyperdrive, Pear, blind custody, encrypted handoff,
relay network, cryptographic receipts, archive durability, witness
tombstone, peer-to-peer, decentralized storage

### Social preview text (for OG cards)
**HiveRelay** — Verifiable trust infrastructure for P2P apps. Atomic
blind custody. AutoHeal durability. Pure P2P trust pipeline. v0.8.0
open source on GitHub.

---

## Tone notes for whoever's building the page

- **No exclamation points.** Claims sound stronger without them.
- **No emojis** in the live copy. (Internal docs are fine; landing
  pages are public-facing.)
- **Code blocks should run as written.** Don't simplify to the point
  of misleading. Better to show 6 honest lines than 3 marketing lines.
- **Concrete > abstract.** "Drops undetected post-expiry serving from
  82% to <1%" is better than "improves trust significantly."
- **Acknowledge limits.** The whitepaper section about what we can't
  prove is a feature of the brand, not a bug. Quote it on the trust
  block.
- **Don't invent benefits.** If a use case isn't in the implemented
  feature set, don't list it. The five use cases above are all things
  the protocol actually enables today.
- **Link generously.** Every claim in the body should have a "read
  more" path to the doc that backs it.
