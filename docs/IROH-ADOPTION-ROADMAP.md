# iroh adoption roadmap

What we're borrowing from iroh (n0/number0), why, and in what order. Grounded
in the iroh study (`docs/IROH-STUDY.md` for the full subsystem breakdown).

## The framing that scopes everything

iroh's relay is a **blind transit relay** — it coordinates NAT hole-punching,
forwards encrypted QUIC packets *until a direct path opens, then drops out*.
HiveRelay is a **blind storage relay** — an always-on peer that *holds*
encrypted blocks so content survives authors going offline. iroh's connectivity
layer is the analog of **Hyperswarm/HyperDHT** (which already does dial-by-key +
hole-punching), not of HiveRelay; HiveRelay sits a layer above.

So we don't copy iroh's relay. We adopt the **ideas that transfer**: its
discovery model, its capability model, its sharing format, and its auth model —
each re-expressed on the Holepunch stack. Several iroh choices (Ed25519 identity,
blind relays, verified streaming, hash-referenced metadata) are things we
*already do* — the study confirms our architecture; no work needed there.

**Adoption principle:** only adopt what fits append-only Hypercore + the blind
ethos. Anything requiring QUIC, BLAKE3/bao, or destructive editing is out of
scope (see "Explicitly not adopting").

---

## Phase 1 — DHT-resolvable relay discovery  ⟵ *starting now*

**iroh lesson (pkarr):** a node publishes a *signed* record mapping
`pubkey → {home-relay URL, addresses}` into a DHT, republished on a short TTL.
Anyone resolves it by pubkey and verifies the signature — no trusted directory;
a malicious resolver can only serve stale data, never forge.

**Our adoption:** publish a **signed relay record** `pubkey → {gatewayUrl,
indexRoom}` as a **hyperdht mutable record** keyed by the relay's identity key.
`hyperdht` already exposes `mutablePut`/`mutableGet` (BEP44-style, signature
verified on read) and the relay already holds the DHT (`this.swarm.dht`) — so
this is pkarr's exact property **natively, with no Mainline/pkarr dependency**.

**Why first (highest leverage):** it **unblocks the Phase-5 desktop bootstrap**.
Today the browser can't bootstrap the relay directory until a fleet relay runs
the index sidecar and we bake an `indexRoom` z32 into the client. With this, a
client that knows only a relay's **pubkey** resolves its *current* `gatewayUrl`
+ `indexRoom` over the DHT — no sidecar, no hardcoded address, self-certifying.
`relay-client.listRelays()` gains a DHT backend alongside the HTTP one.

**Scope:** relay-side `relay-record` codec + `publishRelayRecord()` (mutablePut
on boot, on gateway/indexRoom change, periodic republish); desktop-side resolve
as a second `listRelays()` backend. **Status: building the relay side now.**

---

## Phase 2 — Delegable scoped capabilities (Meadowcap-style)

**iroh lesson (Meadowcap):** replace "hold the namespace key = write everything"
with unforgeable, signed **capability tokens** granting READ or WRITE to a
*region*, that are **delegable and restrictable** (hand someone narrower access +
the right to sub-delegate). Two models: *communal* (each subspace author-owned)
and *owned* (one admin moderates).

**Our adoption:** this is the principled answer to the **still-open
"curated vs open" question** for the canonical index room. The relay operator
holds an owner capability and **delegates scoped write-caps to invited verifier
peers** (the "verifier-as-writer" we deferred in the index layer). Read-caps
become the future basis for non-public catalogue regions. Generalizes our
existing `custody-signing` capability thinking — we already sign + verify
Ed25519 claims, so this is an extension, not a new crypto stack.

**Scope:** a capability format (issuer, grantee, scope = schema/room + optional
prefix + expiry, signature) + verify-on-write in the index sidecar's room
membership; delegation chain verification. **Status: designed, not started.**

---

## Phase 3 — A HiveRelay "ticket" format

**iroh lesson:** content is shared as one copy-pasteable `BlobTicket = hash +
node-addr + format` — *what to verify, who to dial, how to interpret*,
self-contained.

**Our adoption:** a unified **`hiverelay://` ticket** bundling `driveKey` (what
to verify) + a relay/discovery hint (who can serve it — a gateway URL or a relay
pubkey resolvable via Phase 1) + content-type (how to interpret). Replaces the
bare pointers we share today (`catalogBeeKey`, `indexRoom`, raw `hyper://`
keys). The fetcher verifies against the driveKey regardless of which relay
serves the bytes. Pairs naturally with the desktop's existing link parsers
(`sheets://`, `hiveindex://`).

**Status: not started.** Low risk, mostly a format + parser + emit sites.

---

## Phase 4 — Short-lived signed auth tokens for paid seeding

**iroh lesson:** dedicated relays authenticate endpoints with **short-lived
signed tokens** (not raw API keys), so deleting a key revokes access *live, even
mid-connection*.

**Our adoption:** refine the **paid pin-lease / `exposeToken`** model — issue a
short-lived signed token scoped to a seeding grant rather than a static key, so
revocation is immediate and a leaked token expires on its own. Folds into the
existing lease gate.

**Status: not started.** Refinement of shipped pin-lease; do after Phase 2
(shares the capability/token machinery).

---

## Phase 5 — SDK bindings posture + connectivity UX (context, longer-term)

- **One core, generated bindings.** iroh writes the hard networking once in Rust
  and *generates* Python/Swift/Kotlin/Node bindings via UniFFI. The lesson for
  `react-native-pear-end`: lean on one core (Holepunch's Bare runtime is our
  equivalent) + thin generated bindings, not per-platform hand-ports.
- **Relay-first, then upgrade.** iroh brings a connection up *through* the relay
  instantly, then migrates the live session onto a direct path. A target for how
  a PearBrowser app should *feel* on first load (instant via relay → background
  P2P upgrade). Mostly Hyperswarm's job; informational.

**Status: informational; no immediate build.**

---

## Explicitly NOT adopting (and why)

- **QUIC transport / BLAKE3+bao content addressing** — we're committed to the
  Holepunch stack (Noise/UDX, Hypercore Merkle). These are context, not
  migrations.
- **Willow destructive editing** — Willow can truly *delete* entries; Hypercore
  is append-only. We approximate deletion with unseed + eviction + dedup
  reclaim. Worth understanding as a *limitation* of our model (e.g. right-to-
  erasure), not something to chase — adopting it would mean leaving Hypercore.
- **iroh-docs LWW-by-wall-clock** — their listed weakness (clock skew picks a
  non-intuitive winner). Our Autobase linearization + the version-rank we
  hardened in dedup is more robust for the catalogue; we're ahead here.

---

## Phase 1 design (implementing now)

**Record** (`relay-record.js`): a compact, versioned, DHT-value-sized payload —
`{ v, gatewayUrl, indexRoom }` — encode/decode with a hard cap (hyperdht mutable
values are BEP44-bounded, ~1000 bytes; a relay record is well under that).

**Publish** (`RelayNode.publishRelayRecord`): `this.swarm.dht.mutablePut(this.keyPair, encode(record))`
on boot (after swarm ready), again whenever `gatewayUrl`/`indexRoom` change, and
on a periodic timer (DHT records expire). Best-effort: a publish failure logs
and retries next tick, never blocks startup. Signing + signature verification
are handled by hyperdht's mutable-record machinery against `this.keyPair`.

**Resolve** (client): `dht.mutableGet(relayPubkey)` → verified value → decode →
`{ gatewayUrl, indexRoom }`. Feeds `relay-client.listRelays()` (a DHT backend
beside the HTTP `/index/relays` one) and lets the browser load a relay's
`indexRoom` knowing only its pubkey. (Desktop side: next increment.)

**Blind-safety:** the record carries only already-public relay self-description
(its gateway URL + its public index-room key) — the same data the capability doc
+ `/catalog.json` already expose. No user data, no content identity. Keying by
the relay's own pubkey means only the relay can publish its own record.
