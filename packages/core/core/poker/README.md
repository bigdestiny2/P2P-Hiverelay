# PokerApp — card-blind signed-log substrate

> Relay-side substrate for turn-based games with hidden information. Poker is
> the first consumer; the underlying `SignedLog` is generic enough for liar's
> dice, mafia, blind auctions, and sealed-bid markets.

## What this is (and isn't)

This is **not** a poker engine. The relay never sees hole cards, never
evaluates hands, never knows whose turn it is. It is an ordering + availability
layer for signed entries authored by a fixed set of writer pubkeys.

Concretely the relay provides:

1. **Append-only signed log per table.** Every entry must be signed by an
   allowed writer, carry a per-writer monotonic `seq`, and be within a 60s
   clock-skew window. Payload is opaque bytes — the relay never inspects
   or validates `entry.payload`.
2. **Pub/sub fan-out.** Successful appends emit `poker/entry` on the relay's
   pubsub so connected clients (WS subscribers) get push semantics.
3. **State + log read endpoints.** `/api/poker/<tableKey>/state` for cursors;
   `/api/poker/<tableKey>/log?from=N` for replay.
4. **Audit retention** *(when persistence is wired)*. The substrate ships
   in-memory only — durability is the operator's choice. When operators
   mirror entries into a hypercore (the natural fit) those cores are picked
   up by the existing seeder + custody pipeline + cancellation contract
   with the same guarantees as any other seeded content. The
   `seeding-manifest.lifetime: 'session'` hint lets them evict per-hand
   ephemera without conflating it with publication drives.

What the relay does **not** do:

- Validate that an entry's `payload` is a legal poker action.
- Hold any cryptographic material that could reveal a card.
- Run shuffle proofs, decryption-share equations, or hand-rank evaluation.
- Adjudicate disputes (that's the arbitration service — see below).

## Why "signed log" instead of "server-authoritative state"

The hiveworm pattern (relay validates moves against canonical state) is
correct for public-information games. It is **wrong** for poker because:

- The relay would need to see cards to validate "is this action legal."
- Hole-card secrecy collapses the moment any single server component sees
  the deck in cleartext.
- Reliable disconnection handling requires the relay to hold *encrypted*
  reveal shares, not plaintext state.

A signed log keeps the relay card-blind by construction. Player Pear apps
enforce game rules off the log; the relay is byte storage with strong
ordering and signature checks.

## Hand lifecycle (illustrative)

```
[stake commit]      → entry { payload: { kind: 'stake', amount, escrowProof } }
[DKG round 1..N]    → entry { payload: { kind: 'dkg', round, commitment } }
[shuffle round 1..N]→ entry { payload: { kind: 'shuffle', proof } }
[deal share i]      → entry { payload: { kind: 'share', card: i, recipient, ciphertext } }
[bet action]        → entry { payload: { kind: 'bet', amount } }
[community reveal]  → entry { payload: { kind: 'reveal', card: i, share } }
[showdown reveal]   → entry { payload: { kind: 'showdown', card: i, share } }
[settle]            → entry { payload: { kind: 'settle', stacks: [...] } }
```

Every entry is signed by its writer; the relay only sees signatures + opaque
payloads. The Pear-side poker library is responsible for parsing `payload`,
running the shuffle/share verification math, and rendering hands.

## Disconnection survival

The killer problem of P2P poker. Solved here in three layers:

1. **Pre-committed reveal shares.** At deal time, every player publishes
   their decryption shares for *future* board reveals as entries. The shares
   are encrypted to a threshold of other players, so even if the original
   author goes offline, the threshold can still publish on their behalf.
2. **Custody / cancellation contract.** The relay's custody pipeline
   (`custody-intent → receipt → commit`) means the relay can't lie about
   holding those shares — the cancellation contract (#18 work) prevents
   claim-then-bail. If the relay says it has Alice's pre-committed shares,
   it does.
3. **Lifetime hint.** Per-hand share material can be marked
   `lifetime: 'ephemeral'` in the seeding manifest so operators can size
   storage policy without conflating session ephemera with persistent
   publication content.

## Disputes

Slashing-grade disputes go through the arbitration service:

- `poker/missing-share` — share not published by deadline
- `poker/invalid-share` — published share fails verification equation
- `poker/refused-reveal` — player in pot at showdown, didn't reveal

Submit shape and evidence schemas are documented at the top of
[`arbitration-service.js`](../../../services/builtin/arbitration-service.js).
Operators can register their own cryptographic verifier via
`arbitration.setAppEvidenceVerifier(type, fn)` — the bundled verifier is
deliberately a stub that returns `inconclusive` until a real shuffle/share
proof library is wired in.

## Operator wiring

Minimal — HTTP only, in-memory only:

```js
import { PokerApp, handlePokerRoute } from 'p2p-hiverelay'

const poker = new PokerApp({ maxTables: 256 })
await poker.start({ node: relayNode })

// Inside the HTTP server (bare-http-server.js or gateway-server.js):
if (await handlePokerRoute(req, res, { pokerApp: poker })) return
```

Full — HTTP + WS + hypercore persistence + Chaum-Pedersen share verifier:

```js
import {
  PokerApp, handlePokerRoute, PokerWsAdapter,
  HypercorePersistence, makeInvalidShareVerifier
} from 'p2p-hiverelay'
import { ArbitrationService } from 'p2p-hiveservices/builtin/arbitration-service.js'

const poker = new PokerApp({ maxTables: 256 })
await poker.start({ node: relayNode })

// Durable storage: every successful append mirrors to a per-table hypercore.
const persistence = new HypercorePersistence({ pokerApp: poker, store: relayNode.store })
// Rehydrate any tables you intend to keep running across restarts:
await persistence.createPersistentTable({ tableKey, writers, options })

// HTTP routes — list, create, state, log, move.
httpServer.on('request', async (req, res) => {
  if (await handlePokerRoute(req, res, { pokerApp: poker })) return
  // ... other routes
})

// WebSocket push — /api/poker/<tableKey>/events
const ws = new PokerWsAdapter({ pokerApp: poker, server: httpServer })
ws.start()

// Slashing-grade share validation in the arbitration service.
arbitrationService.setAppEvidenceVerifier('poker/invalid-share', makeInvalidShareVerifier())
```

The substrate is opt-in: relays that don't instantiate `PokerApp` are
unaffected. Each layer above PokerApp is also opt-in — you can ship HTTP
without WS, persistence without the verifier, etc.

## Status

- ✅ SignedLog: signature, ordering, skew, byte budget, subscriber fan-out
- ✅ PokerApp: tables, getState, getLog, submitEntry, listTables, reaper,
     replayEntries (for persistence adapters)
- ✅ HTTP adapter: list, create, state, log, move
- ✅ Arbitration: 3 poker dispute types, pluggable verifier
- ✅ Seeding manifest: `lifetime` hint
- ✅ WS fan-out: `PokerWsAdapter`, `/api/poker/<tableKey>/events` with
     initial-state snapshot, per-table fan-out, backpressure disconnect,
     optional API-key gate, 404 at handshake for unknown tables
- ✅ Hypercore persistence: `HypercorePersistence` — one core per table,
     mirrors successful appends, rehydrates on restart, 'mirror-error'
     event on append failure (in-memory log stays source of truth)
- ✅ Reference share-equality verifier: Chaum-Pedersen over ed25519 with
     Fiat-Shamir; pluggable into `arbitration.setAppEvidenceVerifier(
     'poker/invalid-share', ...)`. **Reference quality** — self-consistent
     prove+verify, not audited for production stake; operators with audited
     crypto should register their own
- ⏳ Autobase-per-table persistence (follow-up for a model where each
     player has their own writer core; current adapter is one-core-per-
     table with the relay as the only appender)
- ⏳ Cross-implementation verification of the share verifier against
     RFC 9497 / libsignal / noble-curves (this PR's verifier is self-
     consistent only)
