# Turn-Based Game on the Blind Substrate

Reference adapter for an **async two-player turn-based game** (simultaneous
WeGo orders with commit-reveal) composed entirely from the generic
`hiverelay-blind/1` primitives. No protocol additions, no relay-side
application awareness — the relay never learns that a game exists, only that
opaque cells and fixed-size frames do.

This is the composition pattern from the
[application adoption contract](../../docs/protocol/BLIND-SUBSTRATE-APPLICATION-ADOPTION.md)
made executable: an app-agnostic relay substrate is enough to run sealed-order
turn-based games between two players who are never online at the same time.

## What it demonstrates

| Game need | Substrate composition |
|---|---|
| Sealed orders (no last-mover advantage) | COMMIT/REVEAL entries as fixed-class encrypted **cells**; commitment = `blake2b256(canonical(orders) ‖ nonce ‖ u64be(turn) ‖ gameId)` |
| Opponent learns a reveal exists | read capability for the reveal cell, padded to the frame class, appended to the opponent's **inbox** (capability rendezvous) |
| Knowing it's your move while away | `INBOX.WATCH` long-poll on the opponent-poked inbox (`maxWaitMillis ≤ 30000`), polling fallback |
| Durability before going offline | cell leases (`leaseClass 2` / L7); a move counts as submitted once the cell create is receipt-backed |
| Abandoned games clean up | leases simply stop being renewed; mirrors age out |

The commitment binding covers every replay degree of freedom: different
orders, a reused nonce, a different turn number, or replaying a commitment in
another game (`gameId`).

## Run

```bash
cd examples/turn-based-game
npm install
npm start   # plays a 3-turn game between two in-process players
npm test    # adapter property tests (node:test)
```

The example runs against an in-memory stand-in for the relay's cell store and
inboxes. **All substrate operations are real** — sealed cells, read
capabilities, inbox frames, and watch requests are built by the actual
`@hiverelay/blind-client` functions, so the cryptography exercised here is
the production cryptography. Only the HTTP transport is simulated: replace
`InMemoryRelay`'s `put`/`fetch`/`append` with blind-client transport calls
against a `VerifiedEndpoint` to run against a live relay.

## Files

- `adapter.js` — the game-side adapter (canonical encoding, commitment /
  reveal, poke frames, watch). This is the file to copy as a starting point.
- `game-sim.js` — a deliberately tiny deterministic resolver (seeded RNG in
  state, integer math, fixed resolution order, order validation) plus
  `stateHash`. Swap in your own game; the adapter does not care.
- `example.js` — the full turn loop: commit → reveal → poke → watch → open →
  verify → resolve → hash.
- `test/adapter.test.js` — commitment binding, tampered-reveal rejection,
  canonical encoding stability, resolver determinism.

## Boundaries (from the adoption contract)

- The relay sees: opaque cell blobs (randomized, exact size class), frame
  hashes, capabilities, timing. It never sees orders, unit state, the game
  ID, or that this is a game.
- The application keeps: canonical encoding, commitment/reveal rules,
  capability distribution policy, violation policy (`verifyReveal` returns
  the violation name; what to do about it is the app's call).
- Clocks: lease epochs are retention machinery only. Turn deadlines are the
  application's business and must be log-deterministic, not relay-clock
  based.
