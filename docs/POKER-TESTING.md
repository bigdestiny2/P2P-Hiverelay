# Poker — Testing Guide

> Handover for the maintainer. How to test the relay's **card-blind poker substrate**
> (`packages/services/builtin/poker/`). Everything here is verified against
> `origin/main` (v0.19.0).

## TL;DR

- The poker **substrate + crypto are complete and fully tested** — every suite
  is green (see [Test status](#test-status)).
- **Path A — library (ready *now*):** import the substrate into your Pear app,
  or run the bundled test scripts. No relay changes, no deploy. Start here.
- **Path B — hosted relay over HTTP/WS:** *not wired yet.* The substrate ships
  a reference HTTP adapter but the relay gateway does not mount `/api/poker/*`
  and poker is not in the enable list. ~1 day of integration work — see
  [Hosted relay](#path-b--hosted-relay-httpws-not-wired-yet). Ask if you need it.

## What this is (and isn't)

A signed-log **substrate**, not a poker engine. The relay is **card-blind by
construction**: it never sees hole cards, never evaluates hands, never knows
whose turn it is. It provides exactly four things per table:

1. An **append-only signed log** — every entry must be signed by an allowlisted
   writer pubkey, carry a per-writer monotonic `seq`, sit within a 60s clock
   skew, and name the right table. **`payload` is opaque** — never inspected.
2. **Pub/sub fan-out** — successful appends notify subscribers.
3. **Read endpoints** — current state (cursors) + log replay from an index.
4. **Audit retention** — optional, by mirroring entries into a hypercore (the
   existing seeder/custody pipeline picks it up).

All shuffle proofs, DKG, decryption shares, hand-ranking, turn logic, and
dispute *evidence* live in the **players' apps**, off the log. The relay is
byte storage with strong ordering + signature checks. See
[`packages/services/builtin/poker/README.md`](../packages/services/builtin/poker/README.md)
for the full rationale.

## Test status

Run from a fresh checkout with deps (`npm ci`). All green on v0.19.0:

| Suite | Command | Result |
|---|---|---|
| Substrate + HTTP adapter | `node scripts/test-poker-app.js` | 39 ✓ |
| End-to-end flow (disconnect/restart, WS fan-out, **real Chaum-Pedersen proof**) | `node scripts/test-poker-flow-e2e.js` | 18 ✓ |
| Arbitration poker schemas | `node scripts/test-arbitration-poker-schemas.js` | 37 ✓ |
| VRF (RFC 9381 test vectors) | `node scripts/test-vrf-vectors.js` | 30 ✓ |
| VRF shuffle-verify | `node scripts/test-vrf-service.js` | 65 ✓ |
| Poker hand-seed → deck order | `node scripts/test-poker-hand-seed.js` | 37 ✓ |
| Arbitration panel | `node scripts/test-arbitration-panel.js` | 27 ✓ |
| Services unit suite | `npx brittle test/unit/{poker-block-padding,arbitration-service,services,api-services}.test.js` | 166/166 (432 asserts) ✓ |

## Path A — library quickstart

**Prereqs:** clone + install (the substrate's native deps need a glibc box or
macOS; the relay already runs on Node ≥18).

```bash
git clone https://github.com/bigdestiny2/P2P-Hiverelay.git
cd P2P-Hiverelay && npm ci
node scripts/test-poker-app.js        # sanity: 39 passing
```

Use it in your app:

```js
import { PokerApp }  from 'p2p-hiveservices/builtin/poker/index.js'
import { SignedLog } from 'p2p-hiveservices/builtin/poker/signed-log.js'
import sodium from 'sodium-native'
import b4a from 'b4a'

// Each player holds an ed25519 keypair; its pubkey (hex) goes in the allowlist.
function signEntry (secretKey, entry) {        // entry = { tableKey, writer, seq, ts, payload }
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, SignedLog.canonicalBytes(entry), secretKey)
  return { ...entry, signature: b4a.toString(sig, 'hex') }
}

const app = new PokerApp({})                    // opts below; {} is fine for testing
await app.start({})                             // standalone; or { node: relayNode } for pubsub/seeding

const tableKey = alicePubHex                     // any 64-hex table id (convention: the table's own pubkey)
app.createTable({ tableKey, writers: [alicePubHex, bobPubHex] })

const entry = signEntry(aliceSecretKey, {
  tableKey,
  writer: alicePubHex,
  seq: 0,                                        // per-writer, monotonic, starts at 0, no gaps
  ts: Date.now(),                                // within ±60s of the relay clock
  payload: { kind: 'sit', seat: 0 }              // OPAQUE — put encrypted shares / actions here
})

const r = app.submitEntry(tableKey, entry)       // → { ok: true, index, ts } | { ok: false, reason, detail }
const state = app.getState(tableKey)             // cursors / per-writer seq
const log   = app.getLog(tableKey, 0)            // replay from index 0
const off   = app.subscribe(tableKey, e => { /* push to your UI */ })
// ... off() to unsubscribe; await app.stop() to tear down
```

> **Local HTTP, no relay changes:** if you want the HTTP shape
> (`POST /tables`, `POST /:table/move`, `GET /:table/state`, `GET /:table/log`),
> mount the bundled reference adapter in your own harness:
> ```js
> import { handlePokerRoute } from 'p2p-hiveservices/builtin/poker/http-adapter.js'
> // in your http server: if (req.url.startsWith('/api/poker/')) return handlePokerRoute(req, res, { app })
> ```
> `scripts/test-poker-app.js` drives exactly this against a stub req/res — copy it.

## Substrate API reference

**`new PokerApp(opts)`** — `maxTables`, `defaultLifetimeMs` (idle TTL),
`reaperIntervalMs`, `maxEntriesPerTable`, `log`.

| Method | Returns |
|---|---|
| `await start(ctx)` / `await stop()` | ServiceProvider lifecycle; `ctx.node` enables relay pubsub/seeding |
| `createTable({ tableKey, writers, options? })` | table descriptor (throws on dup / over `maxTables`) |
| `submitEntry(tableKey, signedEntry)` | `{ ok:true, index, ts }` or `{ ok:false, reason, detail }` |
| `getLog(tableKey, fromIdx=0, limit=∞)` | `{ from, to, entries }` |
| `getState(tableKey)` | cursors + per-writer seq |
| `subscribe(tableKey, fn)` | unsubscribe function |

**Entry shape** (all fields required):

```
{ tableKey: <hex64>, writer: <hex64>, seq: <int ≥0>, ts: <ms epoch>,
  payload: <any JSON>, signature: <hex128>   // ed25519 over canonicalBytes(entry-minus-signature)
}
```

**Rejection reasons** (`reason` from `REJECT`): `bad-shape`, `wrong-table`,
`unknown-writer`, `bad-seq` (`detail: { expected, got }`), `bad-ts`
(`'future'`/`'past'`), `oversized`, `bad-sig`.

**Limits:** `TS_SKEW_MS = 60s` · `MAX_ENTRY_BYTES = 64 KiB` (override per-table
via `opts.tsSkewMs` / `maxEntriesPerTable`).

## Supporting services (for fair dealing + disputes)

These are real builtin services your poker app composes with — all tested above:

- **`vrf` (production-ready, RFC 9381):** verifiable randomness for hand
  seeding + provable shuffle order. `test-poker-hand-seed.js` shows combining
  per-player VRF betas into a deck order; `test-vrf-service.js` covers
  shuffle-verify.
- **`arbitration` (experimental):** dispute adjudication off-log. The relay
  holds *evidence*, not cards; `test-poker-flow-e2e.js` Phase 7 verifies a real
  Chaum-Pedersen proof end-to-end → `claim-refuted`. Open voting or a fixed
  panel (`test-arbitration-panel.js`).

## Path B — hosted relay (HTTP/WS) — **not wired yet**

Today poker is **not** enable-able on a running relay: it's absent from the
service enable list (`BUILTIN_MAP` = storage/identity/ai/zk/sla/schema/
arbitration/vrf), `PokerApp` is never instantiated by the relay, and
`/api/poker/*` is mounted nowhere. To test against a live relay we need:

| Step | Effort |
|---|---|
| Register `PokerApp` as builtin `poker` (→ `BUILTIN_MAP`, auto-appears in the Services-tab enable list) | S |
| Mount `/api/poker/*` → `handlePokerRoute` in the gateway, resolving the running `PokerApp` from `serviceRegistry` | S–M |
| WebSocket fan-out `/api/poker/:table/events` (currently deferred) bound to `app.subscribe` | M |
| Integration test + cut a release + enable `poker` on a test relay | S–M |

Estimate: ~1 focused day, 1–2 PRs. **If you need this, ping the maintainer and
it'll be built** (HTTP mount first, then WS).

## Notes / gotchas

- **In-memory only.** Tables + logs live in RAM; idle tables are reaped
  (`defaultLifetimeMs`). Durability is opt-in by mirroring entries into a
  hypercore (operator's choice) — fine to skip for a functional test.
- **`seq` is per-writer and strict** — start at 0, no gaps, no rewinds; each
  writer has an independent counter.
- **Clocks matter** — sign with a real `Date.now()`; >60s skew is rejected.
- **The relay can't help you debug game logic** — by design it never sees
  payloads. Validate poker rules in your app against the replayed log.
