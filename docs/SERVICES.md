> [!NOTE]
> Refreshed for the next relay update: the core builtin services remain opt-in, with new app-facing service providers for encrypted wake notifications (`notify`) and single-writer signed outboxes (`outboxlog`). Services are opt-in (`enableServices` / selected `plugins`); `vrf` is production-ready (RFC 9381, validated against the spec's own test vectors), while `ai`/`zk`/`sla`/`arbitration`, `notify`, and `outboxlog` remain experimental. Notify and outboxlog now have local JSON state, but production provider adapters, billing gates, and operational hardening are still incomplete. See the [CHANGELOG](../CHANGELOG.md) for the authoritative architecture.

# HiveRelay Services Layer

## Overview

HiveRelay has a two-layer architecture:

- **Apps Layer** -- User-facing applications (Ghost Drive, chat, social, POS)
- **Services Layer** -- Headless capabilities that apps consume via RPC

Relay nodes host services and bridge them to apps over Protomux channels. This decouples capabilities from applications: a wallet app can call the ZK service for proofs, the AI service for fraud detection, and the storage service for encrypted data -- all from the same relay connection.

## Architecture

### ServiceProvider (Base Class)

Every service extends `ServiceProvider` and implements:

```javascript
class MyService extends ServiceProvider {
  manifest () {
    return { name: 'my-service', version: '1.0.0', capabilities: ['do-thing'] }
  }
  async start (context) { /* context.node, context.store */ }
  async stop () { /* cleanup */ }
  async 'do-thing' (params, context) { return { result: 'done' } }
}
```

### ServiceRegistry

Central service registry that handles:
- **Registration** -- `register(provider)` / `unregister(name)`
- **RPC dispatch** -- Routes `handleRequest(service, method, params)` to the right provider
- **Discovery** -- `findProviders(name)` returns local + remote providers
- **Catalog** -- `catalog()` returns all available services for peer exchange
- **Stats** -- Per-service request counts and error tracking
- **Lifecycle** -- `startAll(context)` / `stopAll()` for clean init/shutdown

### Service Supervision

The registry now fails closed and supervises persistent services:

| Behavior | Result |
|---|---|
| Service startup throws | Service is marked failed and removed from dispatch/catalog |
| Service emits `error` | Service is marked failed and RPC calls return `SERVICE_UNAVAILABLE` |
| Health check fails | Relay supervision marks the service failed |
| Restart succeeds | Service returns to `running`, restart count increments |
| Restart budget is exhausted | Service remains unavailable instead of being advertised |

Providers can expose either `healthCheck(context)` or `health(context)`. A healthy result is any non-false value; a thrown error or `false` marks the service failed.

Supervision config:

```javascript
serviceSupervision: {
  enabled: true,
  intervalMs: 30_000,
  maxRestarts: 3
}
```

This keeps app-facing routes honest. A broken AI, compute, storage, or plugin service should disappear from service discovery rather than remaining advertised as available.

### ServiceProtocol

Protomux-based RPC over P2P connections:

| Message Type | ID | Direction | Purpose |
|---|---|---|---|
| CATALOG | 0 | Both | Exchange available services on connect |
| REQUEST | 1 | Client -> Server | RPC call: `{ id, service, method, params }` |
| RESPONSE | 2 | Server -> Client | Success: `{ id, result }` |
| ERROR | 3 | Server -> Client | Failure: `{ id, error }` |
| SUBSCRIBE | 4 | Client -> Server | Subscribe to pub/sub topics |
| UNSUBSCRIBE | 5 | Client -> Server | Unsubscribe from topics |
| EVENT | 6 | Server -> Client | Pub/sub event delivery |

Wire format: JSON over Protomux binary channel (future: compact-encoding).

### Router

The Router sits between the ServiceProtocol and the ServiceRegistry, adding:
- **O(1) dispatch** via `service.method` route strings
- **Middleware** -- Global and per-route transformation/auth/logging chains
- **Rate limiting** -- Token bucket per route, per peer
- **Pub/Sub** -- Topic-based event distribution with TTL
- **Worker pools** -- Named pools (cpu/io) for offloading heavy tasks
- **Orchestration** -- Multi-step transactions with rollback

## Built-in Services

### Storage Service

Provides Hyperdrive and Hypercore CRUD operations. Apps use this to create, read, write, and manage drives without handling low-level Hypercore details.

**Capabilities:** `drive-create`, `drive-list`, `drive-get`, `drive-read`, `drive-write`, `drive-delete`, `core-create`, `core-append`, `core-get`

**PolicyGuard integration:** Write operations (`drive-write`, `core-append`) are gated by PolicyGuard. If the app's privacy tier doesn't allow relay storage, writes throw `POLICY_VIOLATION`.

### Identity Service

Manages keypair identities and peer verification using Ed25519 signatures (sodium-universal).

**Capabilities:** `whoami`, `sign`, `verify`, `resolve`, `peers`

- `sign` -- Signs a message with the node's Ed25519 secret key
- `verify` -- Verifies a detached signature against a public key
- `resolve` -- Looks up a pubkey in the device allowlist (private mode)

### ZK Service (Zero-Knowledge Proofs)

Privacy-preserving proof generation and verification.

**Capabilities:** `commit`, `verify-commitment`, `membership-proof`, `verify-membership`, `range-proof`, `verify-range`, `list-circuits`

**Phase 1 (current):** BLAKE2b commitments, Merkle tree membership proofs, range proofs via decomposed commitments.

**Phase 2 (planned):** snarkjs/circom circuit compilation and verification.

### VRF Service (Verifiable Random Functions)

Unbiasable, publicly-verifiable randomness via ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite 0x03). The relay holds a VRF key and, for any input `alpha`, returns a deterministic output `beta` plus an 80-byte proof `pi` that anyone can verify against the relay's VRF public key — the relay cannot bias `beta`, and verifiers need no trust in the operator.

**Capabilities:** `prove`, `verify`, `proof-to-hash`, `pubkey`, `info`, `select`, `shuffle`, `select-verify`, `shuffle-verify`, `beacon-info`, `beacon-latest`, `beacon-round`, `beacon-range`, `beacon-verify`

- **Correctness gate:** the ECVRF core is validated byte-exact against all three RFC 9381 Appendix A.4 test vectors (`pi`, `beta`, and `verify`), plus tamper/negative cases — see `scripts/test-vrf-vectors.js`.
- **Dedicated key:** the VRF seed is domain-separated from the node's EdDSA identity key (`SHA-512("hiverelay/vrf-key/v1" || node_seed)`), so the same scalar never both signs protocol messages and produces VRF proofs. The VRF public key is therefore distinct from the node identity pubkey — consumers fetch it via `pubkey`.
- **Verifiable sortition (`select` / `shuffle`):** the bridge from raw randomness to decisions. The relay binds a draw to a caller's context via `alpha` (e.g. a disputeId or poker handId), proves it, and applies a deterministic, integer-only sortition primitive to `beta` (`packages/services/builtin/vrf/sortition.js`). `select` draws a committee without replacement (uniform or reputation-**weighted**, via `quantizeWeights` + A-Res-style integer draws — no floating point, so every node agrees); `shuffle` returns a verifiable permutation. The result `{ pi, beta, committee/order }` is self-verifying: anyone replays `verify(pubkey, alpha, pi) → beta → weightedSample/seededShuffle`, or calls `select-verify` / `shuffle-verify`. Tested in `scripts/test-vrf-sortition.js` and `scripts/test-vrf-service.js`.
- **Randomness beacon (opt-in):** a chained, self-verifying randomness chain where `beta_N = VRF(beta_{N-1} || N)`, anchored at `beta_0 = SHA-512(domain || pubkey)`. Each round is world-readable and independently verifiable; the operator cannot grind or skip outputs. Enabled via `vrfBeacon: { enabled, intervalMs, domain, retain }`. The retained history is in-memory (a ring buffer of recent rounds); durable persistence is a planned follow-on.
- **Use cases:** unbiasable shuffles/deals (poker, lotteries), fair leader/committee/arbitrator selection (see the Arbitration panel below), and the public beacon.
- **Trust boundary:** the VRF holder cannot bias *which* members are drawn from a fixed pool, but — holding the key — it could grind `alpha`. Bind `alpha` to immutable, append-only content (and, for adversarial settings, fold in an external/multi-party beacon) so grinding is either detectable or impossible.

### AI Service

Model registry and inference routing. Wraps local models (Ollama) or remote endpoints (OpenAI-compatible).

**Capabilities:** `infer`, `list-models`, `register-model`, `remove-model`, `embed`, `status`

- Handler-based: register a function that processes inference requests
- HTTP-endpoint: proxy to any OpenAI-compatible API
- Queue management with configurable concurrency and max queue depth

### SLA Service (Revenue Engine)

Service-level agreement contracts between app developers and relay operators. This is the revenue mechanism -- developers pay relays that meet performance guarantees.

**Capabilities:** `create`, `list`, `get`, `terminate`, `check`, `violations`, `stats`

**Automated enforcement:**
- Reads proof-of-relay reliability scores every 60 seconds
- Detects violations: reliability below threshold, latency above threshold
- **Auto-slashing:** Immediately slashes 1/10 of collateral per violation
- **Auto-termination:** After 3 violations, contract terminates
- Pub/sub events: `sla/created`, `sla/violation`, `sla/terminated`, `sla/expired`

### Schema Service

JSON Schema registration and validation for cross-app data interoperability.

**Capabilities:** `register`, `get`, `list`, `validate`, `versions`

- Versioned schema storage (same schemaId, multiple versions)
- Built-in JSON Schema validator (no external dependencies)
- Supports: type checks, required fields, numeric/string constraints, enums, array validation

### Arbitration Service

Decentralized dispute resolution via peer voting.

**Capabilities:** `submit`, `vote`, `get`, `list`

- Dispute types: `sla-violation`, `proof-failure`, `receipt-dispute`, plus the poker substrate's `poker/missing-share`, `poker/invalid-share`, `poker/refused-reveal`
- Arbitrator eligibility: reputation score > 100, reliability > 0.95, 50+ challenges
- Evidence verification: validates bandwidth receipts cryptographically
- Resolution: majority vote wins, loser slashed, voters gain/lose reputation
- `setAppEvidenceVerifier(appType, fn)` seam — apps register their own cryptographic evidence verifier (e.g. the reference Chaum-Pedersen share-equality verifier for `poker/invalid-share`). Disputes without a registered verifier resolve `inconclusive` rather than `claim-supported`.
- **Verifiable arbitrator panels (opt-in, default OFF):** instead of open voting by any eligible peer, a dispute can be judged by a fixed committee drawn by VRF from the eligible pool. On `submit`, the service builds `alpha = SHA-256(domain || disputeId || type || claimant || respondent || createdAt)`, snapshots the eligible pool (parties excluded; weight = `score × reliability`, optionally `quantizeWeights`'d), and calls the VRF service's `select`. The dispute records the full proof material `{ vrfPubkey, alpha, pi, beta, candidates, members }`, so any observer reproduces the exact committee via `verify(pubkey, alpha, pi) → beta → weightedSample(candidates)` (or the VRF `select-verify` capability). `vote` then gates on panel membership (`ARBITRATOR_NOT_ON_PANEL`) and the quorum is capped to the panel size. Enable globally via `arbitration: { panel: { enabled, size, weighted } }` (or `new ArbitrationService({ panel })`), or per dispute via `params.panel` (`true`/`false` overrides the default). **Graceful fallback to open voting** when there is no VRF service, no reputation pool, or the eligible pool is smaller than the panel size — the dispute records `panel.active === false` with a `reason` and proceeds with open voting. Tested in `scripts/test-arbitration-panel.js`.

### Poker / SignedLog Substrate (v0.10.0)

A card-blind, append-only signed-log substrate for turn-based games with hidden information. It is **not** a service in the `ServiceProvider`/RPC sense — it lives at `packages/services/builtin/poker/` and owns the `/api/poker/*` HTTP + WebSocket namespace. The relay enforces per-writer signatures, monotonic `seq`, a 60s clock-skew bound, and a byte budget; the `entry.payload` stays opaque and all game rules run in the Pear client. Poker is the first consumer; the same substrate composes for liar's dice, mafia, and sealed-bid auctions.

**Verifiable per-hand randomness (`hand-seed.js`):** because the relay is card-blind it cannot shuffle a deck — but it *can* anchor an unbiasable, publicly-verifiable random number to a specific hand that clients fold into their own mental-poker shuffle. The pure, dependency-light helper (`@noble/hashes` only, so it runs unchanged in a Bare/Pear client) exposes:
- `handSeedAlpha(tableKey, handId)` — the canonical VRF input `SHA-256(domain || tableKey || handId)`. Every seat derives the same `alpha`, so all agree on exactly what the relay should prove. A seat requests `vrf.prove({ alpha })` and posts `pi` to the log.
- `verifyHandSeed({ vrfPubkey, tableKey, handId, pi, beta })` — recomputes `alpha`, verifies the proof, and (if given) cross-checks `beta`. Never throws; returns `{ valid, reason, alpha, beta }`.
- `handDeckOrder(beta, deckSize = 52)` — the nothing-up-my-sleeve starting permutation all seats agree on, on top of which the secret commutative encrypt-and-shuffle layers.
- `combineBetas([...])` — XOR-combines independent per-seat betas over the *same* alpha into a hand seed no single party controls. This removes trust in the key-holding relay: the seed is unbiasable unless every contributor colludes, and each contribution stays independently verifiable. Use this for adversarial play (the relay holds the VRF key and could otherwise grind `alpha`, though binding to the append-only log makes grinding detectable). Tested in `scripts/test-poker-hand-seed.js`.

See the [poker substrate README](../packages/services/builtin/poker/README.md).

### Notify Service (v0.1.0 — Encrypted Wake Notifications)

`notify` is a relay-hosted wakeup service for P2P apps. It is not an app
backend and it is not a durable mailbox: the relay only validates signed,
revocable notification capabilities, attempts a bounded encrypted provider
egress, and records redacted delivery events. The device wakes, reconnects,
and syncs authoritative state from the app's Hypercore/Autobase/direct P2P
model.

**Capabilities:** `bind-provider`, `register-device`, `install-receive-cap`,
`install-send-cap`, `revoke`, `send`, `watch`, `unwatch`, `status`,
`delivery-event`, `production-gates`

**Security model:**
- Provider tokens are stored and forwarded only as ciphertext; service reads
  and delivery events do not expose provider tokens or plaintext payloads.
- A wake requires a valid `ReceiveCap` plus a matching `SendCap`; app/vendor
  keys alone cannot wake a user.
- `revoke` covers app, device, binding, receive cap, send cap, channel, and
  relay scopes.
- Delivery events are relay-signed and redacted, so operators and apps can
  meter attempts without leaking wake payloads.
- Watch mode stores opaque Hypercore/feed heads only; app-defined filtering and
  message truth stay in the application.

**Current implementation status:** the v0.1.0 provider has signed object
verification, Node relay JSON persistence under `<storage>/notify-service-state.json`,
quota/replay/dedupe guards, redacted signed delivery events, capability-doc
advertising, a lightweight HTTP facade, Bare-safe client signing helpers, and a
memory push provider for tests. Production APNs/FCM/Web Push adapters and
pricing/billing enforcement are follow-up gates.

Enable it explicitly through `config.plugins` / `services.json` (`notify`) or,
on the Bare/appliance path, with `HIVERELAY_NOTIFY=1`.

See [PUSH-NOTIFICATION-SERVICE-SPEC.md](./PUSH-NOTIFICATION-SERVICE-SPEC.md).

### Signed Outbox Log Service (v0.1.0)

`outboxlog` is a Peerit-compatible single-writer signed outbox bridge for apps
that need a relay-assisted append and sync path while the app stays in charge
of encrypting and interpreting entries. The relay verifies writer signatures,
keeps entries opaque, and exposes a token-gated HTTP/SSE bridge for sync.

**Capabilities:** `create`, `append`, `get`, `head`, `list`, `events`,
`authorize-bridge`, `bridge-token`

**Security model:**
- Only the configured writer can append to a log.
- Entry bodies remain opaque to the relay; plaintext is not allowed by the
  service contract.
- Bridge routes are token-gated and route through the service registry instead
  of a separate app backend.
- Capability docs advertise `outboxlog-v1` only when the provider is running.
- Signed opaque rows and invite keys persist to
  `<storage>/outboxlog-state.json` when a Node relay supplies `config.storage`.

Enable it explicitly through `config.plugins` / `services.json` (`outboxlog`)
or, on the Bare/appliance path, with `HIVERELAY_OUTBOXLOG=1`.

**Namespace registration (required for app-specific records — deployment footgun):**
The outbox is **app-neutral**. Every signed record carries a namespace, and an
app signs its records under a specific one — for example Peerit signs `'peerit'`.
The relay rejects any record whose namespace is **not registered** with
`unknown namespace` (HTTP `400`), so a relay that enables the service but does
not register the app's namespace refuses **every** append from that app. Enabling
`HIVERELAY_OUTBOXLOG=1` alone is not enough — you must also tell the relay which
namespace to admit. Register it one of two ways:

- config: `config.outboxlog.namespace = "peerit"` (or a `config.outboxlog.namespaces`
  map to register several at once)
- env (Bare/appliance): `HIVERELAY_OUTBOXLOG_NAMESPACE=peerit`

The env var is a **default, not an override**: a `outboxlog.namespace` persisted
in `config.json` wins over it (matching `HIVERELAY_ACCEPT_MODE`). When neither is
set, only the app-neutral default namespace is registered, so any app that signs
under its own namespace (Peerit, Poked, etc.) will be rejected until you register
it. This is the most common reason a freshly ENV-provisioned fleet/appliance box
`400`s every publish from an otherwise-working app.

**HTTP shared-NAT rate envelope:** OutboxLog's adapter defaults to 1,200
requests per 60 seconds per client IP. For backward compatibility, public
writes also remain under the relay API's generic 60/minute/IP ceiling until an
operator explicitly configures the dedicated envelope. An explicit setting
makes that envelope authoritative for the public OutboxLog data plane; operator
admin routes retain the generic gate and their separate admin authentication.
For example, a production relay serving roughly 30 active writers behind one
NAT can start with:

```json
{
  "outboxlog": {
    "http": {
      "rateLimit": {
        "enabled": true,
        "windowMs": 60000,
        "max": 12000
      }
    }
  }
}
```

Keep the envelope enabled in production and tune `max` from measured peak
traffic plus headroom. Local or staging deployments can explicitly disable only
this IP envelope with `{ "enabled": false }` (or `rateLimit: false`); token,
admin-auth, body-size, and atomic-commit gates remain active. `windowMs` must be
an integer from 1 through 86,400,000 and `max` from 1 through 10,000,000;
unknown or malformed fields fail relay startup. Authenticated
`GET /api/bridge/status` reports the effective public-write limit, its source,
and the underlying adapter envelope. A `429` includes an integer delta-seconds
`Retry-After` header and exposes it to browser JavaScript through CORS.

**Federation-quorum durability (opt-in):** An atomic commit is locally durable
before it returns. To make one browser-facing ingress wait for independently
operated relays as well, configure `outboxlog.federationQuorum` on **every**
participating operator. The public browser continues to use only the ingress
domain; the operator URLs are private infrastructure configuration. Each relay
uses its existing Ed25519 node identity to sign a receipt for the exact
`(appId, commitId, head)`, and the ingress returns success only after the
configured number of remote receipts verify. If the remote quorum is unavailable
or a signature/head differs, the public commit returns `503` while the exact
locally durable envelope remains safely retryable.

```json
{
  "outboxlog": {
    "namespace": "peerit",
    "legacyWrites": false,
    "federationQuorum": {
      "enabled": true,
      "quorum": 1,
      "timeoutMs": 8000,
      "peers": [
        {
          "id": "independent-operator",
          "url": "https://operator-relay.example",
          "publicKey": "<operator-node-ed25519-public-key>"
        }
      ]
    }
  }
}
```

The independent operator must configure the ingress node's public key in its
own `peers` list (with its internal HTTPS address); this is a mutual allow-list,
not open federation or trust inferred from swarm membership. Browser clients
must pin the same receipt public keys in their signed app roster and verify the
returned receipts before treating a post as published. Do not enable a writable
single-ingress deployment until that operator-side setup and the receipt proof
both pass staging.

**Operator takedown surface (`/api/admin/takedown` · `/restore` · `/takedowns`):**
An operator can drop or restore a single outbox row by its opaque
`(appId, key)` id — content is never read; this exists for operator liability
parity, not for reading user data. The surface is gated by a **dedicated admin
credential that is separate from the browser sync token**, supplied via the
`X-Pear-Admin-Token` header (or `?adminToken=`), so an ordinary client holding a
`/api/token` can never authorize a takedown. It is **safe-by-default**: with no
admin credential configured the three routes return `404` (the surface is simply
not enabled); with one configured, an absent or wrong token returns `401` and
only the exact token succeeds (constant-time compare). Configure the credential
with:

- config: `config.outboxlog.adminKey = "<operator-secret>"`
- env (Bare/appliance): `HIVERELAY_OUTBOXLOG_ADMIN_KEY=<operator-secret>`

There is no default — provision this only on relays where you intend to enable
takedown. Outboxlog claims exactly these three `/api/admin/*` routes and does not
reserve the rest of the `/api/admin/` namespace. The admin key is read once at
node construction (boot-time snapshot, matching `HIVERELAY_API_KEY`); restart the
node to rotate it.

### Storage-Proof Service (v0.20.0 — Trustless Seed Verification, Tier 2)

Signed challenge-response proof that this relay genuinely holds a seeded app. A caller picks a random block of a drive's metadata core; the relay reads it from **local storage only** and returns a Hypercore Merkle proof signed with its swarm identity key. The caller verifies the proof against the **drive key alone** (Hypercore hashes the block into the drive's signed Merkle root, so forged content is rejected) plus the relay signature (attribution + nonce freshness, no replay) — the relay is trusted for nothing.

**Capabilities:** `prove`

- `prove({ coreKey, index, nonce })` -- returns a `buildStorageProof` response object (a signed proof-of-retrievability for block `index` of the drive's metadata core). Reachable over the existing service RPC (`client.callService` / `proveSeeded`).

**Access:** route `storage-proof.prove` is policy `public` (anonymous-callable) in `packages/core/core/router/index.js`.

**Opt-in (default OFF):** a stock node does not run it.
- Node runtime: select `storage-proof` via `config.plugins` / `services.json` (Services tab; persisted under `<storage>/services.json`).
- Bare/appliance runtime: select `storage-proof` via `config.services` (or `config.plugins`), or set env `HIVERELAY_STORAGE_PROOF=1`.

**What it proves (v1):** the drive **metadata** core only — the head the client learns from `open()`, so the `minLength` pin lines up. Blobs-core proofs are a follow-up.

**Security guards:**
- **Privacy gate** -- blind / privacy-redacted drives return `NOT_SEEDED`, indistinguishable from a key the relay does not hold, so `prove` cannot become a possession oracle that defeats catalog redaction.
- **Rate limit** -- a sybil-resistant **global** proof-work token bucket (caps total proof work across all identities) plus a bounded per-caller bucket; cheap rejects (bad input / not-seeded / blind) never spend the budget.
- **Phantom-core DoS guard** -- only serves keys present in `node.appRegistry`; never calls `store.get()` on a caller-supplied key.

**Honest limitation:** this is a challenge-response proof of *retrievability*, not a sealed proof of *replication* — a relay could fetch a block on demand rather than store it; random-index sampling plus a latency bound make that expensive, not cryptographically precluded.

Pairs with the client probes `client.proveSeeded(driveKey, { relay, samples })` (samples up to 16 random blocks, verifies each signed proof against an isolated temp-Corestore verifier pinned to the head; returns `{ ok, proofKind: 'proof-of-retrievability', driveKey, relay, head, passed, total, samples: [{ index, valid, proofKind, reason }] }`, with `ok === true` only if every sample verified) and the replication-based `client.verifySeeded(driveKey, { relay, timeout })`. See `packages/services/builtin/storage-proof-service.js` and the Tier-1 primitive `packages/core/core/protocol/proof-of-storage.js`.

## Creating Custom Services

```javascript
import { ServiceProvider } from './core/services/provider.js'

class WeatherService extends ServiceProvider {
  manifest () {
    return {
      name: 'weather',
      version: '1.0.0',
      description: 'Local weather data',
      capabilities: ['current', 'forecast']
    }
  }

  async start (context) {
    this.node = context.node
  }

  async current (params) {
    return { temp: 22, unit: 'C', location: params.location }
  }

  async forecast (params) {
    return { days: 5, data: [] }
  }
}

// Register with the relay node
registry.register(new WeatherService())
```

Remote peers can then call:
```javascript
const weather = await protocol.request(relayPubkey, 'weather', 'current', { location: 'Dubai' })
```

## Configuration

Services are enabled automatically when the relay node starts. Individual services can be disabled via the config or by not registering them. The SLA service requires proof-of-relay to be active for automated enforcement.

Service lifecycle is controlled by:

```javascript
{
  // Secure-by-default: anonymous swarm peers get the 'anonymous' role and
  // therefore cannot reach 'authenticated-user' or 'relay-admin' service
  // routes. Promote selected pubkeys via serviceAdminAllowlist, or — only if
  // you explicitly want an open, unauthenticated service surface — set this to
  // 'authenticated-user'.
  serviceDefaultPeerRole: 'anonymous',
  serviceAdminAllowlist: [],
  serviceSupervision: {
    enabled: true,
    intervalMs: 30_000,
    maxRestarts: 3
  }
}
```

### Live Management

Services can be managed at runtime via the management console or API:

```bash
p2p-hiverelay manage    # Interactive TUI — Services menu
```

Or programmatically via the HTTP management API:

```bash
# List all services with status
curl http://localhost:9100/api/manage/services

# Disable a service
curl -X POST http://localhost:9100/api/manage/services \
  -H "Content-Type: application/json" \
  -d '{"action": "disable", "service": "ai"}'

# Restart a service
curl -X POST http://localhost:9100/api/manage/services \
  -H "Content-Type: application/json" \
  -d '{"action": "restart", "service": "ai"}'
```

Disabling a configured built-in service removes it from `config.plugins` and
persists that change before the provider is unregistered, so it does not
silently come back after restart. Services supplied by an enabled bundle, such
as `vrf` under the `poker` preset, are rejected on this endpoint; change the
selected bundle through `/api/manage/services/config` instead.

### Service Selection During Setup

The `p2p-hiverelay setup` wizard selects services by node profile. The relay-only profiles run no app services at all (`enableServices: false`); services are opt-in:

| Profile | `enableServices` | Default Services |
|---------|------------------|------------------|
| Relay Core | false | none — availability + custody kernel only |
| Custody Relay | false | none — blind atomic custody focus |
| HomeHive | false | none — private/local relay |
| Service Operator | true | identity, storage, schema, vrf |
| Experimental Lab | true | identity, storage, schema, vrf, ai, zk, sla, arbitration |
| Custom | — | hand-picked from the full service list |

The original core builtin services are `identity`, `storage`, `schema`, `vrf`, `ai`, `zk`, `sla`, and `arbitration`; newer optional providers include `storage-proof`, `poker`, `notify`, and `outboxlog`. `vrf` is production-ready and ships with the Service Operator profile. The `ai`, `zk`, `sla`, `arbitration`, `notify`, and `outboxlog` services are experimental and ship enabled only under explicit custom/plugin selection.
