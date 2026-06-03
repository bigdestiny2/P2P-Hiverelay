> [!NOTE]
> Refreshed for v0.10.0: seven builtin services (`identity`, `storage`, `schema`, `ai`, `zk`, `sla`, `arbitration`) plus the card-blind poker/SignedLog substrate. Services are opt-in (`enableServices`), and `ai`/`zk`/`sla`/`arbitration` are experimental. See the [CHANGELOG](../CHANGELOG.md) for the authoritative architecture.

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

### Poker / SignedLog Substrate (v0.10.0)

A card-blind, append-only signed-log substrate for turn-based games with hidden information. It is **not** a service in the `ServiceProvider`/RPC sense — it lives at `packages/services/builtin/poker/` and owns the `/api/poker/*` HTTP + WebSocket namespace. The relay enforces per-writer signatures, monotonic `seq`, a 60s clock-skew bound, and a byte budget; the `entry.payload` stays opaque and all game rules run in the Pear client. Poker is the first consumer; the same substrate composes for liar's dice, mafia, and sealed-bid auctions.

See the [poker substrate README](../packages/services/builtin/poker/README.md).

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

### Service Selection During Setup

The `p2p-hiverelay setup` wizard selects services by node profile. The relay-only profiles run no app services at all (`enableServices: false`); services are opt-in:

| Profile | `enableServices` | Default Services |
|---------|------------------|------------------|
| Relay Core | false | none — availability + custody kernel only |
| Custody Relay | false | none — blind atomic custody focus |
| HomeHive | false | none — private/local relay |
| Service Operator | true | identity, storage, schema |
| Experimental Lab | true | identity, storage, schema, ai, zk, sla, arbitration |
| Custom | — | hand-picked from the full service list |

The seven builtin services are `identity`, `storage`, `schema`, `ai`, `zk`, `sla`, and `arbitration`. The `ai`, `zk`, `sla`, and `arbitration` services are experimental and ship enabled only under the Experimental Lab profile or an explicit custom selection.
