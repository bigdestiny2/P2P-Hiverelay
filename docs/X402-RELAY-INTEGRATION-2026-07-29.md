# x402 Relay Integration — Research, Decision, and Canary Scaffold

**Date:** 2026-07-29
**Status:** research complete; default-off Node canary scaffold implemented; no live payment or production claim
**Scope:** HiveRelay service facade, operator settlement, agent callers

## Decision

Use x402 v2 as an optional HTTP payment facade in front of a deliberately small
allowlist of HiveRelay service capabilities.

Do not put x402 inside Hyperswarm transport, blind storage, Hypercore
replication, the public Hyperdrive gateway, or management APIs. A relay keeps
moving and storing opaque bytes; the Node HTTP edge quotes, verifies, settles,
and then dispatches one configured service method.

The first canary should be `vrf.prove`, exposed as:

```text
POST /svc/vrf/prove
```

It is a better protocol canary than `mailbox.send` because it is bounded,
verifiable, and has no durable external side effect. `mailbox.send` is the
commercially important target, but the current tree ships OutboxLog
publication, not the many-senders/one-reader mailbox primitive described in the
agent-economy spec.

## Correction to the agent-economy draft

The draft A1 flow uses x402 v1 names:

```text
X-PAYMENT
X-PAYMENT-RESPONSE
```

Current x402 v2 uses:

```text
PAYMENT-REQUIRED   server -> client, on the 402 response
PAYMENT-SIGNATURE  client -> server, on the paid retry
PAYMENT-RESPONSE   server -> client, after settlement
```

Payment data is base64-encoded JSON in headers. Networks use CAIP-2 identifiers
such as `eip155:8453` (Base mainnet) and `eip155:84532` (Base Sepolia).

The scaffold uses the official modular packages at `2.20.0`:

- `@x402/core`
- `@x402/evm`

It registers only the v2 EVM `exact` scheme. V1 compatibility, Solana, `upto`,
and batch settlement are intentionally outside the canary.

## Current protocol flow mapped to HiveRelay

```text
agent
  |
  | POST /svc/vrf/prove
  v
HiveRelay Node HTTP edge
  |
  | 402 + PAYMENT-REQUIRED
  v
agent wallet signs exact token authorization
  |
  | retry + PAYMENT-SIGNATURE
  v
x402 facilitator /verify
  |
  | valid
  v
HiveRelay service router -> vrf.prove
  |
  | proof result
  v
x402 facilitator /settle
  |
  | settlement receipt
  v
200 proof + PAYMENT-RESPONSE
```

The operator's configured `payTo` address receives settlement. The relay does
not pool balances, hold customer funds, or become an escrow.

## Why a separate `/svc/*` facade

Blanket payment middleware over existing relay routes would create dangerous
ambiguity:

- `/api/manage/*` is operator control and must never become purchasable.
- `/v1/hyper/*` is the compatibility gateway; charging it would break existing
  clients and cache behavior.
- OutboxLog and notify routes already have capability/signature semantics that
  payment must complement, not replace.
- `storage-proof.prove` is a public audit primitive. Charging it weakens the
  network's ability to verify operators.
- paid writes need idempotency and settlement-failure behavior per capability.

The `/svc/*` namespace is a narrow translation layer. A route exists only when
the operator maps it to one `service.method`.

## Priced surface recommendation

| Surface | Recommendation | Reason |
|---|---|---|
| `vrf.prove` | Canary first | Bounded, verifiable, no durable side effect |
| `mailbox.send` | First commercial route after mailbox-v1 | Natural postage unit; missing primitive today |
| cold `notify.send` | After provider + idempotency gates | Push may execute before settlement and must dedupe |
| pin lease create/renew | After lease reconciliation design | Existing lease flow is Lightning-invoice based |
| `storage-proof.prove` | Keep free | Public operator-audit primitive |
| beacon range read | Usually free or bundled | Cheap/cache-shaped; weak standalone value |

This preserves the business thesis: charge bot operators for durable service
wrappers, not for raw P2P transport.

## Configuration shape

x402 is off by default. A testnet-only VRF canary can be configured in the
operator's HiveRelay configuration:

```json
{
  "x402": {
    "enabled": true,
    "facilitatorUrl": "https://x402.org/facilitator",
    "publicBaseUrl": "https://canary-relay.example",
    "claimTtlMs": 600000,
    "maxClaims": 50000,
    "routes": {
      "POST /svc/vrf/prove": {
        "serviceRoute": "vrf.prove",
        "sideEffects": "read-only",
        "description": "Create a verifiable randomness proof",
        "unit": "proof",
        "proofType": "ecvrf-proof-v1",
        "accepts": [
          {
            "scheme": "exact",
            "network": "eip155:84532",
            "payTo": "0xOPERATOR_ADDRESS",
            "price": {
              "asset": "0xTOKEN_CONTRACT_ADDRESS",
              "amount": "ATOMIC_TOKEN_AMOUNT"
            }
          }
        ]
      }
    }
  }
}
```

The placeholder addresses must be replaced. The default
`https://x402.org/facilitator` is testnet-only and is not a production
settlement choice.

The scaffold requires explicit `{asset, amount}` atomic-unit prices instead of
`"$0.01"` strings. This makes signed price advertisements deterministic and
allows the config validator to reject identical payment tuples on two routes.

## Discovery

An enabled Node relay advertises:

```json
{
  "features": ["x402-v2"],
  "x402": {
    "version": 2,
    "prices": "/.well-known/x402-prices",
    "servicePrefix": "/svc/"
  }
}
```

The price manifest is relay-signed under the domain
`hiverelay.x402-prices.v1`. It exposes service, HTTP method, path, unit, proof
type, side-effect class, network, asset, atomic amount, and `payTo`.

This local manifest is complementary to x402 Bazaar. Bazaar is useful for broad
agent discovery, but it must not become the relay-selection trust root. A
client should verify the relay signature, apply its own roster/reputation
policy, and treat listing text as untrusted metadata.

## Security posture

The canary includes:

- default-off configuration;
- Node HTTP only; Bare and relaykernel do not advertise the facade;
- exact `/svc/*` allowlisting;
- official x402 v2 verification and settlement code;
- explicit atomic token prices;
- rejection when two routes reuse the same scheme/network/recipient/asset/amount
  tuple;
- duplicate `PAYMENT-SIGNATURE` rejection;
- a bounded in-memory single-use claim store keyed by the payment header;
- claim-before-service execution to stop concurrent duplicate grants;
- `Cache-Control: no-store, private` on challenges and paid responses;
- CORS allow/expose rules for only the x402 headers;
- mandatory idempotency keys for configured write routes;
- relay-signed price manifests;
- no implicit conversion of a payment into relay-admin authority.

These controls respond directly to the current research findings around
settlement timing, replay, resource binding, header/proxy confusion, caching,
and discovery steering.

## Important residual risks

This is a scaffold, not a production payment claim.

1. **Execution and payment are not atomic.** The official flow verifies,
   executes the service, then settles. A settlement failure can leave an
   executed-but-unpaid operation. The canary therefore starts with a read-only
   proof operation. Paid writes require service-level idempotency and a
   reconciliation policy.

2. **The local claim store is not durable.** It blocks concurrent and
   same-process replay. It does not survive restart. Before paid writes, move
   claims and settlement receipts to an append-only durable ledger with atomic
   claim semantics.

3. **Resource binding is indirect.** Exact EVM transfer authorization does not,
   by itself, give HiveRelay a general cryptographic request-body binding. The
   canary rejects duplicate payment tuples across routes so an authorization
   accepted for one configured route cannot match another. A future
   HiveRelay/x402 extension should bind route, canonical body digest, quote id,
   and idempotency key.

4. **Facilitator trust and availability remain.** A hosted facilitator sees
   payment metadata and can refuse, delay, or misreport according to its trust
   model. Production should support at least one self-hosted or independently
   operated facilitator path and record the exact facilitator used in
   reconciliation evidence.

5. **Payments reduce privacy.** Public-chain settlement links payer, recipient,
   asset, amount, and timing. x402 is the liquidity rail, not the privacy rail.
   Cashu/Lightning remains the appropriate parallel option for privacy-focused
   users.

6. **No production facilitator authentication is wired.** The official testnet
   facilitator needs no credentials. CDP and other production facilitators have
   provider-specific authentication/configuration that must be added without
   persisting secrets in public relay config or manifests.

7. **No stock-client canary evidence exists yet.** X4-G1 still requires an
   external x402 v2 client and funded test wallet completing a call against a
   real relay.

8. **No wallet reconciliation exists yet.** X4-G3 requires a durable
   one-to-one mapping among claim id, service receipt, `PAYMENT-RESPONSE`,
   transaction hash, and operator-wallet credit.

9. **Transaction counts are not demand evidence.** Recent population research
   shows x402 counts can be heavily manufactured or internally clustered. The
   product gate should be independent paying operators/bots, retained use, and
   net settled value—not raw calls.

10. **Legal review remains a release gate.** Operator receipts, tax treatment,
    sanctions/KYT behavior, refunds, and money-transmission analysis depend on
    deployment and jurisdiction. This document makes no legal conclusion.

## Canary gates

The original X4 gates should be sharpened:

- **X4-G0 — static:** config invalidity fails closed; duplicate tuples rejected;
  no paid route exists by default.
- **X4-G1 — stock client:** official `@x402/fetch` or `@x402/axios`, with no
  HiveRelay code, completes `vrf.prove` on Base Sepolia.
- **X4-G2 — negatives:** duplicate header, replay, underpayment, wrong asset,
  wrong recipient, wrong network, expiry, and facilitator outage do not execute
  the service.
- **X4-G3 — reconciliation:** claim, service result digest, settlement response,
  transaction, and wallet credit reconcile one-to-one across restart.
- **X4-G4 — first write:** one idempotent `mailbox.send` implementation survives
  lost HTTP responses, duplicated retries, settlement failure, and restart
  without duplicate delivery.
- **X4-G5 — two operators:** the canary passes with two independently operated
  relays and separately controlled recipient wallets/facilitators.

No “payments GA” language should ship before X4-G1 through X4-G5.

## Implementation map

```text
packages/core/incentive/x402/config.js
  strict config, route allowlist, unique payment tuples, SDK route compiler

packages/core/incentive/x402/claim-store.js
  bounded in-memory single-use payment claims

packages/core/incentive/x402/price-manifest.js
  domain-separated signed price advertisement

packages/core/incentive/x402/service-facade.js
  official SDK initialization, verify -> dispatch -> settle flow

packages/core/core/relay-node/api-x402.js
  HTTP route resolution and service-router handoff

packages/core/core/relay-node/api.js
  CORS/header handling and `/svc/*` mount
```

## Validation

Focused unit coverage exercises:

- default-off behavior;
- strict config and unsafe-write rejection;
- duplicate cross-route payment-tuple rejection;
- signed price manifest and tamper detection;
- Node-only capability advertisement;
- 402 before body parsing/service work;
- public CORS preflight with only the x402 payment headers;
- verified execution and settlement response;
- query-parameter forwarding for paid `GET` service routes;
- replay rejection before a second service execution;
- mandatory idempotency key for write routes.

Run:

```sh
./node_modules/.bin/brittle-node --timeout 120000 \
  test/unit/api-x402.test.js \
  test/unit/x402-config.test.js \
  test/unit/x402-price-manifest.test.js \
  test/unit/x402-service-facade.test.js
```

## Primary sources

- x402 Foundation, protocol repository and specification:
  <https://github.com/x402-foundation/x402>
- x402 v2 HTTP headers:
  <https://docs.x402.org/core-concepts/http-402>
- x402 seller integration and Bazaar extension:
  <https://docs.x402.org/getting-started/quickstart-for-sellers>
- x402 networks, tokens, and facilitator support:
  <https://docs.x402.org/core-concepts/network-and-token-support>
- Coinbase x402 v1-to-v2 migration guide:
  <https://docs.cdp.coinbase.com/x402/migration-guide>
- Li, Wang, and Wang, *Five Attacks on x402 Agentic Payment Protocol*
  (preprint, 2026): <https://arxiv.org/abs/2605.11781>
- Li et al., *A402: Binding Cryptocurrency Payments to Service Execution for
  Agentic Commerce* (preprint, 2026): <https://arxiv.org/abs/2603.01179>
- Qin et al., *How Agentic Is Agentic Commerce?* (preprint, 2026):
  <https://arxiv.org/abs/2607.12575>
