# Hiverelay - Security Boundary Alignment (2026-06-23)

This note cross-checks the current threat/security docs against concrete code
boundaries. It is a Level 1 security alignment artifact with one narrow Level 2
test fix captured in the same loop.

## Executive Read

`docs/THREAT-MODEL.md` remains broadly aligned with the current code. The core
security thesis is still honest: Hiverelay reduces trust through append-only
data, signed metadata, replica diversity, cross-client verification, and named
residual risks. The current code has real guardrails for management API auth,
HTTP dispatch boundaries, P2P service restrictions, capability docs, quorum
selection, fork quarantine, verifier checks, relay exposure policy, and swarm
firewalling.

The docs should keep preserving the distinction between shipped guardrails,
partial mitigations, and M2/future work. In particular, supply-chain hardening,
Sybil defense, cryptographic geographic attestation, full Operator Score, and
external release-store proof remain open or partial. Do not flatten these into
"done" language.

## Code Boundary Map

| Boundary | Code / artifact | Current alignment |
|---|---|---|
| Management API auth | `packages/core/core/relay-node/api.js` `_checkAuth`, `_isLocalRequest`, `_requireAuth` | Aligned. API key uses exact bearer-token match. Without an API key, localhost fallback requires socket, host, and origin to be loopback. `trustProxy` disables localhost fallback. |
| HTTP body gate | `packages/core/core/relay-node/api.js` POST content-type gate | Aligned. POST bodies must be `application/json`; chunked or non-JSON requests are rejected before route handling. |
| HTTP dispatch boundary | `packages/core/core/relay-node/api.js` `/api/v1/dispatch` | Aligned. Dispatch requires auth, marks calls as `caller: 'remote'`, and keeps local-only routes behind local request checks. |
| P2P service RPC boundary | `packages/core/core/services/protocol.js` | Aligned. `RESTRICTED_METHODS` blocks sensitive remote service calls, per-peer rate limiting is present, and router dispatch receives `transport: 'p2p'`, `caller: 'remote'`, role, and auth context. |
| Quorum diversity | `packages/core/core/quorum-selector.js`, `packages/client/index.js` | Aligned. Default selection optimizes distinct region/operator tuples and surfaces diversity warnings. A stale integration test was fixed to expect `insufficient-quorum-diversity` when both region and operator floors are missed. |
| Fork detection and quarantine | `packages/core/core/fork-detector.js`, `packages/client/index.js` | Aligned. Divergent evidence is persisted, unresolved forks quarantine drives, forced bypasses are logged, and client quorum comparison can record fork evidence. |
| Cross-client verification | `packages/verifier/index.js` | Aligned. Standalone verifier avoids depending on the main package, compares capability docs/catalogs/drives, and rejects mismatched anchor proofs for the requested drive. |
| Anchor proof verification | `packages/core/core/anchor-proof-verifier.js` | Aligned. Proofs bind app key, relay pubkey, timestamp, anchored flag, and Ed25519 signature, with optional freshness and expected-pubkey checks. |
| Relay exposure policy | `packages/core/core/policy-guard.js` | Aligned as a guardrail. Public/local-first/p2p-only exposure rules fail closed by suspending violating apps. |
| Swarm admission / DoS guard | `packages/core/core/relay-node/swarm-firewall.js` | Aligned. Hyperswarm firewall composes allowlist, blocklist, per-IP rate limits, and optional reputation threshold before Protomux allocation. |
| Device pairing allowlist | `packages/core/core/relay-node/access-control.js` | Aligned at design level. Pairing is time-limited, one-shot by default, token comparisons use timing-safe equality, and persisted allowlist files are chmod `0600`. |

## Doc Alignment Notes

- `docs/THREAT-MODEL.md` is the best canonical security summary. Its "How this
  maps to current code" table correctly keeps several items as partial or open:
  Operator Score, Sybil defense layers, cryptographic geographic attestation,
  federated reputation aggregation, and TEE/HSM deletion.
- `docs/AUDIT-ROADMAP.md` accurately says broad route/fault coverage,
  RelayNode/API decomposition, and service protocol v2 compact encoding remain
  open tracks.
- `docs/SECURITY-STRATEGY.md` is now framed as a strategy tracker rather than a
  release proof artifact. The older immediate-commit wording was replaced with
  current shipped-control language, and M2/future items remain visibly separate
  from implemented guardrails.
- `docs/CRYPTO-GUARANTEES.md` now keeps confidentiality claims scoped to
  blind-mode apps and atomic custody payloads. Non-blind/public content is
  described as readable by the relay operator, with signatures and
  availability diversity providing integrity and resilience rather than
  confidentiality from the relay.
- External proof gaps remain outside this local security alignment loop:
  official Umbrel PR/reviewer evidence, StartOS registry evidence, live fleet
  convergence, and current generated release sidecars.

## Level 2 Fix Applied

`test/unit/client-quorum-fork-integration.test.js` had a stale assertion for
the warning reason emitted by `selectQuorum`. The fixture uses two relays in
the same region and under the same operator, so current behavior correctly
emits `insufficient-quorum-diversity`, not the older
`insufficient-region-diversity` expectation.

## Validation

Passed after the security-doc cleanup pass:

```bash
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/capability-endpoints.test.js \
  test/unit/api-auth.test.js \
  test/unit/api-ui-token.test.js \
  test/unit/api-trustproxy-auth.test.js \
  test/unit/protocol-security.test.js \
  test/unit/swarm-firewall.test.js \
  test/unit/policy-guard.test.js \
  test/unit/verifier.test.js \
  test/unit/quorum-selector.test.js \
  test/unit/client-quorum-fork-integration.test.js \
  test/unit/fork-detector.test.js
```

Result: 208/208 tests passed, 701/701 assertions passed.

```bash
npm run lint
```

Result: passed.

## Follow-Up Edge

The local security-doc cleanup pass has landed. Remaining proof gaps are
external: official Umbrel PR/reviewer evidence, StartOS registry evidence,
live fleet convergence, and current generated release sidecars.
