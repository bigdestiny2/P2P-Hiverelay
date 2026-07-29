# Blind ecosystem migration matrix

**Status:** checked inventory and rollout contract; not deployment or deletion
authorization.

The machine authority is
`deploy/blind/ecosystem-migration-matrix.json`. Its verifier is
`scripts/verify-blind-ecosystem-migration.mjs`. The JSON deliberately contains
no readiness, approval, cutover or deletion booleans. Those decisions are
computed from live code-owned blockers, the legacy-retirement policy and a
separate parity authority for every application and legacy component.

## Boundary that must not drift

| Boundary | May do | Must not be described as |
| --- | --- | --- |
| Blind relay base | `DESCRIBE`, `CELL`, `INBOX`, `CORE`, `FORWARD`; generic admission, leases, storage, streams and accounting | An app backend, semantic index, compute provider, moderation service or operator admin API |
| Application/client | Hold keys and plaintext; define schemas, signatures, reducers, graphs, feeds, moderation and policy | A relay-provided semantic service |
| Nonblind provider | Process inputs the user explicitly sends to a named AI, payment, mobility, push, media, automation, sports, CI or trust provider | Blind merely because traffic reached it through `FORWARD` |
| Nonblind index | Index public or explicitly disclosed content and queries | Part of the blind relay base |
| Operator control | Administer releases and account for generic resource classes on a private interface | A public application data plane |

`DESCRIBE` is capability discovery only. It does not become an application
registry. Application catalogs are signed application data carried over `CORE`
and interpreted by clients.

## Primitive mapping

- `CELL` stores fixed-class opaque immutable content such as encrypted media,
  snapshots, manifests or chunks.
- `INBOX` accepts bounded sealed frames addressed by a capability. Applications
  define what a frame means.
- `CORE` mirrors or serves authorized append-only streams. Applications own
  record schemas, signatures, reducers and forks.
- `FORWARD` is ephemeral bounded transport. A remote compute, payment, search or
  media endpoint remains a disclosed nonblind provider.

## Application delivery inventory

All rows retain identity, schemas, authorization and business semantics in the
application. “Outside base” means a separately disclosed optional dependency,
not a HiveRelay feature.

| Application | Blind families | Retained application concern | Outside base |
| --- | --- | --- | --- |
| Peerit | CELL, INBOX, CORE, FORWARD | Social graph, posts, votes, moderation, ranking, offline outbox | Client index; optional semantic index |
| P2PBuilders | CELL, INBOX, CORE, FORWARD | Builder/project graph and discussion | Client index; optional semantic index |
| Pearfeed | CELL, INBOX, CORE | Authors, subscriptions, ranking and moderation | Client index; optional semantic index |
| Bazaar | CELL, INBOX, CORE, FORWARD | Listings, offers, orders, reputation and disputes | Search, settlement and arbitration providers |
| Exchange | CELL, INBOX, CORE, FORWARD | Markets, matching, risk and settlement intent | Settlement and arbitration providers |
| Rides | CELL, INBOX, CORE, FORWARD | Dispatch workflow, trip state, reputation and safety | Mobility, settlement and arbitration providers |
| Stays | CELL, INBOX, CORE, FORWARD | Availability, booking, reviews and disputes | Search, mobility, settlement and arbitration providers |
| Comms | CELL, INBOX, CORE, FORWARD | Membership, message encryption, signaling and retention | Optional media and native-push providers |
| Dealroom | CELL, INBOX, CORE, FORWARD | Membership, proposals, approvals and audit policy | Arbitration and media providers |
| Home | CELL, INBOX, CORE, FORWARD | Device identity, automation policy and command authorization | Paired device/automation provider |
| OpenClaw | CELL, INBOX, CORE, FORWARD | Agent identity, tools, jobs, artifacts and audit history | Automation and AI providers |
| POS | CELL, INBOX, CORE, FORWARD | Catalog, basket, inventory, receipts and refunds | Settlement provider; client index |
| Sahifa | CELL, INBOX, CORE | Publications, editions, subscriptions and editorial policy | Client/search index; native push |
| Sanduq | CELL, INBOX, CORE, FORWARD | Vault, keys, recovery and access policy | Arbitration/recovery provider |
| Tickets | CELL, INBOX, CORE, FORWARD | Issuance, transfer, admission and refund policy | Settlement and verification providers |
| Matchday Mesh | CELL, INBOX, CORE, FORWARD | Match participants, events and moderation | Sports-data and media providers |
| PearPaste | CELL, INBOX, CORE | Encryption, expiry, capability sharing and versions | None required |
| PearTube | CELL, INBOX, CORE, FORWARD | Channels, playback, comments and moderation | Search and optional media providers |
| Ultimate Sports | CELL, INBOX, CORE, FORWARD | Teams, scores, communities and rankings | Sports-data and index providers |
| PearCup | CELL, INBOX, CORE, FORWARD | Tournaments, fixtures, rules and matchmaking | Optional sports-data provider |
| Hiveworm | CELL, INBOX, CORE, FORWARD | Sessions, moves, leaderboards and anti-cheat policy | None required |
| pear-registry | CELL, CORE | Publishers, package names, versions and release policy | Client catalog/index; optional search |
| OpenGit | CELL, INBOX, CORE, FORWARD | Repositories, refs, reviews, permissions and merges | Optional Git/CI provider; client index |
| anonGPT | CELL, INBOX, CORE, FORWARD | Conversation encryption, model/tool policy and retention | Explicit AI provider |
| Platforms | CELL, INBOX, CORE, FORWARD | Platform manifests, membership, workflows and views | Client catalog/index; optional search |

## Legacy relay component disposition

| Legacy component | Target | Retained outside generic relay | Removal rule |
| --- | --- | --- | --- |
| Service plugin plane | FORWARD plus explicit providers | Provider lifecycle and domain-specific processing | Externalize, then G8 drain |
| OutboxLog | CORE, CELL, INBOX | App signatures, reducers, ordering and offline authoring | Migrate state, compare, restore, then drain |
| WitnessLog / RepairTicket | CORE, CELL, INBOX plus external witness | Selection, adjudication and repair policy | Migrate with independent witness evidence |
| Shard/custody | CELL | Client encryption, dispersal and replica policy | Migrate content/proofs; no “unseed means erasure” claim |
| Seed/storage/gateway | CORE and CELL | Publisher manifests and authorization | Mirror/pin parity and recovery before drain |
| Catalog/federation/index | Application CORE plus client/nonblind indexes | Catalog semantics and search | Externalize; keep DESCRIBE generic |
| Notify | INBOX plus disclosed push bridge | Notification meaning and native provider payload | Externalize push and prove retry/revocation parity |
| Poker | CORE, INBOX, FORWARD | Tables, moves, game crypto and reducers | Move all table semantics into the app |
| AI/identity/schema/SLA/ZK/arbitration/VRF | FORWARD plus explicit provider SDKs | Every provider contract and proof meaning | Remove from base after provider-boundary parity |
| Legacy circuits | FORWARD | End-to-end session protocol | Adapt limits/backpressure and drain old frames |
| Edge transports | Blind edge adapters | Route choice and accurate metadata/anonymity claims | Adapt and retain |
| Legacy client/verifier | `packages/blind-client` | Application keys and interpretation | Cross-runtime migration, then retire imports |
| Operator control/economics | Private operator-control plane | Administration and generic resource economics | Isolate and retain; never publish as app plane |
| Peerit legacy plane | All four families plus Peerit substrate | All social semantics and offline publishing | Peerit parity, migration/clean genesis, rollback and G8 drain |

## Executable authorization model

The verifier combines four independent blocker layers:

1. Live protocol, IPC, browser-client, production runtime and family-store
   blocker arrays.
2. G0–G8 evidence authorities from the legacy-retirement verifier.
3. A code-owned application-specific semantic-parity blocker for every app.
4. A code-owned component-specific migration-parity blocker for every legacy
component.

G0 explicitly consumes the CELL, INBOX and CORE storage blocker authorities in
addition to the wire, IPC, browser-client and production-build authorities. A
store-format publication blocker therefore cannot disappear from the authority
freeze merely because another source happens to use the same blocker code.

The current result is intentionally all red: none of the 25 application
cutovers, 14 legacy-component cutovers or 14 legacy removals is authorized.
That is a truthful migration inventory, not a launch failure. Rows become green
only when their code-owned parity authority and every shared gate they require
are replaced by qualifying evidence.

Report digests and content hashes emitted by the verifier or its supporting
labs are unkeyed checksums, not signatures. They establish byte equality only
relative to an already trusted expected digest. They do not authenticate an
operator, report origin, capture time or deployment. Any release claim must
instead verify a signed manifest that binds the checksum together with the
trusted signer, release sequence, freshness and rollback floor.

This prevents a shared green test, a signed roster, or an edited manifest from
silently authorizing every consumer. Each row needs its own executable evidence
authority. Removal additionally requires the complete legacy-retirement policy,
including observed zero traffic under G8.

```sh
# Inspect the computed report. A zero exit status means the matrix is valid,
# not that cutover or deletion is authorized.
npm run verify:blind-ecosystem-migration

# Release gates: these intentionally exit non-zero while evidence is missing.
npm run verify:blind-ecosystem-migration:strict-cutovers
npm run verify:blind-ecosystem-migration:strict-removals

# The related legacy-retirement report has the same inspect/strict split.
npm run verify:blind-retirement
npm run verify:blind-retirement:strict

# Focused structural, tamper and fail-closed tests.
./node_modules/.bin/brittle test/unit/blind-ecosystem-migration.test.js
```

## Rollout order

1. Inventory every live import, route, persisted record and operator dependency.
2. Build app-owned adapters without changing the live default.
3. Shadow-read or deterministically replay accepted logical state.
4. Exercise privacy, retry, crash, capacity and provider-failure cases.
5. Canary across independently administered operators.
6. Cut over only the row whose computed evidence is green.
7. Retain export and rollback while legacy traffic drains.
8. Remove a legacy component only after its G8 window is observed and the
   strict removal assertion succeeds.

The matrix therefore supports incremental migration. It does not require a
flag-day replacement, and it cannot be used to disguise an untested rewrite as
a production-ready deployment.
