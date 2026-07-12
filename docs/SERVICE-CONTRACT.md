# The Service Contract — what ships on app releases vs relay releases

**Status:** ratified 2026-07-08, after peerit's launch week generated a string of
relay work items and forced the question: *do app releases require HiveRelay
updates?* They must not. This page is the triage rule that keeps it that way.

## The principle

HiveRelay is moving from one historical contract to one replacement contract:

1. The published `ServiceProvider` compatibility plane hosts application-aware services such as
   OutboxLog, shard-store, poker, and notify. Those services may use namespaces,
   schemas, or service-specific RPC and must state their actual visibility. It is
   frozen as a separately built, signed, sunset-bounded compatibility product;
   it is not extended into the replacement.
2. The strict blind substrate is the replacement app-serving product. It is an
   isolated edge plus daemon with only the
   `DESCRIBE`, `CELL`, `INBOX`, `CORE`, and `FORWARD` families. It receives no app
   registration or namespace and never loads the service registry. Its canonical
   contract is the [blind master specification](protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md).

During migration the same ownership rule applies, but only the blind contract is
the long-term substrate: the relay owns **plumbing** and the app owns **meaning**. Once a
versioned generic wire is deployed, an app must be able to ship features and
fixes on its own cadence against compatible fleet boxes—including independently
operated Umbrel/StartOS appliances—without an app-specific relay update.

The test for any proposed change:

> **Would any tenant need this, or does it only make sense because of how one app
> behaves?** Any-tenant → relay-side. One-app → app-side, full stop.

## Ownership table

| Ships on **app** releases (any cadence) | Ships on **relay** releases (rare, versioned) |
|---|---|
| Schema, record types, semantic keys | Resource lifecycle: caps, GC/sweep, TTLs |
| Signatures, verification, merge rules | Transport policy: rate limits, CORS, auth plumbing |
| Rosters (relay/shard membership is an app-side signed pointer) | Persistence: journal, snapshots, checkpointing |
| Identity lifecycle, boot strategy, caching, retry/failover | Takedown *mechanics* (serve-time suppression, content-blind) |
| Read patterns and their optimization | Wire-contract versioning (stable, additive) |
| UI, UX, anything about *meaning* | Anything about *plumbing* |

Corollaries:

- **Each wire surface is a stable, versioned contract.** Legacy OutboxLog uses:
  `POST /api/token`, `POST /api/sync/{create,join,append,heads}`,
  `GET /api/sync/{range,count,get}`, `GET /api/directory`,
  `POST /api/swarm/{join,send}`, `GET /api/swarm/events`, and the enumerated
  operator admin routes (`/api/admin/{takedown,restore,takedowns,sweep}`).
  This surface is frozen for signed migration compatibility rather than expanded.
  Its deadlines and supported predecessor set come only from the non-extendable
  compatibility sunset chain.
  These routes are not the strict blind ABI: they expose app-aware OutboxLog
  concepts and remain only a migration path in the separate compatibility artifact.
- **The strict blind wire has no app namespace.** Its one-route-per-family binary
  ABI, hashes, vectors, admission, isolation, and release gates are maintained
  beside the [implementation specification](protocol/BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md).
  Adding an app changes only its encrypted client profile.
- **Apps treat the relay as an untrusted pipe.** Every record is verified
  client-side (signature, key-binding, PoW), so a relay can withhold or go stale
  but never forge — which is exactly what makes relay updates operationally
  invisible to apps, and app-side caches/CDNs safe (a cache cannot lie to a
  verifying client).
- **The first tenant at scale exposes relay gaps. That is shakedown, not
  coupling.** Fix the gap generically, once; the second tenant should hit
  approximately none of them.

## Worked examples (peerit launch week, 2026-07)

| Item | Side | Why |
|---|---|---|
| Lazy identity, device-tier key store, cache-poisoning fix, instant boot, retry/failover | **App** | Meaning + client strategy. All shipped on peerit.site with zero relay involvement. |
| Browser CORS preflight (v0.24.2) | **Relay** | Any browser tenant needs it. |
| Ghost-outbox sweep + descriptor prune (#184) | **Relay** | Resource lifecycle. Any tenant — buggy or malicious — can leak empty groups until the cap 503s every new author; a leased-resource service without reclamation is incomplete. peerit's churn bug *exposed* the gap; it did not create the need. |
| Rate-limiter shape (read-path exemption; not counting rejected requests) | **Relay** | Generic transport policy. Optional for peerit's health post-client-fix; rides whatever release the relay ships for its own reasons. |
| `GET /api/boot` (cold-boot bundle) | **Rejected** | An app-shaped read pattern pushed into the relay — the canonical violation. Withdrawn; if boot cost matters again, the app-side answer is a verify-client-side cache/CDN in front of the existing read surface. |

## How to use this page

When a work item shows up with a relay-side implementation attached, run the
test question before writing code. If the honest answer is "only this app needs
it," the item goes back to the app team — usually there is a client-side design
(cache, snapshot, retry, roster) that ships the same value without touching the
fleet. If the honest answer is "any tenant," build it generically, namespace-
agnostic, and land it on the relay's own release train without app deadlines
attached.
