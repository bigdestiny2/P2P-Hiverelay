# The Service Contract — what ships on app releases vs relay releases

**Status:** ratified 2026-07-08, after peerit's launch week generated a string of
relay work items and forced the question: *do app releases require HiveRelay
updates?* They must not. This page is the triage rule that keeps it that way.

## The principle

HiveRelay nodes are **generic infrastructure**; services (outboxlog, shard-store,
poker, notify) are mounts, and apps ride them under namespaces. The relay owns
**plumbing**; the app owns **meaning**. An app must be able to ship features and
fixes on its own cadence, against the fleet as it exists today — fleet boxes
(including Umbrel/StartOS appliances we do not operate) update on *their* cadence,
so a fleet update can never be a prerequisite for app health.

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

- **The wire surface is a stable, additive contract.** For outboxlog:
  `POST /api/token`, `POST /api/sync/{create,join,append,heads}`,
  `GET /api/sync/{range,count,get}`, `GET /api/directory`,
  `POST /api/swarm/{join,send}`, `GET /api/swarm/events`, and the enumerated
  operator admin routes (`/api/admin/{takedown,restore,takedowns,sweep}`).
  New capabilities are added, never changed in place; clients feature-detect and
  degrade gracefully against older relays. Deprecations get long windows.
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
