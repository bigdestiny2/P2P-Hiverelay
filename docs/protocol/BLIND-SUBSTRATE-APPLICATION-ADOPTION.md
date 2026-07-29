# HiveRelay Blind Substrate — Application Adoption Contract

**Status:** implementation companion; subordinate to the master protocol and
canonical ABI registry

**Date:** 2026-07-11

**Applies to:** every application adopting `hiverelay-blind/1`, including Peerit

This document fixes the boundary between the replacement HiveRelay product and
the applications it serves. HiveRelay replaces its app-aware application-serving
runtime with the blind substrate. It does not replace an application's data
model, signatures, merge rules, moderation, ranking, user interface, identity,
or recovery policy. Those remain client-side application responsibilities.

Peerit is the first full consumer profile, not a privileged service or relay
plugin. A later application adopts exactly the same public protocol and client
SDK without asking an operator to add a namespace, endpoint, process, schema,
metric label, storage partition, key, or allowlist entry.

The normative protocol is
`BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md`. The implementation boundary is
`BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md`. If this guide conflicts with either
document or the executable registry, the protocol, implementation specification,
and registry win in that order.

---

## 1. Replacement boundary

The final system has one generic relay product and any number of independent
client profiles:

```text
application model/signatures/merge/UI
                 |
       application-side adapter
                 |
       @hiverelay/blind-client
                 |
     canonical hiverelay-blind/1 WIRE
                 |
 generic blind-edge + blind-daemon on each operator relay
```

The relay distribution contains no application adapter. An adapter is ordinary
client code packaged with its application. It converts the application's already
signed records and local state into opaque payload bytes, selects generic
substrate compositions, retains the capabilities needed to retrieve them, and
validates/decrypts the results.

The old OutboxLog, BlindShard, Notify, semantic service, and plugin paths are not
alternate native modes. They may exist only in a separately built and signed,
time-bounded compatibility product while consumers migrate. A clean strict
HiveRelay install serves applications only through the blind substrate.

This replacement is deliberately asymmetric:

- HiveRelay operators upgrade once to the generic substrate.
- Peerit replaces its network and persistence composition with its signed
  substrate profile.
- Other applications migrate when ready by shipping their own client adapter.
- No application migration requires another relay deployment or operator action.

---

## 2. What every application keeps

An application MUST retain authority over:

- canonical record encoding and application signature domains;
- identity, account recovery, device authority, and key rotation;
- immutable IDs, causal links, graph edges, merge and conflict rules;
- moderation, trust, ranking, search, materialized views, and user-visible state;
- capability distribution and revocation policy;
- replica selection, operator-diversity policy, repair, and availability floors;
- local intent journaling, ambiguous-write reconciliation, and retry identity;
- release pins, migration cutoffs, downgrade prevention, and advisory UI states;
- encryption and padding before any application bytes cross the substrate API.

The substrate MUST NOT infer or implement those rules. A relay receipt proves a
bounded generic operation happened; it never proves that a post, vote, account,
message, graph edge, or application state is valid.

---

## 3. What every relay provides

A conforming relay MAY advertise only the closed generic roles and operations in
the canonical ABI. In practical terms it provides:

- fixed-class immutable ciphertext cells with create, get, prove, renew, drop,
  and bounded batch operations;
- bounded opaque inbox frames for capability-created rendezvous compositions;
- encrypted Hypercore availability through the canonical Blind Core profile;
- generic discovery descriptors, admission, receipts, durability evidence, and
  proofs;
- transport adapters carrying the same canonical messages directly or through
  split/Tor privacy profiles; and
- bounded opaque forwarding without parsing an application destination or
  payload.

The relay sees only fields the public ABI permits. It MUST NOT receive an app ID,
app namespace, author key, content type, community, graph field, semantic key,
moderation action, search term, or application-specific retention class.

The relay remains entitled to enforce generic byte, time, concurrency, lease,
admission, and abuse bounds. App-blind does not mean unmetered.

---

## 4. Minimal adapter contract

There is intentionally no relay-side adapter API. The minimal client-side
contract is byte-oriented:

1. Encode and sign one application object using the application's own canonical
   format.
2. Select a generic representation: one cell, a cell capability chain, a bounded
   inbox frame, or an encrypted Core slice.
3. Encrypt and pad through `@hiverelay/blind-client` before transport.
4. Persist the exact logical intent and generated capabilities locally before a
   possibly committing request is sent.
5. Dispatch the canonical request to a descriptor-pinned relay endpoint.
6. Verify the canonical response, relay signature, descriptor binding, request
   commitment, lease/durability evidence, and returned ciphertext.
7. Decrypt locally, validate the application signature and identity rules, then
   apply the application's merge function.
8. Repair to client-selected independent relay identities without reusing
   per-relay write capabilities or ciphertext when the profile forbids it.

Any byte producer can use the minimal cell API without registering itself. More
advanced applications can build reusable local modules around the same boundary,
but those modules MUST remain outside the relay distribution.

### 4.1 Capability ownership

The application is responsible for durably storing and protecting read, renew,
and drop capabilities. A relay never receives decryption keys. A public
application may deliberately distribute read material to all readers; that does
not make the storage request or relay state semantic.

Create, renew, and drop authority MUST use distinct key material. Per-relay
replicas MUST use independently generated capability keys and randomized
ciphertext as required by the selected profile. An adapter MUST NOT turn an
application identity key into a storage management key.

### 4.2 Write lifecycle

An adapter MUST make a valid signed application event locally durable and visible
without waiting for a relay, release service, discovery service, operator registry,
replica threshold, or maintainer. It models publication as separate state machines,
not as a single fetch or a centralized write gate:

```text
DRAFT_LOCAL -> IDENTITY_COMMITTED -> INNER_EVENT_SIGNED
            -> INTENT_JOURNALED -> LOCAL_VISIBLE

per relay target:
  PREPARED -> SENT -> ACKNOWLEDGED | PENDING_UNKNOWN -> READBACK_VERIFIED

durability:
  replica counts -> independently evidenced labels -> repair

discovery:
  QUEUED -> inbox acknowledged and/or optional index observed
```

A transport timeout after send is ambiguous. The adapter reconciles the exact
request identity before attempting a replacement operation. It MUST NOT silently
create a second logical application event. Zero reachable relays leaves the
publication intent queued; one compatible unregistered relay is enough to record
one remote replica. Replica diversity changes only durability and repair labels,
not content validity or local visibility.

Offline operation, admission pressure, relay loss, and discovery failure are
retryable delivery conditions. Only an intrinsic codec or cryptographic
incompatibility can make a locally signed event non-sendable. A strict privacy
profile queues rather than silently downgrading; a user may explicitly authorize
a documented downgrade without changing the application event identity.

### 4.3 Read lifecycle

Relay bytes are untrusted. A reader verifies the generic response and ciphertext
binding, decrypts locally, then independently validates the application record.
Malformed, forged, stale, forked, or unauthorized application bytes are rejected
by the adapter even when the relay operation and receipt are valid.

---

## 5. Mapping old app-aware services

| Old pattern | Replacement composition | New authority owner |
| --- | --- | --- |
| App/author OutboxLog | Encrypted Core or capability-linked cells | Application client |
| BlindShard cohort | Independently randomized cell replicas selected by client policy | Application client |
| Notify topic/service | Generic opaque Inbox plus encrypted app-side rendezvous | Application client |
| Semantic relay index | Local materialized index over verified application records | Application client |
| App namespace/relay plugin | None; only canonical generic operations | Not applicable |
| Global app relay URL | Optional signed recommendations for independent relay descriptors/discovery roots | Application client/bootstrap publisher |
| Relay-side repair | Client-composed prove/read/put/renew across selected relays | Application client |
| Relay majority as truth | Application signatures, causal merge, and witnessed floors | Application protocol |

There is no universal `outbox.peerit.site` storage service shared internally by
all operators. Each operator exposes its own signed generic relay descriptor and
endpoint. An application domain may publish optional bootstrap recommendations
and signed release artifacts, but those are neither relay membership nor content
authority. The domain does not proxy, own, or collapse the independent relay
identities into one trusted backend. A compatible relay discovered by another
authenticated route remains usable without appearing in an application list.

---

## 6. Adoption levels

### 6.1 What can and cannot be adapted blindly

An application can adopt the substrate wherever its relay dependency is generic
availability or transport: opaque persistence, rendezvous, encrypted append
streams, replica repair, discovery, and bounded forwarding. The application may
change its own client profile and data model without changing a relay.

This contract does **not** turn application-specific server computation into a
blind service merely by encrypting its input. A relay that must understand a
search query, moderation rule, game transition, AI prompt, application schema,
or recipient identity is outside the strict blind product. Such a feature must
take one of these explicit paths:

1. move the decision and indexing into the verifying client while relays store
   only opaque inputs/checkpoints;
2. express it as an already frozen, genuinely application-independent primitive
   whose leakage and proof contract are the same for unrelated applications; or
3. remain a separately released non-blind product with accurate visibility and
   trust claims.

A proposed new relay primitive is not generic merely because two applications
could call it. It needs a closed canonical ABI, independent conformance fixtures,
bounded resource/admission semantics, a published metadata view, and no app
identifier, schema, plugin, or operator registration. It must not be smuggled in
through a consumer profile or encrypted field whose relay-side interpretation is
known only to one application.

Applications can migrate in bounded, testable increments. Levels describe client
capability, not different relay modes.

### Level 1 — Opaque cells

The app stores and retrieves fixed-class encrypted cells through direct
transport. This proves schema independence and eliminates semantic relay state,
but direct endpoints still observe source/network metadata and access patterns.

### Level 2 — Durable client composition

The app adds independent replicas, signed relay discovery, durable intent,
ambiguous-write reconciliation, prove/readback, repair, leases, rollback floors,
and operator-diversity policy.

### Level 3 — Discovery and streaming

The app composes generic Inbox for encrypted rendezvous and Blind Core for
encrypted append/replication where those fit its data model. The relay remains
unaware of the application and record types.

### Level 4 — Privacy transport

The app offers descriptor-verified split transport and/or Tor. Privacy claims are
enabled only when their exact non-collusion, capture, downgrade, latency, and
conformance gates pass. Direct opaque transport is blind storage, not anonymity.

A public launch claiming durable decentralized operation MUST meet the levels and
replica policy named by its own signed release profile. It cannot present a lower
level as a completed higher-level promise.

---

## 7. Required conformance evidence

Before an adapter can call itself production-ready it MUST prove, using its final
bundle and pinned ABI:

1. Known application sentinels never appear in public request frames, private IPC,
   relay WAL, checkpoints, filenames, logs, metrics, diagnostics, crash output, or
   receipts.
2. A relay installed before the application existed accepts the new producer
   through the unchanged canonical ABI and needs no restart or configuration.
3. Two unrelated fixture applications and an unknown third byte producer produce
   the same relay-visible schema; only documented generic leakage such as size
   class, timing, endpoint, and access pattern differs.
4. The final Node, Bare/Pear, and browser implementations reproduce canonical
   vectors and reject non-canonical, oversized, truncated, reordered, replayed,
   stale, and wrong-class messages.
5. Fresh read-only/lurker boot creates no write identity, capability, admission
   token, or background write. Explicit authoring commits the user's identity,
   signs and journals the event, and makes it locally visible while offline; zero
   relays queues delivery, and one compatible unregistered relay is usable without
   an application phase, registry, cohort, or maintainer gate.
6. Response loss, page reload, browser restart, multi-tab races, relay loss,
   partial replica success, clock boundaries, lease rollover, and rollback do not
   duplicate or lose an acknowledged logical event beyond the signed policy.
7. App-valid but malicious records cannot escape application validation, and
   relay-valid but app-invalid ciphertext cannot become trusted application state.
8. Direct, split, and Tor modes expose only the claims demonstrated by separate
   capture and collusion tests; opaque bytes alone are never reported as source
   anonymity.
9. The final edge and daemon image closures contain no legacy semantic service,
   app adapter, compiler, unused credential, or shared storage/identity surface.
10. Upgrade, rollback, migration cutoff, emergency advisory, and recovery exercises
    reproduce from signed, content-addressed evidence without an undocumented
    operator step. An advisory may pause automatic background work, but it cannot
    invalidate content, veto explicit authoring, or revoke an already compatible
    client/relay tuple.

The application release key authenticates software and migration artifacts. It
MUST NOT authorize authors, approve relay membership, disable otherwise valid
content, or become an online prerequisite for installed compatible clients. If a
release or bootstrap publisher disappears, clients continue from their last
verified compatible tuple and may discover additional compatible relays through
other authenticated routes.

Application conformance MUST additionally exercise zero-relay authoring, process
restart with queued publication intents, later relay reconnection, and exact
idempotent delivery of the already signed event. Operator-registry and witness
evidence may support a claimed independence or diversity label; absence from such
evidence cannot make a relay incompatible or an application event invalid.

The HiveRelay repository supplies generic protocol, boundary, image, transport,
fault, privacy, and load conformance. Each application repository supplies its
own adapter, semantic validation, migration, UI, identity, recovery, and
end-to-end evidence. Peerit's profile is one example, not a template the relay
must understand.

---

## 8. Expected improvement and honest limits

Applications that migrate gain a smaller and more reusable operator surface,
fixed generic parsing bounds, app-independent horizontal capacity, client-owned
authority, portable relay selection, and the ability to use relays that were not
deployed for that application. They can also select stronger privacy transports
without changing their stored data model.

The substrate does not make every application automatically private, anonymous,
available, or correct. A conforming relay cannot interpret encrypted application
content, but it can still observe the generic metadata exposed by the selected
transport. Public readers may correlate public content after obtaining the app's
read capabilities. Operators may collude, disappear, censor, return stale data,
or run multiple identities. Application adapters therefore remain responsible for
encryption, validation, diversity, repair, floors, and precise user-visible
claims.

That is the intended division: one replaceable, independently operated blind byte
substrate; many sovereign application protocols above it.
