# Notify + OutboxLog design review (2026-07-02)

This document records the design review of two new relay primitives: the **notify**
wake-up service (spec: `docs/PUSH-NOTIFICATION-SERVICE-SPEC.md`, v0.1.0-draft) and the
**outboxlog** signed append-only log (`packages/services/builtin/outboxlog/`). The review
applied two lenses — a DMC-style performance lens (what does each hot path actually cost?)
and a Mafintosh-style smallest-primitive lens (is each piece the minimal composable thing,
with a real lifecycle?) — with multi-agent adversarial verification of every claim against
the source. Of the raw findings, 40 were verified against code; the 5 that mattered were
filed as issues #142–#146, and all fixes (six commits) landed on `fix/notify-outbox-review`
(`65263c9..d7bb9b7`). Full rationale lives in the commit messages; this file is the record
of what was found, what was decided, and what was deliberately left for V2.

## The primitives

**notify** is a relay-hosted wake-up service for P2P apps whose processes the OS suspends.
It holds only revocable signed capabilities (ReceiveCap/SendCap), provider routing
material, bounded encrypted payloads, and relay-signed delivery events — never app state.
Three delivery modes: direct send, watched source, presence fallback.

**outboxlog** is a per-writer signed append-only log the relay hosts blindly: every row is
signed by the writer key, replicated over swarm/HTTP-SSE, and persisted via an operation
journal plus periodic snapshot. The relay stores and serves rows; it cannot forge them.

The one-sentence API rule binding both: **push wakes the app; p2p sync gives the app
truth.** A notification (including a watch wake) is a lossy, opaque hint. Nothing the
relay delivers is authoritative; the woken app fetches real state from its own P2P data.

## Findings and fixes

Commits in merge order (oldest first). Two hardening commits carried no issue number —
they came out of the same review pass and were fixed directly.

| Issue | Severity | Defect | Fix | Commit |
|---|---|---|---|---|
| #143 | HIGH (security) | `delivery-event` had no auth — cross-tenant metadata IDOR (billable flag, device, provider, timing readable by anyone naming an intentId); `status()` leaked relay-global counts | `delivery-event` now requires a request signed by the receiving device key and returns only events whose `device` matches the verified key; `status()` counts scoped to the caller's app/device | `858e4ad` |
| #146 | MED (correctness/security) | Journal silently empty when journal+snapshot both configured (`!statePersistence` guard); restore never re-ran signature verification — anyone writing the state file injected rows attributed to any pubkey | Journal entry lands whenever a journal is configured; restore re-verifies every row (mirroring the append path) and drops unverifiable rows before they consume capacity | `e176cdb` |
| — | MED | `writeSseData()` ignored `res.write()`'s return — a slow SSE reader buffered append events onto the heap without bound; swarm hub had no `destroy()` (channels/descriptors leaked) | Full send buffer pauses the stream (live events dropped; client recovers via reconnect replay / p2p), resumes on `'drain'`; idempotent hub `destroy()` wired into `OutboxLogApp.stop()` | `e9e66e6` |
| — | MED | Abuse buckets hardcoded (`quota_exhausted` unreachable, no operator dial); state persisted only **after** provider egress, so a crash mid-egress erased replay/dedupe guards — restart re-sent and re-billed the same intent | `abuseLimits` configurable per scope (`{perHour, burst}`, 0 disables); durability barrier persists replay+dedupe **before** egress; provider throw records `provider_attempted` with `billable:false` | `8e1a228` |
| #144 | HIGH (outboxlog) / MED (notify) | Full-snapshot rewrite per mutation: notify awaited a full JSON snapshot on every mutating RPC (even rejected sends); outboxlog did a synchronous full-state write per O(1) append | Notify hot paths debounce (250 ms flush, unref'd timer; control-plane ops stay synchronous); outboxlog journal is per-append durability, snapshot demoted to a checkpoint every 256 entries + on flush/stop | `34b1095` |
| #142, #145 | HIGH / MED | Mode-2 `watch` was spec'd, billed, in the SDK — and had no runtime: watches were accepted, persisted, and never fired. Separately, `notify-feed-head` describes exactly what outboxlog is, but the two never referenced each other | `attachWatchSource(kind, factory)` observer registry; `watch()` rejects unattached kinds with `SOURCE_UNAVAILABLE`; restored watches re-arm regardless of wiring order. The relay composes `notify-feed-head` onto the co-resident outboxlog's existing `subscribe()` — one event path, no parallel observer machinery | `d7bb9b7` |

## Design decisions and tradeoffs

Recorded honestly, including the cuts:

- **Delivery-event reads are device-key-scoped.** Only the receiving device can read its
  delivery events. Sender polling is a deliberate V1 cut: the sender already gets its
  `eventId` and status synchronously from `send()`, so the poll path adds surface without
  a V1 consumer. Revisit if async provider adapters make the synchronous answer stale.
- **One deliberate synchronous persist remains on the send path** — the pre-egress
  replay/dedupe durability barrier. Without it, a crash between egress and persist re-sends
  and re-bills. It is bounded by egress rate (not abuse rate — rejected intents debounce),
  which we judged acceptable. Everything else on hot paths coalesces into a debounced
  flush (`persistFlushMs`, default 250 ms); `stop()` flushes pending state.
- **Outboxlog persistence layering.** Journal = per-append WAL (the durability); snapshot
  = checkpoint every 256 entries (`checkpointInterval`) plus on flush/stop. Restore loads
  the checkpoint then replays the journal tail past the snapshot's `journalSeq`.
  Snapshot-only setups keep per-mutation writes, since the snapshot is the durability
  there. Rows that fail signature re-verification on load are **dropped silently**: the
  trust root is the writer key, not the filesystem, so an unverifiable row is treated the
  same as one that never arrived. The tradeoff is that disk corruption sheds rows without
  an error surface; the alternative (loading them) shifts trust to whoever can write the
  state file, which is worse.
- **Watch wakes are opaque and cheap to reason about.** No payload, generic display; the
  woken app syncs over p2p. Wakes coalesce to one per `policy.minIntervalSeconds`
  (default 30 s; the limiter is in-memory and resets on restart — worst case one extra
  wake after a relay restart). Each wake re-checks cap validity/expiry/revocations and
  binding staleness at fire time, spends the same device abuse bucket as a direct send,
  and is recorded as a relay-signed delivery event (`reason: watch_wake`). Registration
  of a source kind with no attached observer is rejected with `SOURCE_UNAVAILABLE` —
  silently accepting (and billing) a watch that can never fire is worse than rejecting.
  `hypercore-head` remains spec'd but unattached in V1.
- **Unknown outcome is not billable.** A provider that throws mid-egress records a
  `provider_attempted` event with `ok:true` at the RPC level but `billable:false`. We
  don't know whether the provider acted, so the operator eats the ambiguity, not the app.
- **Bench budgets are split by context.** The unit test asserts report plumbing with
  co-run-headroom budgets (a shared-process suite run pollutes RSS and GC timing); the
  strict release budgets live only in `scripts/bench-outboxlog.mjs` standalone.

## Benchmark snapshot

`npm run bench:outboxlog` (standalone, `release-local-v1` budget profile, 0 failures) on
2026-07-02 — local run on a workstation (M3 Ultra), Node v22.22.0, otherwise idle. These are
single-machine loopback numbers, not a load test; treat them as a regression baseline.

```
outboxes=1000 recordsPerOutbox=3 appends=4000
append            p50=0.034 ms   p99=0.046 ms   28,411 rows/s
range             p50=0.014 ms   p99=0.114 ms   4,694,284 rows/s
events            p50=0.033 ms   p99=0.043 ms   (n=100)
http publish->SSE p50=0.308 ms   p99=2.61 ms    (n=20)
directory         count=1000     payload p50=628,102 B (~613 KiB)
rss delta         29,294,592 B   (~28 MiB per 1k outboxes)
```

The append numbers reflect the post-#144 journal-first path; the pre-fix synchronous
full-snapshot write would have dominated append latency at this state size.

## Residual risks / V2 items

- **Dormant watches.** If an operator detaches a source kind across restarts (e.g. stops
  running outboxlog), previously accepted watches for that kind load, sit unarmed, and
  fire nothing. They surface only via `status()`; there is no proactive notification or
  auto-expiry for orphaned watches. Registration-time rejection (#142) prevents new ones.
- **Sender-poll path.** Cut from V1 (see above). Needed once provider adapters become
  asynchronous enough that `send()`'s synchronous eventId stops being the final word.
- **`hypercore-head` observer.** Spec'd but has no attached source in V1. Building it
  means per-watch core sessions and the possession-oracle mitigations from the spec's
  threat model; `notify-feed-head` over outboxlog covers the V1 use case without that.
- **Bare runtime durability.** The spec's open questions are silent on it. Persistence
  is Node `fs` (write-temp + rename, `writeFileSync` on the sync paths); the client
  ships Bare-safe signing helpers, but relay-side persistence has not been validated on
  Bare. Worth an explicit note before any Bare-hosted relay is supported.
- **Coalescing limiter is in-memory** (noted above): a relay restart inside a
  `minIntervalSeconds` window can emit one extra wake. Accepted for V1; persisting
  last-fire timestamps is trivial if it ever matters.

## 2026-07-29 sender-owned lane addendum

Pear Bots exposed a fanout problem in the original global-head composition: one
sender outbox can multiplex many recipients, so watching `head!<writer>` wakes
all of them. HiveRelay now also supports `notify-outbox-lane` with an opaque
32-byte `source.lane`. Relay-node subscribes to the same OutboxLog event stream
but forwards only the exact `lane-head!<lane>` mutation. Watch renewal replaces
the prior subscription under the deterministic watch id and does not consume a
second slot.

Blind atomic commits required a corresponding namespace correction. Blind data
rows still require an exact sealed body, while signed global head, commit
authorization, and lane-head records are accepted only under exact control-field
allowlists. Extra plaintext on a control row is rejected. The integration test
uses the real signature verifier and durable atomic commit journal, asserts
lane isolation/coalescing, and confirms the provider receives an empty wake.
