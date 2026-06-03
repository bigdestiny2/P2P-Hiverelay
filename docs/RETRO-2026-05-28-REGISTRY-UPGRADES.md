# What we just shipped, in plain English

**Date:** 2026-05-28
**Releases:** v0.8.24, v0.8.25, v0.8.26
**Source material:** [REGISTRY-DESIGN-COMPARISON-2026-05-28.md](./REGISTRY-DESIGN-COMPARISON-2026-05-28.md) (the design doc that produced these three changes)

## The short version

We took the architecture of a small username-registry someone built for the Holepunch challenge and applied its three best ideas to HiveRelay's own registry layer. Three releases in one day, each surgical, each tested in production within minutes.

The relay is now faster to restart, safer when the disk fills up, and structurally protected against a class of race conditions that could (and did, with low probability) produce duplicate ledger entries.

---

## Imagine the relay is a library

Pretend HiveRelay is a public library. Every Pear app is a book — when you publish your app, the library stocks it on a shelf. Anyone in town can come check it out, read it, return it. The relay (the library) doesn't care what's inside the book (your app data) — it just keeps the book on the shelf and tells visitors which aisle to find it in.

Two card catalogs make the library work:

1. **The "what's on our shelves" catalog** (`AppRegistry`) — a list of every book this specific library branch is hosting, with a card for each one tracking when it last got checked, what shelf it's on, whether the librarian has actually opened the book to confirm it's complete, etc.

2. **The "what every branch has" catalog** (`SeedingRegistry`) — a federated index that all library branches share. Each branch keeps its own running log of "we just stocked book X" / "we just lent book Y" / "we just retired book Z." Branches sync each other's logs so the network knows where every book can be found.

Both catalogs were causing real problems. Three problems, three releases.

---

## Problem 1: The catalog got rewritten from scratch on every change

Before: every time a librarian made a tiny note — "checked book #847's shelf at 3:47pm, it's fine" — the entire card catalog (all 555 cards) was photocopied, the original thrown out, the photocopy stapled back together, and put back on the desk. This happened dozens of times per minute.

This was the cause of the failure two weeks ago where one library branch's photocopier jammed (the disk got full) and the entire catalog stopped updating. Cards that should have been moved to "out for repair" stayed on "available" indefinitely, because the librarian couldn't finish the photocopy. We patched the photocopier with timeouts (v0.8.22) — if the photocopier hangs for more than 8 seconds, abandon the job and keep moving — but the underlying problem was that we were photocopying the entire catalog for every tiny change.

After (v0.8.25): each card has its own index slot. When the librarian updates one card, only that card gets rewritten. The other 554 sit untouched. The photocopier never sees the whole catalog at once. If the disk fills up, one card-write fails loudly (we hear about it immediately, the cascade can't happen), and everything else keeps working.

The technical name for this change: "AppRegistry persistence migrated from JSON-blob to Hyperbee." The on-disk file went from a 75KB JSON document that got rewritten in its entirety to a Hyperbee (an indexed key-value store on top of a Hypercore append-only log) where each card is written as one small block.

**Why this matters:** Closes the disk-full failure mode entirely. As a side benefit we now get free range queries ("show me every card with `anchored=false`") and a free audit trail ("show me every change that ever happened to card #847").

---

## Problem 2: The catalog got rebuilt from scratch on every restart

Before: every time a librarian arrived for their shift, they would read every entry in every branch's running log from page 1, in order, and use those to rebuild the "what every branch has" master catalog from nothing. With ~2,400 entries across 5 branches, this was slow. Restarts that should have taken seconds took minutes.

This is the well-trodden problem that every event-sourced system eventually has to solve: "the log is canonical, but replaying it from offset 0 every time we start up is too slow." The answer is the same everywhere: cache the indexed state in a separate place, restore from the cache, then catch up on anything added since the cache was last written.

After (v0.8.26): each branch keeps a derived-state cache in a Hyperbee called `seeding-registry-index-v1`. Every time an entry is applied to the in-memory catalog, it's also written to the cache. On restart, the cache is read first (fast — indexed, ordered by composite key), the in-memory state is restored, and then the log replay only catches up on entries added since the last cache write.

The logs are still canonical — if the cache is ever lost or corrupted, the relay reconstructs it from the logs without any data loss. The cache is a performance optimization, not a source of truth.

**Why this matters:** Restart time drops from O(N · M) to O(M) (where N = peer logs, M = entries per log). The in-memory state is up before the swarm even reaches steady state. Relays that hold tens of thousands of apps will feel this most.

---

## Problem 3: Two librarians at the same desk could record the same checkout twice

Before: when two requests arrived simultaneously for the same book — say, a "commit custody" message and a "non-serving-proof" message for the same drive intent — both could:

1. Read the current ledger state ("no commit yet")
2. Validate ("ok, a commit is a valid next step")
3. Write the commit

...resulting in two commit entries for the same intent. The downstream effect was usually benign (one of the duplicates would lose timestamp ties), but in pathological cases two commits could pass validation and end up in the ledger.

After (v0.8.24): every mutation that touches the same intent or app key now goes through a per-key serializing lock. Two simultaneous requests for the same intent queue up — the first runs to completion, the second sees the first's effect, only one commit gets written. Different intents stay parallel; the lock is per-key, not global.

The pattern was lifted from the Holepunch challenge's `_withMutationLock`, which solved the exact same problem for username registrations.

**Why this matters:** Closes a class of race conditions that could in principle have caused duplicate-entry ambiguity in the federated ledger. Low-probability in our current workload, but unambiguous to reason about going forward.

---

## How these compose

The three releases work together:

- **v0.8.24** makes sure that when mutations happen, they don't step on each other. (Locks at the in-memory boundary.)
- **v0.8.25** makes sure that when mutations are persisted to disk, one entry's write doesn't drag down the whole catalog. (Per-entry persistence.)
- **v0.8.26** makes sure that when the relay restarts, the previously-persisted state is restored fast instead of being rebuilt from logs. (Indexed-views sidecar.)

You could draw a picture: lock at the front gate (v0.8.24), one card at a time on the way to the filing cabinet (v0.8.25), and an index card at the front of the cabinet that gets you straight to the section you need (v0.8.26).

---

## What's NOT changed

A few things deliberately left alone:

- **The federated multi-writer architecture.** No relay is "the registry owner." Every relay is authoritative for its own log entries, signed end-to-end. The challenge's single-writer pattern works for usernames; it doesn't work for a decentralized federation.
- **The Ed25519 signatures on custody entries.** Cross-relay verification requires payload-level auth; the Noise transport auth on the connection only binds the hop.
- **The wire format.** Catalogs, broadcasts, and Protomux messages are unchanged. Other clients and other relays don't know any of this happened.

---

## Open follow-ups for v0.8.27+

From the design comparison doc, three items are still on the table:

- **Secondary indexes on the bee** (`byPublisher:<pubkey>`, `byTimestamp:<ts>`) — would let us do cheap range queries like "all intents from publisher X" or "all custody events in the last 24h."
- **Per-log `lastIndexedOffset` tracking** — would let restart hydration SKIP the log-replay catchup entirely (the bee is then a complete index, not just a cache).
- **A per-fleet `name → discoveryKey` public Hyperbee** — would give Pear apps a real name-resolution layer ("install pearpaste" → driveKey), modeled on the Holepunch challenge directly. Product decision more than technical.

The first two are mechanical follow-ups to v0.8.26. The third is a new product surface that depends on whether HiveRelay wants to operate a registrar.

---

# State of the live relays right now

All 5 fleet relays on v0.8.26 as of this writing. Pulled live a few minutes ago.

| Relay | IP | Region | Apps | Conns | Version |
|---|---|---|---|---|---|
| utah | 144.172.101.215 | NA | 555 | 9 | 0.8.26 |
| utah-us | 144.172.91.26 | NA | 583 | 9 | 0.8.26 |
| singapore-1 | 104.194.153.179 | SG | 437 | 9 | 0.8.26 |
| singapore-2 | 104.194.152.121 | SG | 536 | 9 | 0.8.26 |
| bern | 45.59.123.112 | EU | 311 | 9 | 0.8.26 |

**Total apps under fleet management: 2,422.** Each relay is connected to ~9 peers (other relays + clients in active sessions). The federation is converging on the same content via the cross-relay self-heal that v0.8.21 introduced.

**Disk usage signals:** All relays passed the post-deploy health check on v0.8.25. The legacy `app-registry.json` files were renamed to `.bak` (utah: 469KB, utah-us: 524KB, sing-1: 367KB) and are no longer touched; new per-entry writes go to the Hyperbee sibling-core on each corestore.

**Restart observation:** v0.8.26 deploy was clean across all 5. The relays came back with their existing app counts intact (no data loss, hydration worked). The bee sidecar populated on first start; subsequent restarts will exercise the hydration fast-path.

**Connection counts** at 9 each suggests the fleet is steady — connections climbing back after restart, settling into the typical 8-15 range.

## Recent release velocity

Releases shipped in the last week:

| Date | Version | What |
|---|---|---|
| 2026-05-22 | v0.8.19 | Circuit-relay bridge data plane + auth-bypass fix |
| 2026-05-22 | v0.8.20 | Anchor honesty + custody auto-attestation |
| 2026-05-22 | v0.8.21 | Hyperdrive 11.x API + persistent download ranges |
| 2026-05-22 | v0.8.22 | Defensive timeouts on reseed + anchor |
| 2026-05-27 | v0.8.23 | Partial-quorum custody-commit + transient errors + exports |
| 2026-05-28 | v0.8.24 | Per-key mutation locks (today) |
| 2026-05-28 | v0.8.25 | AppRegistry → Hyperbee persistence (today) |
| 2026-05-28 | v0.8.26 | SeedingRegistry indexed-views sidecar (today) |

8 releases in 7 days. All production-validated. No data loss, no regression incidents observed. Connection counts steady, app catalogs preserved across every restart.
