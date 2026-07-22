# Feedback: silent partial-pin failure (PearBrowser case study)

> **Historical v2 incident record.** This preserves the May-2026 failure
> analysis for compatibility and postmortem reference. It is not a current
> executable-delivery or release instruction; v3 native releases require
> signed artifacts and complete cold-retrieval proof.

> **TL;DR.** Relays accept a seed request whose `maxStorage` is smaller than
> the drive's actual `byteLength`. They replicate metadata fully, stall
> mid-blob, and never tell the publisher. End users running
> `pear run pear://<key>` experience a silent indefinite hang on first
> launch — same symptom as "no peers found", but the publisher's own
> diagnostic (`pear info`) and the relay client's `seeded` callback both
> say everything is fine. This took an hour to diagnose because the
> failure is invisible from both sides.

Filed by: pearbrowser-desktop maintainers
Date: 2026-05-14
HiveRelay version: 0.8.5 (client) / 0.8.10 (monorepo head)
Related code:
- `packages/core/relay-node/app-lifecycle.js:179-227` (relay's drive replication loop)
- `packages/client/index.js` `seed(key, opts)` (publisher seed request)
- `packages/core/protocol/seed-request.js` (wire schema)

---

## What happened

PearBrowser desktop is published as a single Hyperdrive
(`pear://tco5k7h38uoxatedp1wongdbhjxow1x7jiwm3t1i9cujbebhsbty`). As of
`v0.4.3` the drive is:

```
metadata core:        length 4914,  byteLength    1,236,505    (~1.2 MB)
content (blob) core:  length 10119, byteLength  381,674,831    (~364 MB)
total:                                          382,911,336    (~365 MB)
```

The publisher's pin script asked five relays to pin with these options:

```js
{
  replicas: 5,
  ttlDays: 365,
  maxStorage: 256 * 1024 * 1024,  // 256 MB — set when the drive was 9 MB
  region: null
}
```

The four relays that responded all emitted a `seeded` event with
`acceptances === 4`. From the publisher's perspective: success.

Reality on the relays: `drive.update({ wait: true })` succeeds (small),
`drive.download('/')` runs until it hits the 256 MB allocation, then
either silently throws inside the `Promise.race().catch(() => {})` at
`app-lifecycle.js:222` or stops fetching new blocks for the content
core. The drive stays in `this.apps` with `version: 4914`, the
`reseeded` event still fires, the gateway endpoint
`/v1/hyper/<key>/index.html` works (it serves cached blocks), but
roughly 30% of blob blocks are missing.

End users on a fresh machine:
1. `pear run pear://tco5...` resolves DHT, finds the relay, syncs
   metadata (`length=4914` arrives within seconds)
2. Hyperdrive starts walking the manifest, requesting blob blocks
3. For blocks the relay never finished downloading, the block request
   hangs waiting for *some* peer to serve them. There is none.
4. Terminal sits silent forever. No error, no progress.

Indistinguishable from a network-unreachable bug.

---

## How we reproduced and verified

Wrote a `verify-pin.js` script for the publisher side that does what
`pin-self-on-hiverelay.js` does *not*:

1. Fresh `mkdtempSync` corestore — zero local cache
2. New `Hyperswarm`, join the drive's discovery topic
3. Wait for any peer connection
4. `drive.core.update({ wait: true })` — read length
5. `drive.list('/')` to find a real file
6. `drive.get(<file>)` with a 20-second timeout
7. Exit non-zero if the blob fetch times out

Output before the fix:

```
→ waiting for peers... ✓
→ reading drive length... length=4914
→ sampling a blob... ✗
blob sample failed: blob fetch timed out
metadata is reachable but content blocks are not — partial pin
```

After bumping `maxStorage` to 1 GB and waiting for the relays to backfill
the missing ~30% of blob blocks, the same script returns a real blob
within seconds.

So the bug reproduces deterministically and the fix is real.

**Independent corroboration (2026-05-19):** independently reproduced on
the Drop drive (537 MB, key `i687xpzb…`, release 7999) — metadata
resolves, blobs unreachable, `pear run` hangs silently. Different
publisher, different drive, identical symptom. Confirms this is not
publisher-specific misconfiguration but a systemic large-drive seeding
gap.

---

## What we'd like HiveRelay to change

Ordered by severity. (1) and (2) are correctness; (3) and (4) are UX.

### 1. Reject seed requests when `maxStorage < drive.byteLength`

**Right now**: relay accepts the request, ACKs `accepted: true`, and
starts replicating with no awareness that it can't fit the drive.

**Should**: in the relay's `_onSeedRequest` handler (around the point
where it calls `seedApp(key, opts)`), compute the drive's total byte
size *after* the first `drive.update({ wait: true })`. If
`drive.byteLength + drive.blobs.byteLength > opts.maxStorage`, respond
with `accepted: false, reason: 'maxStorage too small'` and include
the actual size so the client can retry with a bigger cap.

This is the single most important fix. It turns a silent invisible
bug into a loud immediate one. The publisher learns the truth at pin
time, not after deployment.

Note: drive size is unknowable *before* first sync, so the check
must run after metadata arrives, not at request-accept time. The
relay can ACK acceptance, attempt sync, then emit a follow-up
`seed-aborted` message if the size doesn't fit. Either pattern is
fine — what matters is the publisher hears about it.

### 2. Emit `seed-progress` and `seed-stalled` events to the publisher

The relay knows whether `drive.download('/')` is progressing. It
should send back periodic progress updates (`downloadedBlocks /
totalBlocks`, or `downloadedBytes / totalBytes`), and an explicit
`seed-stalled` event when the download stops making progress for >30s
without completing.

The client SDK can re-emit these as `seed-progress` and `seed-stalled`
events on the `HiveRelayClient`. Then a pin script can sit on the
events and print a real progress bar instead of treating the initial
ACK as the final word.

### 3. Provide a content-availability query

Add a `client.queryContent(driveKey)` that asks N relays "do you
currently have all of this drive's blob blocks". Returns
`{ relayPubkey, version, blockCoverage: 1.0 | 0.7 | 0.0, ... }`.

Today the only way for a publisher to know whether end users will
have a working experience is to do what `verify-pin.js` does — boot
a fresh corestore in a temp dir and try fetching a blob. That's
heavyweight for what should be a simple RPC.

### 4. Sane default `maxStorage` in the client SDK

The current default — whatever `seed()` falls back to when `opts` is
omitted — should be a reasonable size for the drive being seeded.
Either:
- compute it from `drive.byteLength + drive.blobs.byteLength` plus a
  growth multiplier (e.g. 4×), OR
- make `maxStorage` a *required* argument with a clear error
  ("specify maxStorage in bytes — at least drive.byteLength")

The current "256 MB default that you have to know to override" is a
trap. Every Pear app project that grows past 256 MB will hit this
silently, because nobody re-reads their pin script after their first
release works.

### 5. Document the failure mode

Add an entry to `docs/DEVELOPER.md` (or a new `docs/PUBLISHING.md`)
explaining:

- `maxStorage` is per-app on each relay, not total
- It must exceed `byteLength + blobs.byteLength` from `pear info` or
  `drive.byteLength`
- `pear-electron` and other "bundles runtime into the drive" stacks
  inflate drive size by 30-400 MB
- The symptom of getting this wrong: `pear info` works, `pear run`
  hangs — looks like a network bug, isn't
- Recommended pattern: a `verify-pin` script that round-trips a blob
  from a fresh corestore after every pin

---

## What we already did on our end

Not a request — just so you can see the shape of a workaround
without these fixes:

- **`scripts/pin-self-on-hiverelay.js`** — bumped `maxStorage` from
  256 MB to 1 GB with a big comment about how to size it and what
  goes wrong when it's too small.
- **`scripts/verify-pin.js`** — fresh-corestore round-trip blob
  fetch, exits non-zero on failure. Pasteable into any other Pear
  project that uses HiveRelay.
- **`scripts/release-prod.sh`** — now does `stage → release → pin →
  verify-pin` in one. The verify step polls up to 10 minutes;
  if it never passes, the release script exits 2. A future
  v0.4.x release literally cannot ship "succeeded but unreachable"
  anymore.

These workarounds suffice for our project, but they don't generalize.
Every project publishing through HiveRelay will hit the same trap
unless the relay side gets at least fixes (1) and (4).

---

## Out of scope

- We are **not** asking for the relay to auto-grow `maxStorage` —
  that would let any publisher fill a relay's disk. The publisher
  should always declare a real cap.
- We are **not** asking for the relay to retry rejected seed
  requests automatically.
- We are **not** asking for changes to the seed protocol's
  cryptographic envelope (signed-seed Ed25519). That part works.

---

## Contact

If you want to look at the failing-then-fixed reproduction:

```
git clone https://github.com/bigdestiny2/pearbrowser-desktop
cd pearbrowser-desktop
node scripts/verify-pin.js --expect 4914
# pre-fix output: "blob sample failed: blob fetch timed out"
# post-fix output: "Drive is fully reachable"
```

The pearbrowser-desktop maintainers will help debug or run experiments
on the production drive at any time — it's a useful real-world load
test (365 MB drive, deployed, has actual end users).

---

## Resolution — v0.8.11 (2026-05-14)

Same-day turnaround. Asks (1), (4), (5) shipped in 0.8.11; (2) and (3)
queued for 0.8.12 with protocol design ahead of them.

| Ask | Status in v0.8.11 |
|---|---|
| (1) Reject seed when `drive.byteLength > maxStorage` | ✅ Relay emits `seed-aborted` after metadata sync + unseeds locally (see `eagerReplicate` in `app-lifecycle.js`) |
| (4) Sane SDK default for `maxStorage` | ✅ Client computes `observedBytes × 4`, falls back to 1 GB. Emits `seed-cap-warning` at seed time when declared cap < observed |
| (5) `docs/PUBLISHING.md` covering the failure mode | ✅ Shipped — references this doc as the case study |
| (2) `seed-progress` / `seed-stalled` push events | ⏳ Deferred to 0.8.12 (new Protomux message types on the seed channel) |
| (3) `client.queryContent(driveKey)` RPC | ⏳ Deferred to 0.8.12 (new REST + SDK surface) |

Relay agent's writeup: see `CHANGELOG.md` v0.8.11 entry.

**PearBrowser side**, after 0.8.11 deploy:
- Bumped `p2p-hiverelay{,-client,-verifier}` deps `^0.8.5` → `^0.8.11`
- Migrated the SDK import path (`p2p-hiverelay/client` → `p2p-hiverelay-client`,
  monorepo split) across `pin-self-on-hiverelay.js`, `publish-and-pin.js`,
  `check-relays.js`, `unseed-drive.js`
- Wired `seed-cap-warning` + `seed-aborted` listeners into the pin script
  so the loud-failure surface is visible in script output
- Re-pinned the production drive with `maxStorage: 1 GB` (above the 478 MB
  recommendedCap the SDK computes). No `seed-cap-warning` / `seed-aborted`
  fired — clean handshake — relays are backfilling the ~30% of blob bytes
  that the prior 256 MB cap had stranded
- `verify-pin.js` stays as belt-and-suspenders. On v0.8.11+ it should pass
  within minutes of any release because the loud-failure path catches the
  partial pin before `verify-pin` would have to

The bug is closed for **new** pins. Future asks (2) and (3) will land
as their own feedback notes / collaboration on the v0.8.12 design.

---

## Follow-up observation: re-seeds early-return without applying new opts

Discovered while validating v0.8.11 against the in-flight production
state (pearbrowser-desktop drive was already partial-pinned at 256 MB
on 4 relays before 0.8.11 deployed).

**Symptom**: re-pinning with the corrected 1 GB cap had no effect.
Relays accepted the request, the SDK saw no `seed-cap-warning`, the
relay emitted no `seed-aborted` — looked like a clean re-pin. But
`verify-pin.js` kept failing for 20+ minutes. The relays were sitting
on their pre-v0.8.11 partial state and never re-triggered
`drive.download('/')` with the new cap.

**Cause**: `packages/core/core/relay-node/app-lifecycle.js:166-175` —

```js
if (this.seededApps.has(appKeyHex)) {
  const existing = this.seededApps.get(appKeyHex)
  if (existing && existing.discoveryKey) {
    return { discoveryKey: dkHex, alreadySeeded: true }
  }
}
```

When a re-seed arrives, the relay returns `alreadySeeded: true`
immediately. The new size-check + `eagerReplicate` retry loop live
inside `_seedAppInner`, which is bypassed by the early return. So the
v0.8.11 fix only covers **fresh** seeds — for any drive a relay was
already pinning before v0.8.11 rolled out, the publisher can't bump
the cap without an explicit unseed-then-reseed dance.

**Why this matters**: this is exactly the upgrade-path case. Every
existing pre-v0.8.11 partial-pin in the wild is stuck. The relay's
own size-check / `seed-aborted` machinery can't help, because it
never runs.

**Proposed fix (small, ask #6)**: when `seedApp(appKey, opts)` finds
an existing entry, compare `opts.maxStorage` (and other
size/availability-affecting opts) against the stored entry's. If
they differ — particularly if `maxStorage` is bigger — re-enter
`_seedAppInner` to re-validate against the now-known drive size and
re-trigger `drive.download('/')` from the current `drive.version`.
This way a re-seed becomes the canonical "publisher updated their
allocation" signal. The `alreadySeeded` early-return then only fires
when opts are byte-identical to the stored entry.

**Alternative (heavier)**: add an explicit `client.refreshSeed(key,
opts)` RPC that always re-runs `_seedAppInner`. The naming makes the
intent loud and the relay can validate the new opts without
ambiguity.

**Operator unblock for our specific case**: on the relay side, the
fix is to bounce the relays connected to our drive — fresh start
clears `seededApps`, the next pin request from us goes through
`_seedAppInner` and pulls the full drive under the 1 GB cap. The
PearBrowser team can wait for v0.8.12 or you can restart the 4
relays serving `pear://tco5...` whenever convenient.

We've added this as ask **(6)** for the v0.8.12 cluster. It pairs
naturally with (2) `seed-progress` (a re-seed with bigger cap and
no progress reported is the same invisible-failure pattern this
whole doc started with).

### Resolution — 2026-05-14, v0.8.12

Ask (6) shipped in v0.8.12. The `alreadySeeded` early-return in
`seedApp` now calls `_reconcileSeedOptsOnRepin(appKey, existing, opts)`
before returning. The reconcile method:

- **Cap raised** (or set where old was null): updates the entry's
  stored cap, emits `seed-cap-raised`, and retriggers `_eagerReplicate`
  to drain blocks the prior cap had blocked. Concurrency-guarded via
  `entry._replicating` so rapid re-pins don't stack.
- **Cap lowered**: emits `seed-cap-warning` (`reason:
  'cap-lowered-on-repin'`) and keeps the prior higher cap. Reducing
  accepted capacity mid-flight isn't honored — the publisher must
  unseed first if they really want to shrink.
- **Cap unchanged** (or both null): no-op (matches prior behavior).

The `maxStorage` value is also now persisted on the registry entry
(`app-registry.json`) so the comparison survives restarts. As a
side effect, the v0.8.11 size-check now fires on reseed at startup
for entries that have the cap persisted — closing the silent-grow
window that existed between v0.8.10 entries and v0.8.11 fresh seeds.

While v0.8.12 was being prepared, the pearbrowser-desktop team's
specific drive was unblocked by bouncing the 3 production VPS relays
that were pinning it. The 4th peer (`0da2f0626d24…`) is an
independent operator outside our fleet.

See `docs/RELEASE-NOTES-0.8.12.md` for the full release notes and
the `seed-cap-raised` / `seed-cap-warning` event payloads.
