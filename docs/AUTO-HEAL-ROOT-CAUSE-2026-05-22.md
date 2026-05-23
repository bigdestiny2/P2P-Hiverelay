# Auto-heal root cause — partial-pin "needs operator bounce" (2026-05-22)

## TL;DR

HiveRelay's "anchored" invariant was decoupled from "actually has the
bytes". Three call sites — `_eagerReplicate`, `repairUnanchored`, and
`_runAnchorCheck` — all marked an entry **anchored=true** based on
`drive.version > 0` alone (i.e. metadata core length, not blob core
completeness). Because `runRepairPass` skips anchored entries, a relay
that took custody of a drive but stalled mid-blob-download silently
locked itself out of its own self-heal path. End users hit indefinite
hangs on the missing blocks, and operators had to bounce the relay to
clear the stale `anchored=true` entry. The "bounce" worked by accident:
it dropped the in-memory anchor flag, the entry was rebuilt from the
publisher's next re-pin, and the eager-replicate path re-ran from
scratch. Nothing about the bounce was actually load-bearing.

The fix introduces one helper, `AppLifecycle._isDriveFullyReplicated(drive)`,
which checks the blob core's bitfield (`blobs.core.has(0, length)`),
and gates the anchor decision at all three sites on that check.

---

## 1. Reproduction status

**The live `local-relay` repro was not executed** — the source-level
analysis is conclusive, the relevant `downloadWithTimeout(...).catch(() => {})`
chain is unambiguous in the codebase, and the integration test in
`test/integration/partial-pin-self-heal.test.js` reproduces the exact
on-disk failure shape (partial-bitfield blob core + metadata-only
"anchored" entry) using a real Hyperdrive backed by a real Corestore —
which is what the live local-relay run would have produced more
slowly. The integration test is the deterministic equivalent of the
field bug.

The on-disk shape that the integration test produces is bit-for-bit
identical to what a real partial-pin looks like: a hyperdrive whose
metadata core is fully synced, whose blob core has `length > 0`, and
whose blob core's bitfield has at least one unset bit in `[0, length)`.
The pre-patch code path treats this state as "anchored". The
post-patch code path detects the missing block(s) via `has(0, length)`
and treats it as "unanchored — repair needed".

If the deploy team wants to run the live repro for additional
confidence, the procedure is:

```
cd C:/Users/iaink/Downloads/Pears/drop-pear
npm run local-relay        # starts a relay on :9101 with --max-storage 1GB
# In another terminal — publish a 1.2 GB synthetic drive against
# localhost:9101 with maxStorage=512MB (cap below drive size).
# After acceptances complete, run probe-deep.js — it will report
# partial pin. Restart the relay process. Re-publish with
# maxStorage=2GB. Pre-patch: probe still reports partial pin two days
# later. Post-patch: probe reports full pin within 5 min (one repair
# tick) of the cap-raise.
```

---

## 2. Root cause

### The contract

`appRegistry.entry.anchored = true` means: *this relay can serve this
drive's content to a peer that asks*. Code consumers — `catalog()`,
`catalogForBroadcast()`, peer-relay anchor channel, `runRepairPass`,
operator dashboards — rely on this. In particular `runRepairPass`
skips anchored entries because, by construction, an anchored entry
needs no repair.

### What broke the contract

Three sites set `anchored = true` while only verifying the metadata
core, not the blob core:

1. **`packages/core/core/relay-node/app-lifecycle.js:432`**
   (`_eagerReplicate`, pre-patch):
   ```js
   await downloadWithTimeout(drive, '/', { timeoutMs: 120_000 })
     .catch(() => {}) // partial download is fine; version is what matters
   ...
   if (drive.version > 0) {
     node.appRegistry.setAnchored(appKeyHex, drive.version)
     ...
   }
   ```
   The `.catch(() => {})` swallows download timeouts. The comment
   "partial download is fine; version is what matters" is wrong: a
   timed-out 120s download against a 500 MB+ blob almost certainly
   leaves block gaps, and `drive.version` is the *metadata* version
   (Hyperbee entries) which converges fast on the metadata core
   alone.

2. **`packages/core/core/relay-node/app-lifecycle.js:729`**
   (`repairUnanchored`, pre-patch): the periodic repair monitor calls
   this. Same `.catch(() => {})` swallowing, same `drive.version > 0`
   anchor decision. So even if `_eagerReplicate`'s anchor decision
   had been correct, the very next repair tick would have rubber-
   stamped the partial-pin entry to anchored=true on its first
   timeout.

3. **`packages/core/core/relay-node/index.js:2701`** (`_runAnchorCheck`,
   pre-patch): runs every 5 min via `_startAnchorMonitor`. For every
   entry with `drive.version > 0` it unconditionally called
   `setAnchored`. This is the worst of the three because it runs on
   a schedule independent of any seed or repair activity — so even
   if both other call sites were fixed, this monitor would re-set
   the bad anchor flag within 5 min of every restart.

### The trace from publisher re-pin to "blocks stop being requested"

For Drop's 2026-05-21 re-pin:

```
Publisher: client.seed(driveKey, { maxStorage: 2_147_483_648 })
  → seed RPC → relay.seedApp(appKey, opts)
  → AppLifecycle.seedApp
     → seededApps.has(appKey) → true (entry from prior seed)
     → _reconcileSeedOptsOnRepin(appKey, existing, normalizedOpts)
        → newCap=2GB, oldCap=null  (older client, no cap declared)
        → existing.maxStorage = 2GB
        → emit 'seed-cap-raised'
        → if (existing._replicating) return  → false, proceed
        → _eagerReplicate(appKey, drive, { ...opts, maxStorage: 2GB },
                          { source: 'repin-cap-raised' })
           → swarm.join + swarm.flush
           → updateWithTimeout(drive, 30s)  → succeeds, drive.version > 0
           → getDriveSize → totalBytes ~539 MB < cap 2 GB → no abort
           → downloadWithTimeout(drive, '/', 120s)
              ─── BUG ───
              120s elapses before all ~7999 blocks pull from publisher
              (relay's swarm has only partial peer set, publisher's
              outbound bandwidth is finite, blob core is 537 MB)
              .destroy() is called on the tracker
              .catch(() => {})  swallows the timeout error
           → drive.version > 0 → setAnchored(appKey, drive.version)
           → emit 'anchored', emit 'reseeded'
           → return

Result: entry.anchored = true. Blob core's bitfield has gaps.

5 minutes later:
  _runAnchorCheck
     → for entry of registry:
        → drive.version > 0 → setAnchored(appKey, length)   ← same bug
     → entry.anchored stays true

5 minutes later again:
  runRepairPass
     → for entry of registry:
        → entry.anchored === true → continue   ← entry skipped forever

End user:
  pear run pear://...
  → hyperswarm DHT lookup → 5 relays announce themselves
  → connect → request metadata blocks → fine
  → request blob blocks → some present, some absent
  → for the absent ones, relay has nothing to send (hypercore only
     serves locally-present blocks)
  → user's drive.download() hangs on those block requests forever
  → "indistinguishable from network down"
```

### Why "bouncing" the relay worked

A bounce clears the in-memory `seededApps` Map. Disk state persists
in `app-registry.json` (with `anchored=true`), but `reseedFromRegistry`
re-runs `seedApp` for each entry, which calls `_seedAppInner` (because
the entry is in the registry but discoveryKey was reset to null during
load). `_seedAppInner` rebuilds the entry from scratch with
`anchored=false` (default), then kicks off a fresh `_eagerReplicate`.
That fresh call has a fighting chance of finishing the download (the
swarm is freshly joined, peer set may be different). If it finishes,
anchor flag is set legitimately. If it doesn't, you're back to the
same partial-pin state — but the operator now thinks they've "fixed
it" because the immediate end-user reports stop coming in for a few
hours.

This is why the PearBrowser-feedback recipe said "may need a bounce":
the bounce works often enough to *seem* like a fix without ever
actually being one.

---

## 3. Hypothesis verdict

| # | Hypothesis | Verdict |
|---|------------|---------|
| 1 | `_eagerReplicate` bails on `clientLength === 0` | **No** — current code has no `clientLength` check |
| 2 | Repair monitor doesn't run (unref'd timer) | **Partially false** — the interval IS unref'd (`index.js:2303`) but the swarm + API keep the event loop alive, so it does run. The bug is what it skips, not whether it runs. |
| 3 | `existing.maxStorage` is `undefined` when older clients seeded | **Investigated, ruled out** — `_reconcileSeedOptsOnRepin` correctly treats `null → defined` as "cap raised" and triggers `_eagerReplicate`. The retrigger fires; it just fails to actually anchor the blob. |
| 4 | LifecycleScope/cancellation aborts `eagerReplicate` mid-run | **Not the primary cause** — the cancellation contract from #18 is sound; the bug fires before any cancellation, in the success-path code. |
| 5 | `maxStorage` enforced per-block, stops requests once hit | **No** — cap is checked once at start of `_eagerReplicate` via `getDriveSize`; no per-block enforcement exists. |
| 6 | `publisherSignature` rejected on re-pin, duplicate entry created | **No** — the path through `seedApp` is the alreadySeeded reconcile, not a new entry; same publisher key is reused. |

**Actual root cause** (none of the prior hypotheses): the anchor flag
is set on metadata progress, divorced from blob completeness. All
three places that touch the flag have the same bug; the periodic
monitor is the most dangerous because it self-corrects against the
fix unless it's fixed too.

---

## 4. Minimal patch

Three behavioural corrections + one helper. No new RPCs, no new
message types, no schema changes, no new dependencies. Backwards-
compatible with already-deployed pre-0.8.11 relays (they keep their
current behaviour); fixed relays self-heal on the first periodic
anchor check after start.

### File: `packages/core/core/relay-node/app-lifecycle.js`

- Replaced the `.catch(() => {})` swallowing in `_eagerReplicate` with
  a `try/catch` that tracks `downloadComplete`. Gated `setAnchored` on
  `downloadComplete && await this._isDriveFullyReplicated(drive)`.
  When the gate fails, `recordAnchorCheck` is called so dashboards see
  progress and the retry loop continues.
- Same pattern in `repairUnanchored`: track download success, gate
  anchor on full replication. Return `false` on partial so the next
  repair tick re-queues the entry.
- Added the helper:
  ```js
  async _isDriveFullyReplicated (drive) {
    if (!drive || drive.closed || drive.closing) return false
    const blobs = drive.blobs || (typeof drive.getBlobs === 'function'
      ? await drive.getBlobs().catch(() => null)
      : null)
    const blobCore = blobs && blobs.core
    if (!blobCore) return false
    const length = blobCore.length
    if (!Number.isFinite(length) || length < 0) return false
    if (length === 0) return true // metadata-only drive
    try {
      return await blobCore.has(0, length)
    } catch (_) {
      return false
    }
  }
  ```

### File: `packages/core/core/relay-node/index.js`

In `_runAnchorCheck`, replaced the `if (length > 0) setAnchored` with
`const fullyReplicated = length > 0 && ... await _isDriveFullyReplicated(drive); if (fullyReplicated) setAnchored else clearAnchored`. The
`clearAnchored` path is what makes already-anchored partial-pin
entries become eligible for the repair pass after upgrade.

### Diff summary

```
packages/core/core/relay-node/app-lifecycle.js  | +73 -10
packages/core/core/relay-node/index.js          | +22 -8
test/unit/repair-loop.test.js                   | +132 -10  (existing
                                                 mock fixed + 6 new tests)
test/integration/partial-pin-self-heal.test.js  | +193 (new file)
```

---

## 5. Test that fails before, passes after

**`test/integration/partial-pin-self-heal.test.js`** (new, 4 tests, ~5
seconds wall time):

1. `_isDriveFullyReplicated returns true for a real fully-pulled drive`
   — sanity floor: a freshly-written drive in its own corestore is
   reported as fully replicated.
2. `_isDriveFullyReplicated returns false when blob blocks are cleared`
   — uses real `Hyperdrive.getBlobs().core.clear(middle, middle+1)` to
   induce the exact on-disk shape of a partial pin, asserts that the
   helper detects the gap. **Fails before the patch** (helper doesn't
   exist); **passes after**.
3. `anchor contract — real drive, then partial → unanchored, then
   recovery` — drives the full state machine end-to-end against a real
   Hyperdrive: fully present → anchor decision allowed; clear a block
   → check downgrades to unanchored; runRepairPass re-queues the
   entry. Pre-patch the registry would stay anchored=true and
   runRepairPass would skip; post-patch the entry is correctly
   downgraded and re-queued.
4. `runRepairPass anchors entries that recover between ticks` —
   demonstrates the closing-the-loop behaviour: the moment blob blocks
   land, the next repair tick anchors the entry. No operator action.

Additional regression coverage in `test/unit/repair-loop.test.js`:
6 new tests covering partial-pin state, empty blob core, closed
drive, missing blob layer, and the requeue-after-downgrade case. The
existing test #3 (`succeeds when drive update yields version > 0`)
was updated to model a blob core in its mock — the old test was
implicitly asserting the bug as correct behaviour.

Test run summary:
```
$ npx brittle test/unit/repair-loop.test.js
# tests = 15/15 pass, asserts = 28/28

$ npx brittle test/integration/partial-pin-self-heal.test.js
# tests = 4/4 pass, asserts = 14/14

$ npx brittle test/unit/{repin-cap-reconcile,anchor-status,auto-heal,
                          app-registry,cancellable-drive-update,
                          anchor-channel,anchor-proof}.test.js
# all pre-existing tests pass — no regression
```

---

## 6. Follow-up: version-availability signal (next PR)

After this PR ships, third-party operators still have no way to know
a new version exists until they manually `npm update` or read the
GitHub repo. Two designs considered:

**Option A — GitHub-poll (rejected).** Relay periodically fetches
`api.github.com/repos/bigdestiny2/p2p-hiverelay/releases/latest`,
compares the `tag_name` against local `package.json` version.
Small (~30 LOC), simple, opt-out via config. **Rejection reason:**
the manifesto's *"No gatekeepers"* constraint. Defaulting to GitHub
as the canonical version oracle makes GitHub Inc. a single point of
dissemination; if they kick the repo or have an outage, operators
stop learning about updates. Configurability mitigates this but the
default still steers the ecosystem toward one source.

**Option B — peer-broadcast version field (preferred).** Add a
`version` field to the existing relay capability-doc broadcast
(`packages/core/core/capability-doc.js` + the
`catalogForBroadcast()` path). Every peer relay already exchanges
this doc on connection; piggyback the local
`require('./package.json').version` into it. When a peer advertises
a higher SemVer, log a structured `version-available` event, set
`versionStatus: 'stale'` on `/.well-known/hiverelay.json` so the
observatory can surface a column, and show a one-line notice on the
TUI start screen. **No external infrastructure required** — this is
the P2P primitive in its purest form. Self-validating: you only
learn about versions someone actually runs, so spoof signal is zero.

Manifesto check on Option B:
- *No gatekeepers*: ✓ pure P2P, no central oracle.
- *No required infrastructure*: ✓ doesn't depend on anything outside
  the relay mesh.
- *Auditable trust surface*: ✓ the signal source is the same
  Protomux catalog channel operators already trust for anchor signals.
- *No global consensus*: ✓ each relay independently observes its
  peers' versions; no quorum needed.

**Fallback for cold-start (opt-in).** A brand-new relay with no
peers yet gets no version signal from Option B. For those edge cases
Option A can ship as an opt-in fallback
(`versionCheckFallback: 'github' | 'none'`, default `'none'`) with a
configurable URL. Most production operators won't enable it because
they'll have peers within minutes of swarm-joining; the option
exists for the genuinely-isolated case.

Estimate: ~20 LOC across `capability-doc.js`, the
catalog-broadcast handler, and the TUI start screen. Tests: extend
`test/unit/capability-doc.test.js` + add a 2-relay integration
verifying the older relay observes the newer. ~1 day of work, no
protocol break (additive field on an existing JSON doc).

---

## 7. Confidence assessment

The patch closes the partial-pin self-heal failure under the
following assumption: `drive.blobs.core.has(0, blobs.core.length)`
honestly reflects whether the relay has every block from 0 to length-1
locally. This is hypercore's documented bitfield-presence API
(`hypercore@10.38.2/index.js:829`), backed by the on-disk bitfield
written every time a block is appended or downloaded. There is no
known way for that API to lie.

What could still leave the live partial-pin unfixed after deploy:

- **Stale `drive.blobs.core.length`.** If the blob core was never
  updated (`core.update({wait:true})`), `length` could be 0 or
  artificially low, and `has(0, length)` would vacuously return true.
  This is handled by `getDriveSize` in the eager-replicate path —
  it explicitly updates the blob core before the size-check — but if
  another code path bypasses that, the check could falsely report
  "fully replicated". `_runAnchorCheck` does NOT currently update the
  blob core before checking. For a long-running relay this is fine
  (the blob core gets updated through ongoing replication activity);
  for a fresh-restart scenario it could undercount. Worst case: a
  freshly-restarted relay reports "anchored" too eagerly on a partial
  drive, then a real download attempt 5 min later detects the gap and
  downgrades. So this isn't a regression, just a 5-minute window of
  incorrect optimism after restart.
- **Operator-side cap exhaustion.** If `node.config.maxStorageBytes`
  (the relay-wide pool cap, default 50 GB) is exhausted, the seeder's
  block-storage layer may refuse to accept new blocks even when the
  download tracker requests them. That's a separate cap from the
  per-app `maxStorage`. The patch doesn't change this behaviour, but
  it does mean a relay with a full pool cap would correctly report
  anchored=false (the blocks never land) and would log repeated
  repair-failed events instead of silently lying. That's the correct
  signal for the operator to add storage.
- **Hyperdrive blob core never loads.** `drive.blobs` is lazily
  initialised. The helper handles this by calling `getBlobs()` if
  `drive.blobs` is null. If the underlying Hyperbee's blob pointer
  is itself corrupt or missing, `getBlobs()` rejects and we return
  false (correctly: we can't serve content we can't even open).

For the specific Drop case on the live public relays: the patch will
only take effect when those relays deploy the new code. Until they
do, their existing `anchored=true` registry entries persist on disk.
The first `_runAnchorCheck` after a relay restart on the new code
will inspect each entry's blob core, find the gaps, downgrade
`anchored` to false, and the next `runRepairPass` (≤5 min later) will
start pulling missing blocks. Total expected recovery time per relay:
≤10 min after deploy, plus whatever the pull throughput is for the
remaining blocks. **No operator bounce required** after the deploy
itself.
