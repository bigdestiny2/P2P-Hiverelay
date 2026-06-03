# Registry design: Hyperbee challenge vs. HiveRelay's current approach

**Date:** 2026-05-28
**Status:** design comparison, no implementation yet
**Source material:**
- Holepunch Challenge `username-registry` (single-writer Hyperbee + Protomux RPC)
- HiveRelay v0.8.23 `SeedingRegistry` (`packages/core/core/registry/index.js`, 1077 LOC)
- HiveRelay v0.8.23 `AppRegistry` (`packages/core/core/app-registry.js`, 679 LOC)

## TL;DR

Three meaningful improvements + one minor one, ranked by leverage:

| Priority | Change | LOC delta | Risk | Wins |
| --- | --- | --- | --- | --- |
| **1** | Replace `AppRegistry`'s JSON-blob persistence with a Hyperbee | -500 LOC | low | Disk-full hangs become single-block append failures (not whole-file rewrites). Range queries free. Audit trail free. |
| **2** | Add a Hyperbee indexed-views sidecar to `SeedingRegistry` | +300-500 LOC | medium | No more O(N·M) log replay on startup. O(log n) point + range queries. Faster cross-relay catalog merge. |
| **3** | Add a per-fleet `name → discoveryKey` public Hyperbee registry | +200-300 LOC | medium | Discoverability by app name. Identity binding via Noise. Clean federation primitive. New product surface. |
| **4** | Adopt the `_withMutationLock` per-key pattern in `SeedingRegistry` mutation paths | +50 LOC | low | Closes documented race windows between concurrent custody mutations on the same intentId. |

Detailed analysis below.

---

## What the Holepunch Challenge taught us

The 109-line `Registry` class in `/Users/localllm/Holepunch Challenge/lib/registry.js` does six things that are worth lifting wholesale:

### 1. Single-writer Hyperbee = atomic mutations on owner

```js
class Registry {
  constructor (core) {
    this.bee = new Hyperbee(core, { keyEncoding: 'utf-8', valueEncoding: enc.beeValue })
    this._mutationLock = Promise.resolve()
  }

  async register (name, publicKey) {
    return this._withMutationLock(async () => {
      const existing = await this.bee.get(name)
      // ...immutability check, tombstone check...
      await this.bee.put(name, { publicKey, deleted: false })
    })
  }
}
```

The bee is replicated everywhere; only the writer can append. No CRDT, no conflict resolution, no "which version wins." Readers see eventual consistency; writers see strong consistency on the owner.

### 2. Two paths over one connection

```js
// Reads: direct Hyperbee replication + query
async lookup (name) {
  await this.core.update({ wait: true, timeout: 5000 })
  const node = await this.bee.get(name)
  return node?.value?.publicKey ?? null
}

// Writes: Protomux RPC over the same swarm connection
async register (name) {
  const res = await this._rpcCall('register', name)
  return res.created
}
```

One Hyperswarm connection carries both. The RPC channel is for mutations; the Hypercore replication channel is for reads. Both share Noise auth.

### 3. Noise → identity (no separate signature step)

```js
rpc.respond('register', { ... }, async (name) => {
  const created = await this.registry.register(name, conn.remotePublicKey)
  // conn.remotePublicKey is the proven owner — Noise already authenticated it
  return { version: this.registry.bee.version, created }
})
```

Because the swarm keypair drove Noise, `conn.remotePublicKey` IS the proven sender. No payload signature needed. (HiveRelay does payload signatures because it needs cross-relay-replicated identity binding — see Item 1 in "Where we diverge.")

### 4. Tombstones, not real deletes

```js
async unregister (name, publicKey) {
  await this.bee.put(name, { publicKey, deleted: true })
}
```

`unregister` doesn't remove the key. It flips a flag. `lookup` filters out tombstones. `register` still sees the tombstone and rejects a different owner. This preserves the immutability rule ("once a name is bound to a pubkey, it cannot point to a different one") while allowing the name to be "freed" from a reader's perspective.

The contributor flagged this as a monotonic-growth issue. True. But for the registry's correctness, it's the right call.

### 5. Replication-staleness handling

```js
async _rpcCall (method, name) {
  const rpc = await this._rpcReady
  const res = await rpc.request(method, name, { ... })
  // Wait for our local core to catch up to the writer's new version
  while (this.core.length < res.version) {
    await this.core.update({ wait: true })
  }
  return res
}
```

Mutations return the new bee version. Client waits until its local replicated core has reached that version before resolving the promise. Eliminates "register-then-lookup returns null" races.

### 6. compact-encoding

```js
exports.beeValue = {
  preencode (state, value) { ... },
  encode (state, value) { ... },
  decode (state) { ... }
}
```

Strong, fast, schema-checked binary encoding. We use this elsewhere in HiveRelay (custody-signing, anchor proofs); we should use it in registry persistence too.

---

## Where HiveRelay diverges, and why

HiveRelay has two registry surfaces, each making different design tradeoffs.

### `SeedingRegistry` — federated multi-writer

`packages/core/core/registry/index.js` (1077 LOC).

```js
this.localLog = this.store.get({ name: 'seeding-registry-local' })
// Each relay has its own append-only log.
// Peers exchange log keys via the hiverelay-registry-meta Protomux channel.
// Every relay replicates + indexes every other relay's log.

this._requests = new Map()           // in-memory rebuild from logs
this._custodyIntents = new Map()
this._custodyReceipts = new Map()
// ... 7 more in-memory indexes
```

**Why multi-writer instead of single-writer.** The federated relay model means there's no canonical owner. Every relay is authoritative for *its own* seed acceptances, custody receipts, anchor proofs, etc. A single-writer Hyperbee would force "which relay is the registry owner?" — a question that has no clean answer in a permissionless federation.

**Why per-entry Ed25519 signatures.** The relay that receives a custody-receipt isn't the only one that needs to verify it. Other relays read each other's logs and replay the same `verifyCustodyEntry` check. Noise auth would only bind the transport hop; payload signatures bind the content end-to-end.

**The cost of these choices:**
1. **No indexed reads.** Every lookup either hits an in-memory `Map` (must be rebuilt from log replay) or scans sequentially. Hyperbee gives O(log n) for free.
2. **O(N · M) startup cost.** N peer logs × M entries each, every restart. With our fleet at ~2,400 total entries across 5 relays' logs, this is bounded — but a 1000-app fleet would feel it.
3. **In-memory index correctness is our responsibility.** A bug in `_indexLog` means inconsistent reads. Hyperbee outsources this to a well-tested library.
4. **No range queries.** "All intents created in the last 24h", "all receipts for publisher X", "all expired custody chains" all require full scans or pre-built secondary indexes.
5. **Cancellations accumulate.** Same monotonic-growth the contributor flagged on his bee — but at least his bee surfaces it cleanly through `bee.createHistoryStream()`. Our cancellations are buried in the log replay.

### `AppRegistry` — local, JSON-blob persistence

`packages/core/core/app-registry.js` (679 LOC).

```js
import { readFile, writeFile, rename } from 'fs/promises'
const REGISTRY_FILE = 'app-registry.json'

export class AppRegistry extends EventEmitter {
  constructor (storagePath) {
    this._filePath = storagePath ? join(storagePath, REGISTRY_FILE) : null
    this.apps = new Map()
    this.byAppId = new Map()
    this._saving = false
    this._savePending = false
    this._saveDebounceTimer = null
  }
}
```

This is the LOCAL catalog. What's THIS relay seeding right now? Used for HTTP `/catalog.json`, P2P broadcasts, anchor tracking, and federation-accept logic.

**Why JSON-blob.** Historical: started as a simple key-value Map persisted as JSON. Grew. Now persists 19 fields per app and is rewritten in its entirety on every mutation.

**Why this is suboptimal:**
1. **Whole-file rewrite on every change.** 555 apps × 19 fields each = a ~75 KB JSON write on every `setAnchored()`, `clearAnchored()`, `recordAnchorCheck()`, `delete()`, etc. Anchor checks happen periodically; reseed happens on startup. We rewrite that JSON dozens of times per minute on a typical relay.
2. **Hung-writeFile vulnerability.** v0.8.22 mitigated with a timeout on `_seedAppInner`'s `drive.ready()` and on `_isDriveFullyReplicated`, but the underlying `save()` itself doesn't yet timeout/error on a hung writeFile (filed as [#26](https://github.com/bigdestiny2/P2P-Hiverelay/issues/26)). The fundamental fragility is the blob-write model.
3. **No range queries.** "All apps with `anchored=false`" requires a full scan. "All apps with `privacyTier='public'` and `parentKey=X`" requires a full scan. We do both routinely.
4. **679 LOC for what could be ~150.** A significant chunk of this is custom save debouncing, dirty-state tracking, and JSON.parse/stringify glue. Hyperbee replaces all of it.

---

## Proposed improvements

### Priority 1 — `AppRegistry` → Hyperbee

**Highest leverage, lowest risk.** Direct lift of the challenge pattern, restricted to LOCAL persistence (not federated). No change to the broadcast/catalog wire format; just swap the persistence layer.

Before:
```js
// 555-app JSON blob, rewritten on every mutation
const data = JSON.parse(await readFile('./app-registry.json'))
// ... mutate ...
await writeFile('./app-registry.json', JSON.stringify(data, null, 2))
```

After:
```js
const core = this.store.get({ name: 'app-registry-local' })
const bee = new Hyperbee(core, { keyEncoding: 'utf-8', valueEncoding: enc.appEntry })
await bee.put(appKeyHex, normalized)
```

**Wins:**
- **Disk-full hangs become single-block append failures.** Hypercore handles partial writes natively. No more cascade.
- **No more 75 KB rewrite per anchor check.** Each `setAnchored()` writes one block.
- **Free range queries.** `bee.createReadStream({ gte: 'a', lte: 'b' })` for prefix scans. `bee.createReadStream()` for iteration.
- **Free audit trail.** `bee.createHistoryStream()` shows the full change history for forensics.
- **Atomic startup load.** No "did the file get half-written?" failure mode; Hypercore enforces this.

**Effort:** ~1 day. New file `app-registry-store.js` (~150 LOC) replaces the relevant parts of `app-registry.js`. Public API of `AppRegistry` stays identical so consumers don't change.

**Risk:** Low. Hyperbee is a heavily-used Holepunch primitive. Migration path: detect old `app-registry.json`, import entries on first startup, then never look at JSON again.

**Carries over:** Item #26 ([app-registry save() write-timeout](https://github.com/bigdestiny2/P2P-Hiverelay/issues/26)) becomes irrelevant — the bee handles fsync semantics natively.

### Priority 2 — `SeedingRegistry` Hyperbee indexed-views sidecar

**Medium-high leverage, medium risk.** Keep the multi-writer Hypercore logs (necessary for federation), but add a per-relay Hyperbee sidecar that maintains *indexed views* of the log entries.

```js
// Existing: append-only multi-writer logs
await this.localLog.append(entry)

// New: also index this entry into our local view bee
await this._indexBee.batch()
  .put(`byAppKey:${appKey}:${timestamp}`, { type, entry })
  .put(`byPublisher:${publisherPubkey}:${timestamp}`, { type, appKey })
  .put(`byIntentId:${intentId}:${entry.type}`, entry)
  .flush()
```

Now reads become:

```js
// Before: scan in-memory _custodyIntents Map (rebuilt from logs)
const intent = this._custodyIntents.get(intentId)

// After: O(log n) bee lookup
const intent = await this._indexBee.get(`byIntentId:${intentId}:custody-intent`)
```

**Wins:**
- **Survives restart without full re-index.** Big deal at 5,000+ entries. Today's restart cost is O(N·M); becomes O(M_new) (only entries since the bee's last indexed offset).
- **Range queries natively.** "Custody intents in last 24h" → `bee.createReadStream({ gte: 'byTimestamp:${t-24h}', lte: 'byTimestamp:${t}' })`.
- **Multiple secondary indexes for free.** byAppKey, byPublisher, byIntentId, byTimestamp, byRelay — each is just a different prefix in the same bee.
- **Persistence layer matches semantic operations.** Today's in-memory `_acceptances` Map is recomputed on every restart; with a bee, the index is the persistence.

**Effort:** ~3-5 days. New file `seeding-registry-index.js` (~300-500 LOC). Bee update hook in `_indexLog` so every append (local OR peer) updates the bee. Crash recovery: the bee stores `lastIndexedOffset` for each log; on startup, replay only entries past the offset.

**Risk:** Medium. Two-phase commit between log append and bee update needs care. If we crash between log-append and bee-update, the next startup must detect the gap and replay. Idempotent index updates make this safe (same entry indexed twice = same bee state).

**Carries over:** Doesn't replace the in-memory Maps (some queries are hot enough to deserve them), but eliminates the rebuild-on-startup cost.

### Priority 3 — Per-fleet `name → discoveryKey` public Hyperbee

**Medium leverage, depends on product direction.** This is a NEW component — direct application of the challenge pattern to a real product gap.

Today: if a Pear app developer publishes `pearpaste`, the discoveryKey is whatever they generated. To discover it, you need to:
- Already know the appKey, OR
- Hit a HiveRelay HTTP `/catalog.json`, OR
- Use the federated catalog gossip

There's no "I know the app name, give me its discoveryKey" lookup. The Holepunch challenge solves this for usernames; we can apply the same pattern to app names.

```js
// New: name-registry.js
class NameRegistry {
  async register (name, driveKey, publisherPubkey) {
    return this._withMutationLock(async () => {
      // Single-writer immutability — once bound, can't reassign
      const existing = await this.bee.get(name)
      if (existing && !b4a.equals(existing.value.publisherPubkey, publisherPubkey)) {
        throw new Error('name already registered to a different publisher')
      }
      await this.bee.put(name, { driveKey, publisherPubkey, registered: Date.now() })
    })
  }

  async lookup (name) {
    const node = await this.bee.get(name)
    if (!node || node.value.deleted) return null
    return { driveKey: node.value.driveKey, publisher: node.value.publisherPubkey }
  }
}
```

Architecture:
- One Hyperbee per fleet-of-relays (e.g., `p2phiverelay.xyz` runs THE name registry for that fleet)
- Other fleets run their own; cross-fleet name conflict is resolved by namespace prefix (`xyz.pearpaste` vs `acme.pearpaste`)
- Writes via Protomux RPC to whichever relay owns the bee key; reads via direct Hyperbee replication
- Identity = the publisher's swarm pubkey (Noise auth)

**Wins:**
- **Discoverability by name.** First-class UX win — install a Pear app by name, not 64-hex-char key.
- **Identity binding.** Publisher's pubkey is the proven owner per the Noise pattern.
- **Federation primitive.** Multiple fleets can run their own bees; clients query whichever they trust.
- **Optional & opt-in.** Doesn't change anything about how relays work today; layered on top.

**Effort:** ~1 week. New package or a sibling to `seeding-registry`. CLI commands. Federation gossip if multiple bees coexist. Migration story for existing publishers.

**Risk:** Product decision more than technical risk. Who owns the bee key? If HiveRelay org runs THE bee, we're a registrar; if every operator runs their own, namespace collisions become a UX problem.

**Defer this** unless there's clear demand. The technical pattern is solid; the product question isn't.

### Priority 4 — Per-key `_withMutationLock` pattern in `SeedingRegistry`

**Low leverage, low risk.** Hygiene.

Today, several `SeedingRegistry` mutation methods have race windows:

```js
async publishCustodyIntent (intent, publisherKeyPair) {
  // ... no lock; concurrent calls for the same intentId can both observe
  //     "no existing intent" and both append duplicates
}

async publishCustodyCommit (commit, publisherKeyPair) {
  // ... no lock; can race with concurrent recordCustodyReceipt indexing
}
```

The challenge's pattern:

```js
async _withMutationLock (fn) {
  const previous = this._mutationLock
  let release
  this._mutationLock = new Promise((resolve) => { release = resolve })
  await previous
  try { return await fn() } finally { release() }
}
```

Per-key version (only serialize within the same intentId):

```js
async _withKeyLock (key, fn) {
  const previous = this._keyLocks.get(key) || Promise.resolve()
  let release
  const next = new Promise((resolve) => { release = resolve })
  this._keyLocks.set(key, next)
  await previous
  try { return await fn() } finally {
    release()
    if (this._keyLocks.get(key) === next) this._keyLocks.delete(key)
  }
}
```

Wrap the 8 mutation paths in `SeedingRegistry` that currently can race.

**Wins:**
- Closes documented race windows.
- Clear contract for atomic mutations.
- Easier to add tests for atomicity guarantees.

**Effort:** ~1 day. ~50 LOC for the pattern + per-method wrap.

**Risk:** Very low. The locks are best-case noops (no contention); worst-case serialize same-key mutations.

---

## What we should NOT change

- **Multi-writer architecture for `SeedingRegistry`.** Federation correctness depends on it. Single-writer would require electing a registrar relay, which contradicts the manifesto.
- **Per-entry Ed25519 signatures on custody entries.** Cross-relay verification requires payload-level auth; Noise transport auth isn't enough.
- **JSON encoding within Hypercore blocks.** It's the current wire format; switching to compact-encoding is a different project (separable from registry redesign).

---

## Sequencing recommendation

If we do anything from this list, here's the order:

1. **First: Priority 4 (mutation lock).** Lowest risk, closes real races. ~1 day. Good warm-up.
2. **Then: Priority 1 (AppRegistry → Hyperbee).** Highest leverage, low risk, removes a class of fragility. Closes [#26](https://github.com/bigdestiny2/P2P-Hiverelay/issues/26). ~1 day.
3. **Then: Priority 2 (SeedingRegistry index sidecar).** Bigger project, medium risk. Plan the crash-recovery + idempotency carefully before starting. ~1 week.
4. **Defer Priority 3** until there's product clarity on whether HiveRelay wants to run a registrar.

Each step lands independently, has its own test surface, and doesn't break wire formats.

---

## Open questions

1. **Hyperbee write-coalescing.** Hyperbee already batches multiple `put`s into one Hypercore append via `bee.batch()`. Do we want to coalesce anchor-check updates across many drives into a single batch? Today's JSON-blob rewrites everything at once; we'd want to preserve that throughput characteristic.

2. **Migration story for existing `app-registry.json`.** First-run-after-upgrade reads the old JSON, imports into the bee, renames the JSON to `.bak`, never touches it again. Reversible? Probably not worth it.

3. **Should the indexed-views sidecar replicate to peers?** The view bee is a *derived* index; in principle each relay can rebuild it from the logs. So no, don't replicate it. Each relay maintains its own.

4. **Compaction.** Both the contributor's bee and ours have monotonic-growth via tombstones / cancellations / supersedes. When does it matter? Probably not for years. Worth planning the eventual compaction primitive but not building it now.
