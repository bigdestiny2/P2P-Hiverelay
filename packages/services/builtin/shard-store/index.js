/**
 * ShardStoreService — the `shard-store` builtin service (ServiceProvider).
 *
 * Content-addressed blind blob surface for custody shards. Every PUT is
 * authorized by a signed pin (custody assignment or payment/quota) and the
 * pin registry is the retention authority — a shard lives while it has >=1
 * live pin. See docs/BLIND-SHARD-STORE-SPEC.md.
 */
import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import b4a from 'b4a'
import { ShardEngine, DEFAULT_MAX_SHARD_BYTES, normalizeShardAddress, shardHash, shardError } from './shard-engine.js'
import { ShardPinRegistry, authorizeShardPin, verifyShardPin, signShardPin, shardPinRef, SHARD_PIN_DOMAIN } from './shard-pin.js'
import {
  buildShardRetrievalProof, buildShardAttestation, buildShardTombstone, verifyShardProof, verifyShardTombstone,
  SHARD_PROOF_DOMAIN, SHARD_PROOF_KIND, SHARD_PROOF_LIMITATION
} from './shard-proof.js'
import { recoverShards, shardAnnounceTopic } from './shard-recover.js'
import { resolveShardRoute, handleShardHttp, createShardHttpState, SHARD_HTTP_PREFIX } from './http-adapter.js'

export const SHARD_STORE_VERSION = '0.1.0'
const DEFAULT_PUT_AUTH = ['custody', 'payment']
const DEFAULT_PROOF_BUCKET = { perHour: 600, burst: 60 }

// Minimal per-caller token bucket (proof-spam throttle), mirroring the notify
// consumeBucket shape so behaviour is familiar.
function consumeProofBucket (buckets, key, quota, now) {
  const perHour = quota.perHour > 0 ? quota.perHour : 0
  const burst = quota.burst > 0 ? quota.burst : perHour
  if (!perHour || !burst) return false
  let b = buckets.get(key)
  if (!b || now - b.start >= 3600000) b = { start: now, count: 0, burstStart: now, burstCount: 0 }
  if (now - b.burstStart >= 60000) { b.burstStart = now; b.burstCount = 0 }
  if (b.count >= perHour || b.burstCount >= burst) { buckets.set(key, b); return false }
  b.count++; b.burstCount++; buckets.set(key, b)
  return true
}

function numOr (v, fallback) {
  return Number.isFinite(v) ? v : fallback
}

function decodeCiphertext (input) {
  if (b4a.isBuffer(input)) return input
  if (input instanceof Uint8Array) return b4a.from(input)
  if (typeof input === 'string') return b4a.from(input, 'base64')
  throw shardError('BAD_CIPHERTEXT', 'ciphertext must be bytes or base64 string')
}

function relayPubkeyFromContext (context, opts) {
  const kp = opts.keyPair || (context.node && (context.node.keyPair || (context.node.swarm && context.node.swarm.keyPair)))
  if (opts.relayPubkey) return opts.relayPubkey
  if (kp && kp.publicKey) return b4a.toString(kp.publicKey, 'hex')
  return null
}

export class ShardStoreService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.opts = opts
    this.engine = opts.engine || null
    this.pins = opts.pins || null
    this.maxShardBytes = Number.isFinite(opts.maxShardBytes) ? opts.maxShardBytes : DEFAULT_MAX_SHARD_BYTES
    this.allowedReasons = Array.isArray(opts.putAuth) ? opts.putAuth : DEFAULT_PUT_AUTH
    // Injected authorization hooks (relay-wired). Tests pass stubs.
    this.resolveCustodyAssignment = opts.resolveCustodyAssignment || null
    this.checkPaymentQuota = opts.checkPaymentQuota || null
    this.checkToken = opts.checkToken || null
    this.relayPubkey = opts.relayPubkey || null
    this.keyPair = opts.keyPair || null
    this.proofBucketQuota = opts.proofBuckets || DEFAULT_PROOF_BUCKET
    this._proofBuckets = new Map()
    this.clock = typeof opts.clock === 'function' ? opts.clock : () => Date.now()
    // Metrics counters (aggregate only — never per-hash, for privacy).
    this._metrics = { put: 0, get: 0, proof: 0, sweep: 0, rejected: 0, evicted: 0 }
    this.store = null
    // Cached shard byte total for the StorageAccounting source callback — a
    // cheap synchronous read (recomputed on put/sweep/unpin/evict), so the
    // relay's accounting sweep never has to walk the shard index (STO-005).
    this._cachedBytes = 0
    this._accounting = null
    // Disk-pressure thresholds for the shard eviction path (STO-005). Above
    // diskPressurePct we shed expired shards; only above hardCeilingPct do we
    // touch still-valid (retainUntil-live) pins, lowest-priority first.
    this.evictionConfig = {
      diskPressurePct: numOr(opts.eviction?.diskPressurePct, 85),
      hardCeilingPct: numOr(opts.eviction?.hardCeilingPct, 97),
      maxEvictionsPerSweep: numOr(opts.eviction?.maxEvictionsPerSweep, 256)
    }
  }

  manifest () {
    return {
      name: 'shard-store',
      version: SHARD_STORE_VERSION,
      description: 'Content-addressed blind blob store for custody shards (shard:<hash>)',
      capabilities: ['put', 'get', 'has', 'unpin', 'prove'],
      addressing: 'blake2b-256-ciphertext',
      pinDomain: SHARD_PIN_DOMAIN,
      proofDomain: SHARD_PROOF_DOMAIN,
      proofKind: SHARD_PROOF_KIND,
      proofLimitation: SHARD_PROOF_LIMITATION,
      putAuth: this.allowedReasons,
      limits: { maxShardBytes: this.maxShardBytes }
    }
  }

  async start (context = {}) {
    this.store = context.store || this.opts.store || null
    this.keyPair = this.keyPair || (context.node && (context.node.keyPair || (context.node.swarm && context.node.swarm.keyPair))) || null
    this.relayPubkey = this.relayPubkey || relayPubkeyFromContext(context, this.opts)
    // Relay-wired authorization hooks. Constructor opts win (tests inject
    // stubs); otherwise the relay supplies them through the service start
    // context, mirroring how keyPair/relayPubkey are pulled from context above.
    // Absent a hook, the matching pin reason is cleanly unauthorized — never a
    // crash. putAuth may likewise be narrowed by the relay to the reasons it can
    // actually back (e.g. ['custody'] until per-pinner payment quota exists), so
    // manifest().putAuth never advertises an unenforceable path.
    this.resolveCustodyAssignment = this.resolveCustodyAssignment || context.resolveCustodyAssignment || null
    this.checkPaymentQuota = this.checkPaymentQuota || context.checkPaymentQuota || null
    this.checkToken = this.checkToken || context.checkToken || null
    if (!Array.isArray(this.opts.putAuth) && Array.isArray(context.shardPutAuth)) {
      this.allowedReasons = context.shardPutAuth
    }
    if (!this.engine) {
      if (!this.store) throw new Error('ShardStoreService: corestore required (context.store)')
      this.engine = new ShardEngine(this.store, { maxShardBytes: this.maxShardBytes })
    }
    if (!this.pins) {
      this.pins = new ShardPinRegistry({
        persistence: this.opts.pinPersistence || null,
        persistFlushMs: this.opts.persistFlushMs,
        clock: this.clock
      })
    }
    await this.engine.ready()
    await this.pins.load()
    await this._refreshCachedBytes()
    // Register shard bytes with the relay's StorageAccounting so they are no
    // longer invisible to the adoption/eviction guards (STO-005). The relay
    // passes its accounting instance via the start context; absent it, the
    // service still works (just uncounted, as before).
    const accounting = this.opts.storageAccounting || context.storageAccounting || null
    if (accounting) this.registerStorageAccounting(accounting)
  }

  /** Recompute the cached shard byte total from the engine (authoritative). */
  async _refreshCachedBytes () {
    try {
      const s = await this.engine.stats()
      this._cachedBytes = Number.isFinite(s.bytes) ? s.bytes : this._cachedBytes
    } catch { /* keep the last known value on a transient stats failure */ }
    return this._cachedBytes
  }

  /**
   * Register this service's shard byte usage with a StorageAccounting instance
   * (STO-005). The callback is synchronous and returns the cached total, so the
   * relay's accounting sweep never walks the shard index.
   */
  registerStorageAccounting (accounting) {
    if (!accounting || typeof accounting.registerExternalSource !== 'function') return false
    this._accounting = accounting
    accounting.registerExternalSource('shard-store', () => this._cachedBytes)
    return true
  }

  async stop () {
    if (this._accounting && typeof this._accounting.unregisterExternalSource === 'function') {
      this._accounting.unregisterExternalSource('shard-store')
    }
    if (this.pins) await this.pins.close()
    if (this.engine) await this.engine.close()
  }

  async put (params = {}) {
    const ciphertext = decodeCiphertext(params.ciphertext)
    // Compute the hash first so pin authorization can bind to it without
    // trusting a client-supplied hash.
    const hash = shardHash(ciphertext)
    if (ciphertext.byteLength > this.maxShardBytes) throw shardError('TOO_LARGE', 'shard exceeds maxShardBytes')
    if (!params.pin) { this._metrics.rejected++; throw shardError('UNAUTHORIZED_PIN', 'a signed pin is required to PUT') }

    let pin
    try {
      pin = await authorizeShardPin(params.pin, {
        hash,
        byteLength: ciphertext.byteLength,
        relayPubkey: this.relayPubkey,
        allowedReasons: this.allowedReasons,
        resolveCustodyAssignment: this.resolveCustodyAssignment,
        checkPaymentQuota: this.checkPaymentQuota,
        checkToken: this.checkToken
      })
    } catch (err) {
      this._metrics.rejected++
      throw err
    }

    const r = await this.engine.put(ciphertext, { claimedHash: params.claimedHash || null })
    const pinRef = this.pins.add(pin)
    if (!r.deduped) this._cachedBytes += r.byteLength // new bytes on disk
    this._metrics.put++
    return {
      ok: true,
      shard: r.address,
      byteLength: r.byteLength,
      deduped: r.deduped,
      pinRef,
      refs: this.pins.refs(hash),
      retainUntil: this.pins.retainUntil(hash)
    }
  }

  async get (params = {}) {
    const r = await this.engine.get(params.shard || params.hash)
    this._metrics.get++
    const out = { ok: true, shard: 'shard:' + r.hash, byteLength: r.byteLength, encoding: 'base64', ciphertext: b4a.toString(r.ciphertext, 'base64') }
    // A nonce upgrades GET to Mode R: a relay-signed, replay-guarded proof that
    // these exact bytes were served for this challenge.
    if (params.nonce && this.keyPair) {
      out.proof = buildShardRetrievalProof({ hash: r.hash, nonce: params.nonce, bytes: r.ciphertext, keyPair: this.keyPair })
    }
    return out
  }

  async has (params = {}) {
    const r = await this.engine.has(params.shard || params.hash)
    return { ok: true, ...r }
  }

  /**
   * Mode A signed possession attestation (no bytes transferred). Only for a
   * held shard; NOT_HELD is indistinguishable from unauthorized/absent. Fresh
   * nonce required; per-caller throttled.
   */
  async prove (params = {}, context = {}) {
    if (!this.keyPair) throw shardError('SERVICE_UNAVAILABLE', 'relay signing key unavailable')
    const hash = normalizeShardAddress(params.shard || params.hash)
    if (!hash) throw shardError('BAD_ADDRESS', 'invalid shard address')
    const nonce = params.nonce
    const caller = String(context.remotePubkey || context.caller || 'anon')
    if (!consumeProofBucket(this._proofBuckets, caller, this.proofBucketQuota, this.clock())) {
      throw shardError('RATE_LIMITED', 'proof rate limit')
    }
    // Phantom-hash DoS guard: a single constant-time index lookup, and an
    // unheld hash is indistinguishable from an unauthorized one.
    const present = (await this.engine.has(hash)).present
    if (!present) throw shardError('NOT_HELD', 'shard not held')
    this._metrics.proof++
    return { ok: true, proof: buildShardAttestation({ hash, nonce, keyPair: this.keyPair }) }
  }

  /** Prometheus lines (aggregate; no per-hash labels). */
  async metricsLines () {
    const s = await this.engine.stats()
    return [
      '# HELP hiverelay_shards_held Content-addressed shards currently held',
      '# TYPE hiverelay_shards_held gauge',
      'hiverelay_shards_held ' + s.shards,
      '# HELP hiverelay_shard_bytes Bytes of shard ciphertext held',
      '# TYPE hiverelay_shard_bytes gauge',
      'hiverelay_shard_bytes ' + s.bytes,
      '# TYPE hiverelay_shard_put_total counter',
      'hiverelay_shard_put_total ' + this._metrics.put,
      '# TYPE hiverelay_shard_get_total counter',
      'hiverelay_shard_get_total ' + this._metrics.get,
      '# TYPE hiverelay_shard_proof_total counter',
      'hiverelay_shard_proof_total ' + this._metrics.proof,
      '# TYPE hiverelay_shard_rejected_total counter',
      'hiverelay_shard_rejected_total ' + this._metrics.rejected
    ]
  }

  /**
   * Retention GC: for every shard whose pins have all expired, sign a
   * non-serving tombstone (proof it stopped serving), delete the blob, and
   * purge the pins. Returns the tombstones (for the custody state machine).
   * The relay calls this on a timer / at custody expiry.
   */
  async sweep () {
    const now = this.clock()
    // Visit every hash with at least one expired pin — not only fully-expired
    // hashes — so an expired pin on a still-live hash is purged and its engine
    // dedup ref reconciled, while the bytes a remaining live pin references are
    // retained (STO-002).
    const expired = this.pins.hashesWithExpiredPins(now)
    const tombstones = []
    const swept = []
    for (const hash of expired) {
      // Reconcile the engine dedup ref-count with the pins we purge: every PUT
      // contributed one engine ref + one pin, so drop one engine ref per purged
      // (expired) pin. Only EXPIRED pins are removed — a live pin added
      // concurrently for this hash survives. Then delete the bytes ONLY if BOTH
      // the engine dedup count AND the remaining pin count are zero (STO-002).
      // The engine serializes this check-then-delete against any concurrent
      // PUT-dedup for the same hash, so a shard a live index generation still
      // references is never silently wiped.
      const purged = this.pins.purgeExpiredPins(hash, now)
      for (let i = 0; i < purged; i++) await this.engine.decRef(hash)
      const pinRefs = this.pins.refs(hash, now)
      const del = await this.engine.deleteIfUnreferenced(hash, { pinRefs })
      if (del.removed) {
        if (this.keyPair) tombstones.push(buildShardTombstone({ hash, at: now, keyPair: this.keyPair }))
        swept.push(hash)
      }
    }
    this._metrics.sweep += swept.length
    if (swept.length) await this._refreshCachedBytes()
    return { ok: true, swept: swept.length, tombstones }
  }

  /**
   * Disk-pressure eviction for shards (STO-005). Bounds unbounded growth from
   * valid long-retainUntil pins that would otherwise fill the disk (the
   * disk-full failure this fleet already hit).
   *
   * Policy, from safest to most aggressive:
   *   1. Below diskPressurePct: no-op.
   *   2. At/above diskPressurePct: sweep expired shards (same as sweep()).
   *   3. At/above hardCeilingPct ONLY: shed still-valid pins, lowest-priority
   *      first (soonest-expiring retainUntil), to claw back space on a truly
   *      full box. Below the hard ceiling a still-valid retainUntil pin is
   *      NEVER evicted — the retention floor holds.
   *
   * @param {object} p
   * @param {number} p.usedPct           current disk used percentage (0-100)
   * @param {number} [p.diskPressurePct] override the configured pressure gate
   * @param {number} [p.hardCeilingPct]  override the configured hard ceiling
   * @param {number} [p.maxEvictions]    cap evictions this pass
   * @returns {{ ok, usedPct, skipped?, expiredEvicted, forcedEvicted, evicted, tombstones }}
   */
  async evictUnderPressure ({ usedPct, diskPressurePct, hardCeilingPct, maxEvictions } = {}) {
    const now = this.clock()
    const pressurePct = numOr(diskPressurePct, this.evictionConfig.diskPressurePct)
    const ceilingPct = numOr(hardCeilingPct, this.evictionConfig.hardCeilingPct)
    const cap = numOr(maxEvictions, this.evictionConfig.maxEvictionsPerSweep)
    const tombstones = []

    if (!Number.isFinite(usedPct) || usedPct < pressurePct) {
      return { ok: true, usedPct, skipped: 'below-pressure', expiredEvicted: 0, forcedEvicted: 0, evicted: 0, tombstones }
    }

    // Step 2: always reclaim expired shards under pressure.
    const swept = await this.sweep()
    for (const tomb of swept.tombstones) tombstones.push(tomb)
    const expiredEvicted = swept.swept
    let forcedEvicted = 0

    // Step 3: only on a truly full box do we touch STILL-VALID pins. Below the
    // hard ceiling the retainUntil floor is absolute — a valid pin is retained.
    if (usedPct >= ceilingPct) {
      // Lowest-priority first = soonest-to-expire retainUntil (least remaining
      // value to the custody set). Deterministic and privacy-preserving (no
      // per-hash logging).
      const ranked = this.pins.liveHashes(now)
        .map(hash => ({ hash, retainUntil: this.pins.retainUntil(hash, now) }))
        .sort((a, b) => a.retainUntil - b.retainUntil)
      for (const { hash } of ranked) {
        if (expiredEvicted + forcedEvicted >= cap) break
        // Force-drop every pin + the bytes for this hash.
        this.pins.purgeHash(hash)
        const del = await this.engine.deleteIfUnreferenced(hash, { pinRefs: 0, force: true })
        if (del.removed) {
          if (this.keyPair) tombstones.push(buildShardTombstone({ hash, at: now, keyPair: this.keyPair }))
          forcedEvicted++
        }
      }
    }

    const evicted = expiredEvicted + forcedEvicted
    this._metrics.evicted += forcedEvicted
    if (evicted) await this._refreshCachedBytes()
    return { ok: true, usedPct, expiredEvicted, forcedEvicted, evicted, tombstones }
  }

  /** Bytes + shard count, for StorageAccounting + metrics (no per-hash detail). */
  async stats () {
    const s = await this.engine.stats()
    return { ok: true, shards: s.shards, bytes: s.bytes }
  }

  /** The DHT topic a holder announces on / a client looks up for a shard. */
  announceTopic (params = {}) {
    return { ok: true, topic: b4a.toString(shardAnnounceTopic(params.shard || params.hash), 'hex') }
  }

  /** Remove one pin. When the last live pin is gone, GC the blob. */
  async unpin (params = {}) {
    const hash = normalizeShardAddress(params.shard || params.hash)
    if (!hash) throw shardError('BAD_ADDRESS', 'invalid shard address')
    if (!params.pinRef || !params.removal) throw shardError('BAD_REQUEST', 'pinRef + signed removal required')
    const res = this.pins.remove(hash, params.pinRef, params.removal)
    let removed = false
    if (res.removed) {
      // One pin gone -> drop the matching engine dedup ref, then delete the
      // bytes ONLY if BOTH the engine dedup count AND the remaining live pin
      // count are zero (STO-002). Atomic vs. a concurrent PUT-dedup.
      await this.engine.decRef(hash)
      const del = await this.engine.deleteIfUnreferenced(hash, { pinRefs: this.pins.refs(hash) })
      removed = del.removed
      if (removed) await this._refreshCachedBytes()
    }
    return { ok: true, refs: res.refs, unpinned: res.removed, gc: removed }
  }
}

export default ShardStoreService
export {
  ShardEngine, DEFAULT_MAX_SHARD_BYTES, normalizeShardAddress, shardHash,
  ShardPinRegistry, authorizeShardPin, verifyShardPin, signShardPin, shardPinRef, SHARD_PIN_DOMAIN,
  buildShardRetrievalProof, buildShardAttestation, buildShardTombstone, verifyShardProof, verifyShardTombstone, SHARD_PROOF_DOMAIN,
  recoverShards, shardAnnounceTopic,
  resolveShardRoute, handleShardHttp, createShardHttpState, SHARD_HTTP_PREFIX
}
