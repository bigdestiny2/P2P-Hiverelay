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
    this.store = null
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
  }

  async stop () {
    if (this.pins) await this.pins.close()
    if (this.engine) await this.engine.close()
  }

  async put (params = {}) {
    const ciphertext = decodeCiphertext(params.ciphertext)
    // Compute the hash first so pin authorization can bind to it without
    // trusting a client-supplied hash.
    const hash = shardHash(ciphertext)
    if (ciphertext.byteLength > this.maxShardBytes) throw shardError('TOO_LARGE', 'shard exceeds maxShardBytes')
    if (!params.pin) throw shardError('UNAUTHORIZED_PIN', 'a signed pin is required to PUT')

    const pin = await authorizeShardPin(params.pin, {
      hash,
      byteLength: ciphertext.byteLength,
      relayPubkey: this.relayPubkey,
      allowedReasons: this.allowedReasons,
      resolveCustodyAssignment: this.resolveCustodyAssignment,
      checkPaymentQuota: this.checkPaymentQuota,
      checkToken: this.checkToken
    })

    const r = await this.engine.put(ciphertext, { claimedHash: params.claimedHash || null })
    const pinRef = this.pins.add(pin)
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
    return { ok: true, proof: buildShardAttestation({ hash, nonce, keyPair: this.keyPair }) }
  }

  /**
   * Retention GC: for every shard whose pins have all expired, sign a
   * non-serving tombstone (proof it stopped serving), delete the blob, and
   * purge the pins. Returns the tombstones (for the custody state machine).
   * The relay calls this on a timer / at custody expiry.
   */
  async sweep () {
    const now = this.clock()
    const expired = this.pins.expiredHashes(now)
    const tombstones = []
    for (const hash of expired) {
      if (this.keyPair) tombstones.push(buildShardTombstone({ hash, at: now, keyPair: this.keyPair }))
      await this.engine.delete(hash)
    }
    this.pins.purgeExpired(now)
    return { ok: true, swept: expired.length, tombstones }
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
    if (this.pins.refs(hash) === 0) {
      const del = await this.engine.delete(hash)
      removed = del.removed
    }
    return { ok: true, refs: res.refs, unpinned: res.removed, gc: removed }
  }
}

export default ShardStoreService
export {
  ShardEngine, DEFAULT_MAX_SHARD_BYTES, normalizeShardAddress, shardHash,
  ShardPinRegistry, authorizeShardPin, verifyShardPin, signShardPin, shardPinRef, SHARD_PIN_DOMAIN,
  buildShardRetrievalProof, buildShardAttestation, buildShardTombstone, verifyShardProof, verifyShardTombstone, SHARD_PROOF_DOMAIN,
  recoverShards, shardAnnounceTopic
}
