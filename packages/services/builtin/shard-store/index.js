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

export const SHARD_STORE_VERSION = '0.1.0'
const DEFAULT_PUT_AUTH = ['custody', 'payment']

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
    this.store = null
  }

  manifest () {
    return {
      name: 'shard-store',
      version: SHARD_STORE_VERSION,
      description: 'Content-addressed blind blob store for custody shards (shard:<hash>)',
      capabilities: ['put', 'get', 'has', 'unpin'],
      addressing: 'blake2b-256-ciphertext',
      pinDomain: SHARD_PIN_DOMAIN,
      putAuth: this.allowedReasons,
      limits: { maxShardBytes: this.maxShardBytes }
    }
  }

  async start (context = {}) {
    this.store = context.store || this.opts.store || null
    this.relayPubkey = this.relayPubkey || relayPubkeyFromContext(context, this.opts)
    if (!this.engine) {
      if (!this.store) throw new Error('ShardStoreService: corestore required (context.store)')
      this.engine = new ShardEngine(this.store, { maxShardBytes: this.maxShardBytes })
    }
    if (!this.pins) {
      this.pins = new ShardPinRegistry({
        persistence: this.opts.pinPersistence || null,
        persistFlushMs: this.opts.persistFlushMs
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
    return { ok: true, shard: 'shard:' + r.hash, byteLength: r.byteLength, encoding: 'base64', ciphertext: b4a.toString(r.ciphertext, 'base64') }
  }

  async has (params = {}) {
    const r = await this.engine.has(params.shard || params.hash)
    return { ok: true, ...r }
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
  ShardPinRegistry, authorizeShardPin, verifyShardPin, signShardPin, shardPinRef, SHARD_PIN_DOMAIN
}
