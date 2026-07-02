/**
 * ShardStoreService — the `shard-store` builtin service (ServiceProvider).
 *
 * Content-addressed blind blob surface for custody shards. M1 exposes the
 * put/get/has/unpin capabilities over the service RPC; the HTTP bridge, pin
 * authorization, custody manifest binding, and possession proofs land in later
 * milestones (docs/BLIND-SHARD-STORE-SPEC.md).
 */
import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import b4a from 'b4a'
import { ShardEngine, DEFAULT_MAX_SHARD_BYTES, normalizeShardAddress, shardHash } from './shard-engine.js'

export const SHARD_STORE_VERSION = '0.1.0'

function decodeCiphertext (input) {
  if (b4a.isBuffer(input)) return input
  if (input instanceof Uint8Array) return b4a.from(input)
  if (typeof input === 'string') return b4a.from(input, 'base64')
  throw Object.assign(new Error('ciphertext must be bytes or base64 string'), { code: 'BAD_CIPHERTEXT' })
}

export class ShardStoreService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.opts = opts
    this.engine = opts.engine || null
    this.maxShardBytes = Number.isFinite(opts.maxShardBytes) ? opts.maxShardBytes : DEFAULT_MAX_SHARD_BYTES
    this.store = null
  }

  manifest () {
    return {
      name: 'shard-store',
      version: SHARD_STORE_VERSION,
      description: 'Content-addressed blind blob store for custody shards (shard:<hash>)',
      capabilities: ['put', 'get', 'has', 'unpin'],
      addressing: 'blake2b-256-ciphertext',
      limits: { maxShardBytes: this.maxShardBytes }
    }
  }

  async start (context = {}) {
    this.store = context.store || this.opts.store || null
    if (!this.engine) {
      if (!this.store) throw new Error('ShardStoreService: corestore required (context.store)')
      this.engine = new ShardEngine(this.store, { maxShardBytes: this.maxShardBytes })
    }
    await this.engine.ready()
  }

  async stop () {
    if (this.engine) await this.engine.close()
  }

  async put (params = {}) {
    const ciphertext = decodeCiphertext(params.ciphertext)
    const r = await this.engine.put(ciphertext, { claimedHash: params.claimedHash || null })
    return { ok: true, shard: r.address, byteLength: r.byteLength, deduped: r.deduped }
  }

  async get (params = {}) {
    const r = await this.engine.get(params.shard || params.hash)
    // base64 keeps the ciphertext opaque + JSON-safe over the RPC envelope.
    return { ok: true, shard: 'shard:' + r.hash, byteLength: r.byteLength, encoding: 'base64', ciphertext: b4a.toString(r.ciphertext, 'base64') }
  }

  async has (params = {}) {
    const r = await this.engine.has(params.shard || params.hash)
    return { ok: true, ...r }
  }

  async unpin (params = {}) {
    const r = await this.engine.unpin(params.shard || params.hash)
    return { ok: true, ...r }
  }
}

export default ShardStoreService
export { ShardEngine, DEFAULT_MAX_SHARD_BYTES, normalizeShardAddress, shardHash }
