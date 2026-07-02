/**
 * ShardEngine — content-addressed blind blob store.
 *
 * A shard is opaque ciphertext addressed by `shard:<hash>` where
 * `hash = blake2b-256(ciphertext)`. The engine only ever hashes, stores, and
 * serves bytes — it never introspects or decrypts. Integrity is self-proving:
 * a caller re-hashes what GET returns and trusts the relay for nothing.
 *
 * Storage: a `hyperblobs` instance over a dedicated Hypercore holds the bytes
 * (and the Merkle tree a possession proof will use, M3); a `Hyperbee` maps
 * `hash -> { blobId, byteLength, refs, addedAt }` to make it content-addressed
 * (hyperblobs itself addresses by offset id, not by content hash).
 *
 * M1 scope: put/get/has/unpin with content-address integrity + dedup + caps.
 * Pin authorization, custody binding, proofs, retention are later milestones —
 * see docs/BLIND-SHARD-STORE-SPEC.md.
 */
import Hyperblobs from 'hyperblobs'
import Hyperbee from 'hyperbee'
import sodium from 'sodium-universal'
import b4a from 'b4a'

const HASH_BYTES = 32
const HEX64 = /^[0-9a-f]{64}$/
export const DEFAULT_MAX_SHARD_BYTES = 4 * 1024 * 1024

export function shardHash (ciphertext) {
  const bytes = b4a.isBuffer(ciphertext) ? ciphertext : b4a.from(ciphertext)
  const out = b4a.alloc(HASH_BYTES)
  sodium.crypto_generichash(out, bytes) // BLAKE2b-256
  return b4a.toString(out, 'hex')
}

/** Accept "shard:<hex>" or a bare 64-hex string; returns lowercase hex or null. */
export function normalizeShardAddress (address) {
  if (typeof address !== 'string') return null
  const raw = address.startsWith('shard:') ? address.slice('shard:'.length) : address
  const lower = raw.trim().toLowerCase()
  return HEX64.test(lower) ? lower : null
}

export function shardError (code, message) {
  const err = new Error(code + (message ? ': ' + message : ''))
  err.code = code
  return err
}

export class ShardEngine {
  constructor (store, { maxShardBytes = DEFAULT_MAX_SHARD_BYTES, namespace = 'shard-store', clock = () => Date.now() } = {}) {
    if (!store || typeof store.get !== 'function') throw new Error('ShardEngine: corestore required')
    this.maxShardBytes = maxShardBytes
    this.clock = clock
    this._blobsCore = store.get({ name: namespace + '/blobs' })
    this._indexCore = store.get({ name: namespace + '/index' })
    this.blobs = new Hyperblobs(this._blobsCore)
    this.index = new Hyperbee(this._indexCore, { keyEncoding: 'utf-8', valueEncoding: 'json' })
    this._ready = null
  }

  async ready () {
    if (!this._ready) this._ready = Promise.all([this._blobsCore.ready(), this.index.ready()])
    await this._ready
  }

  async close () {
    for (const fn of [
      () => (typeof this.blobs.close === 'function' ? this.blobs.close() : null),
      () => this.index.close(),
      () => this._blobsCore.close()
    ]) {
      try { await fn() } catch {}
    }
  }

  /**
   * Store ciphertext. Idempotent: identical bytes -> same hash -> refs bumped,
   * no new storage (`deduped: true`). Rejects a mismatched `claimedHash`.
   */
  async put (ciphertext, { claimedHash = null } = {}) {
    await this.ready()
    const bytes = b4a.isBuffer(ciphertext) ? ciphertext : b4a.from(ciphertext)
    if (bytes.byteLength === 0) throw shardError('EMPTY', 'shard is empty')
    if (bytes.byteLength > this.maxShardBytes) throw shardError('TOO_LARGE', 'shard exceeds maxShardBytes')
    const hash = shardHash(bytes)
    if (claimedHash != null && normalizeShardAddress(claimedHash) !== hash) {
      throw shardError('HASH_MISMATCH', 'ciphertext does not hash to claimedHash')
    }
    const existing = await this.index.get(hash)
    if (existing && existing.value) {
      const rec = existing.value
      rec.refs = (rec.refs || 0) + 1
      await this.index.put(hash, rec)
      return { hash, address: 'shard:' + hash, byteLength: rec.byteLength, deduped: true }
    }
    const blobId = await this.blobs.put(bytes)
    const rec = { hash, blobId, byteLength: bytes.byteLength, refs: 1, addedAt: this.clock() }
    await this.index.put(hash, rec)
    return { hash, address: 'shard:' + hash, byteLength: bytes.byteLength, deduped: false }
  }

  /** Return the exact ciphertext for a held shard, or throw NOT_HELD. */
  async get (address) {
    await this.ready()
    const hash = normalizeShardAddress(address)
    if (!hash) throw shardError('BAD_ADDRESS', 'invalid shard address')
    const node = await this.index.get(hash)
    if (!node || !node.value) throw shardError('NOT_HELD', 'shard not held')
    const bytes = await this.blobs.get(node.value.blobId)
    if (!bytes) throw shardError('NOT_HELD', 'shard not held')
    return { hash, byteLength: node.value.byteLength, ciphertext: bytes }
  }

  async has (address) {
    await this.ready()
    const hash = normalizeShardAddress(address)
    if (!hash) return { present: false }
    const node = await this.index.get(hash)
    return node && node.value ? { present: true, byteLength: node.value.byteLength } : { present: false }
  }

  /** M1 ref-count decrement + GC at zero. Pin-auth arrives in M2. */
  async unpin (address) {
    await this.ready()
    const hash = normalizeShardAddress(address)
    if (!hash) throw shardError('BAD_ADDRESS', 'invalid shard address')
    const node = await this.index.get(hash)
    if (!node || !node.value) return { refs: 0, removed: false }
    const rec = node.value
    rec.refs = Math.max(0, (rec.refs || 0) - 1)
    if (rec.refs === 0) {
      if (typeof this.blobs.clear === 'function') { try { await this.blobs.clear(rec.blobId) } catch {} }
      await this.index.del(hash)
      return { refs: 0, removed: true }
    }
    await this.index.put(hash, rec)
    return { refs: rec.refs, removed: false }
  }

  /** Force-remove a shard's bytes + index row, ignoring the engine ref count.
   *  Used when the pin registry (the retention authority) drops to zero pins. */
  async delete (address) {
    await this.ready()
    const hash = normalizeShardAddress(address)
    if (!hash) throw shardError('BAD_ADDRESS', 'invalid shard address')
    const node = await this.index.get(hash)
    if (!node || !node.value) return { removed: false }
    if (typeof this.blobs.clear === 'function') { try { await this.blobs.clear(node.value.blobId) } catch {} }
    await this.index.del(hash)
    return { removed: true }
  }

  async stats () {
    await this.ready()
    let shards = 0
    let bytes = 0
    for await (const { value } of this.index.createReadStream()) {
      shards++
      bytes += value && Number.isFinite(value.byteLength) ? value.byteLength : 0
    }
    return { shards, bytes }
  }
}
