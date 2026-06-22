/**
 * StorageProofService — Tier-2 trustless seed verification (relay side).
 *
 * Answers `prove({ coreKey, index, nonce })` with a signed Hypercore Merkle
 * proof for block `index` of a SEEDED drive's metadata core, signed with the
 * relay's swarm identity key. The caller verifies it with `verifyStorageProof`
 * against the drive key alone — the relay is trusted for nothing. See
 * packages/core/core/protocol/proof-of-storage.js for the proof itself.
 *
 * SECURITY:
 *  - PRIVACY GATE: never confirms possession of a BLIND / privacy-redacted
 *    drive. A signed proof is cryptographic, relay-attributable evidence that
 *    this relay holds a key; serving it for a blind drive would defeat the
 *    catalog's deliberate redaction (AppRegistry._shouldRedactEntry). Blind/
 *    redacted keys return NOT_SEEDED — INDISTINGUISHABLE from a key the relay
 *    genuinely doesn't hold, so prove() can't be used as a possession oracle.
 *  - PHANTOM-CORE DoS GUARD: only serves keys present in node.appRegistry. It
 *    NEVER calls store.get() on a caller-supplied key (which would create an
 *    unbounded phantom Hypercore per request).
 *  - RATE LIMIT: a GLOBAL token bucket caps total proof work regardless of how
 *    many ephemeral swarm identities connect (the per-caller bucket alone is
 *    bypassable by rotating identities). The global bucket is consumed only for
 *    REAL proof work — cheap rejects (bad input / not-seeded / blind) never
 *    spend it, so a not-seeded flood can't starve honest callers. The per-caller
 *    bucket Map is idle-evicted + size-capped so it can't grow unbounded.
 *  - buildStorageProof reads LOCAL storage only and throws BLOCK_NOT_LOCAL /
 *    BLOCK_OUT_OF_RANGE if the relay doesn't actually hold the block.
 *
 * v1 proves the drive's METADATA core (drive.core) — the head the client learns
 * from open(), so its minLength pin lines up. Proving the blobs core is a
 * follow-up (needs a `core: meta|blobs` selector + a timeout-guarded getBlobs()).
 */

import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import { buildStorageProof } from 'p2p-hiverelay/core/protocol/proof-of-storage.js'
import b4a from 'b4a'

const HEX64 = /^[0-9a-f]{64}$/i

export class StorageProofService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.node = null
    // Bare runtime passes the relay identity here (it has no node.keyPair);
    // the Node runtime sets node.keyPair, so this stays null there.
    this._keyPair = opts.keyPair || null

    // Per-caller token bucket (a sticky identity gets a small burst).
    this._rlTokensPerMin = opts.proofsPerMin != null ? opts.proofsPerMin : 120
    this._rlBurst = opts.proofBurst != null ? opts.proofBurst : 32
    this._buckets = new Map() // callerKey -> { tokens, lastRefill }
    this._maxBuckets = opts.maxBuckets || 5000
    this._bucketTtlMs = opts.bucketTtlMs || 10 * 60_000

    // Global aggregate bucket — the real, sybil-resistant cap on proof WORK.
    this._glPerMin = opts.globalProofsPerMin != null ? opts.globalProofsPerMin : 1200
    this._glBurst = opts.globalProofBurst != null ? opts.globalProofBurst : 400
    this._global = { tokens: this._glBurst, lastRefill: 0 }

    this._sweep = null
  }

  manifest () {
    return {
      name: 'storage-proof',
      version: '1.0.0',
      description: 'Signed challenge-response proof that this relay holds a seeded block',
      capabilities: ['prove']
    }
  }

  async start (context = {}) {
    this.node = context.node
    this._global.lastRefill = Date.now()
    // Bound _buckets: evict fully-refilled idle entries periodically.
    this._sweep = setInterval(() => this._evictIdle(), 60_000)
    if (this._sweep && this._sweep.unref) this._sweep.unref()
  }

  async stop () {
    if (this._sweep) { clearInterval(this._sweep); this._sweep = null }
    this._buckets.clear()
  }

  /**
   * Produce a signed proof of possession for block `index` of a seeded,
   * non-private drive's metadata core.
   * @param {{coreKey:string, index:number, nonce:string}} params
   * @param {{remotePubkey?:Buffer|string, caller?:string}} context
   */
  async prove (params = {}, context = {}) {
    const node = this.node
    if (!node || !node.appRegistry) throw new Error('SERVICE_UNAVAILABLE')
    const keyPair = this._keyPair || node.keyPair
    if (!keyPair || !keyPair.secretKey) throw new Error('NO_RELAY_KEYPAIR')

    // 1. Cheap input validation — reject malformed floods first (no allocation).
    const { coreKey, index, nonce: nonceHex } = params
    if (typeof coreKey !== 'string' || !HEX64.test(coreKey)) throw new Error('BAD_CORE_KEY')
    if (!Number.isInteger(index) || index < 0) throw new Error('BAD_INDEX')
    if (typeof nonceHex !== 'string' || !HEX64.test(nonceHex)) throw new Error('BAD_NONCE')
    const keyHex = coreKey.toLowerCase()

    // 2. Seeded + privacy guard — O(1), BEFORE any rate-bucket spend, so a
    //    not-seeded/blind flood costs only a Map lookup and never starves the
    //    proof budget. Blind/redacted keys return the SAME error as not-held.
    if (!node.appRegistry.has(keyHex)) throw new Error('NOT_SEEDED')
    const entry = node.appRegistry.get(keyHex)
    if (!entry || !entry.drive) throw new Error('NOT_SEEDED') // null-discoveryKey placeholder
    if (this._isRedacted(node.appRegistry, entry)) throw new Error('NOT_SEEDED')

    // 3. Per-caller bucket (only seeded-key callers allocate one).
    if (!this._takeToken(this._callerKey(context))) throw new Error('RATE_LIMITED')

    // 4. Global bucket — caps total proof WORK across all identities. Spent
    //    only here, right before the expensive build, so cheap rejects above
    //    can't drain it.
    if (!this._takeGlobal()) throw new Error('RATE_LIMITED')

    // 5. Resolve the metadata core (the head the client learns via open()).
    const drive = entry.drive
    if (drive.closed || drive.closing) throw new Error('DRIVE_CLOSED')
    if (typeof drive.ready === 'function') await drive.ready()
    const core = drive.core || (drive.db && drive.db.core)
    if (!core) throw new Error('NO_META_CORE')

    // 6. buildStorageProof validates range + local presence and throws
    //    BLOCK_OUT_OF_RANGE / BLOCK_NOT_LOCAL — surfaced as-is.
    const nonce = b4a.from(nonceHex, 'hex')
    return buildStorageProof({ core, index, nonce, keyPair })
  }

  /**
   * Honor the publisher's privacy commitment: a blind or privacy-redacted drive
   * must be indistinguishable from one we don't hold. Reuses the catalog's own
   * predicate so the two surfaces never drift; falls back to the blind flag.
   */
  _isRedacted (appRegistry, entry) {
    if (typeof appRegistry._shouldRedactEntry === 'function') {
      try { return appRegistry._shouldRedactEntry(entry, { redactPrivate: true }) } catch { /* fall through */ }
    }
    return entry.blind === true
  }

  _callerKey (context = {}) {
    const rk = context.remotePubkey
    if (rk) return typeof rk === 'string' ? rk : b4a.toString(rk, 'hex')
    return context.caller || 'local'
  }

  _refill (b, perMin, burst, now) {
    const elapsedMin = (now - b.lastRefill) / 60_000
    b.tokens = Math.min(burst, b.tokens + elapsedMin * perMin)
    b.lastRefill = now
  }

  _takeGlobal () {
    const now = Date.now()
    this._refill(this._global, this._glPerMin, this._glBurst, now)
    if (this._global.tokens < 1) return false
    this._global.tokens -= 1
    return true
  }

  _takeToken (callerKey) {
    const now = Date.now()
    let b = this._buckets.get(callerKey)
    if (!b) {
      if (this._buckets.size >= this._maxBuckets) this._evictIdle(true)
      b = { tokens: this._rlBurst, lastRefill: now }
      this._buckets.set(callerKey, b)
    }
    this._refill(b, this._rlTokensPerMin, this._rlBurst, now)
    if (b.tokens < 1) return false
    b.tokens -= 1
    return true
  }

  /**
   * Drop buckets untouched for longer than the TTL (age-based: a spent bucket
   * only refills on the next take, so a token-count test would never fire for
   * an abandoned identity). A returning caller just gets a fresh full bucket.
   * `force` also trims the oldest entries when still at the size cap.
   */
  _evictIdle (force = false) {
    const now = Date.now()
    for (const [k, b] of this._buckets) {
      if ((now - b.lastRefill) > this._bucketTtlMs) this._buckets.delete(k)
    }
    if (force && this._buckets.size >= this._maxBuckets) {
      // Still over cap: evict the least-recently-refilled entries.
      const oldest = [...this._buckets.entries()].sort((a, b) => a[1].lastRefill - b[1].lastRefill)
      const drop = Math.ceil(this._maxBuckets * 0.1)
      for (let i = 0; i < drop && i < oldest.length; i++) this._buckets.delete(oldest[i][0])
    }
  }
}
