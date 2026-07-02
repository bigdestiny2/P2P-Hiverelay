import b4a from 'b4a'
import {
  buildStorageProof,
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE,
  STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE
} from '../protocol/proof-of-storage.js'

const HEX64 = /^[0-9a-f]{64}$/i
const MAX_PROOF_INDEX = 0xffffffff
const RETRIEVABILITY_PROOF_ROUTES = Object.freeze({
  'POST /api/proof/retrievability': Object.freeze({ kind: 'retrievability-proof' })
})

export function resolveRetrievabilityProofRoute (method, path) {
  const route = RETRIEVABILITY_PROOF_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export class RetrievabilityProofProvider {
  constructor (opts = {}) {
    this.node = null
    this._keyPair = opts.keyPair || null

    this._rlTokensPerMin = opts.proofsPerMin != null ? opts.proofsPerMin : 120
    this._rlBurst = opts.proofBurst != null ? opts.proofBurst : 32
    this._buckets = new Map()
    this._maxBuckets = opts.maxBuckets || 5000
    this._bucketTtlMs = opts.bucketTtlMs || 10 * 60_000

    this._glPerMin = opts.globalProofsPerMin != null ? opts.globalProofsPerMin : 1200
    this._glBurst = opts.globalProofBurst != null ? opts.globalProofBurst : 400
    this._global = { tokens: this._glBurst, lastRefill: 0 }

    this._sweep = null
  }

  start (context = {}) {
    this.node = context.node || null
    if (context.keyPair) this._keyPair = context.keyPair
    this._global.lastRefill = Date.now()
    if (!this._sweep) {
      this._sweep = setInterval(() => this._evictIdle(), 60_000)
      if (this._sweep.unref) this._sweep.unref()
    }
  }

  async stop () {
    if (this._sweep) {
      clearInterval(this._sweep)
      this._sweep = null
    }
    this._buckets.clear()
    this.node = null
  }

  async prove (params = {}, context = {}) {
    const { keyHex, index, nonce, signatureProfile } = normalizeProofChallenge(params)
    const node = this.node
    if (!node || !node.appRegistry) throw proofError('SERVICE_UNAVAILABLE')
    const keyPair = this._keyPair || node.keyPair || (node.swarm && node.swarm.keyPair)
    if (!keyPair || !keyPair.secretKey) throw proofError('NO_RELAY_KEYPAIR')

    if (!node.appRegistry.has(keyHex)) throw proofError('NOT_SEEDED')
    const entry = node.appRegistry.get(keyHex)
    if (!entry || !entry.drive) throw proofError('NOT_SEEDED')
    if (this._isRedacted(node.appRegistry, entry)) throw proofError('NOT_SEEDED')

    if (!this._takeToken(this._callerKey(context))) throw proofError('RATE_LIMITED')
    if (!this._takeGlobal()) throw proofError('RATE_LIMITED')

    const drive = entry.drive
    if (drive.closed || drive.closing) throw proofError('DRIVE_CLOSED')
    if (typeof drive.ready === 'function') await drive.ready()
    const core = drive.core || (drive.db && drive.db.core)
    if (!core) throw proofError('NO_META_CORE')

    return buildStorageProof({ core, index, nonce, keyPair, signatureProfile })
  }

  _isRedacted (appRegistry, entry) {
    if (typeof appRegistry._shouldRedactEntry === 'function') {
      try { return appRegistry._shouldRedactEntry(entry, { redactPrivate: true }) } catch {}
    }
    return entry.blind === true
  }

  _callerKey (context = {}) {
    const rk = context.remotePubkey
    if (rk) return typeof rk === 'string' ? rk : b4a.toString(rk, 'hex')
    return context.caller || 'local'
  }

  _refill (bucket, perMin, burst, now) {
    const elapsedMin = (now - bucket.lastRefill) / 60_000
    bucket.tokens = Math.min(burst, bucket.tokens + elapsedMin * perMin)
    bucket.lastRefill = now
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
    let bucket = this._buckets.get(callerKey)
    if (!bucket) {
      if (this._buckets.size >= this._maxBuckets) this._evictIdle(true)
      bucket = { tokens: this._rlBurst, lastRefill: now }
      this._buckets.set(callerKey, bucket)
    }
    this._refill(bucket, this._rlTokensPerMin, this._rlBurst, now)
    if (bucket.tokens < 1) return false
    bucket.tokens -= 1
    return true
  }

  _evictIdle (force = false) {
    const now = Date.now()
    for (const [key, bucket] of this._buckets) {
      if ((now - bucket.lastRefill) > this._bucketTtlMs) this._buckets.delete(key)
    }
    if (force && this._buckets.size >= this._maxBuckets) {
      const oldest = [...this._buckets.entries()].sort((a, b) => a[1].lastRefill - b[1].lastRefill)
      const drop = Math.ceil(this._maxBuckets * 0.1)
      for (let i = 0; i < drop && i < oldest.length; i++) {
        this._buckets.delete(oldest[i][0])
      }
    }
  }
}

function normalizeProofChallenge (params) {
  const { coreKey, index, nonce: nonceHex } = params || {}
  if (typeof coreKey !== 'string' || !HEX64.test(coreKey)) throw proofError('BAD_CORE_KEY')
  if (!Number.isSafeInteger(index) || index < 0 || index > MAX_PROOF_INDEX) throw proofError('BAD_INDEX')
  if (typeof nonceHex !== 'string' || !HEX64.test(nonceHex)) throw proofError('BAD_NONCE')
  return {
    keyHex: coreKey.toLowerCase(),
    index,
    nonce: b4a.from(nonceHex, 'hex'),
    signatureProfile: normalizeSignatureProfile(params && params.signatureProfile)
  }
}

function normalizeSignatureProfile (profile) {
  if (profile == null || profile === '') return STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE
  if (profile === STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE) return STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE
  if (profile === RETRIEVABILITY_PROOF_SIGNATURE_PROFILE) return RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
  throw proofError('UNSUPPORTED_SIGNATURE_PROFILE')
}

export async function runRetrievabilityProofAction ({
  body = {},
  provider = null,
  context = {}
} = {}) {
  if (!provider || typeof provider.prove !== 'function') {
    return proofFailure('SERVICE_UNAVAILABLE')
  }

  try {
    const proof = await provider.prove(body, context)
    return {
      ok: true,
      status: 200,
      payload: { ok: true, ...proof }
    }
  } catch (err) {
    return proofFailure(err && err.code ? err.code : (err && err.message ? err.message : String(err || 'unknown error')))
  }
}

function proofFailure (code) {
  if (code === 'BAD_CORE_KEY' || code === 'BAD_INDEX' || code === 'BAD_NONCE') {
    return { ok: false, status: 400, payload: { error: code } }
  }
  if (code === 'UNSUPPORTED_SIGNATURE_PROFILE') {
    return { ok: false, status: 400, payload: { error: code } }
  }
  if (code === 'NOT_SEEDED') {
    return { ok: false, status: 404, payload: { error: 'NOT_SEEDED' } }
  }
  if (code === 'RATE_LIMITED') {
    return { ok: false, status: 429, payload: { error: 'RATE_LIMITED' }, headers: { 'Retry-After': '60' } }
  }
  if (code === 'BLOCK_OUT_OF_RANGE') {
    return { ok: false, status: 400, payload: { error: 'BLOCK_OUT_OF_RANGE' } }
  }
  if (code === 'BLOCK_NOT_LOCAL') {
    return { ok: false, status: 409, payload: { error: 'BLOCK_NOT_LOCAL' } }
  }
  if (code === 'DRIVE_CLOSED' || code === 'NO_META_CORE' || code === 'NO_RELAY_KEYPAIR' || code === 'SERVICE_UNAVAILABLE') {
    return { ok: false, status: 503, payload: { error: code } }
  }
  return { ok: false, status: 400, payload: { error: code } }
}

function proofError (code) {
  const err = new Error(code)
  err.code = code
  return err
}
