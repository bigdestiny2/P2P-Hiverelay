/**
 * Shard pins — the authorization + retention record for a stored shard.
 *
 * A shard is retained while it has >=1 live (unexpired) pin. A pin is signed by
 * its `pinner` and authorized by one of:
 *   - custody: the pinned hash is bound to a shareIndex assigned to this relay
 *     in a valid signed custody-intent's shareManifest.
 *   - payment: the pinner is within a paid/quota budget (relay-supplied check).
 *   - token: an operator-issued bearer (relay-supplied check).
 *
 * The pin registry persists pins and re-verifies every pin signature on load,
 * dropping unverifiable rows — the persisted file is not a trust root (same
 * posture as the outboxlog #146 fix).
 */
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { normalizeShardAddress, shardError } from './shard-engine.js'

export const SHARD_PIN_DOMAIN = 'hiverelay.shard-pin.v1'
export const SHARD_PIN_REASONS = Object.freeze(['custody', 'payment', 'token'])

const HEX64 = /^[0-9a-f]{64}$/
const HEX_SIG = /^[0-9a-f]{128}$/

// Deterministic serialization of the pin body (sig excluded), sorted keys.
function stable (value) {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stable(value[k])).join(',') + '}'
  }
  return JSON.stringify(value === undefined ? null : value)
}

function pinBody (pin) {
  return {
    reason: pin.reason,
    hash: pin.hash,
    pinner: pin.pinner,
    custodyIntentId: pin.custodyIntentId || null,
    shareIndex: Number.isInteger(pin.shareIndex) ? pin.shareIndex : null,
    retainUntil: pin.retainUntil,
    nonce: pin.nonce
  }
}

export function shardPinSignable (pin) {
  return b4a.from(SHARD_PIN_DOMAIN + '\0' + stable(pinBody(pin)), 'utf8')
}

/** pinRef = a stable id for a pin (hash of its signed body) — the unpin key. */
export function shardPinRef (pin) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, shardPinSignable(pin))
  return b4a.toString(out, 'hex')
}

export function signShardPin (pin, keyPair) {
  const pinner = pin.pinner || b4a.toString(keyPair.publicKey, 'hex')
  const body = { ...pin, pinner }
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, shardPinSignable(body), keyPair.secretKey)
  return { ...body, sig: b4a.toString(sig, 'hex') }
}

export function verifyShardPin (pin) {
  if (!pin || typeof pin !== 'object') return false
  if (!SHARD_PIN_REASONS.includes(pin.reason)) return false
  if (!HEX64.test(String(pin.hash || '').toLowerCase())) return false
  if (!HEX64.test(String(pin.pinner || '').toLowerCase())) return false
  if (typeof pin.sig !== 'string' || !HEX_SIG.test(pin.sig)) return false
  if (!Number.isFinite(pin.retainUntil)) return false
  if (pin.reason === 'custody' && (!pin.custodyIntentId || !Number.isInteger(pin.shareIndex))) return false
  try {
    return sodium.crypto_sign_verify_detached(
      b4a.from(pin.sig, 'hex'),
      shardPinSignable(pin),
      b4a.from(pin.pinner, 'hex')
    )
  } catch {
    return false
  }
}

/**
 * Authorize a PUT. Returns the accepted (normalized) pin or throws.
 * @param resolveCustodyAssignment (custodyIntentId, relayPubkey) =>
 *        { shareIndex, shard } | null  — from a VERIFIED custody-intent.
 * @param checkPaymentQuota (pinner, byteLength) => boolean
 * @param checkToken (pin) => boolean
 */
export async function authorizeShardPin (pin, {
  hash,
  byteLength,
  relayPubkey,
  allowedReasons,
  resolveCustodyAssignment,
  checkPaymentQuota,
  checkToken
} = {}) {
  if (!verifyShardPin(pin)) throw shardError('BAD_SIGNATURE', 'pin signature invalid')
  if (normalizeShardAddress(pin.hash) !== hash) throw shardError('UNAUTHORIZED_PIN', 'pin does not name this shard')
  if (Array.isArray(allowedReasons) && !allowedReasons.includes(pin.reason)) {
    throw shardError('UNAUTHORIZED_PIN', 'pin reason not permitted by operator config')
  }
  if (pin.reason === 'custody') {
    if (typeof resolveCustodyAssignment !== 'function') throw shardError('UNAUTHORIZED_PIN', 'custody binding unavailable')
    const assign = await resolveCustodyAssignment(pin.custodyIntentId, relayPubkey)
    if (!assign) throw shardError('UNAUTHORIZED_PIN', 'no custody assignment for this relay')
    if (assign.shareIndex !== pin.shareIndex) throw shardError('UNAUTHORIZED_PIN', 'shareIndex does not match assignment')
    if (normalizeShardAddress(assign.shard) !== hash) throw shardError('UNAUTHORIZED_PIN', 'assigned share hash does not match')
    return pin
  }
  if (pin.reason === 'payment') {
    if (typeof checkPaymentQuota !== 'function' || !(await checkPaymentQuota(pin.pinner, byteLength))) {
      throw shardError('QUOTA_EXHAUSTED', 'pinner over quota / payment budget')
    }
    return pin
  }
  if (pin.reason === 'token') {
    if (typeof checkToken !== 'function' || !(await checkToken(pin))) {
      throw shardError('UNAUTHORIZED_PIN', 'invalid capability token')
    }
    return pin
  }
  throw shardError('UNAUTHORIZED_PIN', 'unsupported pin reason')
}

export class ShardPinRegistry {
  constructor ({ persistence = null, clock = () => Date.now(), persistFlushMs = 250 } = {}) {
    this.persistence = persistence
    this.clock = clock
    this.persistFlushMs = persistFlushMs
    this.pins = new Map() // hash -> Map(pinRef -> pin)
    this._persistTimer = null
    this._persistChain = Promise.resolve()
  }

  async load () {
    if (!this.persistence) return
    const snapshot = await this.persistence.load()
    if (!snapshot || !Array.isArray(snapshot.pins)) return
    for (const pin of snapshot.pins) {
      // The persisted file is not a trust root: re-verify every pin, drop bad.
      if (!verifyShardPin(pin)) continue
      this._apply(pin)
    }
  }

  _apply (pin) {
    const ref = shardPinRef(pin)
    let set = this.pins.get(pin.hash)
    if (!set) { set = new Map(); this.pins.set(pin.hash, set) }
    set.set(ref, pin)
    return ref
  }

  /** Add a pre-verified/authorized pin. Returns its pinRef. */
  add (pin) {
    const ref = this._apply(pin)
    this._schedulePersist()
    return ref
  }

  /** Remove a pin; the remover must prove pinner control (a signed removal). */
  remove (hash, pinRef, removal) {
    const set = this.pins.get(hash)
    if (!set || !set.has(pinRef)) return { removed: false, refs: this.refs(hash) }
    const pin = set.get(pinRef)
    // removal is a fresh pin-shaped object (same pinner) proving control.
    if (!removal || removal.pinner !== pin.pinner || !verifyShardPin(removal)) {
      throw shardError('BAD_SIGNATURE', 'unpin must be signed by the pinner')
    }
    set.delete(pinRef)
    if (set.size === 0) this.pins.delete(hash)
    this._schedulePersist()
    return { removed: true, refs: this.refs(hash) }
  }

  livePins (hash, now = this.clock()) {
    const set = this.pins.get(hash)
    if (!set) return []
    return [...set.values()].filter(p => p.retainUntil > now)
  }

  refs (hash, now = this.clock()) {
    return this.livePins(hash, now).length
  }

  retainUntil (hash, now = this.clock()) {
    return this.livePins(hash, now).reduce((max, p) => Math.max(max, p.retainUntil), 0)
  }

  /** hashes whose every pin has expired (candidates for GC). */
  expiredHashes (now = this.clock()) {
    const out = []
    for (const [hash] of this.pins) if (this.refs(hash, now) === 0) out.push(hash)
    return out
  }

  /** Drop all fully-expired hashes from the registry. Returns the purged list. */
  purgeExpired (now = this.clock()) {
    const purged = this.expiredHashes(now)
    for (const hash of purged) this.pins.delete(hash)
    if (purged.length) this._schedulePersist()
    return purged
  }

  snapshot () {
    const pins = []
    for (const set of this.pins.values()) for (const pin of set.values()) pins.push(pin)
    return { version: 1, pins }
  }

  _schedulePersist () {
    if (!this.persistence || this._persistTimer) return
    this._persistTimer = setTimeout(() => {
      this._persistTimer = null
      this.flush().catch(() => {})
    }, this.persistFlushMs)
    if (this._persistTimer.unref) this._persistTimer.unref()
  }

  async flush () {
    if (!this.persistence) return
    if (this._persistTimer) { clearTimeout(this._persistTimer); this._persistTimer = null }
    const snap = this.snapshot()
    this._persistChain = this._persistChain.catch(() => {}).then(() => this.persistence.save(snap))
    await this._persistChain
  }

  async close () {
    await this.flush()
  }
}
