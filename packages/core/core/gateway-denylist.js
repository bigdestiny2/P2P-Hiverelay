/**
 * Federated signed gateway denylist — the fleet-wide takedown channel for
 * the public HTTP gateway surface.
 *
 * A takedown issued on one relay must reach every other relay serving the
 * same public drive. This module is the entry format + local store for that
 * channel:
 *
 *   - Entries name drives by HASHED key only (domain-separated BLAKE2b-256
 *     of the raw 32-byte drive key). The denylist is gossiped in the clear,
 *     so carrying plaintext keys would make the channel itself a content
 *     oracle for "is drive X censored anywhere?" — with hashes only, a
 *     reader learns nothing they cannot already compute for a key they
 *     already hold.
 *   - Every entry is a signed Ed25519 envelope (same primitive as fork
 *     proofs and seeding manifests) from an authorized takedown admin.
 *     Receivers gate on a trusted-admin allow-list; an empty list fails
 *     closed — no remote entry can censor a drive until the operator
 *     explicitly trusts admin keys (same posture as trustedForkObservers).
 *   - Entries carry an expiry and a bounded reason-code enum — no free
 *     text, so the channel cannot be used to smuggle arbitrary content or
 *     defamatory claims into every relay's storage.
 *
 * Distribution reuses the relay's existing federation gossip channel
 * (federation.js `_pullGatewayDenylist`, mirroring `_pullForkProofs`):
 * followed relays are polled for `GET /api/gateway/denylist` on the normal
 * follow interval and each entry is verified + trust-gated locally before
 * it merges. That channel was chosen over an outboxlog namespace because
 * the outboxlog DO-NOT-SERVE tombstone is an operator-local, admin-token
 * gated record-suppression mechanism with no federation semantics — while
 * signed-envelope gossip over the follow graph is exactly how this repo
 * already propagates network-wide evidence (fork proofs), and the entries
 * here are the same shape of self-authenticating signed payload. The
 * carrying peer needs no trust: a relay serving junk entries only wastes
 * its own bandwidth, nothing merges without a trusted admin signature.
 */

import { EventEmitter } from 'events'
import { readFile, writeFile, mkdir, rename, unlink } from 'fs/promises'
import { dirname, basename, join } from 'path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { isValidHexKey } from './constants.js'

const DENYLIST_VERSION = 1
// Domain separator for the target-key hash so a denylist hash can never be
// confused with (or preimage-matched against) any other keyed hash in the
// system. Hash input is domain || raw 32-byte drive key.
const DENYLIST_KEY_DOMAIN = 'hiverelay-gateway-denylist-v1:'
// Bounded reason-code enum. Deliberately small and free-text-free: entries
// replicate to every relay in the fleet, so the reason field is a machine
// code, never a sentence.
const DENYLIST_REASONS = Object.freeze([
  'legal-order', // court / government order presented to the operator
  'csam', // child sexual abuse material report
  'copyright', // copyright / DMCA-style notice
  'malware', // malware or phishing distribution
  'harassment', // harassment / non-consensual intimate content
  'operator-discretion' // operator policy violation not otherwise classified
])
// Target kinds are an enum too, so future surfaces (e.g. app ids) cannot
// sneak in through an unversioned string.
const DENYLIST_TARGET_KINDS = Object.freeze(['drive'])
const DEFAULT_MAX_ENTRIES = 10_000
// Clock-skew tolerance for issuedAt — mirrors fork-proof-signing.js.
const FUTURE_SKEW_TOLERANCE_MS = 5 * 60 * 1000

/**
 * Hash a plaintext 64-hex drive key into the opaque 64-hex identifier the
 * denylist names. One-way for a reader of the channel; cheap to recompute
 * for a gateway holding the requested key.
 */
export function hashDriveKeyForDenylist (keyHex) {
  if (!isValidHexKey(keyHex, 64)) return null
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.concat([
    b4a.from(DENYLIST_KEY_DOMAIN, 'utf8'),
    b4a.from(keyHex.toLowerCase(), 'hex')
  ]))
  return b4a.toString(out, 'hex')
}

/**
 * Sign a takedown entry with an admin identity keypair. `driveKey` is the
 * plaintext 64-hex drive key being taken down; only its hash is placed in
 * the envelope. Returns the full signed envelope ready to gossip.
 *
 * @param {object} fields - { driveKey | keyHash, reason, expiresAt, issuedAt? }
 * @param {object} adminKeyPair - { publicKey: Buffer(32), secretKey: Buffer(64) }
 */
export function signDenylistEntry (fields, adminKeyPair) {
  if (!fields || typeof fields !== 'object') {
    throw new Error('signDenylistEntry: fields required')
  }
  if (!adminKeyPair || !adminKeyPair.publicKey || !adminKeyPair.secretKey) {
    throw new Error('signDenylistEntry: adminKeyPair { publicKey, secretKey } required')
  }
  const keyHash = typeof fields.keyHash === 'string'
    ? fields.keyHash.toLowerCase()
    : hashDriveKeyForDenylist(fields.driveKey)
  if (!isValidHexKey(keyHash, 64)) {
    throw new Error('signDenylistEntry: fields.driveKey must be 64 hex chars')
  }
  if (!DENYLIST_REASONS.includes(fields.reason)) {
    throw new Error('signDenylistEntry: fields.reason must be one of: ' + DENYLIST_REASONS.join(', '))
  }
  const issuedAt = fields.issuedAt === undefined ? Date.now() : fields.issuedAt
  if (!Number.isFinite(issuedAt) || !Number.isFinite(fields.expiresAt) || fields.expiresAt <= issuedAt) {
    throw new Error('signDenylistEntry: expiresAt must be finite and after issuedAt')
  }

  const adminPubkey = b4a.toString(adminKeyPair.publicKey, 'hex')
  const payload = canonicalSignablePayload({
    kind: 'drive',
    keyHash,
    reason: fields.reason,
    issuedAt,
    expiresAt: fields.expiresAt,
    adminPubkey
  })
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, payload, adminKeyPair.secretKey)

  return {
    version: DENYLIST_VERSION,
    target: { kind: 'drive', keyHash },
    reason: fields.reason,
    issuedAt,
    expiresAt: fields.expiresAt,
    admin: {
      pubkey: adminPubkey,
      signature: b4a.toString(sig, 'hex')
    }
  }
}

/**
 * Verify a signed denylist envelope: schema, bounded enums, timestamp
 * sanity (not future-issued beyond skew tolerance; not already expired at
 * `now`), and the Ed25519 signature. Trust in the admin key is a separate
 * gate enforced by GatewayDenylist.
 *
 * @returns {{valid: boolean, admin?: string, reason?: string}}
 */
export function verifyDenylistEntry (entry, opts = {}) {
  try {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { valid: false, reason: 'not an object' }
    }
    if (entry.version !== DENYLIST_VERSION) {
      return { valid: false, reason: 'unsupported denylist version: ' + entry.version }
    }
    const target = entry.target
    if (!target || typeof target !== 'object' || !DENYLIST_TARGET_KINDS.includes(target.kind)) {
      return { valid: false, reason: 'bad target kind' }
    }
    if (typeof target.keyHash !== 'string' || !isValidHexKey(target.keyHash, 64)) {
      return { valid: false, reason: 'bad target.keyHash' }
    }
    if (!DENYLIST_REASONS.includes(entry.reason)) {
      return { valid: false, reason: 'reason is not a bounded code' }
    }
    if (!Number.isFinite(entry.issuedAt) || !Number.isFinite(entry.expiresAt) ||
        entry.expiresAt <= entry.issuedAt) {
      return { valid: false, reason: 'bad issuedAt/expiresAt' }
    }
    const admin = entry.admin
    if (!admin || typeof admin !== 'object') {
      return { valid: false, reason: 'no admin in envelope' }
    }
    if (typeof admin.pubkey !== 'string' || !isValidHexKey(admin.pubkey, 64)) {
      return { valid: false, reason: 'bad admin.pubkey' }
    }
    if (typeof admin.signature !== 'string' || !/^[0-9a-f]{128}$/i.test(admin.signature)) {
      return { valid: false, reason: 'bad admin.signature' }
    }

    const now = typeof opts.now === 'number' ? opts.now : Date.now()
    if (entry.issuedAt > now + FUTURE_SKEW_TOLERANCE_MS) {
      return { valid: false, reason: 'issuedAt is in the future' }
    }
    if (entry.expiresAt <= now) {
      return { valid: false, reason: 'entry expired' }
    }

    const payload = canonicalSignablePayload({
      kind: target.kind,
      keyHash: target.keyHash.toLowerCase(),
      reason: entry.reason,
      issuedAt: entry.issuedAt,
      expiresAt: entry.expiresAt,
      adminPubkey: admin.pubkey.toLowerCase()
    })
    const sig = b4a.from(admin.signature, 'hex')
    const pub = b4a.from(admin.pubkey, 'hex')
    if (!sodium.crypto_sign_verify_detached(sig, payload, pub)) {
      return { valid: false, reason: 'signature verification failed' }
    }
    return { valid: true, admin: admin.pubkey.toLowerCase() }
  } catch (err) {
    return { valid: false, reason: 'verify error: ' + err.message }
  }
}

/**
 * Canonical serialization for signing — newline-joined fields, same
 * convention as fork-proof-signing.js so any field tampering invalidates
 * the signature.
 */
function canonicalSignablePayload (parts) {
  const lines = [
    String(DENYLIST_VERSION),
    String(parts.kind),
    String(parts.keyHash),
    String(parts.reason),
    String(parts.issuedAt),
    String(parts.expiresAt),
    String(parts.adminPubkey)
  ]
  return b4a.from(lines.join('\n'), 'utf8')
}

function normalizeAdminAllowList (input) {
  const out = new Set()
  const items = Array.isArray(input) ? input : (input == null ? [] : [input])
  for (const item of items) {
    if (isValidHexKey(item, 64)) out.add(item.toLowerCase())
  }
  return out
}

export class GatewayDenylist extends EventEmitter {
  /**
   * @param {object} opts
   * @param {Array}  [opts.trustedAdmins] - 64-hex Ed25519 pubkeys allowed to
   *                   censor drives on this node. Empty = fail closed.
   * @param {string} [opts.storagePath] - JSON file for persisting entries
   *                   across restarts. If omitted, state is runtime-only.
   * @param {number} [opts.maxEntries] - bound on live entries (oldest
   *                   expired entries are pruned first; a full list rejects)
   */
  constructor (opts = {}) {
    super()
    this.trustedAdmins = normalizeAdminAllowList(opts.trustedAdmins)
    this.storagePath = opts.storagePath || null
    this.maxEntries = Number.isSafeInteger(opts.maxEntries) && opts.maxEntries > 0
      ? opts.maxEntries
      : DEFAULT_MAX_ENTRIES
    // keyHash -> full signed envelope (re-gossipable). One live entry per
    // target; a newer issuedAt supersedes so renewals can extend expiry.
    this._entries = new Map()
    this._saveInFlight = null
  }

  /**
   * Ingest a signed envelope (local operator action or federation gossip).
   * Verification + trusted-admin gate + dedupe happen here for every entry,
   * no matter which transport carried it.
   *
   * @returns {{ok: boolean, added?: boolean, keyHash?: string, reason?: string}}
   */
  add (entry, opts = {}) {
    const verify = verifyDenylistEntry(entry, { now: opts.now })
    if (!verify.valid) return { ok: false, reason: verify.reason }
    // SECURITY: a valid admin envelope signature only proves SOME admin key
    // signed this takedown. The pubkey must additionally be on the local
    // trusted allow-list — empty list = nothing merges (fail closed), same
    // posture as federation's trustedForkObservers.
    if (!this.trustedAdmins.has(verify.admin)) {
      return { ok: false, reason: 'admin not on trusted allow-list' }
    }

    const keyHash = entry.target.keyHash.toLowerCase()
    const existing = this._entries.get(keyHash)
    if (existing && existing.issuedAt >= entry.issuedAt) {
      return { ok: true, added: false, keyHash }
    }

    this._pruneExpired(opts.now)
    if (!existing && this._entries.size >= this.maxEntries) {
      return { ok: false, reason: 'denylist full' }
    }

    const stored = {
      version: DENYLIST_VERSION,
      target: { kind: entry.target.kind, keyHash },
      reason: entry.reason,
      issuedAt: entry.issuedAt,
      expiresAt: entry.expiresAt,
      admin: {
        pubkey: verify.admin,
        signature: entry.admin.signature.toLowerCase()
      }
    }
    this._entries.set(keyHash, stored)
    this.emit('entry-added', {
      keyHash,
      reason: stored.reason,
      expiresAt: stored.expiresAt,
      admin: verify.admin,
      source: opts.source || null
    })
    if (opts.persist !== false) this.save() // fire-and-forget; errors emit 'persistence-error'
    return { ok: true, added: true, keyHash }
  }

  /**
   * Operator-side issue: sign a takedown for a plaintext drive key and
   * ingest it locally. Sign errors throw (caller bug); ingest failures
   * return { ok: false } like add().
   */
  issue (fields, adminKeyPair, opts = {}) {
    const envelope = signDenylistEntry(fields, adminKeyPair)
    return this.add(envelope, opts)
  }

  /**
   * The live entry denying `keyHex` (64-hex plaintext drive key) at `now`,
   * or null. This is the gateway's per-request enforcement check.
   */
  entryFor (keyHex, now = Date.now()) {
    const keyHash = hashDriveKeyForDenylist(keyHex)
    if (!keyHash) return null
    const entry = this._entries.get(keyHash)
    if (!entry) return null
    if (entry.expiresAt <= now) return null
    return entry
  }

  isDenied (keyHex, now = Date.now()) {
    return this.entryFor(keyHex, now) !== null
  }

  /**
   * Live (unexpired) signed envelopes for gossip serving — never plaintext
   * keys. Sorted by keyHash for a deterministic wire shape.
   */
  list (now = Date.now()) {
    this._pruneExpired(now)
    return Array.from(this._entries.values())
      .sort((a, b) => (a.target.keyHash < b.target.keyHash ? -1 : a.target.keyHash > b.target.keyHash ? 1 : 0))
  }

  snapshot () {
    return {
      entries: this.list(),
      count: this._entries.size,
      trustedAdmins: this.trustedAdmins.size
    }
  }

  _pruneExpired (now = Date.now()) {
    for (const [keyHash, entry] of this._entries) {
      if (entry.expiresAt <= now) this._entries.delete(keyHash)
    }
  }

  /**
   * Load persisted entries from disk. Every entry is re-verified AND
   * re-gated against the current trusted-admin list: an admin removed from
   * the allow-list while the relay was down must not censor drives after
   * restart. Bad or expired entries are skipped, never fatal.
   */
  async load () {
    if (!this.storagePath) return
    let raw
    try {
      raw = await readFile(this.storagePath, 'utf8')
    } catch (err) {
      if (err.code === 'ENOENT') return
      this.emit('persistence-error', { phase: 'load', error: err })
      return
    }
    let data
    try {
      data = JSON.parse(raw)
    } catch (err) {
      this.emit('persistence-error', { phase: 'parse', error: err })
      return
    }
    if (!Array.isArray(data.entries)) return
    for (const entry of data.entries) {
      const result = this.add(entry, { persist: false })
      if (!result.ok) {
        this.emit('persistence-error', {
          phase: 'load-skip-invalid',
          kind: 'entry',
          reason: result.reason
        })
      }
    }
    this.emit('loaded', this.snapshot())
  }

  /**
   * Persist live entries. Same atomic tmp-write + rename contract as
   * federation.js: SIGKILL mid-write leaves either the old file or the new
   * one, never a partial. Concurrent saves coalesce.
   */
  async save ({ throwOnError = false } = {}) {
    if (!this.storagePath) return
    if (!this._saveInFlight) {
      this._saveInFlight = (async () => {
        const tmpPath = join(dirname(this.storagePath), basename(this.storagePath) + '.tmp')
        await mkdir(dirname(this.storagePath), { recursive: true })
        const payload = JSON.stringify({
          version: DENYLIST_VERSION,
          entries: this.list(),
          savedAt: Date.now()
        }, null, 2)
        await writeFile(tmpPath, payload, 'utf8')
        await rename(tmpPath, this.storagePath)
      })().catch(async (err) => {
        const tmpPath = join(dirname(this.storagePath), basename(this.storagePath) + '.tmp')
        try { await unlink(tmpPath) } catch (_) {}
        throw err
      }).finally(() => {
        this._saveInFlight = null
      })
    }
    try {
      return await this._saveInFlight
    } catch (err) {
      this.emit('persistence-error', { phase: 'save', error: err })
      if (throwOnError) throw err
    }
  }
}

export {
  DENYLIST_VERSION as GATEWAY_DENYLIST_VERSION,
  DENYLIST_REASONS as GATEWAY_DENYLIST_REASONS,
  DENYLIST_TARGET_KINDS as GATEWAY_DENYLIST_TARGET_KINDS,
  DEFAULT_MAX_ENTRIES as GATEWAY_DENYLIST_DEFAULT_MAX_ENTRIES
}
