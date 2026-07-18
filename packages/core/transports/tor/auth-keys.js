/**
 * Onion client-authorization key lifecycle (`hiverelay.onion.authkey/1`).
 *
 * Client-side (device) pieces:
 *  - x25519 auth keypair generation (keys are per relay+device, generated on
 *    the device; the private half NEVER leaves it — ONION-INV-004)
 *  - enrollment envelope signing (ed25519, canonical JSON)
 *  - helper to build the ONION_CLIENT_AUTH_ADD command for the device daemon
 *
 * Relay-side pieces:
 *  - enrollment verification + acceptance receipt signing
 *  - file-backed roster store (persistence, expiry sweep, revocation)
 *  - 3-field .auth line generation for filesystem (HiddenServiceDir) deployments
 *
 * Wire formats verified against tor 0.4.9.6 in the M0 spike (2026-07-17):
 *  - ClientAuthV3 / .auth pubkey encoding: base32 (RFC4648, lowercase, no padding, 52 chars)
 *  - ONION_CLIENT_AUTH_ADD secret: base64 (no padding) x25519 PRIVATE key
 *  - .auth file line: `descriptor:x25519:<pub>` (three fields — four-field rejected)
 */

import sodium from 'sodium-universal'
import b4a from 'b4a'
import { readFile, writeFile, rename, mkdir } from 'fs/promises'
import { dirname } from 'path'

export const ENROLLMENT_TYPE = 'hiverelay.onion.authkey/1'
export const RECEIPT_TYPE = 'hiverelay.onion.authkey.receipt/1'
export const DEFAULT_KEY_TTL_MS = 365 * 24 * 60 * 60 * 1000 // 12 months
export const ROTATION_GRACE_MS = 7 * 24 * 60 * 60 * 1000
export const MAX_ENROLLMENT_CLOCK_SKEW_MS = 5 * 60 * 1000

const B32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'
const CLIENT_PUB_RE = /^[a-z2-7]{52}$/

function assertSafeTimestamp (value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`)
  }
}

/** RFC4648 base32, lowercase, no padding (tor's ClientAuthV3/.auth encoding). */
export function base32Encode (buf) {
  let bits = 0
  let value = 0
  let out = ''
  for (const b of buf) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

export function base32Decode (str) {
  let bits = 0
  let value = 0
  const out = []
  for (const ch of String(str).toLowerCase()) {
    const idx = B32_ALPHABET.indexOf(ch)
    if (idx === -1) throw new Error('invalid base32 character: ' + ch)
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return b4a.from(out)
}

export function isValidClientPub (pubB32) {
  return CLIENT_PUB_RE.test(pubB32)
}

/**
 * Generate a per-(relay, device) x25519 auth keypair on the device.
 * Returns { publicKey, secretKey, publicKeyB32, secretKeyB64 } — secretKey
 * and secretKeyB64 are custody-grade secrets, never transmit them.
 */
export function generateClientAuthKeypair () {
  const publicKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_box_keypair(publicKey, secretKey)
  return {
    publicKey,
    secretKey,
    publicKeyB32: base32Encode(publicKey),
    secretKeyB64: b4a.toString(secretKey, 'base64').replace(/=+$/, '')
  }
}

/**
 * Generate an unreachable client-auth public key for fail-closed empty
 * rosters. The private half is destroyed immediately and never returned.
 */
export function generateClientAuthGuardKey () {
  const publicKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_box_keypair(publicKey, secretKey)
  secretKey.fill(0)
  return base32Encode(publicKey)
}

/** Command the device runs against its own tor daemon to install the credential. */
export function clientInstallCommand ({ onionAddress, secretKeyB64, clientName = 'hiverelay', permanent = true }) {
  const addr = String(onionAddress).replace(/\.onion$/, '')
  const flags = permanent ? ' Flags=Permanent' : ''
  return `ONION_CLIENT_AUTH_ADD ${addr} x25519:${secretKeyB64} ClientName=${clientName}${flags}`
}

/** Three-field .auth line for filesystem (HiddenServiceDir) roster files. */
export function dotAuthLine (pubB32) {
  if (!isValidClientPub(pubB32)) throw new Error('invalid x25519 client public key (base32, 52 chars)')
  return `descriptor:x25519:${pubB32}`
}

/** Deterministic JSON (recursive key sort) — the signing domain. */
export function canonicalize (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']'
  const keys = Object.keys(value).sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}'
}

function sign (obj, secretKey) {
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, b4a.from(canonicalize(obj)), secretKey)
  return b4a.toString(sig, 'hex')
}

function verify (obj, signatureHex, publicKeyHex) {
  if (typeof signatureHex !== 'string' || typeof publicKeyHex !== 'string') return false
  try {
    return sodium.crypto_sign_verify_detached(
      b4a.from(signatureHex, 'hex'),
      b4a.from(canonicalize(obj)),
      b4a.from(publicKeyHex, 'hex')
    )
  } catch {
    return false
  }
}

/**
 * Build a signed enrollment envelope (device side).
 * clientSecretKey: 64-byte ed25519 secret key of the client's HiveRelay identity.
 */
export function createEnrollment ({ clientIdentity, clientSecretKey, relayPubkey, onionAuthPubX25519, createdAtMs, expiresAtMs, nonce }) {
  if (!isValidClientPub(onionAuthPubX25519)) throw new Error('invalid x25519 client public key')
  if (!(expiresAtMs > createdAtMs)) throw new Error('expiresAtMs must be greater than createdAtMs')
  const body = {
    type: ENROLLMENT_TYPE,
    relayPubkey,
    clientIdentity,
    onionAuthPubX25519,
    createdAtMs,
    expiresAtMs,
    nonce: nonce || b4a.toString(randomBytes(32), 'hex')
  }
  return { ...body, signature: sign(body, clientSecretKey) }
}

/** Verify an enrollment envelope (relay side). Returns { ok, reason?, envelope }. */
export function verifyEnrollment (envelope, {
  expectedRelayPubkey,
  nowMs = Date.now(),
  maxTtlMs = DEFAULT_KEY_TTL_MS * 2,
  maxClockSkewMs = MAX_ENROLLMENT_CLOCK_SKEW_MS
} = {}) {
  if (!envelope || typeof envelope !== 'object') return { ok: false, reason: 'malformed' }
  const { signature, ...body } = envelope
  if (body.type !== ENROLLMENT_TYPE) return { ok: false, reason: 'wrong-type' }
  if (!isValidClientPub(body.onionAuthPubX25519)) return { ok: false, reason: 'bad-auth-key' }
  if (expectedRelayPubkey && body.relayPubkey !== expectedRelayPubkey) return { ok: false, reason: 'wrong-relay' }
  if (!Number.isSafeInteger(body.createdAtMs) || !Number.isSafeInteger(body.expiresAtMs)) {
    return { ok: false, reason: 'bad-time' }
  }
  if (!(body.expiresAtMs > body.createdAtMs)) return { ok: false, reason: 'bad-expiry' }
  if (body.expiresAtMs - body.createdAtMs > maxTtlMs) return { ok: false, reason: 'ttl-too-long' }
  if (body.createdAtMs > nowMs + maxClockSkewMs) return { ok: false, reason: 'created-in-future' }
  if (body.expiresAtMs <= nowMs) return { ok: false, reason: 'expired' }
  if (!verify(body, signature, body.clientIdentity)) return { ok: false, reason: 'bad-signature' }
  return { ok: true, envelope: body }
}

/** Build a signed acceptance receipt (relay side). relaySecretKey: stable relay identity. */
export function createReceipt ({ relayPubkey, relaySecretKey, status, onionAddress, endpointKeyId, clientIdentity, onionAuthPubX25519, enrolledAtMs, expiresAtMs }) {
  if (status !== 'accepted' && status !== 'rejected') throw new Error('status must be accepted|rejected')
  const body = {
    type: RECEIPT_TYPE,
    status,
    relayPubkey,
    onionAddress,
    endpointKeyId,
    clientIdentity,
    onionAuthPubX25519,
    enrolledAtMs,
    expiresAtMs
  }
  return { ...body, signature: sign(body, relaySecretKey) }
}

/** Verify a receipt (device side). Binds key ↔ onion address ↔ expiry to the relay identity. */
export function verifyReceipt (receipt, { expectedRelayPubkey, expectedClientIdentity } = {}) {
  if (!receipt || typeof receipt !== 'object') return { ok: false, reason: 'malformed' }
  const { signature, ...body } = receipt
  if (body.type !== RECEIPT_TYPE) return { ok: false, reason: 'wrong-type' }
  if (expectedRelayPubkey && body.relayPubkey !== expectedRelayPubkey) return { ok: false, reason: 'wrong-relay' }
  if (expectedClientIdentity && body.clientIdentity !== expectedClientIdentity) return { ok: false, reason: 'wrong-client' }
  if (!verify(body, signature, body.relayPubkey)) return { ok: false, reason: 'bad-signature' }
  return { ok: true, receipt: body }
}

function randomBytes (n) {
  const buf = b4a.alloc(n)
  sodium.randombytes_buf(buf)
  return buf
}

/**
 * File-backed roster of authorized clients (relay side). The roster is
 * operator-private data: it enumerates authorized clients and must never be
 * published or logged (spec §7.3).
 */
export class OnionRosterStore {
  constructor (file, { defaultTtlMs = DEFAULT_KEY_TTL_MS } = {}) {
    this.file = file
    this.defaultTtlMs = defaultTtlMs
    this.keys = new Map() // pub -> { pub, name, addedAtMs, expiresAtMs, revokedAtMs }
    this.loaded = false
  }

  async load () {
    this.keys.clear()
    try {
      const data = JSON.parse(await readFile(this.file, 'utf8'))
      if (!data || data.version !== 1 || !Array.isArray(data.keys)) {
        throw new Error('unsupported or malformed roster schema')
      }
      for (const k of data.keys) {
        if (!k || typeof k !== 'object' || !isValidClientPub(k.pub)) {
          throw new Error('invalid client entry')
        }
        assertSafeTimestamp(k.addedAtMs, 'addedAtMs')
        assertSafeTimestamp(k.expiresAtMs, 'expiresAtMs')
        if (k.expiresAtMs <= k.addedAtMs) {
          throw new Error('expiresAtMs must be greater than addedAtMs')
        }
        if (k.revokedAtMs !== null) {
          assertSafeTimestamp(k.revokedAtMs, 'revokedAtMs')
          if (k.revokedAtMs < k.addedAtMs) throw new Error('revokedAtMs precedes addedAtMs')
        }
        this.keys.set(k.pub, k)
      }
    } catch (err) {
      if (err.code !== 'ENOENT') throw new Error(`corrupt onion roster at ${this.file}: ${err.message}`)
    }
    this.loaded = true
    return this
  }

  async save () {
    await mkdir(dirname(this.file), { recursive: true })
    const tmp = this.file + '.tmp'
    const data = { version: 1, keys: [...this.keys.values()] }
    await writeFile(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 })
    await rename(tmp, this.file)
  }

  /** Add (or re-add with fresh expiry) a client. Returns the entry. */
  add (pubB32, { name = null, expiresAtMs = null, nowMs = Date.now() } = {}) {
    if (!isValidClientPub(pubB32)) throw new Error('invalid x25519 client public key')
    assertSafeTimestamp(nowMs, 'nowMs')
    const effectiveExpiry = expiresAtMs === null
      ? nowMs + this.defaultTtlMs
      : expiresAtMs
    assertSafeTimestamp(effectiveExpiry, 'expiresAtMs')
    if (effectiveExpiry <= nowMs) throw new Error('expiresAtMs must be in the future')
    const entry = {
      pub: pubB32,
      name,
      addedAtMs: nowMs,
      expiresAtMs: effectiveExpiry,
      revokedAtMs: null
    }
    this.keys.set(pubB32, entry)
    return entry
  }

  /** Revoke a client (tombstone). Returns true if it existed. */
  revoke (pubB32, { nowMs = Date.now() } = {}) {
    assertSafeTimestamp(nowMs, 'nowMs')
    const entry = this.keys.get(pubB32)
    if (!entry || entry.revokedAtMs !== null) return false
    entry.revokedAtMs = nowMs
    return true
  }

  /** Active (unexpired, unrevoked) client pubkeys — the ClientAuthV3 set. */
  activeKeys ({ nowMs = Date.now() } = {}) {
    assertSafeTimestamp(nowMs, 'nowMs')
    return [...this.keys.values()]
      .filter((k) => (
        k.revokedAtMs === null &&
        Number.isSafeInteger(k.expiresAtMs) &&
        k.expiresAtMs > nowMs
      ))
      .map((k) => k.pub)
  }

  /** Drop expired/revoked entries past grace. Returns dropped count. */
  purge ({ nowMs = Date.now(), graceMs = ROTATION_GRACE_MS } = {}) {
    assertSafeTimestamp(nowMs, 'nowMs')
    assertSafeTimestamp(graceMs, 'graceMs')
    let dropped = 0
    for (const [pub, k] of this.keys) {
      const dead = k.revokedAtMs !== null
        ? k.revokedAtMs + graceMs <= nowMs
        : k.expiresAtMs + graceMs <= nowMs
      if (dead) { this.keys.delete(pub); dropped++ }
    }
    return dropped
  }
}
