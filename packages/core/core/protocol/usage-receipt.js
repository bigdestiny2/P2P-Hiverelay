/**
 * Usage Receipt Protocol
 *
 * A content-free, COUNTERPARTY-signed attestation that a relay provided a
 * service. Generalizes BandwidthReceipt (bytes served) to arbitrary service
 * usage: the CONSUMER signs "relay R provided <service>.<capability>, N units
 * of <unitKind>, in <epoch>". Because the counterparty signs, a relay cannot
 * forge usage solo — only verified receipts are payout-eligible (the relay's
 * own ServiceRegistry call counters are self-reported and must never drive
 * payment).
 *
 * BLIND-SAFE BY CONSTRUCTION: a receipt carries only identities (pubkeys),
 * a service/capability label, a unit kind, and a COUNT. Never a payload, never
 * content, never an IP, never bytes of user data. Verifiable by anyone.
 *
 * Node-safe (b4a + sodium-universal) so it unit-tests outside Bare.
 */
import b4a from 'b4a'
import sodium from 'sodium-universal'

export const USAGE_RECEIPT_VERSION = 1
export const MAX_UNITS = 1_000_000_000 // per-receipt sanity cap
const HEX64_RE = /^[0-9a-f]{64}$/i
const HEX128_RE = /^[0-9a-f]{128}$/i
const LABEL_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i // service / capability
const UNITKIND_RE = /^[a-z0-9-]{1,32}$/i

function isInt (n, min, max) {
  return Number.isInteger(n) && n >= min && n <= max
}

// Fixed-order, content-free canonical bytes. A JSON array keeps it deterministic
// and escape-safe (no separator-injection across the string fields).
function canonicalBytes (r) {
  return b4a.from(JSON.stringify([
    USAGE_RECEIPT_VERSION,
    String(r.relayPubkey).toLowerCase(),
    String(r.peerPubkey).toLowerCase(),
    r.service,
    r.capability,
    r.unitKind,
    r.units,
    r.epoch,
    r.timestamp,
    r.nonce
  ]), 'utf8')
}

function validFields ({ relayPubkey, service, capability, unitKind, units, epoch }) {
  if (!HEX64_RE.test(String(relayPubkey || ''))) return 'relayPubkey must be 64-hex'
  if (!LABEL_RE.test(String(service || ''))) return 'service label invalid'
  if (!LABEL_RE.test(String(capability || ''))) return 'capability label invalid'
  if (!UNITKIND_RE.test(String(unitKind || ''))) return 'unitKind invalid'
  if (!isInt(units, 0, MAX_UNITS)) return 'units out of range'
  if (!isInt(epoch, 0, Number.MAX_SAFE_INTEGER)) return 'epoch invalid'
  return null
}

/**
 * Create a usage receipt signed by the CONSUMER (counterparty).
 * @param {{publicKey:Buffer, secretKey:Buffer}} keyPair  consumer keypair
 * @param {{relayPubkey, service, capability, unitKind, units, epoch}} fields
 */
export function createUsageReceipt (keyPair, fields) {
  const err = validFields(fields)
  if (err) throw new Error('USAGE_RECEIPT_INVALID: ' + err)
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) throw new Error('USAGE_RECEIPT_INVALID: keyPair required')
  const nonceBuf = b4a.alloc(16)
  sodium.randombytes_buf(nonceBuf)
  const r = {
    v: USAGE_RECEIPT_VERSION,
    relayPubkey: String(fields.relayPubkey).toLowerCase(),
    peerPubkey: b4a.toString(keyPair.publicKey, 'hex'),
    service: fields.service,
    capability: fields.capability,
    unitKind: fields.unitKind,
    units: fields.units,
    epoch: fields.epoch,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: b4a.toString(nonceBuf, 'hex')
  }
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, canonicalBytes(r), keyPair.secretKey)
  r.sig = b4a.toString(sig, 'hex')
  return r
}

/**
 * Verify a usage receipt's counterparty signature + shape. Anyone can call it.
 * Returns true only if the peerSignature is valid over the canonical bytes.
 */
export function verifyUsageReceipt (r) {
  if (!r || typeof r !== 'object') return false
  if (r.v !== USAGE_RECEIPT_VERSION) return false
  if (!HEX64_RE.test(String(r.peerPubkey || ''))) return false
  if (!HEX128_RE.test(String(r.sig || ''))) return false
  if (!HEX64_RE.test(String(r.relayPubkey || ''))) return false
  if (!LABEL_RE.test(String(r.service || '')) || !LABEL_RE.test(String(r.capability || ''))) return false
  if (!UNITKIND_RE.test(String(r.unitKind || ''))) return false
  if (!isInt(r.units, 0, MAX_UNITS) || !isInt(r.epoch, 0, Number.MAX_SAFE_INTEGER)) return false
  if (!isInt(r.timestamp, 0, Number.MAX_SAFE_INTEGER)) return false
  if (typeof r.nonce !== 'string' || r.nonce.length < 8) return false
  let pub, sig
  try { pub = b4a.from(r.peerPubkey, 'hex'); sig = b4a.from(r.sig, 'hex') } catch { return false }
  if (pub.length !== 32 || sig.length !== 64) return false
  return sodium.crypto_sign_verify_detached(sig, canonicalBytes(r), pub)
}

/**
 * Relay-side collector: ingests consumer-signed receipts, rejecting forgeries
 * (bad sig) and replays (same peer+nonce), and aggregates verified units per
 * `<service>.<capability>.<unitKind>`. digest() produces the payout-eligible
 * evidence (a count + per-key totals + a content-free receiptRoot a coordinator
 * can re-verify against the retained receipts).
 */
export class UsageLedger {
  constructor (opts = {}) {
    this.maxReceipts = opts.maxReceipts || 50_000
    this._receipts = [] // verified receipts (bounded FIFO)
    this._seen = new Set() // peerPubkey:nonce — replay guard
    this._agg = new Map() // key -> units
  }

  record (receipt) {
    if (!verifyUsageReceipt(receipt)) return { ok: false, reason: 'bad-signature' }
    const id = receipt.peerPubkey + ':' + receipt.nonce
    if (this._seen.has(id)) return { ok: false, reason: 'replay' }
    this._seen.add(id)
    this._receipts.push(receipt)
    if (this._receipts.length > this.maxReceipts) {
      const evicted = this._receipts.shift()
      this._seen.delete(evicted.peerPubkey + ':' + evicted.nonce)
    }
    const key = `${receipt.service}.${receipt.capability}.${receipt.unitKind}`
    this._agg.set(key, (this._agg.get(key) || 0) + receipt.units)
    return { ok: true }
  }

  totals () { return Object.fromEntries(this._agg) }

  digest () {
    const ids = this._receipts.map((r) => r.peerPubkey + ':' + r.nonce).sort()
    const h = b4a.alloc(32)
    sodium.crypto_generichash(h, b4a.from(JSON.stringify(ids), 'utf8'))
    return { count: this._receipts.length, totals: this.totals(), receiptRoot: b4a.toString(h, 'hex') }
  }
}

// Exposed for tests — the exact bytes that get signed.
export const _canonicalBytes = canonicalBytes
