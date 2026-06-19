// relay-record.js — a signed, DHT-resolvable relay self-description.
//
// Phase 1 of the iroh adoption (see docs/IROH-ADOPTION-ROADMAP.md). Borrows
// pkarr's property — a signed `pubkey → {address}` record any client can
// resolve by key and verify without trusting a directory — but native to the
// Holepunch stack: it's published as a hyperdht MUTABLE record keyed by the
// relay's identity key, so hyperdht signs on put and verifies the signature on
// get for us. A client that knows only a relay's pubkey resolves the relay's
// CURRENT gatewayUrl + indexRoom over the same DHT it already uses for
// connectivity — no sidecar, no hardcoded address, no Mainline/pkarr dep.
//
// Blind-safety: carries ONLY already-public relay self-description (its gateway
// URL + its public index-room key — the same data the capability doc and
// /catalog.json already expose). No user data, no content identity. Keyed by
// the relay's own pubkey, so only the relay can publish its own record.

import b4a from 'b4a'

export const RELAY_RECORD_VERSION = 1
// hyperdht mutable values are BEP44-bounded (~1000 bytes). A relay record is a
// tiny JSON object well under this; we cap defensively so an oversized value
// fails loudly at encode rather than silently at put.
export const MAX_RECORD_BYTES = 1000

const Z32_KEY_RE = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/
const HTTP_RE = /^https?:\/\//i

/**
 * Encode a relay record to a compact Buffer suitable for a hyperdht mutable
 * value. Only http(s) gateway + 52-char z32 indexRoom are included; absent/
 * invalid fields are dropped. Throws if the result exceeds MAX_RECORD_BYTES.
 */
export function encodeRelayRecord ({ gatewayUrl = null, indexRoom = null } = {}) {
  const rec = { v: RELAY_RECORD_VERSION }
  if (typeof gatewayUrl === 'string' && HTTP_RE.test(gatewayUrl)) rec.g = gatewayUrl.trim().replace(/\/+$/, '')
  if (typeof indexRoom === 'string' && Z32_KEY_RE.test(indexRoom)) rec.i = indexRoom
  const buf = b4a.from(JSON.stringify(rec), 'utf8')
  if (buf.length > MAX_RECORD_BYTES) throw new Error('relay record exceeds ' + MAX_RECORD_BYTES + ' bytes')
  return buf
}

/** True if a record would carry anything worth publishing. */
export function relayRecordHasContent ({ gatewayUrl = null, indexRoom = null } = {}) {
  return (typeof gatewayUrl === 'string' && HTTP_RE.test(gatewayUrl)) ||
    (typeof indexRoom === 'string' && Z32_KEY_RE.test(indexRoom))
}

/** Decode + validate a relay record Buffer. Returns null on garbage/old version. */
export function decodeRelayRecord (buf) {
  if (buf == null) return null
  let rec
  try { rec = JSON.parse(b4a.isBuffer(buf) ? b4a.toString(buf, 'utf8') : String(buf)) } catch { return null }
  if (!rec || typeof rec !== 'object' || rec.v !== RELAY_RECORD_VERSION) return null
  return {
    gatewayUrl: (typeof rec.g === 'string' && HTTP_RE.test(rec.g)) ? rec.g : null,
    indexRoom: (typeof rec.i === 'string' && Z32_KEY_RE.test(rec.i)) ? rec.i : null
  }
}

/**
 * Resolve a relay's record by its public key over a hyperdht instance.
 * hyperdht.mutableGet verifies the Ed25519 signature against the key, so a
 * malicious DHT node can only serve stale data, never forge. Returns the
 * decoded `{ gatewayUrl, indexRoom }` or null (not found / unverifiable / garbage).
 *
 * @param {object} dht        a hyperdht instance (has mutableGet)
 * @param {Buffer|string} publicKey  relay pubkey (32-byte Buffer or 64-hex)
 */
export async function resolveRelayRecord (dht, publicKey, opts = {}) {
  if (!dht || typeof dht.mutableGet !== 'function') return null
  const key = typeof publicKey === 'string' ? b4a.from(publicKey, 'hex') : publicKey
  if (!key || key.length !== 32) return null
  let res
  try {
    res = await dht.mutableGet(key, opts)
  } catch {
    return null
  }
  if (!res || res.value == null) return null
  return decodeRelayRecord(res.value)
}
