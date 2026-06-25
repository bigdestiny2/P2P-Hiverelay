/**
 * Privacy helpers — metadata minimization for peer identifiers.
 *
 * The relay is already blind to CONTENT (ciphertext-at-rest, Noise XK on the
 * wire). These helpers shrink the remaining CONNECTION-metadata surface: peer
 * pubkeys and IPs that would otherwise appear verbatim in API payloads and
 * logs, letting an operator (or a seized box) reconstruct who-connected-when.
 *
 * Design:
 *   - A per-PROCESS random salt. Identifiers are therefore unlinkable across
 *     restarts and across relays, and the truncated SHA-256 is not reversible
 *     to the original IP/pubkey. The salt never leaves memory.
 *   - Hashing preserves equality within a single process lifetime, so
 *     rate-limit buckets / reputation lookups that key on the digest still
 *     work — they just stop carrying the raw identifier.
 *
 * All redaction is opt-OUT at the call site (an authenticated operator view can
 * pass the raw value through); the public-facing surfaces default to redacted.
 */

import { createHash, randomBytes } from 'crypto'

// Per-process salt. Module-level so every caller shares one unlinkable basis.
const IDENT_SALT = randomBytes(32)

const DEFAULT_LEN = 16

/**
 * Salted, truncated, non-reversible digest of an identifier (IP or pubkey).
 * Mirrors the WebSocket transport's _hashIp pattern so redacted identifiers
 * are uniform across the codebase.
 *
 * @param {*} value
 * @param {{ salt?: Buffer, len?: number }} [opts]
 * @returns {string|null} 16-hex-char digest, or null for empty input
 */
function hashIdent (value, opts = {}) {
  if (value === null || value === undefined || value === '') return null
  const salt = opts.salt || IDENT_SALT
  const len = Number.isInteger(opts.len) && opts.len > 0 ? opts.len : DEFAULT_LEN
  return createHash('sha256').update(salt).update(String(value)).digest('hex').slice(0, len)
}

/**
 * Redact a hex pubkey for public payloads. Returns a stable, non-reversible
 * short digest (prefixed so it is never mistaken for a real 64-char key).
 *
 * @param {*} hex - 64-char hex pubkey (or any string id)
 * @param {{ salt?: Buffer, len?: number }} [opts]
 * @returns {string|null}
 */
function redactPubkeyHex (hex, opts = {}) {
  if (typeof hex !== 'string' || hex.length < 8) return null
  const digest = hashIdent(hex, opts)
  return digest ? 'anon:' + digest : null
}

/**
 * Redact an IP address for logs. Returns a short salted digest so a log line
 * can still distinguish distinct sources / correlate a burst, without writing
 * the raw address to disk.
 *
 * @param {*} ip
 * @param {{ salt?: Buffer, len?: number }} [opts]
 * @returns {string} digest, or 'unknown' for empty input
 */
function redactIp (ip, opts = {}) {
  const digest = hashIdent(ip, opts)
  return digest ? 'ip:' + digest : 'unknown'
}

export { hashIdent, redactPubkeyHex, redactIp, IDENT_SALT }
