// cashu.js — Cashu wire formats (NUT-01 keys, NUT-02 keyset id, NUT-00 token)
// layered on the BDHKE mint in blind-mint.js. Lets the relay's blind tokens be
// expressed as standard Cashu Proofs / `cashuA` tokens so they interoperate
// with the wider Cashu ecosystem.
//
// The lease is single-denomination, so the relay exposes a keyset with one
// amount -> one key (still a valid NUT-01/02 keyset).

import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes, bytesToHex, concatBytes } from '@noble/hashes/utils.js'
import b4a from 'b4a'

/**
 * NUT-02 keyset id (version byte 0x00). Sort the {amount: pubkeyHex} map by
 * amount ascending, concatenate the compressed pubkey bytes in that order,
 * SHA-256, and take '00' + first 14 hex chars.
 * @param {Record<string|number, string>} keys
 * @returns {string} 16-hex-char keyset id
 */
export function deriveKeysetId (keys) {
  const amounts = Object.keys(keys).map(Number).sort((a, b) => a - b)
  let concat = new Uint8Array(0)
  for (const amount of amounts) {
    concat = concatBytes(concat, hexToBytes(keys[amount]))
  }
  return '00' + bytesToHex(sha256(concat)).slice(0, 14)
}

/**
 * Build a NUT-01/02 keyset for a single-denomination mint.
 * @param {object} mint    BlindMint instance (has .publicKey)
 * @param {number} amount  the denomination amount (e.g. sats)
 * @param {string} [unit='sat']
 * @returns {{ id, unit, keys: Record<string,string> }}
 */
export function buildKeyset (mint, amount, unit = 'sat') {
  const keys = { [amount]: mint.publicKey }
  return { id: deriveKeysetId(keys), unit, keys }
}

/**
 * Assemble a NUT-00 Proof from an unblinded token.
 * @returns {{ amount, id, secret, C }}
 */
export function makeProof (amount, keysetId, secret, C) {
  return { amount, id: keysetId, secret, C }
}

// ─── cashuA (NUT-00 v3) token, base64url JSON ────────────────────────

function base64urlEncode (bytes) {
  return b4a.toString(b4a.from(bytes), 'base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode (str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4))
  return b4a.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64')
}

/**
 * Encode proofs as a `cashuA` token string.
 * @param {object} args
 * @param {string} args.mint    mint URL (informational; relays may use their pubkey/onion)
 * @param {Array}  args.proofs  [{ amount, id, secret, C }]
 * @param {string} [args.unit='sat']
 * @param {string} [args.memo]
 * @returns {string}
 */
export function encodeToken ({ mint, proofs, unit = 'sat', memo }) {
  const payload = { token: [{ mint: mint || '', proofs }], unit }
  if (memo) payload.memo = memo
  return 'cashuA' + base64urlEncode(b4a.from(JSON.stringify(payload), 'utf8'))
}

/**
 * Decode a `cashuA` token string into { mint, unit, proofs, memo }.
 * @param {string} token
 */
export function decodeToken (token) {
  if (typeof token !== 'string' || !token.startsWith('cashuA')) {
    throw new Error('decodeToken: not a cashuA token')
  }
  const json = JSON.parse(b4a.toString(base64urlDecode(token.slice('cashuA'.length)), 'utf8'))
  const entry = Array.isArray(json.token) ? json.token[0] : null
  if (!entry || !Array.isArray(entry.proofs)) throw new Error('decodeToken: malformed token')
  return { mint: entry.mint || '', unit: json.unit || 'sat', proofs: entry.proofs, memo: json.memo }
}
