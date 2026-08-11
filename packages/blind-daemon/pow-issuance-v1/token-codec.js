// pow-issuance-v1 token, challenge, and proof-of-work primitives.
// Shared by the issuer service, the module-form daemon admission adapter, and
// the drill/client tooling. Design note: docs/POW-ISSUANCE-V1.md.
//
// The scheme is deliberately SHA-256-only: the production daemon admission
// contract is a sandboxed synchronous import-free script (production-entrypoint.js)
// with no crypto host APIs, and browser minters run under strict CSP — so every
// derivation uses SHA-256/HMAC-SHA256, never blake2b. The sandbox adapter script
// (sandbox-adapter.js) carries a pure-JS implementation of the same derivations;
// the unit tests pin byte-parity between the two.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import b4a from 'b4a'

export const POW_ISSUANCE_V1_SCHEME_ID = 1 // allocated in docs/POW-ISSUANCE-V1.md; 9 is the deploy-side publisher scheme
export const POW_ISSUANCE_V1_SCHEME_VERSION = 1
export const POW_ISSUANCE_V1_WIRE_VERSION = 1
export const POW_ISSUANCE_V1_MAX_ALLOWANCE = 8

export const POW_ISSUANCE_V1_DEFAULT_DIFFICULTY_BITS = 20
export const POW_ISSUANCE_V1_MAX_DIFFICULTY_BITS = 32
export const POW_ISSUANCE_V1_DEFAULT_CHALLENGE_TTL_SECONDS = 120
export const POW_ISSUANCE_V1_DEFAULT_TOKEN_TTL_EPOCHS = 2
export const POW_ISSUANCE_V1_MAX_TOKEN_TTL_EPOCHS = 4

export const POW_ISSUANCE_V1_ISSUER_KEY_BYTES = 32
export const POW_ISSUANCE_V1_CHALLENGE_ID_BYTES = 32
export const POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES = 1 + 32 + 4 + 4 + 1
export const POW_ISSUANCE_V1_CHALLENGE_BYTES = POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES + 32
export const POW_ISSUANCE_V1_TOKEN_PAYLOAD_BYTES = 1 + 1 + 32 + 32 + 1 + 4
export const POW_ISSUANCE_V1_TOKEN_BYTES = POW_ISSUANCE_V1_TOKEN_PAYLOAD_BYTES + 32

const CHALLENGE_KEY_INFO = b4a.from('hiverelay/pow-issuance-v1/key/challenge', 'ascii')
const TOKEN_KEY_INFO = b4a.from('hiverelay/pow-issuance-v1/key/token', 'ascii')
const ISSUER_KEY_COMMITMENT_DOMAIN = b4a.from('hiverelay/pow-issuance-v1/issuer-key-commitment', 'ascii')
const RECORD_BINDING_DOMAIN = b4a.from('hiverelay/pow-issuance-v1/record-binding', 'ascii')
const SPEND_TAG_DOMAIN = b4a.from('hiverelay/pow-issuance-v1/spend-tag', 'ascii')
const POW_DOMAIN = b4a.from('hiverelay/pow-issuance-v1/pow', 'ascii')

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function asBytes (value, field, length = null) {
  if (!value || typeof value.byteLength !== 'number') fail('POW_ISSUANCE_INVALID', `${field} must be bytes`)
  const bytes = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && bytes.byteLength !== length) {
    fail('POW_ISSUANCE_INVALID', `${field} must be exactly ${length} bytes`)
  }
  return bytes
}

function u32be (value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    fail('POW_ISSUANCE_INVALID', `${field} is outside u32`)
  }
  return value
}

function u64beBytes (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('POW_ISSUANCE_INVALID', `${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    fail('POW_ISSUANCE_INVALID', `${field} is outside u64`)
  }
  const out = b4a.alloc(8)
  out.writeBigUInt64BE(value, 0)
  return out
}

export function hmacSha256 (key, data) {
  return b4a.from(createHmac('sha256', b4a.from(key)).update(b4a.from(data)).digest())
}

export function derivePowIssuanceV1Keys (issuerKey) {
  const master = asBytes(issuerKey, 'pow-issuance-v1 issuer key', POW_ISSUANCE_V1_ISSUER_KEY_BYTES)
  return Object.freeze({
    challengeKey: hmacSha256(master, CHALLENGE_KEY_INFO),
    tokenKey: hmacSha256(master, TOKEN_KEY_INFO)
  })
}

export function powIssuanceV1IssuerKeyCommitment (issuerKey) {
  const master = asBytes(issuerKey, 'pow-issuance-v1 issuer key', POW_ISSUANCE_V1_ISSUER_KEY_BYTES)
  return hmacSha256(ISSUER_KEY_COMMITMENT_DOMAIN, master)
}

export function countLeadingZeroBits (digest) {
  const bytes = asBytes(digest, 'digest')
  let count = 0
  for (const byte of bytes) {
    if (byte === 0) {
      count += 8
      continue
    }
    return count + Math.clz32(byte) - 24
  }
  return count
}

export function mintPowIssuanceV1Challenge (challengeKey, options = {}) {
  const key = asBytes(challengeKey, 'challenge key', 32)
  const challengeId = options.challengeId == null
    ? b4a.from(randomBytes(POW_ISSUANCE_V1_CHALLENGE_ID_BYTES))
    : asBytes(options.challengeId, 'challengeId', POW_ISSUANCE_V1_CHALLENGE_ID_BYTES)
  const issuedAtUnix = u32be(
    options.issuedAtUnix == null ? Math.floor(Date.now() / 1000) : options.issuedAtUnix, 'issuedAtUnix')
  const ttlSeconds = u32be(
    options.ttlSeconds == null ? POW_ISSUANCE_V1_DEFAULT_CHALLENGE_TTL_SECONDS : options.ttlSeconds,
    'ttlSeconds')
  const difficultyBits = options.difficultyBits == null
    ? POW_ISSUANCE_V1_DEFAULT_DIFFICULTY_BITS
    : options.difficultyBits
  if (!Number.isInteger(difficultyBits) || difficultyBits < 1 ||
      difficultyBits > POW_ISSUANCE_V1_MAX_DIFFICULTY_BITS) {
    fail('POW_ISSUANCE_INVALID', 'difficultyBits is outside 1..32')
  }
  const payload = b4a.alloc(POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES)
  payload[0] = POW_ISSUANCE_V1_WIRE_VERSION
  b4a.copy(challengeId, payload, 1)
  payload.writeUInt32BE(issuedAtUnix, 33)
  payload.writeUInt32BE(ttlSeconds, 37)
  payload[41] = difficultyBits
  return b4a.concat([payload, hmacSha256(key, payload)])
}

export function parsePowIssuanceV1Challenge (challengeKey, challenge, options = {}) {
  const key = asBytes(challengeKey, 'challenge key', 32)
  const bytes = asBytes(challenge, 'challenge', POW_ISSUANCE_V1_CHALLENGE_BYTES)
  const payload = bytes.subarray(0, POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES)
  const signature = bytes.subarray(POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES)
  if (!timingSafeEqual(signature, hmacSha256(key, payload))) {
    fail('POW_CHALLENGE_INVALID', 'pow-issuance-v1 challenge signature is invalid')
  }
  if (payload[0] !== POW_ISSUANCE_V1_WIRE_VERSION) {
    fail('POW_CHALLENGE_INVALID', 'pow-issuance-v1 challenge version is unsupported')
  }
  const issuedAtUnix = payload.readUInt32BE(33)
  const ttlSeconds = payload.readUInt32BE(37)
  const nowUnix = options.nowUnix == null ? Math.floor(Date.now() / 1000) : options.nowUnix
  if (nowUnix >= issuedAtUnix + ttlSeconds) {
    fail('POW_CHALLENGE_EXPIRED', 'pow-issuance-v1 challenge has expired')
  }
  return Object.freeze({
    payload: b4a.from(payload),
    challengeId: b4a.from(payload.subarray(1, 33)),
    issuedAtUnix,
    ttlSeconds,
    difficultyBits: payload[41]
  })
}

export function powIssuanceV1Preimage (challengePayload, recordCommitment, nonce) {
  return b4a.concat([
    POW_DOMAIN,
    asBytes(challengePayload, 'challengePayload', POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES),
    asBytes(recordCommitment, 'recordCommitment', 32),
    u64beBytes(nonce, 'nonce')
  ])
}

export function verifyPowIssuanceV1Work (options) {
  const difficultyBits = options.difficultyBits
  if (!Number.isInteger(difficultyBits) || difficultyBits < 1 ||
      difficultyBits > POW_ISSUANCE_V1_MAX_DIFFICULTY_BITS) {
    fail('POW_ISSUANCE_INVALID', 'difficultyBits is outside 1..32')
  }
  const digest = b4a.from(createHash('sha256')
    .update(powIssuanceV1Preimage(options.challengePayload, options.recordCommitment, options.nonce))
    .digest())
  return countLeadingZeroBits(digest) >= difficultyBits
}

export function mintPowIssuanceV1Token (tokenKey, options = {}) {
  const key = asBytes(tokenKey, 'token key', 32)
  const challengeId = asBytes(options.challengeId, 'challengeId', POW_ISSUANCE_V1_CHALLENGE_ID_BYTES)
  const recordCommitment = asBytes(options.recordCommitment, 'recordCommitment', 32)
  const allowance = options.allowance
  if (!Number.isInteger(allowance) || allowance < 1 || allowance > POW_ISSUANCE_V1_MAX_ALLOWANCE) {
    fail('POW_ALLOWANCE_INVALID', 'allowance is outside 1..8')
  }
  const expiryEpoch = u32be(options.expiryEpoch, 'expiryEpoch')
  const payload = b4a.alloc(POW_ISSUANCE_V1_TOKEN_PAYLOAD_BYTES)
  payload[0] = POW_ISSUANCE_V1_WIRE_VERSION
  payload[1] = POW_ISSUANCE_V1_SCHEME_VERSION
  b4a.copy(challengeId, payload, 2)
  b4a.copy(recordCommitment, payload, 34)
  payload[66] = allowance
  payload.writeUInt32BE(expiryEpoch, 67)
  return b4a.concat([payload, hmacSha256(key, payload)])
}

export function parsePowIssuanceV1Token (tokenKey, token) {
  const key = asBytes(tokenKey, 'token key', 32)
  const bytes = asBytes(token, 'token', POW_ISSUANCE_V1_TOKEN_BYTES)
  const payload = bytes.subarray(0, POW_ISSUANCE_V1_TOKEN_PAYLOAD_BYTES)
  const signature = bytes.subarray(POW_ISSUANCE_V1_TOKEN_PAYLOAD_BYTES)
  if (!timingSafeEqual(signature, hmacSha256(key, payload))) {
    fail('SPEND_INVALID', 'pow-issuance-v1 token signature is invalid')
  }
  if (payload[0] !== POW_ISSUANCE_V1_WIRE_VERSION || payload[1] !== POW_ISSUANCE_V1_SCHEME_VERSION) {
    fail('SPEND_INVALID', 'pow-issuance-v1 token version is unsupported')
  }
  const allowance = payload[66]
  if (allowance < 1 || allowance > POW_ISSUANCE_V1_MAX_ALLOWANCE) {
    fail('SPEND_INVALID', 'pow-issuance-v1 token allowance is outside 1..8')
  }
  return Object.freeze({
    token: b4a.from(bytes),
    challengeId: b4a.from(payload.subarray(2, 34)),
    recordCommitment: b4a.from(payload.subarray(34, 66)),
    allowance,
    expiryEpoch: payload.readUInt32BE(67)
  })
}

export function powIssuanceV1RecordBindingRoot (commitments) {
  if (!Array.isArray(commitments) || commitments.length < 1 ||
      commitments.length > POW_ISSUANCE_V1_MAX_ALLOWANCE) {
    fail('POW_ISSUANCE_INVALID', 'commitment list is outside 1..8 slots')
  }
  const parts = [RECORD_BINDING_DOMAIN, b4a.from([commitments.length])]
  for (const [index, commitment] of commitments.entries()) {
    parts.push(asBytes(commitment, `commitments[${index}]`, 32))
  }
  return hmacSha256(RECORD_BINDING_DOMAIN, b4a.concat(parts.slice(1)))
}

export function buildPowIssuanceV1Presentation (token, spendIndex, commitments) {
  const tokenBytes = asBytes(token, 'token', POW_ISSUANCE_V1_TOKEN_BYTES)
  if (!Array.isArray(commitments) || commitments.length < 1 ||
      commitments.length > POW_ISSUANCE_V1_MAX_ALLOWANCE) {
    fail('POW_ISSUANCE_INVALID', 'commitment list is outside 1..8 slots')
  }
  if (!Number.isInteger(spendIndex) || spendIndex < 0 || spendIndex >= commitments.length) {
    fail('POW_ISSUANCE_INVALID', 'spendIndex is outside the commitment list')
  }
  const siblings = []
  for (const [index, commitment] of commitments.entries()) {
    if (index !== spendIndex) siblings.push(asBytes(commitment, `commitments[${index}]`, 32))
  }
  return b4a.concat([tokenBytes, b4a.from([spendIndex]), ...siblings])
}

export function parsePowIssuanceV1Presentation (presentation) {
  const bytes = asBytes(presentation, 'admission token')
  if (bytes.byteLength < POW_ISSUANCE_V1_TOKEN_BYTES + 1 ||
      (bytes.byteLength - POW_ISSUANCE_V1_TOKEN_BYTES - 1) % 32 !== 0) {
    fail('SPEND_INVALID', 'pow-issuance-v1 presentation is malformed')
  }
  const spendIndex = bytes[POW_ISSUANCE_V1_TOKEN_BYTES]
  const siblingCount = (bytes.byteLength - POW_ISSUANCE_V1_TOKEN_BYTES - 1) / 32
  const siblings = []
  for (let index = 0; index < siblingCount; index++) {
    const start = POW_ISSUANCE_V1_TOKEN_BYTES + 1 + index * 32
    siblings.push(b4a.from(bytes.subarray(start, start + 32)))
  }
  return Object.freeze({
    token: b4a.from(bytes.subarray(0, POW_ISSUANCE_V1_TOKEN_BYTES)),
    spendIndex,
    siblings: Object.freeze(siblings)
  })
}

export function powIssuanceV1SpendTag (token, spendIndex) {
  const tokenBytes = asBytes(token, 'token', POW_ISSUANCE_V1_TOKEN_BYTES)
  if (!Number.isInteger(spendIndex) || spendIndex < 0 || spendIndex > 255) {
    fail('POW_ISSUANCE_INVALID', 'spendIndex is outside u8')
  }
  return hmacSha256(SPEND_TAG_DOMAIN, b4a.concat([tokenBytes, b4a.from([spendIndex])]))
}

export function wipePowIssuanceV1Key (key) {
  if (key && typeof key.fill === 'function') key.fill(0)
}
