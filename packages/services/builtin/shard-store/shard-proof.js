/**
 * Shard possession proofs — two modes, both relay-swarm-key signed,
 * domain-separated, nonce-guarded, and verifiable against the shard hash alone
 * (the relay is trusted for nothing). Mirrors proof-of-storage.js conventions.
 *
 * Mode R (retrieval, strongest): the relay returns the bytes plus a signature
 * over `DOMAIN||R||hash||nonce||blake2b(bytes)`. The verifier re-hashes the
 * bytes (== hash proves it is the right shard, content-addressed) and checks
 * the signature — proving the relay served the correct bytes for THIS fresh
 * challenge (non-replayable), attributable to the relay key.
 *
 * Mode A (attestation, no bytes transferred): a signature over
 * `DOMAIN||A||hash||nonce`. It is a relay-attributable, replay-guarded CLAIM of
 * possession for a witness that does not want to pull the whole share. It is
 * NOT cryptographic proof of byte-possession to a bytes-less verifier — that is
 * the honest limitation (enforced socially by reputation + a contradicting
 * Mode R proof), documented like RETRIEVABILITY_PROOF_LIMITATION.
 */
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { normalizeShardAddress, shardHash } from './shard-engine.js'

export const SHARD_PROOF_DOMAIN = 'hiverelay.shard-possession.v1'
export const SHARD_PROOF_KIND = 'proof-of-shard-possession'
export const SHARD_PROOF_SIGNATURE_PROFILE = 'shard-possession-v1'
export const SHARD_PROOF_LIMITATION =
  'challenge-response possession proof; Mode A is a signed claim, not proof-of-bytes to a bytes-less verifier'

const HEX64 = /^[0-9a-f]{64}$/

function blake2bHex (buf) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, buf)
  return b4a.toString(out, 'hex')
}

export function shardRetrievalSignable (hash, nonceHex, bytes) {
  return b4a.from(SHARD_PROOF_DOMAIN + '\0R\0' + hash + '\0' + nonceHex + '\0' + blake2bHex(bytes), 'utf8')
}

export function shardAttestSignable (hash, nonceHex) {
  return b4a.from(SHARD_PROOF_DOMAIN + '\0A\0' + hash + '\0' + nonceHex, 'utf8')
}

// Non-serving tombstone: the relay signs that it stopped serving shard:<hash>
// at time `at` (custody expiry / GC). Feeds custody-non-serving-proof.
export function shardTombstoneSignable (hash, at) {
  return b4a.from(SHARD_PROOF_DOMAIN + '\0T\0' + hash + '\0' + String(at), 'utf8')
}

export function buildShardTombstone ({ hash, at, keyPair }) {
  const h = normalizeShardAddress(hash)
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, shardTombstoneSignable(h, at), keyPair.secretKey)
  return {
    mode: 'T',
    kind: SHARD_PROOF_KIND,
    hash: h,
    at,
    relay: b4a.toString(keyPair.publicKey, 'hex'),
    signature: b4a.toString(sig, 'hex')
  }
}

export function verifyShardTombstone (tomb, { hash, relayPubkey } = {}) {
  if (!tomb || tomb.mode !== 'T') return false
  const h = normalizeShardAddress(hash || tomb.hash)
  if (!h || tomb.hash !== h || !Number.isFinite(tomb.at)) return false
  const relay = String(relayPubkey || tomb.relay || '').toLowerCase()
  if (!HEX64.test(relay) || (tomb.relay && tomb.relay.toLowerCase() !== relay)) return false
  try {
    return sodium.crypto_sign_verify_detached(b4a.from(tomb.signature, 'hex'), shardTombstoneSignable(h, tomb.at), b4a.from(relay, 'hex'))
  } catch {
    return false
  }
}

function normNonce (nonce) {
  const hex = b4a.isBuffer(nonce) ? b4a.toString(nonce, 'hex') : String(nonce || '').toLowerCase()
  return HEX64.test(hex) ? hex : null
}

export function buildShardRetrievalProof ({ hash, nonce, bytes, keyPair }) {
  const h = normalizeShardAddress(hash)
  const n = normNonce(nonce)
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, shardRetrievalSignable(h, n, bytes), keyPair.secretKey)
  return {
    mode: 'R',
    kind: SHARD_PROOF_KIND,
    hash: h,
    nonce: n,
    relay: b4a.toString(keyPair.publicKey, 'hex'),
    blockHash: blake2bHex(bytes),
    signature: b4a.toString(sig, 'hex'),
    limitation: SHARD_PROOF_LIMITATION
  }
}

export function buildShardAttestation ({ hash, nonce, keyPair }) {
  const h = normalizeShardAddress(hash)
  const n = normNonce(nonce)
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, shardAttestSignable(h, n), keyPair.secretKey)
  return {
    mode: 'A',
    kind: SHARD_PROOF_KIND,
    hash: h,
    nonce: n,
    relay: b4a.toString(keyPair.publicKey, 'hex'),
    signature: b4a.toString(sig, 'hex'),
    limitation: SHARD_PROOF_LIMITATION
  }
}

/**
 * Verify a shard possession proof against the hash + relay key alone.
 * Mode R requires `bytes` (the verifier re-hashes to confirm content + checks
 * the signature); Mode A verifies only the relay's signed claim.
 */
export function verifyShardProof (proof, { hash, nonce, relayPubkey, bytes } = {}) {
  if (!proof || typeof proof !== 'object') return false
  const h = normalizeShardAddress(hash || proof.hash)
  if (!h || proof.hash !== h) return false
  const n = normNonce(nonce || proof.nonce)
  if (!n || proof.nonce !== n) return false
  const relay = String(relayPubkey || proof.relay || '').toLowerCase()
  if (!HEX64.test(relay) || (proof.relay && proof.relay.toLowerCase() !== relay)) return false
  if (typeof proof.signature !== 'string') return false

  let signable
  if (proof.mode === 'R') {
    if (!bytes) return false // Mode R is verifiable only with the bytes in hand
    if (shardHash(bytes) !== h) return false // content-address integrity
    signable = shardRetrievalSignable(h, n, bytes)
  } else if (proof.mode === 'A') {
    signable = shardAttestSignable(h, n)
  } else {
    return false
  }
  try {
    return sodium.crypto_sign_verify_detached(b4a.from(proof.signature, 'hex'), signable, b4a.from(relay, 'hex'))
  } catch {
    return false
  }
}
