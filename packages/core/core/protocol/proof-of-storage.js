/**
 * Proof-of-Storage — trustless, signed proof that a relay holds a specific block.
 *
 * Tier 2 of seed verification. Where Tier 1 (`client.verifySeeded`) proves the
 * content is genuine + served by the swarm, this proves a SPECIFIC relay can
 * produce, on demand, a valid Hypercore Merkle proof for a randomly-sampled
 * block — signed by that relay over a fresh challenge nonce.
 *
 * Trust model — two independent checks, neither trusting the relay:
 *
 *   1. CONTENT (Hypercore intrinsic). The proof is a real Hypercore block proof
 *      (the same structure replication sends). A key-only verifier feeds it to
 *      `core.verify()`, which checks the block hashes into the drive key's
 *      SIGNED Merkle root. A forged/substituted block fails — the relay cannot
 *      fabricate content for a key it isn't the author of.
 *
 *   2. ATTRIBUTION + FRESHNESS (relay signature). The relay signs
 *      `coreKey || u32(index) || nonce || blake2b(block)` with its swarm
 *      identity key. The client checks that signature against the relay's known
 *      pubkey, so the proof is attributable to THIS relay and bound to THIS
 *      challenge nonce — a recorded proof can't be replayed for a new nonce.
 *
 * Honest limitation: this is a challenge-response proof-of-retrievability, not a
 * proof-of-replication. A relay could in principle fetch the block on demand
 * rather than store it. Random-index sampling across the full core + a latency
 * bound make that expensive and detectable, but it is not cryptographically
 * precluded. For hard guarantees you'd need sealed PoRep (out of scope).
 */

import c from 'compact-encoding'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { wire } from 'hypercore/lib/messages.js'

/**
 * The bytes a relay signs / a client verifies. Binds the proof to a specific
 * core, block index, challenge nonce, and the block's content hash.
 * Returns { signable, blockHash }.
 */
export function storageProofSignable (coreKey, index, nonce, blockValue) {
  const idx = c.encode(c.uint32, index) // 4-byte LE
  const blockHash = b4a.alloc(32)
  sodium.crypto_generichash(blockHash, blockValue)
  return { signable: b4a.concat([coreKey, idx, nonce, blockHash]), blockHash }
}

/**
 * RELAY SIDE — build a signed proof for block `index` of `core`.
 * Reads LOCAL storage only: if the relay doesn't hold the block it throws
 * (it must never fetch-on-demand to answer a proof — that would defeat it).
 *
 * @param {Hypercore} core - the (already-open) Hypercore the relay seeds
 * @param {number} index - block index being challenged
 * @param {Buffer} nonce - 32-byte challenge nonce from the verifier
 * @param {{publicKey:Buffer, secretKey:Buffer}} keyPair - the relay's identity key
 * @returns {Promise<Object>} wire-ready proof response (all buffers hex-encoded)
 */
export async function buildStorageProof ({ core, index, nonce, keyPair }) {
  if (!Number.isInteger(index) || index < 0 || index >= core.length) {
    throw new Error('BLOCK_OUT_OF_RANGE')
  }
  if (!(await core.has(index))) {
    throw new Error('BLOCK_NOT_LOCAL') // honest failure — we don't hold it
  }

  const tree = core.core.tree
  const req = {
    fork: tree.fork,
    block: { index, nodes: 0 },
    hash: null,
    seek: null,
    upgrade: { start: 0, length: core.length },
    manifest: false
  }
  const proof = await tree.proof(req)
  proof.block.value = await core.core.blocks.get(index)

  const proofBytes = c.encode(wire.data, {
    request: 0,
    fork: tree.fork,
    block: proof.block,
    hash: null,
    seek: null,
    upgrade: proof.upgrade || null
  })

  const { signable, blockHash } = storageProofSignable(core.key, index, nonce, proof.block.value)
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, signable, keyPair.secretKey)

  return {
    coreKey: b4a.toString(core.key, 'hex'),
    index,
    nonce: b4a.toString(nonce, 'hex'),
    proof: b4a.toString(proofBytes, 'hex'),
    blockHash: b4a.toString(blockHash, 'hex'),
    relayPubkey: b4a.toString(keyPair.publicKey, 'hex'),
    signature: b4a.toString(signature, 'hex')
  }
}

/**
 * CLIENT SIDE — verify a proof response against what we expected to be proven.
 *
 * `verifierCore` is a key-only Hypercore opened on the drive key (no prior
 * content needed; may be reused across samples — Hypercore verifies each block
 * against the same signed root). `expect` is { driveKey, index, nonce, relayPubkey }.
 *
 * Returns a detailed verdict; `valid` is true only if BOTH the content proof
 * and the relay signature check out for the exact challenge we issued.
 */
export async function verifyStorageProof ({ verifierCore, response, expect }) {
  const r = {
    valid: false,
    coreValid: false,
    indexValid: false,
    nonceValid: false,
    relayValid: false,
    contentValid: false,
    lengthValid: true,
    sigValid: false,
    provenLength: 0,
    reason: null
  }
  try {
    if (!response || typeof response !== 'object') { r.reason = 'NO_RESPONSE'; return r }
    const driveKeyHex = hex(expect.driveKey)
    const relayHex = hex(expect.relayPubkey)
    const nonceHex = hex(expect.nonce)

    // Bind the response to the exact challenge we issued — cheap rejects first.
    r.coreValid = response.coreKey === driveKeyHex
    if (!r.coreValid) { r.reason = 'CORE_MISMATCH'; return r }
    r.indexValid = response.index === expect.index
    if (!r.indexValid) { r.reason = 'INDEX_MISMATCH'; return r }
    r.nonceValid = response.nonce === nonceHex
    if (!r.nonceValid) { r.reason = 'NONCE_MISMATCH'; return r }
    r.relayValid = response.relayPubkey === relayHex
    if (!r.relayValid) { r.reason = 'RELAY_MISMATCH'; return r }

    // (1) CONTENT — decode the proof and verify it against the drive key alone.
    const decoded = c.decode(wire.data, b4a.from(response.proof, 'hex'))
    if (!decoded.block || decoded.block.index !== expect.index || !decoded.block.value) {
      r.reason = 'PROOF_SHAPE_INVALID'; return r
    }
    const blockValue = decoded.block.value
    try {
      await verifierCore.core.verify(decoded)
      r.contentValid = true
    } catch (e) {
      r.reason = 'CONTENT_INVALID:' + (e.code || e.message)
      return r
    }

    // Length-pin (optional): the proof's upgrade.length is author-signed (the
    // signature core.verify just validated covers the root at that length), so
    // it's trustworthy. If the caller pins a minimum (e.g. the current head
    // learned from Tier-1 open), reject a relay that proves an OLD, shorter
    // version — holding an old block isn't holding the current app.
    r.provenLength = (decoded.upgrade && decoded.upgrade.length) || 0
    if (expect.minLength != null) {
      r.lengthValid = r.provenLength >= expect.minLength
      if (!r.lengthValid) { r.reason = 'LENGTH_TOO_SHORT'; return r }
    }

    // (2) ATTRIBUTION + FRESHNESS — the relay signature over the verified block.
    const { signable, blockHash } = storageProofSignable(
      b4a.from(driveKeyHex, 'hex'), expect.index, b4a.from(nonceHex, 'hex'), blockValue
    )
    // The relay's claimed blockHash must match the content we actually verified.
    if (response.blockHash !== b4a.toString(blockHash, 'hex')) { r.reason = 'BLOCKHASH_MISMATCH'; return r }
    const sigBuf = b4a.from(response.signature, 'hex')
    r.sigValid = sigBuf.byteLength === sodium.crypto_sign_BYTES &&
      sodium.crypto_sign_verify_detached(sigBuf, signable, b4a.from(relayHex, 'hex'))
    if (!r.sigValid) { r.reason = 'SIG_INVALID'; return r }

    r.valid = true
    return r
  } catch (e) {
    r.reason = 'ERROR:' + (e.code || e.message)
    return r
  }
}

function hex (v) { return typeof v === 'string' ? v : b4a.toString(v, 'hex') }
