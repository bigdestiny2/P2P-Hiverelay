/**
 * Verifiable retrieval (R1) — client-side verifier for gateway proof bundles.
 *
 * Counterpart to packages/core/gateway/verify-bundle.js. A gateway GET with
 * `?verify=1` (or `Accept: application/vnd.hiverelay.hc-block`) returns a
 * versioned bundle instead of raw bytes; `verifyBlockBundle` re-derives the
 * whole trust chain from the drive key alone and REJECTS anything that does
 * not prove out — the gateway is never trusted:
 *
 *   1. TREE HEADER SIGNATURE BY THE DRIVE KEY. The entry proof's embedded
 *      manifest must hash to envelope.driveKey (hc11: key === manifest hash),
 *      and a key-only Hypercore fed the proof (`applyProof`) verifies the
 *      signed tree header at envelope.driveVersion.
 *   2. PATH BINDING. The proved bee node must decode to exactly the requested
 *      path (`files\0<path>` sub-prefix) and its blob descriptor must equal
 *      the envelope's claimed `blob`.
 *   3. CONTENT KEY DERIVATION. The blobs core key is re-derived from the
 *      drive manifest (`Hyperdrive.getContentManifest`) — never taken from
 *      the envelope — and the blob proof's manifest must hash to it.
 *   4. BLOCK INTO SIGNED ROOT. A second key-only core fed the blob proof
 *      verifies blockBytes hash into the blobs core's signed root; both
 *      envelope tree headers must match the verified state (length, fork,
 *      signature, recomputed root hash), so stale headers reject.
 *   5. BLOCK BYTES MATCH. The envelope's blockBytes must be byte-identical to
 *      the proved block, sit inside the entry-proved blob extent, and have
 *      the exact length the descriptor arithmetic demands.
 *
 * Scope (matches the envelope doc): v1 verifies MANIFEST drives (every drive
 * created on hypercore 11 / hyperdrive 13). Compat (pre-manifest) drives are
 * rejected with reason COMPAT_DRIVE_UNSUPPORTED — their blobs key is not
 * publicly derivable without an extra header proof.
 *
 *   const verdict = await verifyBlockBundle(bundle)
 *   // verdict.valid === true ⇒ verdict.blockBytes are the drive-key-signed
 *   // bytes for bundle.path covering bundle.fileRange.
 */

import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import Hypercore from 'hypercore'
import c from 'compact-encoding'
import b4a from 'b4a'
import crypto from 'hypercore-crypto'
import { wire } from 'hypercore/lib/messages.js'
import { Node as BeeNode } from 'hyperbee/lib/messages.js'
import { rm } from 'fs/promises'
import { join } from 'path'
import { HC_BLOCK_ENVELOPE_VERSION } from 'p2p-hiverelay/gateway/verify-bundle.js'

export const HC_BLOCK_VERIFY_VERSION = HC_BLOCK_ENVELOPE_VERSION

// Hyperdrive stores files under a fixed 'files' sub (SubEncoder prefix + 0x00).
const BEE_FILES_PREFIX = 'files\x00'
const HEX_64 = /^[0-9a-f]{64}$/

let _sandboxSeq = 0

function portableTmpdir () {
  const env = (typeof globalThis.process !== 'undefined' && globalThis.process.env) ||
    (typeof globalThis.Bare !== 'undefined' && globalThis.Bare.env) ||
    {}
  return env.TMPDIR || env.TMP || env.TEMP || '/tmp'
}

/**
 * Verify a gateway hc-block bundle against the drive key it claims.
 *
 * @param {object} bundle - the decoded JSON envelope (application/vnd.hiverelay.hc-block+json)
 * @param {object} [opts]
 * @param {Corestore} [opts.store] - verifier cores are opened on this store;
 *   defaults to a throwaway temp-dir Corestore sandbox (removed afterwards).
 * @returns {Promise<object>} verdict — `valid` is true only if EVERY check
 *   passed; on failure `reason` names the first failed check.
 */
export async function verifyBlockBundle (bundle, opts = {}) {
  const r = {
    valid: false,
    versionValid: false,
    driveKeyValid: false,
    entryValid: false,
    pathValid: false,
    blobValid: false,
    blobsKeyValid: false,
    blockValid: false,
    headerValid: false,
    reason: null,
    driveKey: null,
    driveVersion: null,
    path: null,
    blockIndex: null,
    blockBytes: null,
    blob: null,
    blobsKey: null
  }
  try {
    // ── Shape ────────────────────────────────────────────────────
    if (!bundle || typeof bundle !== 'object') { r.reason = 'NO_BUNDLE'; return r }
    if (bundle.v !== HC_BLOCK_ENVELOPE_VERSION) { r.reason = 'ENVELOPE_VERSION_UNSUPPORTED'; return r }
    r.versionValid = true
    if (typeof bundle.driveKey !== 'string' || !HEX_64.test(bundle.driveKey)) { r.reason = 'DRIVE_KEY_INVALID'; return r }
    if (typeof bundle.blobsKey !== 'string' || !HEX_64.test(bundle.blobsKey)) { r.reason = 'BLOBS_KEY_INVALID'; return r }
    if (!Number.isSafeInteger(bundle.driveVersion) || bundle.driveVersion < 1) { r.reason = 'DRIVE_VERSION_INVALID'; return r }
    if (typeof bundle.path !== 'string' || !bundle.path.startsWith('/')) { r.reason = 'PATH_INVALID'; return r }
    if (!Number.isSafeInteger(bundle.blockIndex) || bundle.blockIndex < 0) { r.reason = 'BLOCK_INDEX_INVALID'; return r }
    const blob = bundle.blob
    if (!blob || typeof blob !== 'object' ||
        !Number.isSafeInteger(blob.blockOffset) || blob.blockOffset < 0 ||
        !Number.isSafeInteger(blob.blockLength) || blob.blockLength < 1 ||
        !Number.isSafeInteger(blob.byteOffset) || blob.byteOffset < 0 ||
        !Number.isSafeInteger(blob.byteLength) || blob.byteLength < 1 ||
        !Number.isSafeInteger(blob.blockSize) || blob.blockSize < 1) { r.reason = 'BLOB_INVALID'; return r }
    // blockSize is gateway-claimed but entry-provable arithmetic must hold:
    // blockLength chunks of blockSize cover exactly byteLength.
    if ((blob.blockLength - 1) * blob.blockSize >= blob.byteLength ||
        blob.byteLength > blob.blockLength * blob.blockSize) { r.reason = 'BLOB_INVALID'; return r }
    const fileRange = bundle.fileRange
    if (!fileRange || !Number.isSafeInteger(fileRange.start) || fileRange.start < 0 ||
        !Number.isSafeInteger(fileRange.end) || fileRange.end < fileRange.start) { r.reason = 'RANGE_INVALID'; return r }
    const entry = bundle.entry
    if (!entry || typeof entry !== 'object' ||
        !Number.isSafeInteger(entry.blockIndex) || entry.blockIndex < 0) { r.reason = 'ENTRY_INVALID'; return r }
    if (!validHeader(bundle.treeHeader) || !validHeader(entry.treeHeader)) { r.reason = 'HEADER_INVALID'; return r }
    const blockBytes = decodeHex(bundle.blockBytes)
    const entryBlockBytes = decodeHex(entry.blockBytes)
    const proofBytes = decodeHex(bundle.proof)
    const entryProofBytes = decodeHex(entry.proof)
    if (!blockBytes || !entryBlockBytes || !proofBytes || !entryProofBytes) { r.reason = 'HEX_INVALID'; return r }

    r.driveKey = bundle.driveKey
    r.driveVersion = bundle.driveVersion
    r.path = bundle.path
    r.blockIndex = bundle.blockIndex
    r.blob = { ...blob }
    r.blobsKey = bundle.blobsKey

    // ── Entry proof: manifest ⇒ drive key, block pins path ──────
    let entryProof
    try {
      entryProof = c.decode(wire.data, entryProofBytes)
    } catch (e) {
      r.reason = 'ENTRY_PROOF_INVALID:' + (e.code || e.message); return r
    }
    if (!entryProof.block || !entryProof.upgrade || !entryProof.manifest) {
      r.reason = entryProof.manifest ? 'ENTRY_PROOF_INVALID' : 'COMPAT_DRIVE_UNSUPPORTED'; return r
    }
    if (entryProof.block.index !== entry.blockIndex) { r.reason = 'ENTRY_INDEX_MISMATCH'; return r }
    if (!b4a.equals(entryProof.block.value, entryBlockBytes)) { r.reason = 'ENTRY_BYTES_MISMATCH'; return r }
    const driveKey = b4a.from(bundle.driveKey, 'hex')
    if (!b4a.equals(Hypercore.key(entryProof.manifest), driveKey)) { r.reason = 'DRIVE_KEY_MISMATCH'; return r }
    r.driveKeyValid = true

    // The entry proof must be pinned at exactly the claimed drive version.
    if (entryProof.upgrade.length !== bundle.driveVersion) { r.reason = 'DRIVE_VERSION_MISMATCH'; return r }
    if (!headerMatches(entry.treeHeader, entryProof)) { r.reason = 'ENTRY_HEADER_MISMATCH'; return r }

    // ── Path binding: the proved bee node names this path + blob ─
    let beeNode
    try {
      beeNode = BeeNode.decode(entryBlockBytes)
    } catch (e) {
      r.reason = 'ENTRY_NODE_INVALID:' + (e.code || e.message); return r
    }
    if (!beeNode || !b4a.equals(beeNode.key, b4a.from(BEE_FILES_PREFIX + bundle.path, 'utf8'))) {
      r.reason = 'PATH_MISMATCH'; return r
    }
    r.pathValid = true
    let entryValue
    try {
      entryValue = JSON.parse(b4a.toString(beeNode.value, 'utf8'))
    } catch {
      r.reason = 'ENTRY_NODE_INVALID'; return r
    }
    const provedBlob = entryValue && entryValue.blob
    if (!provedBlob ||
        provedBlob.blockOffset !== blob.blockOffset ||
        provedBlob.blockLength !== blob.blockLength ||
        provedBlob.byteOffset !== blob.byteOffset ||
        provedBlob.byteLength !== blob.byteLength) { r.reason = 'BLOB_MISMATCH'; return r }
    r.blobValid = true

    // ── Blobs key: re-derived from the drive manifest, never trusted ─
    const blobsManifest = Hyperdrive.getContentManifest(entryProof.manifest, driveKey)
    if (!blobsManifest) { r.reason = 'COMPAT_DRIVE_UNSUPPORTED'; return r }
    const blobsKey = Hypercore.key(blobsManifest)
    if (!b4a.equals(blobsKey, b4a.from(bundle.blobsKey, 'hex'))) { r.reason = 'BLOBS_KEY_MISMATCH'; return r }
    r.blobsKeyValid = true

    // ── Block proof: extent mapping + claimed bytes match proof ──
    let blockProof
    try {
      blockProof = c.decode(wire.data, proofBytes)
    } catch (e) {
      r.reason = 'BLOCK_PROOF_INVALID:' + (e.code || e.message); return r
    }
    if (!blockProof.block || !blockProof.upgrade || !blockProof.manifest) { r.reason = 'BLOCK_PROOF_INVALID'; return r }
    const blockRel = bundle.blockIndex - blob.blockOffset
    if (blockRel < 0 || blockRel >= blob.blockLength) { r.reason = 'BLOCK_OUT_OF_RANGE'; return r }
    if (blockProof.block.index !== bundle.blockIndex) { r.reason = 'BLOCK_INDEX_MISMATCH'; return r }
    if (!b4a.equals(blockProof.block.value, blockBytes)) { r.reason = 'BLOCK_BYTES_MISMATCH'; return r }
    if (!b4a.equals(Hypercore.key(blockProof.manifest), blobsKey)) { r.reason = 'BLOBS_MANIFEST_MISMATCH'; return r }
    const expectedBlockBytes = blockRel < blob.blockLength - 1
      ? blob.blockSize
      : blob.byteLength - blockRel * blob.blockSize
    if (blockBytes.byteLength !== expectedBlockBytes) { r.reason = 'BLOCK_SIZE_MISMATCH'; return r }
    if (fileRange.start !== blockRel * blob.blockSize ||
        fileRange.end !== fileRange.start + blockBytes.byteLength - 1) { r.reason = 'RANGE_MISMATCH'; return r }
    if (!headerMatches(bundle.treeHeader, blockProof)) { r.reason = 'BLOCK_HEADER_MISMATCH'; return r }

    // ── Cryptographic verification: key-only cores, hypercore does it ─
    const ownSandbox = !opts.store
    const sandboxDir = ownSandbox
      ? join(portableTmpdir(), 'hiverelay-hc-block-' + process.pid + '-' + (_sandboxSeq++))
      : null
    const store = ownSandbox ? new Corestore(sandboxDir) : opts.store
    const beeCore = store.get({ key: driveKey })
    const blobsCore = store.get({ key: blobsKey })
    try {
      await beeCore.ready()
      await blobsCore.ready()

      let applied = false
      try {
        applied = await beeCore.applyProof(entryProof)
      } catch (e) {
        r.reason = 'ENTRY_INVALID:' + (e.code || e.message); return r
      }
      if (!applied) { r.reason = 'ENTRY_INVALID:VERIFY_REJECTED'; return r }
      r.entryValid = true
      if (!rootHashMatches(beeCore, entry.treeHeader.rootHash)) { r.reason = 'ENTRY_ROOT_MISMATCH'; return r }

      try {
        applied = await blobsCore.applyProof(blockProof)
      } catch (e) {
        r.reason = 'BLOCK_INVALID:' + (e.code || e.message); return r
      }
      if (!applied) { r.reason = 'BLOCK_INVALID:VERIFY_REJECTED'; return r }
      r.blockValid = true
      if (!rootHashMatches(blobsCore, bundle.treeHeader.rootHash)) { r.reason = 'BLOCK_ROOT_MISMATCH'; return r }
      r.headerValid = true
    } finally {
      try { await beeCore.close() } catch {}
      try { await blobsCore.close() } catch {}
      if (ownSandbox) {
        try { await store.close() } catch {}
        try { await rm(sandboxDir, { recursive: true, force: true }) } catch {}
      }
    }

    r.blockBytes = blockBytes
    r.valid = true
    return r
  } catch (e) {
    r.reason = 'ERROR:' + (e.code || e.message)
    return r
  }
}

function validHeader (header) {
  return !!header && typeof header === 'object' &&
    Number.isSafeInteger(header.fork) && header.fork >= 0 &&
    Number.isSafeInteger(header.length) && header.length >= 1 &&
    typeof header.rootHash === 'string' && HEX_64.test(header.rootHash) &&
    typeof header.signature === 'string' && header.signature.length > 0 &&
    /^[0-9a-f]+$/.test(header.signature) && header.signature.length % 2 === 0
}

// The envelope's claimed tree header must be exactly what the proof carried:
// length + fork + the signature hypercore itself verified. (The root hash is
// cross-checked against the post-applyProof verified state below.)
function headerMatches (header, proof) {
  return header.length === proof.upgrade.length &&
    header.fork === proof.fork &&
    header.signature === b4a.toString(proof.upgrade.signature, 'hex')
}

// Recompute the signed root from the nodes applyProof committed — the tree
// hash must equal the envelope's claimed rootHash (stale/forged headers fail).
function rootHashMatches (core, rootHashHex) {
  const roots = core && core.core && core.core.state && core.core.state.roots
  if (!Array.isArray(roots) || roots.length === 0) return false
  return b4a.equals(crypto.tree(roots), b4a.from(rootHashHex, 'hex'))
}

function decodeHex (value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) return null
  return b4a.from(value, 'hex')
}
