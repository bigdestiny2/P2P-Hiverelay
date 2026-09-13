import c from 'compact-encoding'
import crypto from 'hypercore-crypto'
import flat from 'flat-tree'
import { wire } from 'hypercore/messages.js'

export const HEAD_DOMAIN = Buffer.from('hiverelay.private.hc11.head-identity.v1\0', 'ascii')
export const CORPUS_MAGIC = Buffer.from('HRHC11C1', 'ascii')
export const BUNDLE_MAGIC = Buffer.from('HRHC11P1', 'ascii')
export const FORMAT_CONTRACT = Object.freeze({
  version: 1,
  head: 'ASCII hiverelay.private.hc11.head-identity.v1 NUL || u8(1) || key32 || fork_u64be || length_u64be || treeHash32; digest BLAKE2b-256',
  corpus: 'HRHC11C1 || profileDigest32 || headIdentity || headFrame_bytes32be || count_u32be || ordered all-block frame_bytes32be[count]',
  bundle: 'HRHC11P1 || profileDigest32 || headIdentity || headFrame_bytes32be || count_u32be || ascending selected frame_bytes32be[count]',
  bounds: { headBytes: 4096, proofBytes: 4194048, blockBytes: 1048576, corpusBytes: 67108864, blocks: 4096, samples: 16, nodesPerList: 64, signatureBytes: 1024 },
  upstream: 'hypercore/messages wire.data; request=0; flags=24(head) or25(block); fork exact; upgrade start=0,length=exact,additionalNodes empty; manifest v1,flags0,blake2b,quorum1,one ed25519 signer; canonical compact uints; no patch/prologue/linked/userData',
  versions: { hypercore: '11.34.1', corestore: '7.11.1', compactEncoding: '3.3.0', hypercoreCrypto: '3.7.0', flatTree: '1.13.0' }
})
export const PROFILE_DIGEST = crypto.hash(Buffer.from(JSON.stringify(FORMAT_CONTRACT)))
export const HEAD_BYTES = HEAD_DOMAIN.length + 81
export const MAX_PROOF_BYTES = 4 * 1024 * 1024 - 256
export class CoreUpstreamError extends Error {
  constructor (code, message) { super(message); this.name = 'CoreUpstreamError'; this.code = code }
}
export function fail (code, message) { throw new CoreUpstreamError(code, message) }
export function ownedBytes (input, max, label = 'bytes', min = 1) {
  if (!(input instanceof Uint8Array) || input.byteLength < min || input.byteLength > max) fail('CORE_INPUT', `${label} length/type invalid`)
  return Buffer.from(input)
}
export function safeInteger (value, label, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (typeof value === 'bigint') {
    if (value < BigInt(min) || value > BigInt(max)) fail('CORE_INPUT', `${label} outside pinned safe range`)
    return Number(value)
  }
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('CORE_INPUT', `${label} outside pinned safe range`)
  return value
}
export function limitsOf (input = {}) {
  const limits = {
    maxBlocks: input.maxBlocks ?? 256,
    maxBlockBytes: input.maxBlockBytes ?? 64 * 1024,
    maxCorpusBytes: input.maxCorpusBytes ?? 4 * 1024 * 1024,
    maxProofBytes: input.maxProofBytes ?? MAX_PROOF_BYTES,
    maxConcurrent: input.maxConcurrent ?? 2,
    timeoutMillis: input.timeoutMillis ?? 10000,
    maxWireBytes: input.maxWireBytes ?? 16 * 1024 * 1024
  }
  const bounds = { maxBlocks: [1, 4096], maxBlockBytes: [8, 1024 * 1024], maxCorpusBytes: [256, 64 * 1024 * 1024], maxProofBytes: [256, MAX_PROOF_BYTES], maxConcurrent: [1, 8], timeoutMillis: [10, 60000], maxWireBytes: [256, 128 * 1024 * 1024] }
  for (const [key, [lo, hi]] of Object.entries(bounds)) limits[key] = safeInteger(limits[key], key, lo, hi)
  return Object.freeze(limits)
}
export function headIdentity (head) {
  const key = ownedBytes(head.corePublicKey, 32, 'key', 32)
  const hash = ownedBytes(head.treeHash, 32, 'treeHash', 32)
  const fork = safeInteger(head.fork, 'fork')
  const length = safeInteger(head.length, 'length', 1)
  const out = Buffer.alloc(HEAD_BYTES)
  HEAD_DOMAIN.copy(out)
  let o = HEAD_DOMAIN.length
  out[o++] = 1; key.copy(out, o); o += 32
  out.writeBigUInt64BE(BigInt(fork), o); o += 8
  out.writeBigUInt64BE(BigInt(length), o); o += 8; hash.copy(out, o)
  return out
}
export function headHash (head) { return crypto.hash(headIdentity(head)) }
export function requestHead (request, limits) {
  if (!request || typeof request !== 'object') fail('CORE_INPUT', 'request required')
  return Object.freeze({ corePublicKey: ownedBytes(request.corePublicKey, 32, 'corePublicKey', 32), fork: safeInteger(request.fork, 'fork'), length: safeInteger(request.length, 'length', 1, limits.maxBlocks), signedHeadHash: ownedBytes(request.signedHeadHash, 32, 'private head identity digest', 32) })
}
export function indicesOf (values, head) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 16) fail('CORE_INPUT', 'one to sixteen indices required')
  const result = values.map(v => safeInteger(v, 'blockIndex', 0, head.length - 1))
  if (result.some((v, i) => i > 0 && v <= result[i - 1])) fail('CORE_INPUT', 'indices must be ascending and distinct')
  return result
}
class Reader {
  constructor (bytes) { this.bytes = bytes; this.offset = 0 }
  take (n) { if (n < 0 || n > this.bytes.length - this.offset) fail('CORE_FORMAT', 'truncated bytes'); const b = this.bytes.subarray(this.offset, this.offset + n); this.offset += n; return b }
  u32 () { return this.take(4).readUInt32BE() }
  blob (max) { const n = this.u32(); if (n < 1 || n > max) fail('CORE_FORMAT', 'blob bound'); return this.take(n) }
  uint () {
    const first = this.take(1)[0]
    if (first < 253) return first
    const n = first === 253 ? this.take(2).readUInt16LE() : first === 254 ? this.take(4).readUInt32LE() : this.take(8).readBigUInt64LE()
    const value = safeInteger(n, 'compact integer')
    if (value < (first === 253 ? 253 : first === 254 ? 65536 : 4294967296)) fail('CORE_FORMAT', 'noncanonical compact integer')
    return value
  }

  compactBlob (max, min = 1) { const n = this.uint(); if (n < min || n > max) fail('CORE_FORMAT', 'upstream blob bound'); return this.take(n) }
  nodes () {
    const count = this.uint()
    if (count > 64 || count > Math.floor((this.bytes.length - this.offset) / 34)) fail('CORE_FORMAT', 'upstream node count bound')
    for (let i = 0; i < count; i++) { this.uint(); this.uint(); this.take(32) }
  }

  end () { if (this.offset !== this.bytes.length) fail('CORE_FORMAT', 'trailing bytes') }
}
// Scan counts before invoking upstream codecs, which otherwise allocate arrays
// from attacker-controlled compact integers. This profile is intentionally narrow.
export function decodeFrame (input, limits, isHead = false) {
  const bytes = ownedBytes(input, isHead ? 4096 : limits.maxBlockBytes + 8192, 'upstream frame')
  const r = new Reader(bytes)
  if (r.uint() !== (isHead ? 24 : 25) || r.uint() !== 0) fail('CORE_FORMAT', 'upstream flags/request invalid')
  r.uint()
  if (!isHead) { r.uint(); r.compactBlob(limits.maxBlockBytes); r.nodes() }
  if (r.uint() !== 0) fail('CORE_FORMAT', 'upgrade must start at zero')
  safeInteger(r.uint(), 'upgrade length', 1, limits.maxBlocks)
  r.nodes()
  if (r.uint() !== 0) fail('CORE_FORMAT', 'exact signed head cannot contain additional upgrade nodes')
  r.compactBlob(1024, 64)
  if (r.uint() !== 1 || r.uint() !== 0 || r.uint() !== 0 || r.uint() !== 1 || r.uint() !== 1 || r.uint() !== 0) fail('CORE_FORMAT', 'unsupported manifest profile')
  r.take(32); r.take(32); r.end()
  const proof = c.decode(wire.data, bytes)
  if (!Buffer.from(c.encode(wire.data, proof)).equals(bytes)) fail('CORE_FORMAT', 'upstream canonical encoding mismatch')
  // verifyFullyRemote authenticates an upgrade, but does not itself reject an
  // unrelated leftover block root. Require the complete canonical path into
  // exactly one signed full root and forbid unused upgrade nodes.
  const roots = flat.fullRoots(2 * proof.upgrade.length)
  let blockRoot = -1
  if (proof.block) {
    let index = 2 * proof.block.index
    blockRoot = roots.find(root => flat.leftSpan(root) <= index && flat.rightSpan(root) >= index)
    if (blockRoot == null) fail('CORE_FORMAT', 'block is outside signed roots')
    const expected = []
    while (index !== blockRoot) { expected.push(flat.sibling(index)); index = flat.parent(index) }
    if (proof.block.nodes.length !== expected.length || proof.block.nodes.some((n, i) => n.index !== expected[i])) fail('CORE_FORMAT', 'block path does not exactly reach signed root')
  }
  const expected = roots.filter(root => root !== blockRoot)
  if (proof.upgrade.nodes.length !== expected.length || proof.upgrade.nodes.some((n, i) => n.index !== expected[i])) fail('CORE_FORMAT', 'upgrade roots are not canonical')
  return proof
}
export function encodeFrame (core, proof, limits, isHead = false) {
  const encoded = Buffer.from(c.encode(wire.data, { request: 0, fork: proof.fork, block: isHead ? null : proof.block, hash: null, seek: null, upgrade: proof.upgrade, manifest: core.manifest }))
  decodeFrame(encoded, limits, isHead)
  return encoded
}
function decodeHead (bytes, limits) {
  const r = new Reader(bytes)
  if (!r.take(HEAD_DOMAIN.length).equals(HEAD_DOMAIN) || r.take(1)[0] !== 1) fail('CORE_FORMAT', 'head profile mismatch')
  const corePublicKey = Buffer.from(r.take(32)); const fork = r.take(8).readBigUInt64BE(); const length = r.take(8).readBigUInt64BE(); const treeHash = Buffer.from(r.take(32))
  r.end()
  return { corePublicKey, fork: safeInteger(fork, 'fork'), length: safeInteger(length, 'length', 1, limits.maxBlocks), treeHash }
}
function sized (bytes) { const n = Buffer.alloc(4); n.writeUInt32BE(bytes.length); return [n, bytes] }
export function encodeContainer (head, headFrame, frames, limits, bundle = false) {
  const max = bundle ? limits.maxProofBytes : limits.maxCorpusBytes
  const count = Buffer.alloc(4); count.writeUInt32BE(frames.length)
  const parts = [bundle ? BUNDLE_MAGIC : CORPUS_MAGIC, PROFILE_DIGEST, headIdentity(head), ...sized(headFrame), count]
  let length = parts.reduce((n, b) => n + b.length, 0)
  for (const frame of frames) { length += 4 + frame.length; if (length > max) fail('CORE_TOO_LARGE', 'encoded corpus/proof bound'); parts.push(...sized(frame)) }
  if (length > max) fail('CORE_TOO_LARGE', 'encoded corpus/proof bound')
  return Buffer.concat(parts, length)
}
export function decodeContainer (input, limits, bundle = false) {
  const bytes = ownedBytes(input, bundle ? limits.maxProofBytes : limits.maxCorpusBytes, 'corpus/proof')
  const r = new Reader(bytes)
  if (!r.take(8).equals(bundle ? BUNDLE_MAGIC : CORPUS_MAGIC) || !r.take(32).equals(PROFILE_DIGEST)) fail('CORE_FORMAT', 'container profile mismatch')
  const head = decodeHead(r.take(HEAD_BYTES), limits)
  const headFrame = Buffer.from(r.blob(4096)); const headProof = decodeFrame(headFrame, limits, true)
  const count = r.u32()
  if ((bundle && (count < 1 || count > 16)) || (!bundle && count !== head.length) || count > Math.floor((bytes.length - r.offset) / 5)) fail('CORE_FORMAT', 'container count bound')
  const frames = []; const proofs = []
  let previous = -1
  for (let i = 0; i < count; i++) {
    const frame = Buffer.from(r.blob(limits.maxBlockBytes + 8192)); const proof = decodeFrame(frame, limits)
    if (proof.block.index >= head.length || proof.block.index <= previous || (!bundle && proof.block.index !== i)) fail('CORE_FORMAT', 'container indices invalid')
    previous = proof.block.index
    frames.push(frame); proofs.push(proof)
  }
  r.end()
  return { head, headFrame, headProof, frames, proofs }
}
export function matchHead (head, requested) {
  if (!head.corePublicKey.equals(requested.corePublicKey) || head.fork !== requested.fork || head.length !== requested.length || !headHash(head).equals(requested.signedHeadHash)) fail('CORE_HEAD_INVALID', 'private authenticated head mismatch')
}
