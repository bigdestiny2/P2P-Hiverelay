import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'
import Corestore from 'corestore'
import c from 'compact-encoding'
import { wire } from 'hypercore/messages.js'
import { RealCoreUpstreamV1 } from '../index.js'
import { BUNDLE_MAGIC, HEAD_BYTES, PROFILE_DIGEST, decodeContainer, decodeFrame, encodeContainer, limitsOf } from '../format.js'
import { fixture, headRequest } from './helpers.mjs'
const blocks = ['private-alpha', 'private-bravo', 'private-charlie'].map(x => Buffer.from(x))

test('genuine encrypted mirror, exact proof, wrong head and tamper rejection; offline fresh process', { timeout: 20000 }, async t => {
  const f = await fixture(t)
  await f.writer.append(blocks)
  const request = await headRequest(f.writer)
  const result = await f.upstream.activateMirror({ request })
  assert.equal(result.verified, true)
  assert.equal(f.connections(), 1)
  assert.equal(f.upstream.status().inFlight, 0)
  assert.deepEqual(await fs.readdir(path.join(f.root, 'upstream')), [])
  const decoded = decodeContainer(result.corpus, f.upstream.limits)
  assert.deepEqual(decoded.proofs[1].block.value, await f.writer.get(1, { raw: true }))
  assert.notDeepEqual(decoded.proofs[1].block.value, blocks[1])
  assert.equal(result.corpus.includes(blocks[1]), false)
  f.persist(result.corpus)
  const challenge = { ...request, blockIndices: [0n, 2n] }
  const expected = await f.upstream.estimateProofBytes({ request: challenge })
  const proof = await f.upstream.serveProof({ generation: request, blockIndices: challenge.blockIndices, corpus: result.corpus })
  assert.equal(proof.length, expected)
  assert.equal(await f.upstream.verifyProofBundle({ request: challenge, proof }), true)
  const changed = Buffer.from(proof); changed[changed.length - 2] ^= 1
  await assert.rejects(f.upstream.verifyProofBundle({ request: challenge, proof: changed }))
  const wrong = { ...challenge, signedHeadHash: Buffer.alloc(32, 42) }
  await assert.rejects(f.upstream.verifyProofBundle({ request: wrong, proof }))
  const corrupt = decodeContainer(result.corpus, f.upstream.limits)
  const bad = c.decode(wire.data, corrupt.frames[0]); bad.block.value[0] ^= 1
  corrupt.frames[0] = Buffer.from(c.encode(wire.data, bad))
  const corrupted = encodeContainer(corrupt.head, corrupt.headFrame, corrupt.frames, f.upstream.limits)
  await assert.rejects(f.upstream.serveProof({ generation: request, blockIndices: [0], corpus: corrupted }))
  const inputPath = path.join(f.root, 'offline.json')
  await fs.writeFile(inputPath, JSON.stringify({ corpus: result.corpus.toString('hex'), key: request.corePublicKey.toString('hex'), fork: request.fork.toString(), length: request.length.toString(), head: request.signedHeadHash.toString('hex'), indices: ['0', '2'], expected: proof.toString('hex'), scratch: path.join(f.root, 'fresh-process') }))
  await f.writerStore.close()
  const child = spawn(process.execPath, [new URL('./offline-child.mjs', import.meta.url).pathname, inputPath], { stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''; child.stdout.on('data', d => { out += d }); child.stderr.on('data', d => { out += d })
  const code = await new Promise(resolve => child.on('close', resolve))
  assert.equal(code, 0, out); assert.match(out, /offline-proof-identical/)
})

test('exact append, retained old proof, hash-only expired floor, higher fork lower length', { timeout: 20000 }, async t => {
  const f = await fixture(t); await f.writer.append(blocks)
  const first = await headRequest(f.writer); const old = await f.upstream.activateMirror({ request: first })
  assert.equal(old.verified, true)
  const oldProof = await f.upstream.serveProof({ generation: first, blockIndices: [1], corpus: old.corpus })
  await f.writer.append(Buffer.from('new-fourth'))
  const next = await headRequest(f.writer)
  const extended = await f.upstream.activateMirror({ request: next, previousGeneration: { ...first, corpus: null } })
  assert.equal(extended.verified, true)
  const stale = await f.upstream.activateMirror({ request: first })
  assert.equal(stale.verified, false, 'prefix of later signed head is not exact head')
  assert.deepEqual(await f.upstream.serveProof({ generation: first, blockIndices: [1], corpus: old.corpus }), oldProof)
  await f.writer.truncate(1); await f.writer.append(Buffer.from('replacement'))
  const higher = await headRequest(f.writer)
  assert.equal(higher.fork, 1n); assert.equal(higher.length, 2n)
  assert.equal((await f.upstream.activateMirror({ request: higher, previousGeneration: next })).verified, true)
  assert.throws(() => f.upstream.activateMirror({ request: first, previousGeneration: higher }), { code: 'CORE_HEAD_INVALID' })
  assert.deepEqual(await f.upstream.serveProof({ generation: first, blockIndices: [1], corpus: old.corpus }), oldProof)
})

test('genuine same-fork signed equivocation fails prefix continuity', { timeout: 15000 }, async t => {
  const f = await fixture(t); await f.writer.append(blocks)
  const prior = await headRequest(f.writer)
  const otherStore = new Corestore(path.join(f.root, 'equivocator'))
  const other = otherStore.get({ keyPair: f.keyPair, encryptionKey: Buffer.alloc(32, 19) }); await other.ready()
  t.after(() => otherStore.close())
  assert.deepEqual(other.key, f.writer.key)
  await other.append([Buffer.from('different-history'), ...blocks])
  const request = await headRequest(other)
  const upstream = new RealCoreUpstreamV1({ root: path.join(f.root, 'equivocation-acquire'), connect: () => other.replicate(false), readCorpus: () => {} })
  t.after(() => upstream.close())
  assert.equal((await upstream.activateMirror({ request })).verified, true, 'signature alone is genuine')
  assert.equal((await upstream.activateMirror({ request, previousGeneration: prior })).verified, false)
})

test('sparse missing data times out, source disconnect cancels; late connector remains charged', { timeout: 10000 }, async t => {
  const f = await fixture(t, { limits: { timeoutMillis: 1000 } }); await f.writer.append(blocks)
  const request = await headRequest(f.writer)
  await f.writer.clear(1)
  await assert.rejects(f.upstream.activateMirror({ request }), { code: 'CORE_ABORTED' })
  assert.equal(f.connections(), 1)
  assert.equal(await f.upstream.close(), true)
  let provide; let entered; const connected = new Promise(resolve => { entered = resolve }); const controller = new AbortController()
  const late = new RealCoreUpstreamV1({ root: path.join(f.root, 'late'), limits: { timeoutMillis: 3000, maxConcurrent: 1 }, connect: () => { entered(); return new Promise(resolve => { provide = resolve }) }, readCorpus: () => {} })
  t.after(() => late.close())
  const opening = late.activateMirror({ request, signal: controller.signal }); await connected; controller.abort()
  await assert.rejects(opening, { code: 'CORE_ABORTED' })
  assert.equal(late.status().inFlight, 1)
  await assert.rejects(late.activateMirror({ request }), { code: 'CORE_BUSY' })
  assert.equal(await late.close({ timeoutMillis: 20 }), false)
  const remote = f.writer.replicate(false); provide(remote)
  assert.equal(await late.close(), true)
  assert.equal(late.status().inFlight, 0); assert.equal(remote.destroyed, true)
})

test('abort before admission, block/wire/corpus limits and strict decoding bounds', { timeout: 10000 }, async t => {
  const f = await fixture(t, { limits: { maxBlockBytes: 16, timeoutMillis: 1000 } }); await f.writer.append(blocks)
  const request = await headRequest(f.writer)
  const controller = new AbortController(); controller.abort()
  await assert.rejects(f.upstream.activateMirror({ request, signal: controller.signal }), { code: 'CORE_ABORTED' }); assert.equal(f.connections(), 0)
  assert.equal((await f.upstream.activateMirror({ request })).verified, false, 'oversized ciphertext refused')
  assert.throws(() => f.upstream.activateMirror({ request: { ...request, fork: 1n << 60n } }), { code: 'CORE_INPUT' })
  const maliciousFrame = Buffer.from([25, 0, 0, 0, 1, 42, 255, 255, 255, 255, 255, 255, 255, 255, 0])
  assert.throws(() => decodeFrame(maliciousFrame, limitsOf()))
  assert.throws(() => decodeContainer(Buffer.concat([BUNDLE_MAGIC, PROFILE_DIGEST, Buffer.alloc(HEAD_BYTES + 100)]), limitsOf(), true))
})

test('upstream leftover-root trap and malformed canonical containers are refused', { timeout: 15000 }, async t => {
  const f = await fixture(t); await f.writer.append(blocks)
  const request = await headRequest(f.writer)
  const activation = await f.upstream.activateMirror({ request }); assert.equal(activation.verified, true)
  const decoded = decodeContainer(activation.corpus, f.upstream.limits)
  const unrelated = { ...decoded.headProof, block: { index: 0, value: Buffer.from('forged-ciphertext'), nodes: [] } }
  const actualUpstreamBatch = await f.writer.verifyFullyRemote(unrelated)
  assert.deepEqual(actualUpstreamBatch.hash(), decoded.head.treeHash, 'pinned verifier authenticates head while unrelated leaf remains unused')
  const unrelatedBytes = Buffer.from(c.encode(wire.data, unrelated))
  assert.throws(() => decodeFrame(unrelatedBytes, f.upstream.limits), { code: 'CORE_FORMAT' })
  const forms = [
    Buffer.concat([activation.corpus, Buffer.from([0])]),
    activation.corpus.subarray(0, activation.corpus.length - 1),
    Buffer.from(activation.corpus)
  ]
  forms[2][8] ^= 1
  for (const bytes of forms) await assert.rejects(f.upstream.serveProof({ generation: request, blockIndices: [0], corpus: bytes }))
  assert.throws(() => f.upstream.serveProof({ generation: request, blockIndices: [1, 1], corpus: activation.corpus }))
  const dupe = encodeContainer(decoded.head, decoded.headFrame, [decoded.frames[0], decoded.frames[0], decoded.frames[2]], f.upstream.limits)
  await assert.rejects(f.upstream.serveProof({ generation: request, blockIndices: [0], corpus: dupe }))
  const countBomb = Buffer.from(activation.corpus)
  countBomb.writeUInt32BE(0xffffffff, 8 + 32 + HEAD_BYTES + 4 + decoded.headFrame.length)
  assert.throws(() => decodeContainer(countBomb, f.upstream.limits))
  const exact = new RealCoreUpstreamV1({ root: path.join(f.root, 'exact-limit'), connect: () => f.writer.replicate(false), readCorpus: () => activation.corpus, limits: { maxCorpusBytes: activation.corpus.length } })
  t.after(() => exact.close())
  assert.equal((await exact.activateMirror({ request })).verified, true)
  const tooSmall = new RealCoreUpstreamV1({ root: path.join(f.root, 'too-small'), connect: () => f.writer.replicate(false), readCorpus: () => activation.corpus, limits: { maxCorpusBytes: activation.corpus.length - 1 } })
  t.after(() => tooSmall.close())
  assert.equal((await tooSmall.activateMirror({ request })).verified, false)
})

test('real source disconnect and wire budget abort acquired sessions', { timeout: 15000 }, async t => {
  const f = await fixture(t); await f.writer.append(blocks)
  const request = await headRequest(f.writer)
  let cut = false
  const disconnected = new RealCoreUpstreamV1({ root: path.join(f.root, 'disconnected'), connect: () => { const stream = f.writer.replicate(false); stream.once('data', () => { cut = true; stream.destroy() }); return stream }, readCorpus: () => {}, limits: { timeoutMillis: 1000 } })
  t.after(() => disconnected.close())
  await assert.rejects(disconnected.activateMirror({ request }), { code: 'CORE_ABORTED' }); assert.equal(cut, true)
  assert.equal(await disconnected.close(), true)
  const metered = new RealCoreUpstreamV1({ root: path.join(f.root, 'wire-limit'), connect: () => f.writer.replicate(false), readCorpus: () => {}, limits: { maxWireBytes: 256 } })
  t.after(() => metered.close())
  await assert.rejects(metered.activateMirror({ request }), { code: 'CORE_ABORTED' })
  assert.equal(await metered.close(), true)
})

test('late cleanup cancellation cannot mint activation and retains capacity until release', { timeout: 15000 }, async t => {
  const f = await fixture(t); await f.writer.append(blocks)
  const request = await headRequest(f.writer)
  const controller = new AbortController(); let entered; let release
  const atRemoval = new Promise(resolve => { entered = resolve }); const removalGate = new Promise(resolve => { release = resolve })
  const original = fs.rm
  fs.rm = async function (target, options) {
    if (String(target).startsWith(path.join(f.root, 'upstream', 'acquire-'))) { entered(); await removalGate }
    return original.call(this, target, options)
  }
  try {
    const pending = f.upstream.activateMirror({ request, signal: controller.signal })
    await atRemoval; controller.abort()
    await assert.rejects(pending, { code: 'CORE_ABORTED' })
    assert.equal(f.upstream.status().inFlight, 1)
    release(); assert.equal(await f.upstream.close(), true); assert.equal(f.upstream.status().inFlight, 0)
  } finally { release(); fs.rm = original }
})

test('caller buffers are captured before yielding; authenticated proof paths cover irregular trees', { timeout: 20000 }, async t => {
  const f = await fixture(t)
  for (let i = 0; i < 9; i++) await f.writer.append(Buffer.from('irregular-block-' + i))
  const request = await headRequest(f.writer)
  const original = Buffer.from(request.signedHeadHash)
  const pending = f.upstream.activateMirror({ request }); request.signedHeadHash[0] ^= 1
  const activation = await pending; request.signedHeadHash = original
  assert.equal(activation.verified, true)
  const corpus = Buffer.from(activation.corpus)
  const serving = f.upstream.serveProof({ generation: request, blockIndices: [0, 3, 7, 8], corpus })
  corpus[0] ^= 1
  const proof = await serving
  assert.equal(await f.upstream.verifyProofBundle({ request: { ...request, blockIndices: [0, 3, 7, 8] }, proof }), true)
})

test('native cleanup failure fences the instance and keeps its resource reservation', { timeout: 15000 }, async t => {
  const f = await fixture(t); await f.writer.append(blocks)
  const request = await headRequest(f.writer)
  const original = fs.rm
  fs.rm = async function (target, options) {
    if (String(target).startsWith(path.join(f.root, 'upstream', 'acquire-'))) throw Object.assign(new Error('fixture removal refused'), { code: 'EIO' })
    return original.call(this, target, options)
  }
  try {
    await assert.rejects(f.upstream.activateMirror({ request }), { code: 'CORE_RELEASE_FAILED' })
    assert.equal(f.upstream.status().inFlight, 1)
    assert.equal(f.upstream.status().reservedCorpusBytes, f.upstream.limits.maxCorpusBytes)
    assert.equal(f.upstream.status().closing, true)
    await assert.rejects(f.upstream.activateMirror({ request }), { code: 'CORE_CLOSED' })
    assert.equal(await f.upstream.close(), false)
  } finally { fs.rm = original }
})
