import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { fixture, gate, turn, Hypercore } from './helpers.mjs'
import { NodeCoreProofClientV1, STATUS } from '../index.js'
import { VerifiedOperationResult } from '../../blind-client/results.js'
import { PROFILE_DIGEST, decodeContainer, limitsOf } from '../../blind-core-upstream-hc11-v1/format.js'
import { RealCoreUpstreamV1 } from '../../blind-core-upstream-hc11-v1/index.js'
import { decodeCanonical, encodeCanonical } from '../../blind-protocol/codec.js'
import { coreServeResultV1 } from '../../blind-protocol/schemas.js'

test('actual acquired encrypted HC11 bytes flow through private transport and produce a branded result offline', async t => {
  const f = await fixture(t)
  const created = await f.request({ admission: { profileId: 1, schemeId: 1, parameterHash: Buffer.alloc(32, 7), token: Buffer.alloc(32, 8) } })
  const response = f.response(created)
  let calls = 0
  const client = f.client({
    async request (options) {
      calls++
      assert.deepEqual(options.body, created.requestBytes)
      assert.equal(options.familyId, 4); assert.equal(options.operationId, 2)
      assert.equal(options.expectedResultBodyBytes, 4 * 1024 * 1024)
      return response
    }
  })
  const result = await client.prove(f.options(created))
  assert(result instanceof VerifiedOperationResult)
  assert.deepEqual(result.snapshotBytes(), response.body)
  assert.equal(calls, 1)
  assert.equal(client.status().inFlight, 0)
  assert.equal(STATUS.defaultSelected, false); assert.equal(STATUS.durableAttemptComposed, false)
  assert(!f.proof.includes(Buffer.from('private-ciphertext-one')), 'acquisition returned ciphertext without a reader key')
  const returned = result.snapshotBytes(); returned.fill(0)
  assert.deepEqual(result.snapshotBytes(), response.body)
  assert.equal(await client.close(), true)
})

test('actual proof verifier refuses ciphertext tampering and exact key/fork/length/private-head/sample mismatches', async t => {
  const f = await fixture(t)
  const original = await f.request()
  const decoded = decodeContainer(f.proof, limitsOf(), true)
  const tampered = Buffer.from(f.proof)
  const offset = tampered.indexOf(decoded.proofs[0].block.value)
  assert(offset > 0); tampered[offset] ^= 1
  const cases = [
    ['ciphertext', original, tampered],
    ['key', await f.request({ corePublicKey: Buffer.alloc(32, 99) }), f.proof],
    ['fork', await f.request({ fork: 1n }), f.proof],
    ['length', await f.request({ length: 4n }), f.proof],
    ['head', await f.request({ signedHeadHash: Buffer.alloc(32, 98) }), f.proof],
    ['sample', await f.request({ blockIndices: [1n] }), f.proof],
    ['missing', original, Buffer.from([1])]
  ]
  for (const [label, created, proof] of cases) {
    const client = f.client({ request: async () => f.response(created, proof) })
    await assert.rejects(client.prove(f.options(created)), error => /^CORE_|RELAY_PROTOCOL_VIOLATION/.test(error.code), label)
    assert.equal(client.status().inFlight, 0, label)
  }
})

test('signed relay result, nonce, commitment, head and missing/false transport result remain mandatory', async t => {
  const f = await fixture(t); const created = await f.request()
  const badSignature = f.response(created)
  const decoded = decodeCanonical(coreServeResultV1, badSignature.body, { copyBytes: true })
  decoded.acknowledgement.signature[0] ^= 1
  badSignature.body = encodeCanonical(coreServeResultV1, decoded)
  const responses = [badSignature,
    f.response(created, f.proof, { requestNonce: Buffer.alloc(32, 23) }),
    f.response(created, f.proof, { requestCommitment: Buffer.alloc(32, 24) }),
    f.response(created, f.proof, { signedHeadHash: Buffer.alloc(32, 25) }),
    null, { ok: true }, { ok: Promise.resolve(true), body: f.response(created).body }]
  for (const response of responses) {
    const client = f.client({ request: async () => response })
    await assert.rejects(client.prove(f.options(created)))
  }
  const client = f.client()
  await assert.rejects(client.verifyResult({ ...f.options(created), resultBytes: f.response(created).body, coreProofVerifier: () => true }), { code: 'CORE_CLIENT_INPUT' })
  assert.throws(() => new NodeCoreProofClientV1({ root: f.root, profileDigest: PROFILE_DIGEST, verifier: async () => true }), { code: 'CORE_CLIENT_INPUT' })
  assert.throws(() => new NodeCoreProofClientV1({ root: f.root, profileDigest: Buffer.alloc(32, 5) }), { code: 'CORE_CLIENT_INPUT' })
})

test('pending genuine native verification is never accepted for Promise truthiness and owns mutable inputs', async t => {
  const f = await fixture(t)
  const created = await f.request({ admission: { profileId: 1, schemeId: 1, parameterHash: Buffer.alloc(32, 7), token: Buffer.alloc(32, 8) } })
  const response = f.response(created); const expected = Buffer.from(response.body)
  const entered = gate(); const held = gate(); const original = Hypercore.prototype.verifyFullyRemote
  let paused = false
  Hypercore.prototype.verifyFullyRemote = async function (...args) {
    const batch = await original.apply(this, args)
    if (!paused) { paused = true; entered.release(); await held.waiting }
    return batch
  }
  t.after(() => { Hypercore.prototype.verifyFullyRemote = original; held.release() })
  const client = f.client()
  let successes = 0
  const pending = client.verifyResult({ ...f.options(created), resultBytes: response.body }).then(result => { successes++; return result })
  await entered.waiting
  created.requestBytes.fill(0); created.requestCommitment.fill(0); response.body.fill(0)
  await turn(); assert.equal(successes, 0)
  await assert.rejects(client.verifyResult({}), { code: 'CORE_CLIENT_BUSY' })
  held.release()
  assert.deepEqual((await pending).snapshotBytes(), expected)
  assert.equal(successes, 1)
})

test('each response including a replay requires fresh actual verification; no proof authorization is reusable', async t => {
  const f = await fixture(t); const created = await f.request(); const response = f.response(created)
  const original = Hypercore.prototype.verifyFullyRemote; let calls = 0
  Hypercore.prototype.verifyFullyRemote = function (...args) { calls++; return original.apply(this, args) }
  t.after(() => { Hypercore.prototype.verifyFullyRemote = original })
  const client = f.client()
  await client.verifyResult({ ...f.options(created), resultBytes: response.body })
  const first = calls; assert(first >= 3)
  await client.verifyResult({ ...f.options(created), resultBytes: response.body })
  assert.equal(calls, 2 * first)
  const different = await f.request({ blockIndices: [1n] })
  await assert.rejects(client.verifyResult({ ...f.options(different), resultBytes: f.response(different).body }), { code: 'CORE_HEAD_INVALID' })
  assert(calls > 2 * first)
})

test('late actual verification cannot win a deadline when synchronous work delays timer delivery', async t => {
  const f = await fixture(t); const created = await f.request()
  const original = RealCoreUpstreamV1.prototype.verifyProofBundle
  let completedActualVerification = false
  RealCoreUpstreamV1.prototype.verifyProofBundle = async function (...args) {
    const verified = await original.apply(this, args)
    completedActualVerification = verified === true
    // Delay only delivery of the actual result after native verification/cleanup.
    // No cryptographic result is fabricated or replaced in this control.
    const until = performance.now() + 1500
    while (performance.now() < until) { /* Intentionally prevent timer delivery. */ }
    return verified
  }
  t.after(() => { RealCoreUpstreamV1.prototype.verifyProofBundle = original })
  const client = f.client()
  await assert.rejects(client.verifyResult({ ...f.options(created), resultBytes: f.response(created).body, timeoutMillis: 1000 }), { code: 'CORE_CLIENT_ABORTED' })
  assert.equal(completedActualVerification, true)
  await turn()
  assert.equal(client.status().inFlight, 0)
})

test('qualified namespace drift while the actual native proof is pending fails closed', async t => {
  const f = await fixture(t); const created = await f.request()
  const entered = gate(); const held = gate(); const original = Hypercore.prototype.verifyFullyRemote
  let paused = false
  Hypercore.prototype.verifyFullyRemote = async function (...args) {
    const batch = await original.apply(this, args)
    if (!paused) { paused = true; entered.release(); await held.waiting }
    return batch
  }
  t.after(() => { Hypercore.prototype.verifyFullyRemote = original; held.release() })
  const client = f.client({ request: async () => f.response(created) })
  const pending = client.prove(f.options(created))
  const rejected = assert.rejects(pending, { code: 'RELAY_PROTOCOL_VIOLATION' })
  await entered.waiting
  f.continuityRoot[0] ^= 1
  held.release(); await rejected
})

test('late ignored transport timeout retains the only slot and cannot return a late success', async t => {
  const f = await fixture(t); const created = await f.request(); const held = gate()
  const client = f.client({ request: () => held.waiting })
  let successes = 0
  const pending = client.prove({ ...f.options(created), timeoutMillis: 20 }).then(result => { successes++; return result })
  await assert.rejects(pending, { code: 'CORE_CLIENT_ABORTED' })
  assert.equal(client.status().inFlight, 1)
  await assert.rejects(client.prove(f.options(created)), { code: 'CORE_CLIENT_BUSY' })
  assert.equal(await client.close({ timeoutMillis: 20 }), false)
  held.release(f.response(created))
  await turn()
  assert.equal(await client.close(), true)
  assert.equal(successes, 0)
})

test('aborted final native cleanup remains charged, close is false, and no successful result is minted', async t => {
  const f = await fixture(t); const created = await f.request(); const response = f.response(created)
  const entered = gate(); const held = gate(); const original = fs.rm
  fs.rm = async function (target, ...args) {
    if (String(target).includes('/verifier-0/acquire-')) { entered.release(); await held.waiting }
    return original.call(this, target, ...args)
  }
  t.after(() => { fs.rm = original; held.release() })
  const controller = new AbortController(); const client = f.client()
  let successes = 0
  const pending = client.verifyResult({ ...f.options(created), resultBytes: response.body, signal: controller.signal }).then(value => { successes++; return value })
  const rejected = assert.rejects(pending, { code: 'CORE_CLIENT_ABORTED' })
  await entered.waiting; controller.abort(); await rejected
  assert.equal(client.status().nativeInFlight, 1)
  await assert.rejects(client.prove(f.options(created)), { code: 'CORE_CLIENT_BUSY' })
  assert.equal(await client.close({ timeoutMillis: 20 }), false)
  held.release(); assert.equal(await client.close(), true)
  assert.equal(successes, 0)
})

test('native cleanup failure fences capacity and refuses replacement work', async t => {
  const f = await fixture(t); const created = await f.request(); const original = fs.rm
  fs.rm = async function (target, ...args) {
    if (String(target).includes('/verifier-0/acquire-')) throw Object.assign(Error('test cleanup EIO'), { code: 'EIO' })
    return original.call(this, target, ...args)
  }
  t.after(() => { fs.rm = original })
  const client = f.client()
  await assert.rejects(client.verifyResult({ ...f.options(created), resultBytes: f.response(created).body }), { code: 'CORE_RELEASE_FAILED' })
  assert.equal(client.status().nativeInFlight, 1); assert.equal(client.status().closing, true)
  await assert.rejects(client.verifyResult({}), { code: 'CORE_CLIENT_CLOSED' })
  assert.equal(await client.close({ timeoutMillis: 20 }), false)
})

test('native cleanup timeout retains admission until actual cleanup settles and suppresses late success', async t => {
  const f = await fixture(t); const created = await f.request()
  const entered = gate(); const held = gate(); const original = fs.rm
  fs.rm = async function (target, ...args) {
    if (String(target).includes('/verifier-0/acquire-')) { entered.release(); await held.waiting }
    return original.call(this, target, ...args)
  }
  t.after(() => { fs.rm = original; held.release() })
  const client = f.client(); let successes = 0
  const pending = client.verifyResult({ ...f.options(created), resultBytes: f.response(created).body, timeoutMillis: 500 }).then(value => { successes++; return value })
  const rejected = assert.rejects(pending, { code: 'CORE_CLIENT_ABORTED' })
  await entered.waiting; await rejected
  assert.equal(client.status().nativeInFlight, 1)
  await assert.rejects(client.verifyResult({}), { code: 'CORE_CLIENT_BUSY' })
  assert.equal(await client.close({ timeoutMillis: 20 }), false)
  held.release(); assert.equal(await client.close(), true)
  assert.equal(successes, 0)
})

test('pre-abort, noncanonical/mismatched request and private size bounds refuse before transport', async t => {
  const f = await fixture(t); const created = await f.request(); let calls = 0
  const client = f.client({ request: async () => { calls++; return f.response(created) } })
  const controller = new AbortController(); controller.abort()
  await assert.rejects(client.prove({ ...f.options(created), signal: controller.signal }), { code: 'CORE_CLIENT_ABORTED' })
  await assert.rejects(client.prove({ ...f.options(created), requestCommitment: Buffer.alloc(32) }), { code: 'CORE_CLIENT_INPUT' })
  await assert.rejects(client.prove({ ...f.options(created), requestBytes: Buffer.concat([created.requestBytes, Buffer.from([0])]) }))
  await assert.rejects(client.prove({ ...f.options(created), requestBytes: Buffer.alloc(16385) }))
  const tooLong = await f.request({ length: 257n })
  await assert.rejects(client.prove(f.options(tooLong)), { code: 'CORE_INPUT' })
  assert.equal(calls, 0)
})
