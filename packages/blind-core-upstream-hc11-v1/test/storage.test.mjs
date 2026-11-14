import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import fs from 'node:fs/promises'
import sodium from 'sodium-universal'
import {
  FAMILY, OPERATION, coreMirrorRequestCommitment, coreServeRequestCommitment,
  coreServeResultV1, decodeCanonical
} from '../../blind-protocol/index.js'
import { BlindCoreStorageEngine } from '../../blind-daemon/core-storage-engine.js'
import { BlindCoreRuntimeAdapter } from '../../blind-daemon/core-runtime-adapter.js'
import { fixtureRelayBinding } from '../../blind-daemon/test/stream-fixtures.js'
import { RealCoreUpstreamV1 } from '../index.js'
import { fixture, headRequest } from './helpers.mjs'

function keys () {
  const publicKey = Buffer.alloc(32); const secretKey = Buffer.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, Buffer.alloc(32, 56))
  return { publicKey, signer: { async sign ({ payload }) { const signature = Buffer.alloc(64); sodium.crypto_sign_detached(signature, payload, secretKey); return signature } } }
}
function admission (commitment, byte, lease) {
  return { spendTag: Buffer.alloc(32, byte), requestCommitment: commitment, profileId: 1, schemeId: 1, parameterHash: Buffer.alloc(32, 0xc7), costClass: { resourceClass: 1, leaseClass: lease, costUnits: 1n }, walCommitRecord: Buffer.alloc(48, byte ^ 255) }
}
const token = { profileId: 1, schemeId: 1, parameterHash: Buffer.alloc(32, 0xc7), token: Buffer.alloc(32, 0xc8) }
const input = (operationId, request, commitment, prepared) => ({ profile: { familyId: FAMILY.CORE, operationId }, request, requestCommitment: commitment, preparedAdmission: prepared, descriptorSnapshot: {}, signal: new AbortController().signal })

test('unchanged real storage/runtime persists genuine corpus, signed charged proof and restart replay', { timeout: 25000 }, async t => {
  const f = await fixture(t); await f.writer.append([Buffer.from('private-store-a'), Buffer.from('private-store-b')])
  const signing = keys(); let epoch = 1000
  const options = { root: path.join(f.root, 'blind-storage'), relayPublicKey: signing.publicKey, partitionKey: Buffer.alloc(32, 0x81), ownerFenceTokenHash: Buffer.alloc(32, 0x91), durabilityContinuityHash: Buffer.alloc(32, 0x92), nowEpoch: () => epoch, nowUnixMillis: () => BigInt(epoch) * 21600000n, maximumCorpusBytes: 1024 * 1024 }
  await fs.mkdir(options.root, { mode: 0o700 })
  let storage = new BlindCoreStorageEngine(options); await storage.open()
  let connections = 0
  const upstream = new RealCoreUpstreamV1({ root: path.join(f.root, 'storage-upstream'), connect: () => { connections++; assert.ok(storage.status().accounting.mirrorAttempts > 0, 'admission persisted before acquisition'); return f.writer.replicate(false) }, readCorpus: async ({ request }) => { const source = storage.inspectCore(request.corePublicKey); return storage.transactionStore.readOpaque(source.corpus, source.corpus.byteLength, source.corpus.hash) } })
  t.after(async () => { await upstream.close(); await storage.close() })
  const makeAdapter = () => new BlindCoreRuntimeAdapter({ storage, upstream, signer: signing.signer, descriptorState: { resultBinding: () => fixtureRelayBinding(signing.publicKey) } })
  let runtime = makeAdapter()
  const head = await headRequest(f.writer)
  const mirror = { version: 1, ...head, leaseClass: 1, clientNonce: Buffer.alloc(32, 0x51), admission: token }
  const mirrorCommit = coreMirrorRequestCommitment({ ...mirror, relayPublicKey: signing.publicKey })
  const mirrorInput = input(OPERATION.CORE.MIRROR, mirror, mirrorCommit, admission(mirrorCommit, 0xa1, 1))
  const result = await runtime.execute(mirrorInput)
  assert.ok(storage.inspectCore(head.corePublicKey)); assert.equal(connections, 1)
  const challenge = { version: 1, ...head, blockIndices: [0n, 1n], clientNonce: Buffer.alloc(32, 0x61), admission: token }
  const commitment = coreServeRequestCommitment({ ...challenge, relayPublicKey: signing.publicKey })
  const proveInput = input(OPERATION.CORE.PROVE, challenge, commitment, admission(commitment, 0xa2, 0))
  const proof = await runtime.execute(proveInput)
  const decoded = decodeCanonical(coreServeResultV1, proof.body)
  assert.equal(await upstream.verifyProofBundle({ request: challenge, proof: decoded.proofsAndBlocks }), true)
  const pending = []
  for (const byte of [0xa3, 0xa4]) {
    await f.writer.append(Buffer.from('private-later-' + byte))
    const nextHead = await headRequest(f.writer)
    const nextRequest = { version: 1, ...nextHead, leaseClass: 1, clientNonce: Buffer.alloc(32, byte), admission: token }
    const nextCommit = coreMirrorRequestCommitment({ ...nextRequest, relayPublicKey: signing.publicKey })
    const nextInput = input(OPERATION.CORE.MIRROR, nextRequest, nextCommit, admission(nextCommit, byte, 1))
    const accepted = await storage.acceptMirror({ ...nextInput, resultBinding: fixtureRelayBinding(signing.publicKey), buildAcknowledgement: fields => runtime.buildAcknowledgement(fields) })
    const activation = await upstream.activateMirror({ request: nextRequest, previousGeneration: storage.inspectCoreFloor(head.corePublicKey) })
    assert.equal(activation.verified, true)
    pending.push({ accepted, activation })
  }
  await storage.completeMirror(pending[1].accepted.spendTag, pending[1].activation)
  assert.equal((await storage.completeMirror(pending[0].accepted.spendTag, pending[0].activation)).state, 'TERMINAL')
  assert.equal(storage.inspectCore(head.corePublicKey).length, 4n, 'reverse completion cannot activate superseded candidate')
  const replay = () => storage.serveProof({ ...proveInput, serveProof: fields => upstream.serveProof(fields) })
  assert.deepEqual((await replay()).body, proof.body, 'real old corpus remains pinned across new activation')
  await storage.close(); await f.writerStore.close()
  storage = new BlindCoreStorageEngine(options); await storage.open(); runtime = makeAdapter()
  assert.deepEqual((await runtime.execute(mirrorInput)).body, result.body)
  assert.deepEqual((await replay()).body, proof.body, 'storage-owned pinned retry survives restart offline')
  assert.equal(connections, 3, 'restart retries require no upstream')
  // Record the unchanged integration gap: runtime estimation selects the active
  // body before storage's paid-old-proof replay can select its retained source.
  await assert.rejects(runtime.execute(proveInput), { code: 'CORE_HEAD_INVALID' })
  epoch = 1005; await storage.sweepProofPins(); await storage.sweepExpiredCores()
  assert.equal(storage.inspectCore(head.corePublicKey), null)
  const floor = storage.inspectCoreFloor(head.corePublicKey)
  assert.equal(floor.active, false); assert.equal(floor.corpus, null)
  assert.equal(floor.length, 4n)
})
