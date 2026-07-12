import fs from 'node:fs/promises'
import path from 'node:path'
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  FAMILY,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  blake2b256,
  blindCoreAckV1,
  coreMirrorRequestCommitment,
  coreOpenReplicationRequestCommitment,
  coreOpenReplicationResultV1,
  coreServeRequestCommitment,
  coreServeResultV1,
  decodeCanonical,
  encodeCanonical,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { BlindCoreRuntimeAdapter, isCommittedCoreResult } from '../core-runtime-adapter.js'
import { BlindCoreStorageEngine } from '../core-storage-engine.js'
import {
  CoreReplicationStreamService,
  coreOpenReplicationLogicalRetryKey
} from '../core-stream.js'
import { StreamSessionPlane } from '../stream-session.js'
import {
  fixtureBytes,
  fixtureCoreOpen,
  fixtureCoreResult,
  fixtureReadiness,
  fixtureRelayBinding
} from './stream-fixtures.js'

const EPOCH_MILLIS = 21600000n
const PARTITION_KEY = b4a.alloc(32, 0x81)
const FENCE_HASH = b4a.alloc(32, 0x91)
const CONTINUITY_HASH = b4a.alloc(32, 0x92)

function signingAuthority () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {
    publicKey,
    signer: {
      async sign ({ payload }) {
        const signature = b4a.alloc(sodium.crypto_sign_BYTES)
        sodium.crypto_sign_detached(signature, payload, secretKey)
        return signature
      }
    }
  }
}

async function signedCoreOpenResult (keys, value) {
  value = { ...value, signature: b4a.alloc(sodium.crypto_sign_BYTES) }
  let complete = encodeCanonical(coreOpenReplicationResultV1, value)
  const unsigned = complete.subarray(0, complete.byteLength - sodium.crypto_sign_BYTES)
  value.signature = await keys.signer.sign({
    payload: resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CORE_OPEN_RESULT, unsigned)
  })
  complete = encodeCanonical(coreOpenReplicationResultV1, value)
  return decodeCanonical(coreOpenReplicationResultV1, complete, { copyBytes: true })
}

function clock () {
  return {
    epoch: 1000,
    millis: 1000n * EPOCH_MILLIS,
    nowEpoch () { return this.epoch },
    nowUnixMillis () { return this.millis }
  }
}

async function temporaryRoot (t, name) {
  const root = await fs.mkdtemp(`/private/tmp/${name}-`)
  t.teardown(async () => fs.rm(root, { recursive: true, force: true }))
  return root
}

function storageOptions (root, time, relayPublicKey, overrides = {}) {
  return {
    root,
    relayPublicKey,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: CONTINUITY_HASH,
    nowEpoch: () => time.nowEpoch(),
    nowUnixMillis: () => time.nowUnixMillis(),
    maximumCorpusBytes: 1024 * 1024,
    maximumSponsoredCoreLength: 1_000_000n,
    ...overrides
  }
}

function admission (requestCommitment, spendByte, leaseClass, resourceClass = 1) {
  return {
    spendTag: b4a.alloc(32, spendByte),
    requestCommitment: b4a.from(requestCommitment),
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32, 0xc7),
    costClass: { resourceClass, leaseClass, costUnits: 1n },
    walCommitRecord: b4a.alloc(48, spendByte ^ 0xff)
  }
}

function mirrorRequest (relayPublicKey, overrides = {}) {
  const request = {
    version: 1,
    corePublicKey: overrides.corePublicKey || b4a.alloc(32, 0x31),
    fork: overrides.fork == null ? 0n : overrides.fork,
    length: overrides.length == null ? 4n : overrides.length,
    signedHeadHash: overrides.signedHeadHash || b4a.alloc(32, 0x41),
    leaseClass: overrides.leaseClass == null ? 1 : overrides.leaseClass,
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0x51),
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0xc7),
      token: b4a.alloc(32, 0xc8)
    }
  }
  const requestCommitment = coreMirrorRequestCommitment({ ...request, relayPublicKey })
  return { request, requestCommitment }
}

function proveRequest (relayPublicKey, mirror, overrides = {}) {
  const request = {
    version: 1,
    corePublicKey: b4a.from(mirror.request.corePublicKey),
    fork: mirror.request.fork,
    length: mirror.request.length,
    signedHeadHash: b4a.from(mirror.request.signedHeadHash),
    blockIndices: overrides.blockIndices || [0n, mirror.request.length - 1n],
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0x61),
    admission: overrides.admission === false
      ? null
      : {
          profileId: 1,
          schemeId: 1,
          parameterHash: b4a.alloc(32, 0xc7),
          token: b4a.alloc(32, 0xc9)
        }
  }
  const requestCommitment = coreServeRequestCommitment({ ...request, relayPublicKey })
  return { request, requestCommitment }
}

function descriptorAuthority (relayPublicKey) {
  let binding = fixtureRelayBinding(relayPublicKey)
  return {
    resultBinding () { return binding },
    refresh (overrides) { binding = fixtureRelayBinding(relayPublicKey, overrides) },
    binding () { return binding }
  }
}

function upstreamAuthority () {
  let activations = 0
  let serves = 0
  let tamper = false
  let invalidHeadByte = null
  let unavailableAttempts = 0
  function proof ({ generation, blockIndices, corpus }) {
    const indices = b4a.alloc(blockIndices.length * 8)
    let offset = 0
    for (let index of blockIndices) {
      for (let byte = 7; byte >= 0; byte--) {
        indices[offset + byte] = Number(index & 0xffn)
        index >>= 8n
      }
      offset += 8
    }
    const output = b4a.concat([
      b4a.from([generation.signedHeadHash[0]]),
      indices,
      corpus.subarray(0, 64)
    ])
    if (tamper) output[output.byteLength - 1] ^= 1
    return output
  }
  return {
    async activateMirror ({ request }) {
      activations++
      if (unavailableAttempts > 0) {
        unavailableAttempts--
        throw new Error('injected upstream unavailability')
      }
      if (invalidHeadByte != null && request.signedHeadHash[0] === invalidHeadByte) {
        return { verified: false }
      }
      const corpus = b4a.alloc(4096, request.signedHeadHash[0])
      return {
        verified: true,
        corpus,
        corpusByteLength: corpus.byteLength,
        corpusHash: blake2b256(corpus)
      }
    },
    async serveProof (input) {
      serves++
      return proof(input)
    },
    async estimateProofBytes ({ request }) {
      return 1 + request.blockIndices.length * 8 + 64
    },
    setTamper (value) { tamper = value },
    setInvalidHeadByte (value) { invalidHeadByte = value },
    setUnavailableAttempts (value) { unavailableAttempts = value },
    activations: () => activations,
    serves: () => serves
  }
}

function adapterHarness (storage, keys, descriptor, upstream) {
  return new BlindCoreRuntimeAdapter({
    storage,
    descriptorState: descriptor,
    signer: keys.signer,
    upstream
  })
}

function executionInput (operationId, request, requestCommitment, preparedAdmission = null) {
  return {
    profile: { familyId: FAMILY.CORE, operationId },
    request,
    requestCommitment,
    preparedAdmission,
    descriptorSnapshot: Object.freeze({}),
    signal: new AbortController().signal
  }
}

async function rejectsCode (t, promise, code) {
  try {
    await promise
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
    return error
  }
}

async function blobCount (root) {
  let count = 0
  const buckets = await fs.readdir(path.join(root, 'blobs'))
  for (const bucket of buckets) count += (await fs.readdir(path.join(root, 'blobs', bucket))).length
  return count
}

test('CORE.MIRROR commits before activation and exact signed retry survives descriptor refresh and restart', async t => {
  const root = await temporaryRoot(t, 'blind-core-mirror')
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)
  const upstream = upstreamAuthority()
  let storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  let adapter = adapterHarness(storage, keys, descriptor, upstream)
  const mirror = mirrorRequest(keys.publicKey)
  const prepared = admission(mirror.requestCommitment, 0xa1, mirror.request.leaseClass)
  const input = executionInput(OPERATION.CORE.MIRROR, mirror.request, mirror.requestCommitment, prepared)

  const first = await adapter.execute(input)
  t.ok(isCommittedCoreResult(first))
  const firstBytes = b4a.from(first.body)
  const ack = decodeCanonical(blindCoreAckV1, firstBytes, { copyBytes: true })
  t.is(ack.result, 1)
  t.is(ack.leaseEpoch, 1004)
  t.is(storage.inspectCore(mirror.request.corePublicKey).stateRevision, 0n)
  t.is(upstream.activations(), 1)
  t.is(storage.status().accounting.corpusBytes, 4096)
  t.is(await blobCount(root), 1)
  t.is(await adapter.verifyResult({
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    result: ack,
    request: mirror.request,
    requestCommitment: mirror.requestCommitment,
    expectedRelayBinding: descriptor.binding()
  }), true)
  t.is(await adapter.verifyResult({
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    result: { ...ack, leaseEpoch: ack.leaseEpoch + 1 },
    request: mirror.request,
    requestCommitment: mirror.requestCommitment,
    expectedRelayBinding: descriptor.binding()
  }), false)

  descriptor.refresh({
    descriptorSequence: 10n,
    descriptorHash: b4a.alloc(32, 0x74)
  })
  const refreshedRetry = await adapter.execute(input)
  t.alike(refreshedRetry.body, firstBytes)
  t.is(upstream.activations(), 1)
  await storage.close()

  storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  adapter = adapterHarness(storage, keys, descriptor, upstream)
  const restartRetry = await adapter.execute(input)
  t.alike(restartRetry.body, firstBytes)
  t.is(upstream.activations(), 1)
  t.alike(storage.inspectCore(mirror.request.corePublicKey).signedHeadHash, mirror.request.signedHeadHash)
  t.is(storage.status().accounting.corpusBytes, 4096)
  await storage.close()
})

test('CORE.PROVE pins its immutable source across extension, detects substitution, and expires durably', async t => {
  const root = await temporaryRoot(t, 'blind-core-prove')
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)
  const upstream = upstreamAuthority()
  let storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  let adapter = adapterHarness(storage, keys, descriptor, upstream)
  const mirror = mirrorRequest(keys.publicKey)
  await adapter.execute(executionInput(OPERATION.CORE.MIRROR, mirror.request, mirror.requestCommitment,
    admission(mirror.requestCommitment, 0xa2, 1)))

  const challenge = proveRequest(keys.publicKey, mirror)
  const prepared = admission(challenge.requestCommitment, 0xb1, 0)
  const input = executionInput(OPERATION.CORE.PROVE, challenge.request, challenge.requestCommitment, prepared)
  const first = await adapter.execute(input)
  const firstValue = decodeCanonical(coreServeResultV1, first.body, { copyBytes: true })
  t.is(firstValue.acknowledgement.result, 2)
  const retry = await adapter.execute(input)
  t.alike(retry.body, first.body)
  t.is(storage.status().accounting.proofPins, 1)

  const extension = mirrorRequest(keys.publicKey, {
    corePublicKey: mirror.request.corePublicKey,
    length: 5n,
    signedHeadHash: b4a.alloc(32, 0x42),
    clientNonce: b4a.alloc(32, 0x52)
  })
  await adapter.execute(executionInput(OPERATION.CORE.MIRROR, extension.request, extension.requestCommitment,
    admission(extension.requestCommitment, 0xa3, 1)))
  t.is(storage.inspectCore(mirror.request.corePublicKey).length, 5n)
  t.is(storage.status().accounting.corpusBytes, 8192)
  t.is(await blobCount(root), 2)
  const afterExtension = await adapter.execute(input)
  t.alike(afterExtension.body, first.body)

  upstream.setTamper(true)
  await t.exception(adapter.execute(input), /no longer reproduces exact bytes/)
  upstream.setTamper(false)
  await storage.close()

  storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  adapter = adapterHarness(storage, keys, descriptor, upstream)
  const afterRestart = await adapter.execute(input)
  t.alike(afterRestart.body, first.body)
  time.millis += 15n * 60n * 1000n + 1n
  t.is(await storage.sweepProofPins(), 1)
  t.is(storage.status().accounting.proofPins, 0)
  t.is(storage.status().accounting.corpusBytes, 4096)
  t.is(await blobCount(root), 1)
  await rejectsCode(t, adapter.execute(input), 'RETRY_TERMINAL')
  await storage.close()
})

test('CORE sponsorship orders concurrent candidates and refuses stale, conflicting, and invalid heads', async t => {
  const root = await temporaryRoot(t, 'blind-core-order')
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)
  const upstream = upstreamAuthority()
  const storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  const adapter = adapterHarness(storage, keys, descriptor, upstream)
  const initial = mirrorRequest(keys.publicKey)
  await adapter.execute(executionInput(OPERATION.CORE.MIRROR, initial.request, initial.requestCommitment,
    admission(initial.requestCommitment, 0xc1, 1)))

  const stale = mirrorRequest(keys.publicKey, {
    corePublicKey: initial.request.corePublicKey,
    length: 3n,
    clientNonce: b4a.alloc(32, 0x62)
  })
  await rejectsCode(t, adapter.execute(executionInput(OPERATION.CORE.MIRROR, stale.request,
    stale.requestCommitment, admission(stale.requestCommitment, 0xc2, 1))), 'STALE_REVISION')

  const conflict = mirrorRequest(keys.publicKey, {
    corePublicKey: initial.request.corePublicKey,
    signedHeadHash: b4a.alloc(32, 0x43),
    clientNonce: b4a.alloc(32, 0x63)
  })
  await rejectsCode(t, adapter.execute(executionInput(OPERATION.CORE.MIRROR, conflict.request,
    conflict.requestCommitment, admission(conflict.requestCommitment, 0xc3, 1))), 'CONFLICT')

  upstream.setInvalidHeadByte(0x44)
  const invalid = mirrorRequest(keys.publicKey, {
    corePublicKey: initial.request.corePublicKey,
    fork: 1n,
    length: 2n,
    signedHeadHash: b4a.alloc(32, 0x44),
    clientNonce: b4a.alloc(32, 0x64)
  })
  const invalidAck = await adapter.execute(executionInput(OPERATION.CORE.MIRROR, invalid.request,
    invalid.requestCommitment, admission(invalid.requestCommitment, 0xc4, 1)))
  t.is(decodeCanonical(blindCoreAckV1, invalidAck.body).result, 1)
  t.is(storage.inspectCore(initial.request.corePublicKey).fork, 0n)
  const invalidRetry = await adapter.execute(executionInput(OPERATION.CORE.MIRROR, invalid.request,
    invalid.requestCommitment, admission(invalid.requestCommitment, 0xc4, 1)))
  t.alike(invalidRetry.body, invalidAck.body)

  const higherFork = mirrorRequest(keys.publicKey, {
    corePublicKey: initial.request.corePublicKey,
    fork: 2n,
    length: 1n,
    signedHeadHash: b4a.alloc(32, 0x45),
    clientNonce: b4a.alloc(32, 0x65)
  })
  const extension = mirrorRequest(keys.publicKey, {
    corePublicKey: initial.request.corePublicKey,
    length: 6n,
    signedHeadHash: b4a.alloc(32, 0x46),
    clientNonce: b4a.alloc(32, 0x66)
  })
  const acceptedHigher = await storage.acceptMirror({
    ...executionInput(OPERATION.CORE.MIRROR, higherFork.request, higherFork.requestCommitment,
      admission(higherFork.requestCommitment, 0xc5, 1)),
    resultBinding: descriptor.binding(),
    buildAcknowledgement: fields => adapter.buildAcknowledgement(fields)
  })
  await rejectsCode(t, storage.acceptMirror({
    ...executionInput(OPERATION.CORE.MIRROR, extension.request, extension.requestCommitment,
      admission(extension.requestCommitment, 0xc6, 1)),
    resultBinding: descriptor.binding(),
    buildAcknowledgement: fields => adapter.buildAcknowledgement(fields)
  }), 'STALE_REVISION')
  await storage.completeMirror(acceptedHigher.spendTag, await upstream.activateMirror({ request: higherFork.request }))
  t.is(storage.inspectCore(initial.request.corePublicKey).fork, 2n)
  t.is(storage.inspectCore(initial.request.corePublicKey).length, 1n)
  await storage.close()
})

test('CORE WAL crash boundaries recover accepted activation work and committed activation exactly', async t => {
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)

  const acceptedRoot = await temporaryRoot(t, 'blind-core-crash-accepted')
  let faultSequence = 1n
  let faulted = false
  let storage = new BlindCoreStorageEngine(storageOptions(acceptedRoot, time, keys.publicKey, {
    faultInjector: async (point, context) => {
      if (!faulted && point === 'wal:after-sync' && context.sequence === faultSequence) {
        faulted = true
        throw new Error('injected post-fsync crash')
      }
    }
  }))
  await storage.open()
  const acceptedUpstream = upstreamAuthority()
  let adapter = adapterHarness(storage, keys, descriptor, acceptedUpstream)
  const acceptedMirror = mirrorRequest(keys.publicKey)
  const acceptedInput = executionInput(OPERATION.CORE.MIRROR, acceptedMirror.request,
    acceptedMirror.requestCommitment, admission(acceptedMirror.requestCommitment, 0xe1, 1))
  await t.exception(adapter.execute(acceptedInput), /injected post-fsync crash/)
  t.is(acceptedUpstream.activations(), 0)
  await storage.close()

  storage = new BlindCoreStorageEngine(storageOptions(acceptedRoot, time, keys.publicKey))
  await storage.open()
  t.is(storage.inspectMirrorSpend(acceptedInput.preparedAdmission.spendTag).state, 'ACCEPTED')
  adapter = adapterHarness(storage, keys, descriptor, acceptedUpstream)
  const resumed = await adapter.execute(acceptedInput)
  t.ok(isCommittedCoreResult(resumed))
  t.is(acceptedUpstream.activations(), 1)
  t.is(storage.inspectCore(acceptedMirror.request.corePublicKey).length, 4n)
  await storage.close()

  const activatedRoot = await temporaryRoot(t, 'blind-core-crash-activated')
  faultSequence = 2n
  faulted = false
  storage = new BlindCoreStorageEngine(storageOptions(activatedRoot, time, keys.publicKey, {
    faultInjector: async (point, context) => {
      if (!faulted && point === 'wal:after-sync' && context.sequence === faultSequence) {
        faulted = true
        throw new Error('injected activation commit crash')
      }
    }
  }))
  await storage.open()
  const activatedUpstream = upstreamAuthority()
  adapter = adapterHarness(storage, keys, descriptor, activatedUpstream)
  const activatedMirror = mirrorRequest(keys.publicKey, {
    corePublicKey: b4a.alloc(32, 0x32),
    clientNonce: b4a.alloc(32, 0x53)
  })
  const activatedInput = executionInput(OPERATION.CORE.MIRROR, activatedMirror.request,
    activatedMirror.requestCommitment, admission(activatedMirror.requestCommitment, 0xe2, 1))
  await t.exception(adapter.execute(activatedInput), /injected activation commit crash/)
  t.is(activatedUpstream.activations(), 1)
  await storage.close()

  storage = new BlindCoreStorageEngine(storageOptions(activatedRoot, time, keys.publicKey))
  await storage.open()
  t.is(storage.inspectCore(activatedMirror.request.corePublicKey).length, 4n)
  adapter = adapterHarness(storage, keys, descriptor, activatedUpstream)
  const activatedRetry = await adapter.execute(activatedInput)
  t.ok(isCommittedCoreResult(activatedRetry))
  t.is(activatedUpstream.activations(), 1)
  t.is(await blobCount(activatedRoot), 1)
  await storage.close()
})

test('concurrent exact CORE retries coalesce activation and charged proof work', async t => {
  const root = await temporaryRoot(t, 'blind-core-concurrent')
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)
  const upstream = upstreamAuthority()
  const storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  const adapter = adapterHarness(storage, keys, descriptor, upstream)
  const mirror = mirrorRequest(keys.publicKey)
  const mirrorInput = executionInput(OPERATION.CORE.MIRROR, mirror.request, mirror.requestCommitment,
    admission(mirror.requestCommitment, 0xf1, 1))
  const mirrorResults = await Promise.all([adapter.execute(mirrorInput), adapter.execute(mirrorInput)])
  t.alike(mirrorResults[0].body, mirrorResults[1].body)
  t.is(upstream.activations(), 1)
  t.is(storage.status().accounting.mirrorAttempts, 1)
  t.is(storage.status().accounting.activeCores, 1)

  const challenge = proveRequest(keys.publicKey, mirror)
  const proveInput = executionInput(OPERATION.CORE.PROVE, challenge.request, challenge.requestCommitment,
    admission(challenge.requestCommitment, 0xf2, 0))
  const proveResults = await Promise.all([adapter.execute(proveInput), adapter.execute(proveInput)])
  t.alike(proveResults[0].body, proveResults[1].body)
  t.is(upstream.serves(), 1)
  t.is(storage.status().accounting.proofPins, 1)
  await storage.close()
})

test('CORE activation unavailability is bounded RETRY_PENDING and sponsorship expiry retains the rollback floor', async t => {
  const root = await temporaryRoot(t, 'blind-core-retry-expiry')
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)
  const upstream = upstreamAuthority()
  upstream.setUnavailableAttempts(1)
  const storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  const adapter = adapterHarness(storage, keys, descriptor, upstream)
  const mirror = mirrorRequest(keys.publicKey)
  const input = executionInput(OPERATION.CORE.MIRROR, mirror.request, mirror.requestCommitment,
    admission(mirror.requestCommitment, 0xf3, 1))

  const accepted = await adapter.execute(input)
  const pending = storage.inspectMirrorSpend(input.preparedAdmission.spendTag)
  t.is(pending.state, 'RETRY_PENDING')
  t.is(pending.retryCount, 1)
  t.is(storage.inspectCore(mirror.request.corePublicKey), null)
  const resumed = await adapter.execute(input)
  t.alike(resumed.body, accepted.body)
  t.is(storage.inspectMirrorSpend(input.preparedAdmission.spendTag).state, 'ACTIVE')
  t.is(upstream.activations(), 2)

  time.epoch = 1004
  time.millis = BigInt(time.epoch) * EPOCH_MILLIS
  t.is(await storage.sweepExpiredCores(), 1)
  t.is(storage.inspectCore(mirror.request.corePublicKey), null)
  t.is(storage.status().accounting.activeCores, 0)
  t.is(storage.status().accounting.corpusBytes, 0)
  t.is(await blobCount(root), 0)

  const stale = mirrorRequest(keys.publicKey, {
    corePublicKey: mirror.request.corePublicKey,
    fork: 0n,
    length: 3n,
    clientNonce: b4a.alloc(32, 0x68)
  })
  await rejectsCode(t, adapter.execute(executionInput(OPERATION.CORE.MIRROR, stale.request,
    stale.requestCommitment, admission(stale.requestCommitment, 0xf4, 1))), 'STALE_REVISION')

  const responsor = mirrorRequest(keys.publicKey, {
    corePublicKey: mirror.request.corePublicKey,
    fork: mirror.request.fork,
    length: mirror.request.length,
    signedHeadHash: mirror.request.signedHeadHash,
    clientNonce: b4a.alloc(32, 0x69)
  })
  await adapter.execute(executionInput(OPERATION.CORE.MIRROR, responsor.request,
    responsor.requestCommitment, admission(responsor.requestCommitment, 0xf5, 1)))
  t.is(storage.inspectCore(mirror.request.corePublicKey).stateRevision, 1n)
  t.is(storage.inspectCore(mirror.request.corePublicKey).leaseEpoch, 1008)
  await storage.close()
})

test('CORE storage rejects invalid signed result builders before a WAL spend is committed', async t => {
  const root = await temporaryRoot(t, 'blind-core-invalid-result')
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)
  const storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  const mirror = mirrorRequest(keys.publicKey)
  const prepared = admission(mirror.requestCommitment, 0xf6, 1)
  await rejectsCode(t, storage.acceptMirror({
    ...executionInput(OPERATION.CORE.MIRROR, mirror.request, mirror.requestCommitment, prepared),
    resultBinding: descriptor.binding(),
    buildAcknowledgement: async fields => encodeCanonical(blindCoreAckV1, {
      version: 1,
      relayBinding: fields.relayBinding,
      corePublicKey: fields.request.corePublicKey,
      fork: fields.request.fork,
      length: fields.request.length,
      signedHeadHash: fields.request.signedHeadHash,
      observedAtEpoch: fields.observedAtEpoch,
      leaseEpoch: fields.leaseEpoch,
      result: fields.result,
      requestNonce: fields.request.clientNonce,
      requestCommitment: fields.requestCommitment,
      signature: b4a.alloc(64, 0xff)
    })
  }), 'INTERNAL')
  t.is(storage.status().accounting.mirrorAttempts, 0)
  t.is(storage.status().accounting.walSequence, 0n)
  await storage.close()
})

test('CORE.PROVE refuses a charged source race before committing the spend or a dangling pin', async t => {
  const root = await temporaryRoot(t, 'blind-core-proof-race')
  const time = clock()
  const keys = signingAuthority()
  const descriptor = descriptorAuthority(keys.publicKey)
  const upstream = upstreamAuthority()
  const storage = new BlindCoreStorageEngine(storageOptions(root, time, keys.publicKey))
  await storage.open()
  const adapter = adapterHarness(storage, keys, descriptor, upstream)
  const mirror = mirrorRequest(keys.publicKey)
  await adapter.execute(executionInput(OPERATION.CORE.MIRROR, mirror.request, mirror.requestCommitment,
    admission(mirror.requestCommitment, 0xa7, 1)))

  const originalServe = upstream.serveProof.bind(upstream)
  let releaseProof
  let startedProof
  const started = new Promise(resolve => { startedProof = resolve })
  const blocked = new Promise(resolve => { releaseProof = resolve })
  upstream.serveProof = async input => {
    startedProof()
    await blocked
    return originalServe(input)
  }
  const challenge = proveRequest(keys.publicKey, mirror)
  const proveInput = executionInput(OPERATION.CORE.PROVE, challenge.request, challenge.requestCommitment,
    admission(challenge.requestCommitment, 0xb7, 0))
  const proving = adapter.execute(proveInput)
  await started

  const extension = mirrorRequest(keys.publicKey, {
    corePublicKey: mirror.request.corePublicKey,
    length: 5n,
    signedHeadHash: b4a.alloc(32, 0x47),
    clientNonce: b4a.alloc(32, 0x67)
  })
  await adapter.execute(executionInput(OPERATION.CORE.MIRROR, extension.request,
    extension.requestCommitment, admission(extension.requestCommitment, 0xa8, 1)))
  releaseProof()
  await rejectsCode(t, proving, 'STALE_REVISION')
  t.is(storage.status().accounting.proofPins, 0)
  t.is((await storage.proveState(proveInput)).kind, 'fresh')
  t.is(await blobCount(root), 1)
  await storage.close()
})

test('recovered CORE.OPEN_REPLICATION is forced terminal and cannot allocate a replacement child', async t => {
  const root = await temporaryRoot(t, 'blind-core-open-recovery')
  const time = clock()
  const keys = signingAuthority()
  const relayPublicKey = keys.publicKey
  const wireProfileHash = fixtureBytes(32, 0x12)
  const parentSessionId = fixtureBytes(16, 0x13)
  const request = fixtureCoreOpen(wireProfileHash)
  const requestCommitment = coreOpenReplicationRequestCommitment({
    relayPublicKey,
    wireProfileHash,
    sessionClass: request.sessionClass,
    controlChannelId: request.controlChannelId,
    parentChannelBinding: request.parentChannelBinding,
    clientNonce: request.clientNonce
  })
  const prepared = admission(requestCommitment, 0xd1, 0)
  let storage = new BlindCoreStorageEngine(storageOptions(root, time, relayPublicKey))
  await storage.open()
  const persistence = storage.openPersistence()
  const record = {
    logicalRetryKey: coreOpenReplicationLogicalRetryKey(relayPublicKey, request),
    spendTag: prepared.spendTag,
    requestCommitment,
    wireProfileHash,
    sessionClass: request.sessionClass,
    clientNonce: request.clientNonce,
    parentSessionId,
    controlChannelId: request.controlChannelId,
    parentChannelBinding: request.parentChannelBinding,
    streamId: 40n,
    maxSessionBytes: 16n * 1024n * 1024n,
    idleMillis: 30000,
    lifetimeMillis: 600000,
    openedAtEpoch: 1000,
    result: await signedCoreOpenResult(keys, fixtureCoreResult(relayPublicKey, {
      request,
      streamId: 40n,
      maxSessionBytes: 16n * 1024n * 1024n,
      idleMillis: 30000,
      lifetimeMillis: 600000,
      openedAtEpoch: 1000,
      requestCommitment
    })),
    preparedAdmission: prepared
  }
  await persistence.reserve(record)
  await storage.close()

  storage = new BlindCoreStorageEngine(storageOptions(root, time, relayPublicKey))
  await storage.open()
  const recovered = storage.inspectOpenRecords()
  t.is(recovered.length, 1)
  t.is(recovered[0].lifecycleState, 3)
  t.is(b4a.toString(recovered[0].terminalReason, 'ascii'), 'restart-terminal')

  let admissions = 0
  let upstreamOpens = 0
  const readiness = fixtureReadiness()
  const plane = new StreamSessionPlane({
    monotonicMillis: () => 100n,
    randomBytes: length => b4a.alloc(length, 0x71),
    schedule: () => ({}),
    cancelSchedule: () => {}
  })
  const service = new CoreReplicationStreamService({
    plane,
    relayPublicKey,
    wireProfileHash,
    recoveredRecords: recovered,
    authenticateParent: async ({ request }) => ({
      verified: true,
      authenticatedExporter: true,
      computedParentChannelBinding: b4a.from(request.parentChannelBinding),
      controlChannelId: request.controlChannelId,
      parentSessionId,
      readiness
    }),
    authorizeAdmission: async () => { admissions++; return { accepted: true, spendTag: prepared.spendTag } },
    allocateStreamId: async () => 41n,
    buildResult: async fields => signedCoreOpenResult(keys, fixtureCoreResult(relayPublicKey, fields)),
    openUpstream: async () => { upstreamOpens++; return { write: async () => {} } },
    nowEpoch: async () => 1000,
    persistence: storage.openPersistence()
  })
  const error = await rejectsCode(t,
    service.open(request, { transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE }),
    'RETRY_TERMINAL')
  t.ok(/no longer live/.test(error.message))
  t.is(admissions, 0)
  t.is(upstreamOpens, 0)
  await service.close()
  await plane.close()
  await storage.close()
})

test('CORE child stream applies real backpressure, abort cleanup, and the exact aggregate byte cap', async t => {
  async function openChild (openUpstream) {
    let nextStreamId = 40n
    const relayPublicKey = fixtureBytes(32, 0x11)
    const wireProfileHash = fixtureBytes(32, 0x12)
    const parentSessionId = fixtureBytes(16, 0x13)
    const readiness = fixtureReadiness()
    const terminal = []
    const plane = new StreamSessionPlane({
      monotonicMillis: () => 100n,
      randomBytes: length => b4a.alloc(length, 0x71),
      schedule: () => ({}),
      cancelSchedule: () => {}
    })
    const service = new CoreReplicationStreamService({
      plane,
      relayPublicKey,
      wireProfileHash,
      authenticateParent: async ({ request }) => ({
        verified: true,
        authenticatedExporter: true,
        computedParentChannelBinding: b4a.from(request.parentChannelBinding),
        controlChannelId: request.controlChannelId,
        parentSessionId,
        readiness
      }),
      authorizeAdmission: async () => ({ accepted: true, spendTag: b4a.alloc(16, 0x21) }),
      allocateStreamId: async () => nextStreamId++,
      buildResult: fields => fixtureCoreResult(relayPublicKey, fields),
      openUpstream,
      nowEpoch: async () => 1000,
      persistence: {
        reserve: async () => {},
        activate: async () => {},
        terminal: async record => terminal.push(record)
      }
    })
    const request = fixtureCoreOpen(wireProfileHash)
    const opened = await service.open(request, { transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE })
    const caller = {
      write: async () => {},
      end: async () => {},
      abort: async () => {}
    }
    const child = service.attach(opened.ticket, {
      streamId: opened.result.streamId,
      parentSessionId,
      descriptorSequence: readiness.descriptorSequence,
      descriptorHash: readiness.descriptorHash,
      caller
    })
    return { plane, service, child, terminal }
  }

  let releaseWrite
  let aborts = 0
  const blocked = await openChild(async () => ({
    write: async () => new Promise(resolve => { releaseWrite = resolve }),
    abort: async () => { aborts++ }
  }))
  const first = blocked.child.fromCaller(b4a.alloc(512 * 1024, 0x81))
  const second = blocked.child.fromCaller(b4a.alloc(512 * 1024, 0x82))
  await Promise.resolve()
  await Promise.resolve()
  t.is(blocked.plane.bufferedBytes, 1024 * 1024)
  const firstRejected = t.exception(first, /terminal/)
  const secondRejected = t.exception(second, /terminal/)
  await blocked.child.close('test-abort')
  await firstRejected
  await secondRejected
  t.is(blocked.plane.bufferedBytes, 0)
  t.is(aborts, 1)
  t.is(blocked.terminal.length, 1)
  if (releaseWrite) releaseWrite()
  await blocked.service.close()
  await blocked.plane.close()

  const order = []
  let releaseOrderedWrite
  const ordered = await openChild(async () => ({
    write: async () => {
      order.push('write-start')
      await new Promise(resolve => { releaseOrderedWrite = resolve })
      order.push('write-end')
    },
    end: async () => { order.push('fin') },
    abort: async () => {}
  }))
  const orderedWrite = ordered.child.fromCaller(b4a.alloc(1024, 0x84))
  const orderedFin = ordered.child.callerFin()
  await Promise.resolve()
  await Promise.resolve()
  t.alike(order, ['write-start'])
  releaseOrderedWrite()
  await orderedWrite
  await orderedFin
  t.alike(order, ['write-start', 'write-end', 'fin'])
  t.is(ordered.child.scope.closed, false)
  await ordered.child.upstreamFin()
  t.is(ordered.child.scope.closed, true)
  await ordered.service.close()
  await ordered.plane.close()

  const capped = await openChild(async () => ({ write: async () => {}, abort: async () => {} }))
  const mebibyte = b4a.alloc(1024 * 1024, 0x83)
  for (let index = 0; index < 16; index++) await capped.child.fromCaller(mebibyte)
  await rejectsCode(t, capped.child.fromCaller(b4a.from([1])), 'TOO_LARGE')
  await Promise.resolve()
  await Promise.resolve()
  t.is(capped.plane.activeStreams, 0)
  t.is(capped.terminal.length, 1)
  t.is(capped.terminal[0].terminalReason, 'byte-cap')
  await capped.service.close()
  await capped.plane.close()
})
