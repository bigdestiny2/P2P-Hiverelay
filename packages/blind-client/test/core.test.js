import b4a from 'b4a'
import test from 'brittle'
import { FAMILY, OPERATION } from '@hiverelay/blind-protocol/registry'
import {
  coreMirrorRequestCommitment,
  coreOpenReplicationRequestCommitment,
  coreServeRequestCommitment
} from '@hiverelay/blind-protocol/hashes'
import {
  coreMirrorRequestV1,
  coreOpenReplicationV1,
  coreServeChallengeV1
} from '@hiverelay/blind-protocol/schemas'
import { decodeCanonical } from '@hiverelay/blind-protocol/codec'
import {
  BlindClientError,
  createCoreMirrorRequest,
  createCoreOpenReplicationRequest,
  createCoreProveRequest
} from '../index.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'

const runtime = createNodeCryptoRuntime()
const relayPublicKey = b4a.alloc(32, 0x41)
const corePublicKey = b4a.alloc(32, 0x42)
const signedHeadHash = b4a.alloc(32, 0x43)
const admission = {
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 0x44),
  token: b4a.from([0x45])
}

test('Core mirror binds one opaque signed head without application metadata', async t => {
  const created = await createCoreMirrorRequest({
    runtime,
    relayPublicKey,
    corePublicKey,
    fork: 2n,
    length: 100n,
    signedHeadHash,
    leaseClass: 3,
    admission
  })
  const decoded = decodeCanonical(coreMirrorRequestV1, created.requestBytes, { copyBytes: true })
  t.alike(created.requestCommitment, coreMirrorRequestCommitment({ relayPublicKey, ...decoded }))
  t.is(created.wire.familyId, FAMILY.CORE)
  t.is(created.wire.operationId, OPERATION.CORE.MIRROR)
  t.is(decoded.length, 100n)
  t.absent(decoded.app)
  t.absent(decoded.feedType)
  t.absent(decoded.author)
})

test('Core prove preserves sorted block selection and optional admission', async t => {
  const created = await createCoreProveRequest({
    runtime,
    relayPublicKey,
    corePublicKey,
    fork: 2n,
    length: 100n,
    signedHeadHash,
    blockIndices: [0n, 4n, 99n]
  })
  const decoded = decodeCanonical(coreServeChallengeV1, created.requestBytes, { copyBytes: true })
  t.alike(decoded.blockIndices, [0n, 4n, 99n])
  t.is(decoded.admission, null)
  t.alike(created.requestCommitment, coreServeRequestCommitment({ relayPublicKey, ...decoded }))
  await t.exception(createCoreProveRequest({
    runtime,
    relayPublicKey,
    corePublicKey,
    fork: 2n,
    length: 100n,
    signedHeadHash,
    blockIndices: [4n, 4n]
  }), /strictly sorted/)
  await t.exception(createCoreProveRequest({
    runtime,
    relayPublicKey,
    corePublicKey,
    fork: 2n,
    length: 100n,
    signedHeadHash,
    blockIndices: [100n]
  }), /below length/)
})

test('Core open replication is exporter-bound and explicitly native-stream-only', async t => {
  const wireProfileHash = b4a.alloc(32, 0x46)
  const parentChannelBinding = b4a.alloc(32, 0x47)
  const created = await createCoreOpenReplicationRequest({
    runtime,
    relayPublicKey,
    wireProfileHash,
    sessionClass: 2,
    controlChannelId: 9n,
    parentChannelBinding,
    admission
  })
  const decoded = decodeCanonical(coreOpenReplicationV1, created.requestBytes, { copyBytes: true })
  t.alike(created.requestCommitment, coreOpenReplicationRequestCommitment({ relayPublicKey, ...decoded }))
  t.is(created.wire.operationId, OPERATION.CORE.OPEN_REPLICATION)
  t.is(created.wire.requiresAuthenticatedStream, true)
  t.is(created.wire.controlChannelId, 9n)
  t.alike(decoded.parentChannelBinding, parentChannelBinding)
  await t.exception(createCoreOpenReplicationRequest({
    runtime,
    relayPublicKey,
    wireProfileHash,
    sessionClass: 2,
    controlChannelId: 0n,
    parentChannelBinding,
    admission
  }), BlindClientError)
  await t.exception(createCoreOpenReplicationRequest({
    runtime,
    relayPublicKey,
    wireProfileHash,
    sessionClass: 2,
    controlChannelId: 9n,
    parentChannelBinding: b4a.alloc(32),
    admission
  }), /must be nonzero/)
})

test('Core mutating/open operations acquire admission only after cheap bounds', async t => {
  let calls = 0
  const provider = async context => {
    calls++
    t.alike(context.relayPublicKey, relayPublicKey)
    return admission
  }
  await t.exception(createCoreMirrorRequest({
    runtime,
    relayPublicKey,
    corePublicKey,
    fork: 0n,
    length: 0n,
    signedHeadHash,
    leaseClass: 1,
    admissionProvider: provider
  }), /outside its u64 bounds/)
  t.is(calls, 0)
  const mirror = await createCoreMirrorRequest({
    runtime,
    relayPublicKey,
    corePublicKey,
    fork: 0n,
    length: 1n,
    signedHeadHash,
    leaseClass: 1,
    admissionProvider: provider
  })
  t.is(calls, 1)
  t.ok(mirror.request.admission)
})

test('admission providers cannot mutate commitment inputs or retain mutable request admission', async t => {
  const issued = {
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32, 0x71),
    token: b4a.from([0x72])
  }
  const mirror = await createCoreMirrorRequest({
    runtime,
    relayPublicKey,
    corePublicKey,
    fork: 0n,
    length: 2n,
    signedHeadHash,
    leaseClass: 1,
    admissionProvider: async context => {
      context.relayPublicKey.fill(0)
      context.requestCommitment.fill(0)
      return issued
    }
  })
  const decoded = decodeCanonical(coreMirrorRequestV1, mirror.requestBytes, { copyBytes: true })
  t.alike(mirror.requestCommitment, coreMirrorRequestCommitment({ relayPublicKey, ...decoded }))
  t.alike(mirror.request.admission.parameterHash, b4a.alloc(32, 0x71))
  issued.parameterHash.fill(0)
  issued.token.fill(0)
  t.alike(mirror.request.admission.parameterHash, b4a.alloc(32, 0x71))
  t.alike(mirror.request.admission.token, b4a.from([0x72]))
})
