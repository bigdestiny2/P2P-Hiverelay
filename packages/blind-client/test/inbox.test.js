import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY,
  INBOX_APPEND_AUTH_MODE,
  INBOX_FRAME_CLASS,
  INBOX_MANAGE_OPERATION,
  OPERATION
} from '@hiverelay/blind-protocol/registry'
import {
  blake2b256,
  inboxAppendRequestCommitment,
  inboxCreateCommitment,
  inboxPhysicalTopic,
  inboxReadRequestCommitment
} from '@hiverelay/blind-protocol/hashes'
import {
  inboxAppendV1,
  inboxCreateV1,
  inboxManageV1,
  inboxReadV1,
  inboxWatchV1
} from '@hiverelay/blind-protocol/schemas'
import { decodeCanonical } from '@hiverelay/blind-protocol/codec'
import {
  BlindClientError,
  createAppendInboxRequest,
  createCloseInboxRequest,
  createInboxReplica,
  createReadInboxRequest,
  createRenewInboxRequest,
  createWatchInboxRequest,
  destroyInboxWriteCapability,
  verifyCapabilitySignature
} from '../index.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'

const runtime = createNodeCryptoRuntime()
const relayPublicKey = b4a.alloc(32, 0x71)
const admission = {
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 0x72),
  token: b4a.from([0x73])
}

function unique (values) {
  return new Set(values.map(value => b4a.toString(value, 'hex'))).size === values.length
}

test('signed inbox creation is self-certifying, relay-bound and app-opaque', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 400,
    frameClassBits: 0x05,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED,
    retentionClass: 2,
    leaseClass: 3,
    admission
  })
  const decoded = decodeCanonical(inboxCreateV1, created.requestBytes, { copyBytes: true })
  t.alike(decoded.physicalTopic, inboxPhysicalTopic(decoded))
  t.alike(decoded.physicalTopic, created.readCap.physicalTopic)
  t.ok(unique([decoded.createPublicKey, decoded.appendPublicKey, decoded.renewPublicKey, decoded.closePublicKey, relayPublicKey]))
  const expected = inboxCreateCommitment({ relayPublicKey, ...decoded })
  t.alike(created.createCommitment, expected)
  t.ok(verifyCapabilitySignature(decoded.createPublicKey, expected, decoded.createSignature))
  t.is(created.wire.familyId, FAMILY.INBOX)
  t.is(created.wire.operationId, OPERATION.INBOX.CREATE)
  t.is(created.writeCap.appendPrivateKey.byteLength, 32)
  t.absent(decoded.app)
  t.absent(decoded.namespace)
  t.absent(decoded.author)
})

test('open and signed appends preserve exact fixed opaque frames and authorization mode', async t => {
  const signed = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 401,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const signedFrame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x81)
  const signedAppend = await createAppendInboxRequest({
    runtime,
    writeCap: signed.writeCap,
    frameClass: 1,
    frame: signedFrame,
    admission
  })
  const signedDecoded = decodeCanonical(inboxAppendV1, signedAppend.requestBytes, { copyBytes: true })
  const signedCommitment = inboxAppendRequestCommitment({
    relayPublicKey,
    physicalTopic: signed.readCap.physicalTopic,
    frameClass: 1,
    frameHash: blake2b256(signedFrame),
    clientNonce: signedDecoded.clientNonce
  })
  t.alike(signedDecoded.frame, signedFrame)
  t.alike(signedAppend.requestCommitment, signedCommitment)
  t.ok(verifyCapabilitySignature(signed.readCap.appendPublicKey, signedCommitment, signedDecoded.appendSignature))
  await t.exception(createAppendInboxRequest({
    runtime,
    readCap: signed.readCap,
    frameClass: 1,
    frame: signedFrame,
    admission
  }), /requires its append capability/)

  const open = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 402,
    frameClassBits: 0x03,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  t.is(open.readCap.appendPublicKey, null)
  t.is(open.writeCap.appendPrivateKey, null)
  const openFrame = b4a.alloc(INBOX_FRAME_CLASS[2], 0x82)
  const openAppend = await createAppendInboxRequest({
    runtime,
    readCap: open.readCap,
    frameClass: 2,
    frame: openFrame,
    admission
  })
  t.is(openAppend.request.appendSignature, null)
  t.alike(openAppend.request.frameHash, blake2b256(openFrame))
})

test('inbox frame bounds fail before admission or request allocation', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 403,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  let admissionCalls = 0
  await t.exception(createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frameClass: 2,
    frame: b4a.alloc(INBOX_FRAME_CLASS[2]),
    admissionProvider: async () => { admissionCalls++; return admission }
  }), /not enabled/)
  await t.exception(createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frameClass: 1,
    frame: b4a.alloc(INBOX_FRAME_CLASS[1] - 1),
    admissionProvider: async () => { admissionCalls++; return admission }
  }), /exactly 4096 bytes/)
  t.is(admissionCalls, 0)
})

test('inbox renew and close bind independent capabilities and exact CAS state', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 404,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const renew = await createRenewInboxRequest({
    runtime,
    writeCap: created.writeCap,
    expectedRevision: 3n,
    expectedLeaseEpoch: 410,
    leaseClass: 2,
    admission
  })
  const renewDecoded = decodeCanonical(inboxManageV1, renew.requestBytes, { copyBytes: true })
  t.is(renewDecoded.operation, INBOX_MANAGE_OPERATION.RENEW)
  t.ok(verifyCapabilitySignature(created.request.renewPublicKey, renew.requestCommitment, renewDecoded.signature))
  t.ok(renewDecoded.admission)

  const close = createCloseInboxRequest({
    runtime,
    writeCap: created.writeCap,
    expectedRevision: 4n,
    expectedLeaseEpoch: 438
  })
  const closeDecoded = decodeCanonical(inboxManageV1, close.requestBytes, { copyBytes: true })
  t.is(closeDecoded.operation, INBOX_MANAGE_OPERATION.CLOSE)
  t.is(closeDecoded.leaseClass, 0)
  t.is(closeDecoded.admission, null)
  t.ok(verifyCapabilitySignature(created.request.closePublicKey, close.requestCommitment, closeDecoded.signature))
  t.unlike(renew.requestCommitment, close.requestCommitment)
})

test('inbox read and watch are bounded request identities, not semantic subscriptions', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 405,
    frameClassBits: 0x03,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const cursor = b4a.from([1, 2, 3])
  const read = await createReadInboxRequest({ runtime, readCap: created.readCap, cursor, limit: 2 })
  const readDecoded = decodeCanonical(inboxReadV1, read.requestBytes, { copyBytes: true })
  t.alike(readDecoded.cursor, cursor)
  t.is(readDecoded.limit, 2)
  t.is(readDecoded.admission, null)
  t.alike(read.requestCommitment, inboxReadRequestCommitment({
    relayPublicKey,
    physicalTopic: created.readCap.physicalTopic,
    cursor,
    limit: 2,
    clientNonce: readDecoded.clientNonce
  }))
  t.ok(read.wire.expectedResultBodyBytes < 64 * 1024)

  const watch = await createWatchInboxRequest({
    runtime,
    readCap: created.readCap,
    afterRevision: 7n,
    limit: 3,
    maxWaitMillis: 30000,
    admission
  })
  const watchDecoded = decodeCanonical(inboxWatchV1, watch.requestBytes, { copyBytes: true })
  t.is(watchDecoded.afterRevision, 7n)
  t.is(watchDecoded.maxWaitMillis, 30000)
  t.is(watch.wire.operationId, OPERATION.INBOX.WATCH)
  t.unlike(read.requestCommitment, watch.requestCommitment)
  await t.exception(createWatchInboxRequest({
    runtime,
    readCap: created.readCap,
    afterRevision: 7n,
    limit: 1,
    maxWaitMillis: 30001,
    admission
  }), BlindClientError)
  await t.exception(createReadInboxRequest({
    runtime,
    readCap: created.readCap,
    cursor: b4a.alloc(129),
    limit: 1
  }), /cursor exceeds/)
})

test('destroying an inbox write capability wipes every secret without mutating its read capability', async t => {
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 406,
    frameClassBits: 0x01,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const topic = b4a.from(created.readCap.physicalTopic)
  destroyInboxWriteCapability(created.writeCap)
  t.alike(created.writeCap.createPrivateKey, b4a.alloc(32))
  t.alike(created.writeCap.appendPrivateKey, b4a.alloc(32))
  t.alike(created.writeCap.renewPrivateKey, b4a.alloc(32))
  t.alike(created.writeCap.closePrivateKey, b4a.alloc(32))
  t.alike(created.readCap.physicalTopic, topic)
})
