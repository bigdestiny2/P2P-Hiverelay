import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  INBOX_APPEND_RESULT,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  blake2b256,
  blindErrorV1,
  decodeCanonical,
  decodeOuterEnvelope,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  inboxAppendAckV1,
  inboxAppendV1,
  inboxCreateV1,
  inboxManageV1,
  inboxReadResultV1,
  inboxReadV1,
  inboxReceiptV1,
  inboxWatchV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { BlindEdge } from '@hiverelay/blind-edge'
import { loadDaemonBootstrapConfig } from '../../packages/blind-daemon/bootstrap-config.js'
import { assembleProductionBlindDaemon } from '../../packages/blind-daemon/production-runtime.js'
import {
  inboxAppendFixture,
  inboxCloseFixture,
  inboxCreateFixture,
  inboxReadFixture,
  inboxRenewFixture,
  inboxWatchFixture,
  runtimeInboxFixture
} from '../../packages/blind-daemon/test/production-runtime-inbox-fixture.js'
import { removeBlindBoundaryScratch } from '../blind-boundary-scratch.js'

function splitAdmissionAdapter () {
  const preflights = new WeakSet()
  const prepared = input => Object.freeze({
    spendTag: blake2b256(input.admission.token),
    requestCommitment: b4a.from(input.requestCommitment),
    costClass: Object.freeze({ ...input.costClass }),
    walCommitRecord: b4a.from(input.admission.token),
    profileId: input.admission.profileId,
    schemeId: input.admission.schemeId,
    parameterHash: b4a.from(input.admission.parameterHash)
  })
  return Object.freeze({
    async prepare (input) { return prepared(input) },
    async preparePreflight () {
      const authority = Object.freeze({})
      preflights.add(authority)
      return authority
    },
    async confirmAfterEof (input) {
      if (!preflights.has(input.adapterPreflight)) throw new Error('unknown admission preflight')
      preflights.delete(input.adapterPreflight)
      return prepared(input)
    }
  })
}

function verifyResultSignature (t, codec, value, domainId, relayPublicKey) {
  const canonical = encodeCanonical(codec, value)
  const unsigned = canonical.subarray(0, canonical.byteLength - sodium.crypto_sign_BYTES)
  t.ok(sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(domainId, unsigned), relayPublicKey))
}

test('public INBOX operations round-trip through the metadata-stripping edge into production storage', async t => {
  const fixture = await runtimeInboxFixture()
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const localPeerBootstrap = Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() })
  const daemonErrors = []
  const runtime = await assembleProductionBlindDaemon({
    bootstrap: localPeerBootstrap,
    environment: fixture.environment,
    enableCellRuntime: true,
    enableInboxRuntime: true,
    resolveAdmissionAdapter: async () => splitAdmissionAdapter(),
    releaseGate: async () => {},
    onError: error => daemonErrors.push(error)
  })
  const dispatchContexts = []
  const coordinatorDispatch = runtime.coordinator.dispatch.bind(runtime.coordinator)
  runtime.coordinator.dispatch = async (frame, context) => {
    dispatchContexts.push(Object.freeze({ ...context }))
    return coordinatorDispatch(frame, context)
  }
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    allowInsecureLoopback: true,
    releaseGate: () => {},
    readinessTopology: {
      unarySocketPath: localPeerBootstrap.unarySocketPath,
      streamSocketPath: localPeerBootstrap.streamSocketPath,
      launchTopologyHash: localPeerBootstrap.launchTopologyHash,
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    },
    onError: error => daemonErrors.push(error)
  })
  t.teardown(async () => {
    let failure = null
    try {
      await edge.close()
    } catch (error) {
      failure = error
    }
    try {
      await runtime.close()
    } catch (error) {
      failure = failure || error
    }
    await removeBlindBoundaryScratch(fixture.directory)
    if (failure) throw failure
  })
  await runtime.start()
  await edge.start()

  const port = edge.address().port
  async function exchangePublicInbox (operationId, codec, request, requestByte) {
    const dispatch = encodeDispatchFrame({
      frameKind: FRAME_KIND.REQUEST,
      familyId: FAMILY.INBOX,
      operationId,
      requestId: b4a.alloc(16, requestByte),
      body: encodeCanonical(codec, request)
    })
    const outer = encodeOuterEnvelope({ innerDispatch: dispatch, outerClass: 3 })
    const response = await fetch(`http://127.0.0.1:${port}/api/blind/v1/inbox`, {
      method: 'POST',
      headers: { 'content-type': PROTOCOL.mediaType },
      body: outer
    })
    t.is(response.status, 200)
    t.is(response.headers.get('content-type'), PROTOCOL.mediaType)
    const resultBytes = b4a.from(await response.arrayBuffer())
    const resultOuter = decodeOuterEnvelope(resultBytes, { copyInner: true, copyBody: true })
    t.is(resultOuter.outerClass, 3)
    return resultOuter.frame
  }

  function successValue (frame, operationId, codec) {
    if (frame.frameKind === FRAME_KIND.ERROR) {
      const error = decodeCanonical(blindErrorV1, frame.body)
      const name = Object.keys(ERROR_CODE).find(key => ERROR_CODE[key] === error.code) || error.code
      throw new Error(`public INBOX operation returned ${name}`)
    }
    t.is(frame.frameKind, FRAME_KIND.RESPONSE)
    t.is(frame.familyId, FAMILY.INBOX)
    t.is(frame.operationId, operationId)
    return decodeCanonical(codec, frame.body, { copyBytes: true })
  }

  const relayPublicKey = fixture.relayPublicKey
  const created0 = inboxCreateFixture(relayPublicKey, fixture.parameterHash, fixture.currentEpoch)
  const created = successValue(
    await exchangePublicInbox(OPERATION.INBOX.CREATE, inboxCreateV1, created0.request, 0xa1),
    OPERATION.INBOX.CREATE, inboxReceiptV1)
  t.is(created.result, INBOX_RECEIPT_RESULT.CREATED)
  t.is(created.stateRevision, 0n)
  verifyResultSignature(t, inboxReceiptV1, created, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, relayPublicKey)

  const append = inboxAppendFixture(created0, relayPublicKey, fixture.parameterHash, 0xb3)
  const appended = successValue(
    await exchangePublicInbox(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xa2),
    OPERATION.INBOX.APPEND, inboxAppendAckV1)
  t.is(appended.result, INBOX_APPEND_RESULT.STORED)
  t.is(appended.appendRevision, 1n)
  t.alike(appended.frameHash, append.frameHash)
  verifyResultSignature(t, inboxAppendAckV1, appended,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, relayPublicKey)

  const read = inboxReadFixture(created0, fixture.parameterHash)
  const page = successValue(
    await exchangePublicInbox(OPERATION.INBOX.READ, inboxReadV1, read, 0xa3),
    OPERATION.INBOX.READ, inboxReadResultV1)
  t.is(page.snapshotRevision, 1n)
  t.is(page.entries.length, 1)
  t.alike(page.entries[0].frame, append.frame)
  verifyResultSignature(t, inboxReadResultV1, page,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, relayPublicKey)

  const quietWatch = inboxWatchFixture(created0, fixture.parameterHash, {
    afterRevision: 1n,
    maxWaitMillis: 25,
    spendByte: 0xf5
  })
  const quiet = successValue(
    await exchangePublicInbox(OPERATION.INBOX.WATCH, inboxWatchV1, quietWatch, 0xa4),
    OPERATION.INBOX.WATCH, inboxReadResultV1)
  t.is(quiet.entries.length, 0)
  t.is(quiet.snapshotRevision, 1n)

  const renewed = successValue(
    await exchangePublicInbox(OPERATION.INBOX.RENEW, inboxManageV1,
      inboxRenewFixture(created0, created, relayPublicKey, fixture.parameterHash), 0xa5),
    OPERATION.INBOX.RENEW, inboxReceiptV1)
  t.is(renewed.result, INBOX_RECEIPT_RESULT.RENEWED)
  t.is(renewed.stateRevision, 1n)
  t.ok(renewed.leaseEpoch > created.leaseEpoch)

  const closed = successValue(
    await exchangePublicInbox(OPERATION.INBOX.CLOSE, inboxManageV1,
      inboxCloseFixture(created0, renewed, relayPublicKey), 0xa6),
    OPERATION.INBOX.CLOSE, inboxReceiptV1)
  t.is(closed.result, INBOX_RECEIPT_RESULT.CLOSED)
  t.is(closed.leaseClass, 0)
  verifyResultSignature(t, inboxReceiptV1, closed, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, relayPublicKey)

  const afterClose = await exchangePublicInbox(OPERATION.INBOX.READ, inboxReadV1,
    inboxReadFixture(created0, fixture.parameterHash, { nonceByte: 0xf6 }), 0xa7)
  t.is(afterClose.frameKind, FRAME_KIND.ERROR)
  t.is(decodeCanonical(blindErrorV1, afterClose.body).code, ERROR_CODE.NOT_FOUND)

  t.is(runtime.inboxStorage.status().inboxCount, 1)
  t.is(runtime.inboxStorage.status().frameCount, 1)
  t.ok(dispatchContexts.length >= 7)
  for (const context of dispatchContexts) {
    t.is(context.transportId, TRANSPORT_ID.HTTPS_DIRECT)
    t.absent(context.sourceIp)
    t.absent(context.origin)
    t.absent(context.headers)
    t.absent(context.app)
  }
  t.alike(daemonErrors, [])
})
