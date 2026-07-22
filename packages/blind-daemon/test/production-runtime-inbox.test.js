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
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  blake2b256,
  blindErrorV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  getCellV1,
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
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import {
  PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig
} from '../production-runtime.js'
import {
  inboxAppendFixture,
  inboxCloseFixture,
  inboxCreateFixture,
  inboxReadFixture,
  inboxRenewFixture,
  inboxWatchFixture,
  runtimeInboxFixture
} from './production-runtime-inbox-fixture.js'
import { removeBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'

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

async function assembleInboxRuntime (fixture, options = {}) {
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const localPeerBootstrap = Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() })
  const runtimeConfig = loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds)
  return assembleProductionBlindDaemon({
    bootstrap: localPeerBootstrap,
    runtimeConfig,
    enableCellRuntime: options.enableCellRuntime !== false,
    enableInboxRuntime: options.enableInboxRuntime !== false,
    resolveAdmissionAdapter: async () => splitAdmissionAdapter(),
    releaseGate: async () => {},
    ...options.overrides
  })
}

function inboxFrame (operationId, codec, request, requestByte) {
  return {
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.INBOX,
    operationId,
    requestId: b4a.alloc(16, requestByte),
    body: encodeCanonical(codec, request)
  }
}

function inboxContext (overrides = {}) {
  const now = process.hrtime.bigint() / 1_000_000n
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: null,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 30_000n,
    ...overrides
  }
}

function responseValue (result, codec) {
  const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  if (frame.frameKind !== FRAME_KIND.RESPONSE) {
    const error = decodeCanonical(blindErrorV1, frame.body)
    throw new Error(`expected a response frame, got error code ${error.code}`)
  }
  return decodeCanonical(codec, frame.body, { copyBytes: true })
}

function errorName (result) {
  const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  if (frame.frameKind !== FRAME_KIND.ERROR) throw new Error('expected an error frame')
  const value = decodeCanonical(blindErrorV1, frame.body)
  return Object.keys(ERROR_CODE).find(name => ERROR_CODE[name] === value.code)
}

function verifyResultSignature (t, codec, value, domainId, relayPublicKey) {
  const canonical = encodeCanonical(codec, value)
  const unsigned = canonical.subarray(0, canonical.byteLength - sodium.crypto_sign_BYTES)
  t.ok(sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(domainId, unsigned), relayPublicKey))
}

async function rejectsCode (t, promise, code) {
  let rejected = null
  try {
    await promise
  } catch (error) {
    rejected = error
  }
  t.is(rejected && rejected.code, code)
  return rejected
}

test('production INBOX assembly serves the full public lifecycle through its real coordinator and storage', async t => {
  const fixture = await runtimeInboxFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  let replayOffset = -15_000n
  const runtime = await assembleInboxRuntime(fixture, {
    overrides: {
      testOnlyPrivateIpcReplayJournalOptions: {
        monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset
      }
    }
  })
  t.teardown(() => runtime.close())
  replayOffset = 0n

  const status = runtime.status()
  t.is(status.enabledOperationBits, PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS)
  t.absent(status.exclusions.includes('INBOX_PUBLIC_EXECUTION_UNASSEMBLED'),
    'assembled INBOX public execution is no longer excluded')
  t.ok(status.exclusions.includes('SHARED_ALL_FAMILY_WAL_DISPATCH_UNASSEMBLED'),
    'remaining INBOX runtime blockers stay visible')
  t.is(status.inbox.family, 'INBOX')
  t.is(status.inbox.productionReady, false)
  t.is(status.inboxStorage.opened, true)

  const relayPublicKey = fixture.relayPublicKey
  const created0 = inboxCreateFixture(relayPublicKey, fixture.parameterHash, fixture.currentEpoch)
  const createFrame = inboxFrame(OPERATION.INBOX.CREATE, inboxCreateV1, created0.request, 0xa1)
  const created = responseValue(await runtime.coordinator.dispatch(createFrame, inboxContext()), inboxReceiptV1)
  t.is(created.result, INBOX_RECEIPT_RESULT.CREATED)
  t.is(created.stateRevision, 0n)
  t.alike(created.topicCommitment, blake2b256(created0.request.physicalTopic))
  t.alike(created.requestNonce, created0.request.clientNonce)
  verifyResultSignature(t, inboxReceiptV1, created, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, relayPublicKey)
  t.is(runtime.inboxStorage.status().inboxCount, 1)

  const append = inboxAppendFixture(created0, relayPublicKey, fixture.parameterHash, 0xb3)
  const appended = responseValue(await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xa2), inboxContext()), inboxAppendAckV1)
  t.is(appended.result, INBOX_APPEND_RESULT.STORED)
  t.is(appended.appendRevision, 1n)
  t.alike(appended.frameHash, append.frameHash)
  verifyResultSignature(t, inboxAppendAckV1, appended, RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, relayPublicKey)
  t.is(runtime.inboxStorage.status().frameCount, 1)

  const read = inboxReadFixture(created0, fixture.parameterHash)
  const page = responseValue(await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.READ, inboxReadV1, read, 0xa3), inboxContext()), inboxReadResultV1)
  t.is(page.snapshotRevision, 1n)
  t.is(page.entries.length, 1)
  t.alike(page.entries[0].frame, append.frame)
  verifyResultSignature(t, inboxReadResultV1, page, RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, relayPublicKey)

  const chargedRead = inboxReadFixture(created0, fixture.parameterHash, { charged: true })
  const chargedFrame = inboxFrame(OPERATION.INBOX.READ, inboxReadV1, chargedRead, 0xa4)
  const charged = await runtime.coordinator.dispatch(chargedFrame, inboxContext())
  t.is(responseValue(charged, inboxReadResultV1).entries.length, 1)
  t.alike((await runtime.coordinator.dispatch(chargedFrame, inboxContext())).dispatch, charged.dispatch,
    'charged INBOX READ replays one exact signed page through production wiring')

  const watch = inboxWatchFixture(created0, fixture.parameterHash, { afterRevision: 0n })
  const woken = responseValue(await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.WATCH, inboxWatchV1, watch, 0xa5), inboxContext()), inboxReadResultV1)
  t.is(woken.snapshotRevision, 1n)
  t.is(woken.entries.length, 1)

  const quietWatch = inboxWatchFixture(created0, fixture.parameterHash, {
    afterRevision: 1n,
    maxWaitMillis: 25,
    spendByte: 0xf5
  })
  const quiet = responseValue(await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.WATCH, inboxWatchV1, quietWatch, 0xa6), inboxContext()), inboxReadResultV1)
  t.is(quiet.entries.length, 0)
  t.is(runtime.inboxStorage.status().waiterCount, 0)

  const renew = inboxRenewFixture(created0, created, relayPublicKey, fixture.parameterHash)
  const renewed = responseValue(await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.RENEW, inboxManageV1, renew, 0xa7), inboxContext()), inboxReceiptV1)
  t.is(renewed.result, INBOX_RECEIPT_RESULT.RENEWED)
  t.is(renewed.stateRevision, 1n)
  t.ok(renewed.leaseEpoch > created.leaseEpoch)
  verifyResultSignature(t, inboxReceiptV1, renewed, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, relayPublicKey)

  const close = inboxCloseFixture(created0, renewed, relayPublicKey)
  const closed = responseValue(await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.CLOSE, inboxManageV1, close, 0xa8), inboxContext()), inboxReceiptV1)
  t.is(closed.result, INBOX_RECEIPT_RESULT.CLOSED)
  t.is(closed.leaseClass, 0)
  verifyResultSignature(t, inboxReceiptV1, closed, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, relayPublicKey)

  const readAfterClose = await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.READ, inboxReadV1, inboxReadFixture(created0, fixture.parameterHash, {
      nonceByte: 0xf6
    }), 0xa9), inboxContext())
  t.is(errorName(readAfterClose), 'NOT_FOUND')

  const cellRead = await runtime.coordinator.dispatch({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: b4a.alloc(16, 0xaa),
    body: encodeCanonical(getCellV1, {
      version: 1,
      storageSlot: b4a.alloc(32, 0xab),
      clientNonce: b4a.alloc(32, 0xac),
      admission: null
    })
  }, inboxContext({
    absoluteDeadlineMonotonicMillis: (process.hrtime.bigint() / 1_000_000n) + 5_000n
  }))
  t.is(errorName(cellRead), 'NOT_FOUND', 'the CELL line keeps dispatching beside INBOX')
  await runtime.close()
  t.is('partitionKey' in runtime.inboxStorage.transactionStore, false,
    'INBOX storage retains no partition secret')
})

test('production INBOX assembly requires its disjoint store root and cursor key', async t => {
  const fixture = await runtimeInboxFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))

  const missing = { ...fixture.environment }
  delete missing.HIVERELAY_BLIND_INBOX_STORE_ROOT
  delete missing.HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE
  await rejectsCode(t, assembleInboxRuntime(fixture, {
    overrides: { environment: missing, runtimeConfig: null }
  }), 'BLIND_RUNTIME_CONFIG_INVALID')

  const overlapping = { ...fixture.environment, HIVERELAY_BLIND_INBOX_STORE_ROOT: fixture.environment.HIVERELAY_BLIND_STORE_ROOT }
  await rejectsCode(t, assembleInboxRuntime(fixture, {
    overrides: { environment: overlapping, runtimeConfig: null }
  }), 'BLIND_RUNTIME_INBOX_STORE_ROOT_OVERLAP')
})

test('production INBOX assembly requires the signed INBOX operation bits and the CELL line', async t => {
  const fixture = await runtimeInboxFixture({ inboxRuntime: false })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  await rejectsCode(t, assembleInboxRuntime(fixture), 'BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED')
  await rejectsCode(t, assembleInboxRuntime(fixture, {
    enableCellRuntime: false
  }), 'BLIND_RUNTIME_INBOX_CELL_RUNTIME_REQUIRED')

  const disabled = await assembleInboxRuntime(fixture, { enableInboxRuntime: false })
  t.teardown(() => disabled.close())
  t.ok(disabled.status().exclusions.includes('INBOX_PUBLIC_EXECUTION_UNASSEMBLED'),
    'a CELL-only production runtime keeps the INBOX exclusion')
  t.is(disabled.status().inbox, null)
  t.is(disabled.status().inboxStorage, null)
})

test('production INBOX charged reads pin their page across a store restart', async t => {
  const fixture = await runtimeInboxFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  let runtime = await assembleInboxRuntime(fixture)
  const relayPublicKey = fixture.relayPublicKey
  const created0 = inboxCreateFixture(relayPublicKey, fixture.parameterHash, fixture.currentEpoch)
  await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.CREATE, inboxCreateV1, created0.request, 0xb1), inboxContext())
  const append = inboxAppendFixture(created0, relayPublicKey, fixture.parameterHash, 0xc2)
  await runtime.coordinator.dispatch(
    inboxFrame(OPERATION.INBOX.APPEND, inboxAppendV1, append, 0xb2), inboxContext())
  const chargedRead = inboxReadFixture(created0, fixture.parameterHash, { charged: true, spendByte: 0xc3 })
  const chargedFrame = inboxFrame(OPERATION.INBOX.READ, inboxReadV1, chargedRead, 0xb3)
  const first = await runtime.coordinator.dispatch(chargedFrame, inboxContext())
  t.is(responseValue(first, inboxReadResultV1).entries.length, 1)
  await runtime.close()

  runtime = await assembleInboxRuntime(fixture)
  t.teardown(() => runtime.close())
  t.is(runtime.inboxStorage.status().inboxCount, 1, 'INBOX store recovered its inbox from the WAL')
  t.is(runtime.inboxStorage.status().frameCount, 1, 'INBOX store recovered its frame from the WAL')
  t.alike((await runtime.coordinator.dispatch(chargedFrame, inboxContext())).dispatch, first.dispatch,
    'charged INBOX READ replays the exact pinned page after a production restart')
})
