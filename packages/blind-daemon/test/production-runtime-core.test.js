import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CORE_ACK_RESULT,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  blake2b256,
  blindCoreAckV1,
  blindErrorV1,
  coreOpenReplicationV1,
  coreMirrorRequestV1,
  coreServeChallengeV1,
  coreServeResultV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  getCellV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import {
  PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS,
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig
} from '../production-runtime.js'
import {
  CORE_TEST_SHAPE,
  coreMirrorFixture,
  coreOpenReplicationFixture,
  coreProveFixture,
  runtimeCoreFixture
} from './production-runtime-core-fixture.js'
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

async function assembleCoreRuntime (fixture, options = {}) {
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const localPeerBootstrap = Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() })
  const runtimeConfig = loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds)
  return assembleProductionBlindDaemon({
    bootstrap: localPeerBootstrap,
    runtimeConfig,
    enableCellRuntime: options.enableCellRuntime !== false,
    enableInboxRuntime: options.enableInboxRuntime !== false,
    enableCoreRuntime: options.enableCoreRuntime !== false,
    resolveAdmissionAdapter: async () => splitAdmissionAdapter(),
    releaseGate: async () => {},
    ...options.overrides
  })
}

function coreFrame (operationId, codec, request, requestByte) {
  return {
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CORE,
    operationId,
    requestId: b4a.alloc(16, requestByte),
    body: encodeCanonical(codec, request)
  }
}

function coreContext (overrides = {}) {
  const now = process.hrtime.bigint() / 1_000_000n
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: null,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 15_000n,
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

test('production CORE assembly serves the unary public lifecycle through its real coordinator and storage', async t => {
  const fixture = await runtimeCoreFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  let replayOffset = -15_000n
  const runtime = await assembleCoreRuntime(fixture, {
    overrides: {
      testOnlyPrivateIpcReplayJournalOptions: {
        monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset
      }
    }
  })
  t.teardown(() => runtime.close())
  replayOffset = 0n

  const status = runtime.status()
  t.is(status.enabledOperationBits, PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS)
  t.absent(status.exclusions.includes('CORE_PUBLIC_EXECUTION_UNASSEMBLED'),
    'assembled CORE unary public execution is no longer excluded')
  t.ok(status.exclusions.includes('CORE_UPSTREAM_SIGNED_HEAD_PROOF_AUTHORITY_UNASSEMBLED'),
    'the unassembled upstream signed-head proof authority stays visible')
  t.ok(status.exclusions.includes('CORE_NATIVE_CHILD_PRIVATE_IPC_HANDOFF_UNASSEMBLED'),
    'the unassembled native child handoff stays visible')
  t.absent(status.exclusions.includes('CORE_COMMITTED_RESULT_COORDINATOR_BINDING_UNASSEMBLED'),
    'the committed-result coordinator binding is assembled by this line')
  t.is(status.core.family, 'CORE')
  t.is(status.core.productionReady, false)
  t.is(status.coreStorage.family, 'CORE')

  const relayPublicKey = fixture.relayPublicKey
  const mirror = coreMirrorFixture(fixture.parameterHash)
  const mirrorFrame = coreFrame(OPERATION.CORE.MIRROR, coreMirrorRequestV1, mirror, 0xa1)
  const first = await runtime.coordinator.dispatch(mirrorFrame, coreContext())
  const accepted = responseValue(first, blindCoreAckV1)
  t.is(accepted.result, CORE_ACK_RESULT.MIRROR_ACCEPTED)
  t.alike(accepted.corePublicKey, mirror.corePublicKey)
  t.is(accepted.fork, mirror.fork)
  t.is(accepted.length, mirror.length)
  t.alike(accepted.signedHeadHash, mirror.signedHeadHash)
  t.alike(accepted.requestNonce, mirror.clientNonce)
  t.ok(accepted.leaseEpoch >= fixture.currentEpoch + 4)
  verifyResultSignature(t, blindCoreAckV1, accepted, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, relayPublicKey)
  t.is(runtime.coreStorage.status().accounting.mirrorAttempts, 1)
  t.is(runtime.coreStorage.status().accounting.activeCores, 0,
    'the unassembled upstream cannot activate the accepted sponsorship')
  const spendTag = blake2b256(mirror.admission.token)
  t.is(runtime.coreStorage.inspectMirrorSpend(spendTag).state, 'RETRY_PENDING',
    'mirror activation is durably pending on the unavailable upstream')

  t.alike((await runtime.coordinator.dispatch(mirrorFrame, coreContext())).dispatch, first.dispatch,
    'charged CORE.MIRROR replays the exact committed acknowledgement through production wiring')

  const prove = coreProveFixture(mirror, fixture.parameterHash)
  const unsponsored = await runtime.coordinator.dispatch(
    coreFrame(OPERATION.CORE.PROVE, coreServeChallengeV1, prove, 0xa2), coreContext())
  t.is(errorName(unsponsored), 'NOT_FOUND', 'PROVE serves only an ACTIVE sponsored generation')

  const chargedProve = coreProveFixture(mirror, fixture.parameterHash, { charged: true })
  const chargedUnsponsored = await runtime.coordinator.dispatch(
    coreFrame(OPERATION.CORE.PROVE, coreServeChallengeV1, chargedProve, 0xa3), coreContext())
  t.is(errorName(chargedUnsponsored), 'NOT_FOUND', 'charged PROVE fails before its spend without an active core')
  t.is(runtime.coreStorage.status().accounting.proofSpendTombstones, 0,
    'the failed charged PROVE consumed no spend')

  const open = coreOpenReplicationFixture(fixture.parameterHash)
  const opened = await runtime.coordinator.dispatch(
    coreFrame(OPERATION.CORE.OPEN_REPLICATION, coreOpenReplicationV1, open, 0xa4), coreContext())
  t.is(errorName(opened), 'TRANSPORT_UNSUPPORTED',
    'OPEN_REPLICATION stays outside the assembled unary descriptor bits')

  const extension = coreMirrorFixture(fixture.parameterHash, {
    length: CORE_TEST_SHAPE.extensionLength,
    clientNonce: b4a.alloc(32, 0x52),
    spendByte: 0xb3
  })
  const extended = responseValue(await runtime.coordinator.dispatch(
    coreFrame(OPERATION.CORE.MIRROR, coreMirrorRequestV1, extension, 0xa5), coreContext()), blindCoreAckV1)
  t.is(extended.result, CORE_ACK_RESULT.MIRROR_ACCEPTED)
  t.is(extended.length, CORE_TEST_SHAPE.extensionLength)
  verifyResultSignature(t, blindCoreAckV1, extended, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, relayPublicKey)

  const renew = coreMirrorFixture(fixture.parameterHash, {
    length: CORE_TEST_SHAPE.extensionLength,
    clientNonce: b4a.alloc(32, 0x53),
    spendByte: 0xb4
  })
  const notDue = await runtime.coordinator.dispatch(
    coreFrame(OPERATION.CORE.MIRROR, coreMirrorRequestV1, renew, 0xa6), coreContext())
  t.is(errorName(notDue), 'RENEW_NOT_DUE',
    'a sponsorship that advances no admitted dimension is refused before spend')

  const cellRead = await runtime.coordinator.dispatch({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: b4a.alloc(16, 0xa7),
    body: encodeCanonical(getCellV1, {
      version: 1,
      storageSlot: b4a.alloc(32, 0xab),
      clientNonce: b4a.alloc(32, 0xac),
      admission: null
    })
  }, coreContext())
  t.is(errorName(cellRead), 'NOT_FOUND', 'the CELL line keeps dispatching beside CORE')
  await runtime.close()
  t.alike(runtime.coreStorage.transactionStore.partitionKey, b4a.alloc(32),
    'CORE store-owned partition key is destroyed on close')
})

test('production CORE assembly requires its disjoint store root and the INBOX line', async t => {
  const fixture = await runtimeCoreFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))

  const missing = { ...fixture.environment }
  delete missing.HIVERELAY_BLIND_CORE_STORE_ROOT
  await rejectsCode(t, assembleCoreRuntime(fixture, {
    overrides: { environment: missing, runtimeConfig: null }
  }), 'BLIND_RUNTIME_CONFIG_INVALID')

  const overlapping = { ...fixture.environment, HIVERELAY_BLIND_CORE_STORE_ROOT: fixture.environment.HIVERELAY_BLIND_STORE_ROOT }
  await rejectsCode(t, assembleCoreRuntime(fixture, {
    overrides: { environment: overlapping, runtimeConfig: null }
  }), 'BLIND_RUNTIME_CORE_STORE_ROOT_OVERLAP')

  const overlappingInbox = { ...fixture.environment, HIVERELAY_BLIND_CORE_STORE_ROOT: fixture.environment.HIVERELAY_BLIND_INBOX_STORE_ROOT }
  await rejectsCode(t, assembleCoreRuntime(fixture, {
    overrides: { environment: overlappingInbox, runtimeConfig: null }
  }), 'BLIND_RUNTIME_CORE_STORE_ROOT_OVERLAP')

  await rejectsCode(t, assembleCoreRuntime(fixture, {
    enableInboxRuntime: false
  }), 'BLIND_RUNTIME_CORE_INBOX_RUNTIME_REQUIRED')
})

test('production CORE assembly requires the signed CORE unary operation bits', async t => {
  const fixture = await runtimeCoreFixture({ coreRuntime: false })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  await rejectsCode(t, assembleCoreRuntime(fixture), 'BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED')

  const disabled = await assembleCoreRuntime(fixture, { enableCoreRuntime: false })
  t.teardown(() => disabled.close())
  t.ok(disabled.status().exclusions.includes('CORE_PUBLIC_EXECUTION_UNASSEMBLED'),
    'an INBOX-only production runtime keeps the CORE exclusion')
  t.is(disabled.status().core, null)
  t.is(disabled.status().coreStorage, null)
})

test('production CORE sponsorship and its committed replay survive a store restart', async t => {
  const fixture = await runtimeCoreFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  let runtime = await assembleCoreRuntime(fixture)
  const relayPublicKey = fixture.relayPublicKey
  const mirror = coreMirrorFixture(fixture.parameterHash)
  const mirrorFrame = coreFrame(OPERATION.CORE.MIRROR, coreMirrorRequestV1, mirror, 0xb1)
  const first = await runtime.coordinator.dispatch(mirrorFrame, coreContext())
  t.is(responseValue(first, blindCoreAckV1).result, CORE_ACK_RESULT.MIRROR_ACCEPTED)
  verifyResultSignature(t, blindCoreAckV1, responseValue(first, blindCoreAckV1),
    RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, relayPublicKey)
  await runtime.close()

  runtime = await assembleCoreRuntime(fixture)
  t.teardown(() => runtime.close())
  t.is(runtime.coreStorage.status().accounting.mirrorAttempts, 1,
    'CORE store recovered its accepted sponsorship from the WAL')
  t.is(runtime.coreStorage.inspectMirrorSpend(blake2b256(mirror.admission.token)).state, 'RETRY_PENDING',
    'CORE store recovered the pending activation for its resume')
  t.alike((await runtime.coordinator.dispatch(mirrorFrame, coreContext())).dispatch, first.dispatch,
    'charged CORE.MIRROR replays the exact committed acknowledgement after a production restart')

  const prove = coreProveFixture(mirror, fixture.parameterHash)
  const unsponsored = await runtime.coordinator.dispatch(
    coreFrame(OPERATION.CORE.PROVE, coreServeChallengeV1, prove, 0xb2), coreContext())
  t.is(errorName(unsponsored), 'NOT_FOUND', 'PROVE stays honest about the unactivated sponsorship')
})
