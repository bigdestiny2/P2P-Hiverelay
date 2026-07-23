import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CORE_ACK_RESULT,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  blake2b256,
  blindCoreAckV1,
  blindErrorV1,
  coreMirrorRequestV1,
  coreOpenReplicationV1,
  coreServeChallengeV1,
  decodeCanonical,
  decodeOuterEnvelope,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { BlindEdge } from '@hiverelay/blind-edge'
import { loadDaemonBootstrapConfig } from '../../packages/blind-daemon/bootstrap-config.js'
import { assembleProductionBlindDaemon } from '../../packages/blind-daemon/production-runtime.js'
import {
  coreMirrorFixture,
  coreOpenReplicationFixture,
  coreProveFixture,
  runtimeCoreFixture
} from '../../packages/blind-daemon/test/production-runtime-core-fixture.js'
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

test('public CORE unary operations round-trip through the metadata-stripping edge into production storage', async t => {
  const fixture = await runtimeCoreFixture()
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const localPeerBootstrap = Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() })
  const daemonErrors = []
  const runtime = await assembleProductionBlindDaemon({
    bootstrap: localPeerBootstrap,
    environment: fixture.environment,
    enableCellRuntime: true,
    enableInboxRuntime: true,
    enableCoreRuntime: true,
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
  async function postPublicCore (operationId, codec, request, requestByte) {
    const dispatch = encodeDispatchFrame({
      frameKind: FRAME_KIND.REQUEST,
      familyId: FAMILY.CORE,
      operationId,
      requestId: b4a.alloc(16, requestByte),
      body: encodeCanonical(codec, request)
    })
    const outer = encodeOuterEnvelope({ innerDispatch: dispatch, outerClass: 3 })
    return fetch(`http://127.0.0.1:${port}/api/blind/v1/core`, {
      method: 'POST',
      headers: { 'content-type': PROTOCOL.mediaType },
      body: outer
    })
  }

  async function exchangePublicCore (operationId, codec, request, requestByte) {
    const response = await postPublicCore(operationId, codec, request, requestByte)
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
      throw new Error(`public CORE operation returned ${name}`)
    }
    t.is(frame.frameKind, FRAME_KIND.RESPONSE)
    t.is(frame.familyId, FAMILY.CORE)
    t.is(frame.operationId, operationId)
    return decodeCanonical(codec, frame.body, { copyBytes: true })
  }

  const relayPublicKey = fixture.relayPublicKey
  const mirror = coreMirrorFixture(fixture.parameterHash)
  const accepted = successValue(
    await exchangePublicCore(OPERATION.CORE.MIRROR, coreMirrorRequestV1, mirror, 0xa1),
    OPERATION.CORE.MIRROR, blindCoreAckV1)
  t.is(accepted.result, CORE_ACK_RESULT.MIRROR_ACCEPTED)
  t.alike(accepted.corePublicKey, mirror.corePublicKey)
  t.is(accepted.length, mirror.length)
  t.alike(accepted.requestNonce, mirror.clientNonce)
  verifyResultSignature(t, blindCoreAckV1, accepted, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, relayPublicKey)

  const replay = successValue(
    await exchangePublicCore(OPERATION.CORE.MIRROR, coreMirrorRequestV1, mirror, 0xa2),
    OPERATION.CORE.MIRROR, blindCoreAckV1)
  t.alike(replay, accepted, 'an exact public retry replays the committed acknowledgement')

  const prove = coreProveFixture(mirror, fixture.parameterHash)
  const unsponsored = await exchangePublicCore(OPERATION.CORE.PROVE, coreServeChallengeV1, prove, 0xa3)
  t.is(unsponsored.frameKind, FRAME_KIND.ERROR)
  t.is(decodeCanonical(blindErrorV1, unsponsored.body).code, ERROR_CODE.NOT_FOUND,
    'PROVE serves only an ACTIVE sponsored generation')

  const open = coreOpenReplicationFixture(fixture.parameterHash)
  const rejected = await postPublicCore(
    OPERATION.CORE.OPEN_REPLICATION, coreOpenReplicationV1, open, 0xa4)
  t.is(rejected.status, 400,
    'reserved OPEN_REPLICATION fails closed at the public edge before daemon dispatch')
  t.is(rejected.headers.get('content-type'), 'text/plain; charset=utf-8',
    'the fail-closed edge rejection is a plain transport response, not a Blind envelope')
  t.is((await rejected.arrayBuffer()).byteLength, 0,
    'the fail-closed edge rejection carries no Blind envelope body')

  t.is(runtime.coreStorage.status().accounting.mirrorAttempts, 1)
  t.is(runtime.coreStorage.inspectMirrorSpend(blake2b256(mirror.admission.token)).state, 'RETRY_PENDING')
  t.ok(dispatchContexts.length >= 3)
  for (const context of dispatchContexts) {
    t.is(context.transportId, TRANSPORT_ID.HTTPS_DIRECT)
    t.absent(context.sourceIp)
    t.absent(context.origin)
    t.absent(context.headers)
    t.absent(context.app)
  }
  t.alike(daemonErrors, [])
})
