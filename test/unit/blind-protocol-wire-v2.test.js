import test from 'brittle'
import b4a from 'b4a'
import {
  decodeCanonical,
  encodeCanonical
} from '../../packages/blind-protocol/codec.js'
import {
  createWireAbiV2Value,
  decodeWireAbiV2,
  encodeWireAbiV2
} from '../../packages/blind-protocol/abi-registry-v2.js'
import {
  DIRECT_HTTPS_ROUTE_KIND_V2,
  FORWARD_HTTPS_DOMAIN_V2,
  FORWARD_HTTPS_LIMITS_V1,
  FORWARD_HTTPS_RESULT_OUTCOME_V1,
  FORWARD_HTTPS_TRANSPORT_VARIANTS_V2,
  FORWARD_HTTPS_TURN_KIND_V1,
  ForwardHttpsTurnReplayWindowV1,
  RELEASE_PROFILE_V2,
  WIRE_V2_SCHEMA,
  WIRE_V2_SCHEMA_DECLARATIONS,
  assertForwardHttpsCatalogTargetV1,
  blindForwardHttpsTurnRequestV1,
  blindForwardHttpsTurnResultV1,
  forwardHttpsSessionIdV1,
  forwardHttpsTurnRequestCommitmentV1,
  forwardHttpsTurnResultSignaturePayloadV1,
  normalizeReleaseProfileInputV2
} from '../../packages/blind-protocol/wire-v2.js'

const fill = (length, value) => b4a.alloc(length, value)

function capability () {
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    sourceRelayPublicKey: fill(32, 1),
    sourceDescriptorSequence: 11n,
    sourceDescriptorHash: fill(32, 2),
    targetRelayPublicKey: fill(32, 3),
    targetDescriptorSequence: 22n,
    targetDescriptorHash: fill(32, 4),
    targetCatalogEntryId: fill(32, 5),
    routeId: fill(16, 6),
    routePrefixRelayPublicKey: fill(32, 1),
    maxRelayCount: 2,
    remainingTransitions: 1,
    circuitClass: 1,
    maxCircuitBytes: 16n * 1024n * 1024n,
    initialWindowBytes: 65_536,
    idleMillis: 30_000,
    lifetimeMillis: 600_000,
    issuedAtEpoch: 1_800_000_000,
    expiresAtEpoch: 1_800_000_600,
    circuitNonce: fill(32, 7),
    tlsExporterBindingHash: fill(32, 8),
    signature: fill(64, 9)
  }
}

function request (parent = capability()) {
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    turnKind: FORWARD_HTTPS_TURN_KIND_V1.DATA,
    flags: 0,
    sessionId: forwardHttpsSessionIdV1(parent),
    sequence: 0n,
    requestNonce: fill(32, 10),
    parentCapability: parent,
    inner: {
      version: 1,
      circuitNonce: parent.circuitNonce,
      offset: 0n,
      bytes: fill(64, 11)
    },
    padding: fill(FORWARD_HTTPS_LIMITS_V1.MAX_REQUEST_INNER_BYTES - 106, 12)
  }
}

function successResult (requestBytes) {
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    turnKind: FORWARD_HTTPS_TURN_KIND_V1.DATA,
    outcome: FORWARD_HTTPS_RESULT_OUTCOME_V1.SUCCESS,
    sessionId: forwardHttpsSessionIdV1(capability()),
    sequence: 0n,
    requestCommitment: forwardHttpsTurnRequestCommitmentV1(requestBytes),
    relayPublicKey: fill(32, 3),
    descriptorSequence: 22n,
    descriptorHash: fill(32, 4),
    signature: fill(64, 13),
    inner: {
      version: 1,
      circuitNonce: fill(32, 7),
      offset: 0n,
      bytes: fill(32, 14)
    }
  }
}

test('WIRE v2 is an additive protocol 1.1 ABI with exact frozen allocations', t => {
  t.alike(WIRE_V2_SCHEMA, {
    BlindForwardHttpsTurnRequestV1: 74,
    BlindForwardHttpsTurnResultV1: 75
  })
  t.is(RELEASE_PROFILE_V2.LIMITED_PUBLIC_TEST_V1.operationBits, 0x0001ffff)
  t.is(RELEASE_PROFILE_V2.LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1.operationBits, 0x003dffff)
  t.is(RELEASE_PROFILE_V2.LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1.operationBits & (1 << 17), 0)
  t.is(normalizeReleaseProfileInputV2('BASELINE_17'), 'LIMITED_PUBLIC_TEST_V1')
  t.is(DIRECT_HTTPS_ROUTE_KIND_V2.DIRECT_HTTPS_FORWARD_ONE_HOP, 7)
  t.is(FORWARD_HTTPS_TRANSPORT_VARIANTS_V2.length, 4)
  t.alike(FORWARD_HTTPS_TRANSPORT_VARIANTS_V2.map(row => row.requestSchemaId), [74, 74, 74, 74])
  t.alike(Object.values(FORWARD_HTTPS_DOMAIN_V2).map(row => row.domainId), [17, 112, 214])

  const abi = createWireAbiV2Value(fill(32, 15))
  const encoded = encodeWireAbiV2(abi)
  const decoded = decodeWireAbiV2(encoded)
  t.is(decoded.protocolMajor, 1)
  t.is(decoded.protocolMinor, 1)
  t.is(decoded.additionalSchemas.length, 2)
  t.is(decoded.forwardReadinessOperationBits, 0)
  t.absent(b4a.toString(encoded, 'utf8').includes('BASELINE_17'), 'input-only alias is not serialised')

  const resultFields = WIRE_V2_SCHEMA_DECLARATIONS[1].fields.join('|')
  t.ok(resultFields.includes('ERROR:BlindErrorV1'), 'the only error branch reuses BlindErrorV1')
  t.ok(resultFields.includes('SUCCESS.OPEN:BlindForwardOpenResultV1'), 'OPEN success is bidirectional')
  t.ok(resultFields.includes('SUCCESS.DATA:BlindForwardDataV1'), 'DATA success is bidirectional')
  t.ok(resultFields.includes('SUCCESS.WINDOW:BlindForwardWindowV1'), 'WINDOW success is bidirectional')
  t.ok(resultFields.includes('SUCCESS.CLOSE:BlindForwardCloseV1'), 'CLOSE success is bidirectional')
  t.ok(resultFields.includes('no-ACK-schema'), 'the result union has no ACK branch')
})

test('WIRE v2 generic request/result and canonical error are each exactly 65536 bytes', t => {
  const requestValue = request()
  const requestBytes = encodeCanonical(blindForwardHttpsTurnRequestV1, requestValue)
  t.is(requestBytes.byteLength, 65_536)
  t.alike(decodeCanonical(blindForwardHttpsTurnRequestV1, requestBytes), requestValue)

  const success = successResult(requestBytes)
  const successBytes = encodeCanonical(blindForwardHttpsTurnResultV1, success)
  t.is(successBytes.byteLength, 65_536)
  t.alike(decodeCanonical(blindForwardHttpsTurnResultV1, successBytes), {
    ...success,
    padding: fill(65_536 - 221 - 74, 0)
  })

  const error = {
    ...success,
    outcome: FORWARD_HTTPS_RESULT_OUTCOME_V1.ERROR,
    inner: { version: 1, code: 1, retryable: 0, retryAfterEpoch: null }
  }
  const errorBytes = encodeCanonical(blindForwardHttpsTurnResultV1, error)
  t.is(errorBytes.byteLength, 65_536)
  t.alike(decodeCanonical(blindForwardHttpsTurnResultV1, errorBytes).inner, error.inner)

  const payloadA = forwardHttpsTurnResultSignaturePayloadV1(success)
  const changedPadding = { ...success, padding: fill(65_536 - 221 - 74, 99) }
  const payloadB = forwardHttpsTurnResultSignaturePayloadV1(changedPadding)
  t.is(payloadA.byteLength, FORWARD_HTTPS_DOMAIN_V2.RESULT.exactAsciiBytes.length + 8 + 65_472)
  t.unlike(payloadA, payloadB, 'result signature binds every padding byte')
})

test('WIRE v2 exact catalog target and single outstanding replay fail closed', t => {
  const parent = capability()
  t.ok(assertForwardHttpsCatalogTargetV1(parent, {
    catalogEntryId: parent.targetCatalogEntryId,
    relayPublicKey: parent.targetRelayPublicKey,
    descriptorSequence: parent.targetDescriptorSequence,
    descriptorHash: parent.targetDescriptorHash
  }))
  t.exception(() => assertForwardHttpsCatalogTargetV1(parent, {
    catalogEntryId: parent.targetCatalogEntryId,
    relayPublicKey: parent.targetRelayPublicKey,
    descriptorSequence: parent.targetDescriptorSequence,
    descriptorHash: parent.targetDescriptorHash,
    host: 'arbitrary.invalid'
  }), /must not contain caller dial fields/)
  t.exception(() => encodeCanonical(blindForwardHttpsTurnRequestV1, request({
    ...parent,
    targetRelayPublicKey: parent.sourceRelayPublicKey
  })), /source and target relay keys must differ/)
  t.exception(() => encodeCanonical(blindForwardHttpsTurnRequestV1, request({
    ...parent,
    url: 'https://arbitrary.invalid'
  })), /url is forbidden/)

  const requestBytes = encodeCanonical(blindForwardHttpsTurnRequestV1, request(parent))
  const replay = new ForwardHttpsTurnReplayWindowV1(forwardHttpsSessionIdV1(parent))
  t.is(replay.accept(requestBytes).disposition, 'ACCEPTED')
  t.is(replay.accept(requestBytes).disposition, 'IDEMPOTENT_RETRY')
  const changed = b4a.from(requestBytes)
  changed[changed.byteLength - 1] ^= 1
  t.exception(() => replay.accept(changed), /changed bytes reused/)
  t.ok(replay.terminal)
})
