import test from 'brittle'
import b4a from 'b4a'
import {
  ABI_STATUS,
  ABI_RELEASE_BLOCKERS,
  DISPATCH_LIMITS,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  HASH_DOMAIN,
  IMPLEMENTED_SCHEMAS,
  OHTTP_TRANSPORT_ERROR_CODE,
  OHTTP_TRANSPORT_ERROR_ROWS,
  OPERATION_CAP_ROWS,
  OPERATION,
  REQUIRED_SCHEMA_NAMES,
  STREAM_WIRE_CLASS,
  blindForwardHopAcceptV1,
  blindForwardHopOpenV1,
  blindForwardRouteHopV1,
  blindForwardRouteScopeV1,
  blindOhttpTransportErrorV1,
  blindTransportRouteV1,
  blake2b256,
  coreOpenReplicationRequestCommitment,
  coreOpenReplicationResultV1,
  coreOpenReplicationV1,
  decodeCanonical,
  decodeDispatchFrame,
  draftAbiRegistryValue,
  encodeCanonical,
  encodeDispatchFrame,
  forwardRouteScopeGenesisHash,
  forwardRouteScopeHopHash
} from '../index.js'

const KiB = 1024
const MiB = 1024 * KiB
const bytes = (length, value) => b4a.alloc(length, value)

function relayBinding (seed, overrides = {}) {
  return {
    version: 1,
    relayPublicKey: bytes(32, seed),
    storeId: bytes(32, seed + 1),
    descriptorSequence: 1n,
    descriptorHash: bytes(32, seed + 2),
    durabilityProfileId: 1,
    durabilityContinuityHash: bytes(32, seed + 3),
    durabilityProfileHash: bytes(32, seed + 4),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: bytes(32, 0),
    externalCommitWitness: null,
    ...overrides
  }
}

function admission () {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: bytes(32, 0xa1),
    token: bytes(1, 0xa2)
  }
}

function streamingRoute () {
  return {
    version: 1,
    routeKind: 2,
    routeId: bytes(16, 0x10),
    previousRelayKey: bytes(32, 0x11),
    previousEndpointId: 1,
    nextRelayKey: bytes(32, 0x12),
    nextDescriptorSequence: 2n,
    nextDescriptorHash: bytes(32, 0x13),
    nextEndpointId: 2,
    envelopeClassBits: 0,
    wireClassBits: 0x0e,
    maxCanonicalDispatchBytes: DISPATCH_LIMITS.MAX_WIRE_BYTES,
    maxEncapsulatedRequestBytes: 0,
    maxOpenBytes: 128 * KiB,
    maxCircuitBytes: 256n * BigInt(MiB),
    maxConcurrentStreams: 16,
    maxRelayCount: 4,
    hopAdmissionProfileId: 7,
    issuedEpoch: 20,
    expiresEpoch: 24,
    routeNonce: bytes(32, 0x14),
    previousSignature: bytes(64, 0x15)
  }
}

function routeScope () {
  const root = {
    version: 1,
    rootRouteId: bytes(16, 0x10),
    rootCircuitNonce: bytes(32, 0x21),
    rootRequestCommitment: bytes(32, 0x22),
    maxRelayCount: 4,
    expiresEpoch: 24
  }
  const genesis = forwardRouteScopeGenesisHash(root)
  const hop = {
    hopIndex: 0,
    relayPublicKey: bytes(32, 0x11),
    descriptorSequence: 3n,
    descriptorHash: bytes(32, 0x20),
    previousScopeHash: bytes(32, 0)
  }
  return {
    ...root,
    hops: [{
      ...hop,
      scopeHash: forwardRouteScopeHopHash({ ...hop, previousScopeHash: genesis }),
      relaySignature: bytes(64, 0x25)
    }]
  }
}

function forwardHopOpen () {
  return {
    version: 1,
    route: streamingRoute(),
    routeScope: routeScope(),
    previousDescriptorSequence: 3n,
    previousDescriptorHash: bytes(32, 0x20),
    circuitNonce: bytes(32, 0x21),
    requestedWireClass: 3,
    circuitClass: 3,
    grantedInitialWindow: MiB,
    maxDataBytes: 65535,
    maxCircuitBytes: 256n * BigInt(MiB),
    idleMillis: 120_000,
    lifetimeMillis: 60 * 60_000,
    clientRequestCommitment: bytes(32, 0x22),
    handshakeFlight1: bytes(32, 0x23),
    forwarderSignature: bytes(64, 0x24)
  }
}

function forwardHopAccept () {
  return {
    version: 1,
    previousRelayKey: bytes(32, 0x30),
    previousDescriptorSequence: 3n,
    previousDescriptorHash: bytes(32, 0x31),
    nextRelayKey: bytes(32, 0x32),
    nextDescriptorSequence: 4n,
    nextDescriptorHash: bytes(32, 0x33),
    nextRelayBinding: relayBinding(0x32, {
      relayPublicKey: bytes(32, 0x32),
      descriptorSequence: 4n,
      descriptorHash: bytes(32, 0x33)
    }),
    routeId: bytes(16, 0x34),
    circuitNonce: bytes(32, 0x35),
    nextStreamId: 5n,
    grantedWireClass: 3,
    circuitClass: 3,
    grantedInitialWindow: MiB,
    maxDataBytes: 65535,
    maxCircuitBytes: 256n * BigInt(MiB),
    idleMillis: 120_000,
    lifetimeMillis: 60 * 60_000,
    openedAtEpoch: 21,
    hopOpenCommitment: bytes(32, 0x36),
    acceptedRouteScopeHash: bytes(32, 0x39),
    acceptedRelayCount: 1,
    handshakeFlight2: bytes(96, 0x37),
    nextSignature: bytes(64, 0x38)
  }
}

test('blind registry: frozen codes, wire class and schema gate stay synchronized', t => {
  t.is(ERROR_CODE.TRANSPORT_UNSUPPORTED, 20)
  t.is(STREAM_WIRE_CLASS[3], 65535)
  t.is(DISPATCH_LIMITS.MAX_FORWARD_DATA_BYTES, 65535)
  t.is(REQUIRED_SCHEMA_NAMES.length, 150)
  t.is(IMPLEMENTED_SCHEMAS.length, 143)
  t.is(ABI_STATUS.missingSchemaNames.length, 0)
  t.alike(ABI_RELEASE_BLOCKERS, ['FORWARD_ROUTE_SCOPE_AUTHORITY_REGENERATION_PENDING'])
  t.is(ABI_STATUS.releaseReady, false)
  const draftRegistry = draftAbiRegistryValue()
  t.is(draftRegistry.dispatchLimits.find(limit => limit.name === 'MAX_FORWARD_DATA_BYTES').value, 65535)
  t.is(draftRegistry.forwardCircuitClasses.find(entry => entry.id === 2).maxCircuitBytes, 64 * MiB)
  t.is(draftRegistry.coreSessionClasses.find(entry => entry.id === 2).maxSessionBytes, 64 * MiB)
  for (const name of [
    'AdmissionProfileV1',
    'BlindCoreReadCapV1',
    'BlindForwardHopAcceptV1',
    'BlindForwardHopOpenV1',
    'BlindForwardRouteHopV1',
    'BlindForwardRouteScopeV1',
    'BlindLocalCheckpointV1',
    'BlindOhttpTransportErrorV1',
    'BlindStoreManifestV1',
    'BlindWalHeaderV2',
    'BuildManifestV1',
    'CellBlobV1',
    'CellRecordV1',
    'ChargedUnaryRetryV1',
    'CoreOpenReplicationResultV1',
    'CoreOpenReplicationV1',
    'DurabilityProfileV1',
    'OpaqueChainCheckpointV1',
    'OpaqueChainFrameV1',
    'ReadCellCapV1',
    'WriteCellCapV1'
  ]) t.ok(REQUIRED_SCHEMA_NAMES.includes(name), `${name} is release-gated`)
})

test('blind OHTTP transport error: protected pre-dispatch code is exactly two bytes', t => {
  t.is(OHTTP_TRANSPORT_ERROR_CODE.MALFORMED_INNER, 1)
  t.is(OHTTP_TRANSPORT_ERROR_CODE.TARGET_UNAVAILABLE, 2)
  t.is(OHTTP_TRANSPORT_ERROR_CODE.TARGET_TIMEOUT, 3)
  t.alike(OHTTP_TRANSPORT_ERROR_ROWS.map(row => [row.code, row.protectedStatus, row.deliveryBoundary, row.retryAction]), [
    [1, 400, 1, 0],
    [2, 503, 2, 1],
    [3, 504, 3, 2]
  ])
  t.is(OPERATION_CAP_ROWS.length, 22)
  for (const code of [1, 2, 3]) {
    const encoded = encodeCanonical(blindOhttpTransportErrorV1, { version: 1, code })
    t.alike(encoded, b4a.from([1, code]))
    t.is(decodeCanonical(blindOhttpTransportErrorV1, encoded).code, code)
  }
  t.exception(() => encodeCanonical(blindOhttpTransportErrorV1, { version: 1, code: 0 }), /outside 1..3/)
  t.exception(() => encodeCanonical(blindOhttpTransportErrorV1, { version: 1, code: 4 }), /outside 1..3/)
})

test('blind forwarding: route and adjacent-hop records are byte-exact', t => {
  const route = encodeCanonical(blindTransportRouteV1, streamingRoute())
  t.is(route.byteLength, 256)
  t.is(decodeCanonical(blindTransportRouteV1, route).nextDescriptorSequence, 2n)

  const open = encodeCanonical(blindForwardHopOpenV1, forwardHopOpen())
  t.is(open.byteLength, 771)
  const decodedOpen = decodeCanonical(blindForwardHopOpenV1, open)
  t.is(decodedOpen.maxDataBytes, 65535)
  t.alike(decodedOpen.handshakeFlight1, bytes(32, 0x23))

  const accept = encodeCanonical(blindForwardHopAcceptV1, forwardHopAccept())
  t.is(accept.byteLength, 667)
  const decodedAccept = decodeCanonical(blindForwardHopAcceptV1, accept)
  t.is(decodedAccept.nextStreamId, 5n)
  t.alike(decodedAccept.handshakeFlight2, bytes(96, 0x37))

  const scope = encodeCanonical(blindForwardRouteScopeV1, routeScope())
  t.is(decodeCanonical(blindForwardRouteHopV1,
    encodeCanonical(blindForwardRouteHopV1, routeScope().hops[0])).hopIndex, 0)
  t.alike(decodeCanonical(blindForwardRouteScopeV1, scope).hops[0].relayPublicKey, bytes(32, 0x11))
})

test('blind forwarding: route, class and stream invariants fail closed', t => {
  t.exception(() => encodeCanonical(blindTransportRouteV1, {
    ...streamingRoute(),
    expiresEpoch: 25
  }), /route epoch window/)
  t.exception(() => encodeCanonical(blindTransportRouteV1, {
    ...streamingRoute(),
    wireClassBits: 0x80
  }), /reserved bit/)
  t.exception(() => encodeCanonical(blindForwardHopOpenV1, {
    ...forwardHopOpen(),
    maxDataBytes: 64 * KiB
  }), /selected wire class/)
  t.exception(() => encodeCanonical(blindForwardHopOpenV1, {
    ...forwardHopOpen(),
    grantedInitialWindow: 256 * KiB
  }), /frozen class tuple/)
  t.exception(() => encodeCanonical(blindForwardHopAcceptV1, {
    ...forwardHopAccept(),
    nextStreamId: 0n
  }), /must be nonzero/)
})

test('blind core: open and signed result freeze the upstream child limits', t => {
  const open = {
    version: 1,
    wireProfileHash: bytes(32, 0x40),
    sessionClass: 2,
    controlChannelId: 0x0102030405060708n,
    parentChannelBinding: bytes(32, 0x47),
    clientNonce: bytes(32, 0x41),
    admission: admission()
  }
  const encodedOpen = encodeCanonical(coreOpenReplicationV1, open)
  t.is(encodedOpen.byteLength, 144)
  t.is(decodeCanonical(coreOpenReplicationV1, encodedOpen).sessionClass, 2)
  t.is(decodeCanonical(coreOpenReplicationV1, encodedOpen).controlChannelId, 0x0102030405060708n)
  t.alike(decodeCanonical(coreOpenReplicationV1, encodedOpen).parentChannelBinding, bytes(32, 0x47))
  const commitment = coreOpenReplicationRequestCommitment({
    relayPublicKey: bytes(32, 0x42),
    wireProfileHash: open.wireProfileHash,
    sessionClass: open.sessionClass,
    controlChannelId: open.controlChannelId,
    parentChannelBinding: open.parentChannelBinding,
    clientNonce: open.clientNonce
  })
  t.alike(commitment, blake2b256(b4a.concat([
    b4a.from(HASH_DOMAIN.REQUEST, 'ascii'),
    b4a.from('core-open-replication', 'ascii'),
    bytes(32, 0x42),
    open.wireProfileHash,
    b4a.from([2]),
    b4a.from('0102030405060708', 'hex'),
    open.parentChannelBinding,
    open.clientNonce
  ])))

  const result = {
    version: 1,
    relayBinding: relayBinding(0x42),
    wireProfileHash: bytes(32, 0x43),
    sessionClass: 2,
    controlChannelId: 0x0102030405060708n,
    parentChannelBinding: bytes(32, 0x47),
    streamId: 9n,
    maxSessionBytes: 64n * BigInt(MiB),
    idleMillis: 60_000,
    lifetimeMillis: 30 * 60_000,
    openedAtEpoch: 50,
    requestNonce: bytes(32, 0x44),
    requestCommitment: bytes(32, 0x45),
    signature: bytes(64, 0x46)
  }
  const encodedResult = encodeCanonical(coreOpenReplicationResultV1, result)
  t.is(encodedResult.byteLength, 441)
  t.is(decodeCanonical(coreOpenReplicationResultV1, encodedResult).maxSessionBytes, 64n * BigInt(MiB))
  t.exception(() => encodeCanonical(coreOpenReplicationResultV1, {
    ...result,
    maxSessionBytes: 16n * BigInt(MiB)
  }), /frozen class tuple/)
  t.exception(() => encodeCanonical(coreOpenReplicationResultV1, {
    ...result,
    streamId: 0n
  }), /must be nonzero/)
  t.exception(() => encodeCanonical(coreOpenReplicationV1, {
    ...open,
    parentChannelBinding: bytes(32, 0)
  }), /must be nonzero/)
  t.exception(() => encodeCanonical(coreOpenReplicationV1, {
    ...open,
    controlChannelId: 0n
  }), /must be nonzero/)
  t.exception(() => coreOpenReplicationRequestCommitment({
    relayPublicKey: result.relayBinding.relayPublicKey,
    ...open,
    controlChannelId: 0n
  }), /must be nonzero/)
})

test('blind dispatch: CORE open returns a child but never uses kind-4 frames', t => {
  const requestId = bytes(16, 0x51)
  const response = encodeDispatchFrame({
    frameKind: FRAME_KIND.RESPONSE,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.OPEN_REPLICATION,
    requestId,
    streamId: 7n,
    body: b4a.alloc(0)
  })
  t.is(decodeDispatchFrame(response).streamId, 7n)

  t.exception(() => encodeDispatchFrame({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.OPEN_REPLICATION,
    requestId: b4a.alloc(16),
    streamId: 7n,
    sequence: 1n,
    body: bytes(1, 0x52)
  }), /frame kind is not allowed for the operation/)
})
