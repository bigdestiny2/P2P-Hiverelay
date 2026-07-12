import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  FORWARD_CIRCUIT_CLASS,
  STREAM_WIRE_CLASS,
  forwardRouteScopeGenesisHash,
  forwardRouteScopeHopHash
} from '@hiverelay/blind-protocol'

const KiB = 1024
const MiB = 1024 * KiB

export const fixtureBytes = (length, value) => b4a.alloc(length, value)

export function fixtureAdmission (seed = 0xa0) {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: fixtureBytes(32, seed),
    token: fixtureBytes(8, seed + 1)
  }
}

export function fixtureReadiness (overrides = {}) {
  return {
    descriptorSequence: 9n,
    descriptorHash: fixtureBytes(32, 0x22),
    expiresMonotonicMillis: 1_000_000n,
    ...overrides
  }
}

export function fixtureRelayBinding (relayPublicKey, overrides = {}) {
  return {
    version: 1,
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: fixtureBytes(32, 0x71),
    descriptorSequence: 9n,
    descriptorHash: fixtureBytes(32, 0x22),
    durabilityProfileId: 1,
    durabilityContinuityHash: fixtureBytes(32, 0x72),
    durabilityProfileHash: fixtureBytes(32, 0x73),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: fixtureBytes(32, 0),
    externalCommitWitness: null,
    ...overrides
  }
}

export function fixtureCoreOpen (wireProfileHash, overrides = {}) {
  return {
    version: 1,
    wireProfileHash: b4a.from(wireProfileHash),
    sessionClass: 1,
    controlChannelId: 17n,
    parentChannelBinding: fixtureBytes(32, 0x33),
    clientNonce: fixtureBytes(32, 0x34),
    admission: fixtureAdmission(),
    ...overrides
  }
}

export function fixtureCoreResult (relayPublicKey, fields, overrides = {}) {
  return {
    version: 1,
    relayBinding: fixtureRelayBinding(relayPublicKey),
    wireProfileHash: b4a.from(fields.request.wireProfileHash),
    sessionClass: fields.request.sessionClass,
    controlChannelId: fields.request.controlChannelId,
    parentChannelBinding: b4a.from(fields.request.parentChannelBinding),
    streamId: fields.streamId,
    maxSessionBytes: fields.maxSessionBytes,
    idleMillis: fields.idleMillis,
    lifetimeMillis: fields.lifetimeMillis,
    openedAtEpoch: fields.openedAtEpoch,
    requestNonce: b4a.from(fields.request.clientNonce),
    requestCommitment: b4a.from(fields.requestCommitment),
    signature: fixtureBytes(64, 0x35),
    ...overrides
  }
}

export function fixtureForwardOpen (overrides = {}) {
  return {
    version: 1,
    routeId: fixtureBytes(16, 0x41),
    nextDescriptorSequence: 10n,
    nextDescriptorHash: fixtureBytes(32, 0x42),
    requestedWireClass: 1,
    circuitClass: 1,
    circuitNonce: fixtureBytes(32, 0x43),
    parentRouteScopeHash: fixtureBytes(32, 0),
    hopAdmission: fixtureAdmission(0xb0),
    innerHandshake: fixtureBytes(32, 0x44),
    ...overrides
  }
}

export function fixtureRoute (relayPublicKey, request, overrides = {}) {
  return {
    version: 1,
    routeKind: 2,
    routeId: b4a.from(request.routeId),
    previousRelayKey: b4a.from(relayPublicKey),
    previousEndpointId: 1,
    nextRelayKey: fixtureBytes(32, 0x51),
    nextDescriptorSequence: request.nextDescriptorSequence,
    nextDescriptorHash: b4a.from(request.nextDescriptorHash),
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
    routeNonce: fixtureBytes(32, 0x52),
    previousSignature: fixtureBytes(64, 0x53),
    ...overrides
  }
}

export function fixtureRouteScope (relayPublicKey, route, requestCommitment, request, overrides = {}) {
  const root = {
    version: 1,
    rootRouteId: b4a.from(route.routeId),
    rootCircuitNonce: b4a.from(request.circuitNonce),
    rootRequestCommitment: b4a.from(requestCommitment),
    maxRelayCount: route.maxRelayCount,
    expiresEpoch: route.expiresEpoch
  }
  const genesisHash = forwardRouteScopeGenesisHash(root)
  const hop = {
    hopIndex: 0,
    relayPublicKey: b4a.from(relayPublicKey),
    descriptorSequence: 9n,
    descriptorHash: fixtureBytes(32, 0x22),
    previousScopeHash: fixtureBytes(32, 0)
  }
  hop.scopeHash = forwardRouteScopeHopHash({ ...hop, previousScopeHash: genesisHash })
  hop.relaySignature = fixtureBytes(64, 0x60)
  return { ...root, hops: [hop], ...overrides }
}

export function fixtureHopOpen (fields, overrides = {}) {
  const routeScope = fields.routeScope || fixtureRouteScope(fields.route.previousRelayKey,
    fields.route, fields.clientRequestCommitment, fields.request)
  return {
    version: 1,
    route: fields.route,
    routeScope,
    previousDescriptorSequence: 9n,
    previousDescriptorHash: fixtureBytes(32, 0x22),
    circuitNonce: b4a.from(fields.request.circuitNonce),
    requestedWireClass: fields.request.requestedWireClass,
    circuitClass: fields.request.circuitClass,
    grantedInitialWindow: fields.grantedInitialWindow,
    maxDataBytes: fields.maxDataBytes,
    maxCircuitBytes: fields.maxCircuitBytes,
    idleMillis: fields.idleMillis,
    lifetimeMillis: fields.lifetimeMillis,
    clientRequestCommitment: b4a.from(fields.clientRequestCommitment),
    handshakeFlight1: fixtureBytes(32, 0x54),
    forwarderSignature: fixtureBytes(64, 0x55),
    ...overrides
  }
}

export function fixtureHopAccept (relayPublicKey, route, request, overrides = {}) {
  const limits = FORWARD_CIRCUIT_CLASS[request.circuitClass]
  const openedAtEpoch = 100
  return {
    version: 1,
    previousRelayKey: b4a.from(relayPublicKey),
    previousDescriptorSequence: 9n,
    previousDescriptorHash: fixtureBytes(32, 0x22),
    nextRelayKey: b4a.from(route.nextRelayKey),
    nextDescriptorSequence: route.nextDescriptorSequence,
    nextDescriptorHash: b4a.from(route.nextDescriptorHash),
    nextRelayBinding: fixtureRelayBinding(route.nextRelayKey, {
      descriptorSequence: route.nextDescriptorSequence,
      descriptorHash: b4a.from(route.nextDescriptorHash)
    }),
    routeId: b4a.from(route.routeId),
    circuitNonce: b4a.from(request.circuitNonce),
    nextStreamId: 91n,
    grantedWireClass: request.requestedWireClass,
    circuitClass: request.circuitClass,
    grantedInitialWindow: limits.grantedInitialWindow,
    maxDataBytes: STREAM_WIRE_CLASS[request.requestedWireClass],
    maxCircuitBytes: BigInt(limits.maxCircuitBytes),
    idleMillis: limits.idleMillis,
    lifetimeMillis: limits.lifetimeMillis,
    openedAtEpoch,
    hopOpenCommitment: fixtureBytes(32, 0x56),
    acceptedRouteScopeHash: fixtureBytes(32, 0x5a),
    acceptedRelayCount: 1,
    handshakeFlight2: fixtureBytes(96, 0x57),
    nextSignature: fixtureBytes(64, 0x58),
    ...overrides
  }
}

export function fixtureForwardResult (relayPublicKey, fields, overrides = {}) {
  const accept = fields.hopAccept
  return {
    version: 1,
    relayBinding: fixtureRelayBinding(relayPublicKey, {
      descriptorSequence: accept.previousDescriptorSequence,
      descriptorHash: b4a.from(accept.previousDescriptorHash)
    }),
    routeId: b4a.from(fields.request.routeId),
    nextDescriptorSequence: fields.request.nextDescriptorSequence,
    nextDescriptorHash: b4a.from(fields.request.nextDescriptorHash),
    circuitNonce: b4a.from(fields.request.circuitNonce),
    grantedWireClass: fields.request.requestedWireClass,
    circuitClass: fields.request.circuitClass,
    streamId: fields.callerStreamId,
    grantedInitialWindow: fields.grantedInitialWindow,
    maxDataBytes: fields.maxDataBytes,
    maxCircuitBytes: fields.maxCircuitBytes,
    idleMillis: fields.idleMillis,
    lifetimeMillis: fields.lifetimeMillis,
    openedAtEpoch: accept.openedAtEpoch,
    requestCommitment: b4a.from(fields.requestCommitment),
    acceptedRouteScopeHash: b4a.from(accept.acceptedRouteScopeHash),
    acceptedRelayCount: accept.acceptedRelayCount,
    nextHopAccept: accept,
    signature: fixtureBytes(64, 0x59),
    ...overrides
  }
}
