import b4a from 'b4a'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  BlindProtocolError,
  blindForwardHopOpenV1,
  blindForwardRouteScopeV1,
  decodeCanonical,
  encodeCanonical,
  forwardRouteScopeGenesisHash,
  forwardRouteScopeHopHash,
  forwardRouteScopeSignaturePayload
} from '@hiverelay/blind-protocol'

const ZERO_SCOPE_HASH = b4a.alloc(32)

export const FORWARD_PARENT_ORIGIN = Object.freeze({
  DIRECT: 'direct',
  FORWARDED: 'forwarded'
})

function fail (code, message) {
  throw new BlindProtocolError(code, message)
}

function fixed (value, length, field) {
  if (!value || typeof value.byteLength !== 'number') fail('BAD_ENCODING', `${field} must be bytes`)
  const output = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (output.byteLength !== length) fail('BAD_ENCODING', `${field} must be exactly ${length} bytes`)
  return output
}

function sameBytes (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

function isZero (value) {
  for (const byte of value) {
    if (byte !== 0) return false
  }
  return true
}

function epoch (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('BAD_ENCODING', `${field} is outside u32`)
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_ENCODING', `${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value >= (1n << 64n)) {
    fail('BAD_ENCODING', `${field} is outside u64`)
  }
  return value
}

function canonicalScope (value) {
  return decodeCanonical(blindForwardRouteScopeV1,
    encodeCanonical(blindForwardRouteScopeV1, value), { copyBytes: true })
}

function canonicalHopOpen (value) {
  return decodeCanonical(blindForwardHopOpenV1,
    encodeCanonical(blindForwardHopOpenV1, value), { copyBytes: true })
}

function lastScopeHash (scope) {
  return scope.hops[scope.hops.length - 1].scopeHash
}

function descriptorTuple (value, prefix = '') {
  if (!value || typeof value !== 'object') fail('TRANSPORT_UNSUPPORTED', `${prefix}descriptor context is absent`)
  return {
    descriptorSequence: u64(value.descriptorSequence, `${prefix}descriptorSequence`),
    descriptorHash: b4a.from(fixed(value.descriptorHash, 32, `${prefix}descriptorHash`))
  }
}

function copyScope (scope) {
  return canonicalScope(scope)
}

export function createDirectForwardParentContext () {
  return Object.freeze({
    origin: FORWARD_PARENT_ORIGIN.DIRECT,
    inheritedScopeHash: null,
    inheritedRelayCount: 0,
    routeScope: null
  })
}

export function createForwardedForwardParentContext (routeScope) {
  const scope = copyScope(routeScope)
  return Object.freeze({
    origin: FORWARD_PARENT_ORIGIN.FORWARDED,
    inheritedScopeHash: b4a.from(lastScopeHash(scope)),
    inheritedRelayCount: scope.hops.length,
    routeScope: scope
  })
}

export function normalizeForwardParentContext (value) {
  if (!value || typeof value !== 'object') {
    fail('TRANSPORT_UNSUPPORTED', 'FORWARD parent route context is absent')
  }
  if (value.origin === FORWARD_PARENT_ORIGIN.DIRECT) {
    if (value.inheritedRelayCount !== 0 ||
        (value.inheritedScopeHash != null && !isZero(fixed(value.inheritedScopeHash, 32, 'inheritedScopeHash'))) ||
        value.routeScope != null) {
      fail('CONFLICT', 'direct FORWARD parent context carries inherited route state')
    }
    return createDirectForwardParentContext()
  }
  if (value.origin !== FORWARD_PARENT_ORIGIN.FORWARDED) {
    fail('TRANSPORT_UNSUPPORTED', 'FORWARD parent origin is not supported')
  }
  const inheritedScopeHash = b4a.from(fixed(value.inheritedScopeHash, 32, 'inheritedScopeHash'))
  if (isZero(inheritedScopeHash)) fail('CONFLICT', 'forwarded FORWARD parent context has a zero scope hash')
  const scope = copyScope(value.routeScope)
  if (!Number.isSafeInteger(value.inheritedRelayCount) ||
      value.inheritedRelayCount !== scope.hops.length ||
      !sameBytes(inheritedScopeHash, lastScopeHash(scope))) {
    fail('CONFLICT', 'forwarded FORWARD parent context does not bind its complete route prefix')
  }
  return Object.freeze({
    origin: FORWARD_PARENT_ORIGIN.FORWARDED,
    inheritedScopeHash,
    inheritedRelayCount: value.inheritedRelayCount,
    routeScope: scope
  })
}

export async function verifyForwardRouteScope (routeScope, options = {}) {
  if (typeof options.verifySignature !== 'function') throw new TypeError('verifySignature hook is required')
  if (typeof options.verifyDescriptorBinding !== 'function') throw new TypeError('verifyDescriptorBinding hook is required')
  const nowEpoch = epoch(options.nowEpoch, 'nowEpoch')
  const scope = canonicalScope(routeScope)
  if (scope.expiresEpoch <= nowEpoch) fail('EXPIRED', 'FORWARD route scope is expired')

  const genesis = forwardRouteScopeGenesisHash(scope)
  const relayKeys = new Set()
  for (let index = 0; index < scope.hops.length; index++) {
    const hop = scope.hops[index]
    const relayKey = b4a.toString(hop.relayPublicKey, 'hex')
    if (relayKeys.has(relayKey)) fail('CONFLICT', 'FORWARD route scope contains a relay cycle')
    relayKeys.add(relayKey)
    const hashParent = index === 0 ? genesis : scope.hops[index - 1].scopeHash
    const expectedHash = forwardRouteScopeHopHash({
      previousScopeHash: hashParent,
      hopIndex: hop.hopIndex,
      relayPublicKey: hop.relayPublicKey,
      descriptorSequence: hop.descriptorSequence,
      descriptorHash: hop.descriptorHash
    })
    if (!sameBytes(expectedHash, hop.scopeHash)) {
      fail('CONFLICT', 'FORWARD route-scope prefix hash is invalid')
    }
    const descriptorVerified = await options.verifyDescriptorBinding({
      relayPublicKey: b4a.from(hop.relayPublicKey),
      descriptorSequence: hop.descriptorSequence,
      descriptorHash: b4a.from(hop.descriptorHash),
      hopIndex: index,
      routeScope: copyScope(scope),
      signal: options.signal
    })
    if (descriptorVerified !== true) fail('CONFLICT', 'FORWARD route-scope descriptor binding is invalid')
    const signatureVerified = await options.verifySignature({
      domainId: AUXILIARY_SIGNATURE_DOMAIN_ID.FORWARD_ROUTE_SCOPE,
      publicKey: b4a.from(hop.relayPublicKey),
      signature: b4a.from(hop.relaySignature),
      payload: forwardRouteScopeSignaturePayload(hop.scopeHash),
      scopeHash: b4a.from(hop.scopeHash),
      hopIndex: index,
      routeScope: copyScope(scope),
      signal: options.signal
    })
    if (signatureVerified !== true) fail('CONFLICT', 'FORWARD route-scope relay signature is invalid')
  }
  return scope
}

export async function extendForwardRouteScope (options = {}) {
  if (typeof options.sign !== 'function') throw new TypeError('sign hook is required')
  const relayPublicKey = b4a.from(fixed(options.relayPublicKey, 32, 'relayPublicKey'))
  const descriptor = descriptorTuple(options.descriptor, 'current ')
  let scope
  let hashParent
  let previousScopeHash
  if (options.routeScope == null) {
    scope = {
      version: 1,
      rootRouteId: b4a.from(fixed(options.rootRouteId, 16, 'rootRouteId')),
      rootCircuitNonce: b4a.from(fixed(options.rootCircuitNonce, 32, 'rootCircuitNonce')),
      rootRequestCommitment: b4a.from(fixed(options.rootRequestCommitment, 32, 'rootRequestCommitment')),
      maxRelayCount: options.maxRelayCount,
      expiresEpoch: epoch(options.expiresEpoch, 'expiresEpoch'),
      hops: []
    }
    if (!Number.isSafeInteger(scope.maxRelayCount) || scope.maxRelayCount < 2 || scope.maxRelayCount > 4) {
      fail('BAD_ENCODING', 'maxRelayCount is outside 2..4')
    }
    hashParent = forwardRouteScopeGenesisHash(scope)
    previousScopeHash = ZERO_SCOPE_HASH
  } else {
    scope = copyScope(options.routeScope)
    hashParent = lastScopeHash(scope)
    previousScopeHash = hashParent
  }
  if (scope.hops.length >= scope.maxRelayCount || scope.hops.length >= 4) {
    fail('TOO_LARGE', 'FORWARD route scope exceeds its relay-count bound')
  }
  if (scope.hops.some(hop => sameBytes(hop.relayPublicKey, relayPublicKey))) {
    fail('CONFLICT', 'FORWARD route scope repeats the current relay')
  }
  const hopIndex = scope.hops.length
  const scopeHash = forwardRouteScopeHopHash({
    previousScopeHash: hashParent,
    hopIndex,
    relayPublicKey,
    descriptorSequence: descriptor.descriptorSequence,
    descriptorHash: descriptor.descriptorHash
  })
  const relaySignature = b4a.from(fixed(await options.sign({
    domainId: AUXILIARY_SIGNATURE_DOMAIN_ID.FORWARD_ROUTE_SCOPE,
    publicKey: b4a.from(relayPublicKey),
    payload: forwardRouteScopeSignaturePayload(scopeHash),
    scopeHash: b4a.from(scopeHash),
    hopIndex,
    signal: options.signal
  }), 64, 'relaySignature'))
  scope.hops.push({
    hopIndex,
    relayPublicKey,
    descriptorSequence: descriptor.descriptorSequence,
    descriptorHash: descriptor.descriptorHash,
    previousScopeHash: b4a.from(previousScopeHash),
    scopeHash,
    relaySignature
  })
  return canonicalScope(scope)
}

export async function verifyForwardHopOpenRouteScope (rawHopOpen, options = {}) {
  const hopOpen = canonicalHopOpen(rawHopOpen)
  const receiverRelayPublicKey = fixed(options.receiverRelayPublicKey, 32, 'receiverRelayPublicKey')
  const receiverDescriptor = descriptorTuple(options.receiverDescriptor, 'receiver ')
  if (!sameBytes(hopOpen.route.nextRelayKey, receiverRelayPublicKey)) {
    fail('CONFLICT', 'FORWARD HopOpen route is addressed to another relay')
  }
  if (hopOpen.route.nextDescriptorSequence !== receiverDescriptor.descriptorSequence ||
      !sameBytes(hopOpen.route.nextDescriptorHash, receiverDescriptor.descriptorHash)) {
    fail('CONFLICT', 'FORWARD HopOpen route does not bind the receiving relay descriptor')
  }
  const routeScope = await verifyForwardRouteScope(hopOpen.routeScope, options)
  if (routeScope.maxRelayCount !== hopOpen.route.maxRelayCount) {
    fail('CONFLICT', 'FORWARD HopOpen changed the signed root relay-count bound')
  }
  if (hopOpen.route.expiresEpoch !== routeScope.expiresEpoch) {
    fail('CONFLICT', 'FORWARD HopOpen changed the signed root expiry')
  }
  const last = routeScope.hops[routeScope.hops.length - 1]
  if (!sameBytes(last.relayPublicKey, hopOpen.route.previousRelayKey) ||
      last.descriptorSequence !== hopOpen.previousDescriptorSequence ||
      !sameBytes(last.descriptorHash, hopOpen.previousDescriptorHash)) {
    fail('CONFLICT', 'FORWARD HopOpen route scope does not bind the adjacent forwarding relay')
  }
  if (routeScope.hops.some(hop => sameBytes(hop.relayPublicKey, receiverRelayPublicKey))) {
    fail('CONFLICT', 'FORWARD HopOpen would create a relay cycle')
  }
  return createForwardedForwardParentContext(routeScope)
}
