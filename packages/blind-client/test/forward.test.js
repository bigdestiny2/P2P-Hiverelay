import b4a from 'b4a'
import sodium from 'sodium-universal'
import test from 'brittle'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  FAMILY,
  FORWARD_CIRCUIT_CLASS,
  FORWARD_CLOSE_KIND,
  FRAME_KIND,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  STREAM_WIRE_CLASS
} from '@hiverelay/blind-protocol/registry'
import {
  auxiliarySignaturePayload,
  forwardOpenRequestCommitment,
  resultSignaturePayload
} from '@hiverelay/blind-protocol/hashes'
import {
  blindForwardDataV1,
  blindForwardHopAcceptV1,
  blindForwardOpenResultV1,
  blindForwardOpenV1,
  blindForwardWindowV1
} from '@hiverelay/blind-protocol/schemas'
import { decodeCanonical, encodeCanonical } from '@hiverelay/blind-protocol/codec'
import { decodeDispatchFrame, encodeDispatchFrame } from '@hiverelay/blind-protocol/dispatch'
import {
  BlindClientError,
  ForwardClientCircuit,
  createForwardOpenRequest
} from '../index.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'
import { verifiedEndpointContext, verifyOperationResult } from '../control.js'
import { verifiedEndpointFixture } from './endpoint-fixture.js'

const runtime = createNodeCryptoRuntime()
const previousRelayKey = b4a.alloc(32, 0x51)
const routeId = b4a.alloc(16, 0x52)
const nextDescriptorHash = b4a.alloc(32, 0x53)
const circuitNonce = b4a.alloc(32, 0x54)
const admission = {
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 0x55),
  token: b4a.from([0x56])
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey }
}

function signFinalField (encoding, value, domainId, secretKey, field, payload) {
  value[field] = b4a.alloc(64)
  const complete = encodeCanonical(encoding, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(value[field], payload(domainId, unsigned), secretKey)
  return value
}

function relayBinding (context) {
  return {
    version: 1,
    relayPublicKey: context.relayPublicKey,
    storeId: context.storeId,
    descriptorSequence: context.descriptorSequence,
    descriptorHash: context.descriptorHash,
    durabilityProfileId: context.durabilityProfileId,
    durabilityContinuityHash: context.durabilityContinuityHash,
    durabilityProfileHash: context.durabilityProfileHash,
    restoreEvidenceHeadSequence: context.restoreEvidenceHeadSequence,
    restoreEvidenceHeadHash: context.restoreEvidenceHeadHash,
    externalCommitWitness: null
  }
}

function circuit () {
  return new ForwardClientCircuit({
    streamId: 5n,
    circuitNonce,
    grantedWireClass: 1,
    circuitClass: 1,
    grantedInitialWindow: FORWARD_CIRCUIT_CLASS[1].grantedInitialWindow,
    maxDataBytes: STREAM_WIRE_CLASS[1],
    maxCircuitBytes: BigInt(FORWARD_CIRCUIT_CLASS[1].maxCircuitBytes)
  })
}

test('Forward OPEN selects only a signed route tuple and carries no open-proxy destination', async t => {
  const innerHandshake = b4a.alloc(32, 0x57)
  const created = await createForwardOpenRequest({
    runtime,
    previousRelayKey,
    routeId,
    nextDescriptorSequence: 8n,
    nextDescriptorHash,
    requestedWireClass: 1,
    circuitClass: 2,
    circuitNonce,
    innerHandshake,
    expectedInnerHandshakeBytes: 32,
    admission
  })
  const decoded = decodeCanonical(blindForwardOpenV1, created.requestBytes, { copyBytes: true })
  t.alike(created.requestCommitment, forwardOpenRequestCommitment({ previousRelayKey, ...decoded }))
  t.alike(created.circuitNonce, circuitNonce)
  t.is(created.wire.familyId, FAMILY.FORWARD)
  t.is(created.wire.operationId, OPERATION.FORWARD.OPEN)
  t.is(created.wire.requiresAuthenticatedStream, true)
  t.alike(decoded.parentRouteScopeHash, b4a.alloc(32))
  t.absent(decoded.hostname)
  t.absent(decoded.url)
  t.absent(decoded.destination)
  t.absent(decoded.app)
})

test('Forward OPEN validates transport shape before acquiring admission', async t => {
  let calls = 0
  await t.exception(createForwardOpenRequest({
    runtime,
    previousRelayKey,
    routeId,
    nextDescriptorSequence: 8n,
    nextDescriptorHash,
    requestedWireClass: 1,
    circuitClass: 1,
    innerHandshake: b4a.alloc(31),
    expectedInnerHandshakeBytes: 32,
    admissionProvider: async () => { calls++; return admission }
  }), /exactly 32 bytes|transport profile/)
  t.is(calls, 0)
})

test('Forward OPEN binds an inherited route-scope hash before admission', async t => {
  const parentRouteScopeHash = b4a.alloc(32, 0x58)
  let admissionContext = null
  const created = await createForwardOpenRequest({
    runtime,
    previousRelayKey,
    routeId,
    nextDescriptorSequence: 8n,
    nextDescriptorHash,
    requestedWireClass: 1,
    circuitClass: 1,
    circuitNonce,
    parentRouteScopeHash,
    innerHandshake: b4a.alloc(32, 0x59),
    admissionProvider: async context => {
      admissionContext = context
      return admission
    }
  })
  const decoded = decodeCanonical(blindForwardOpenV1, created.requestBytes, { copyBytes: true })
  t.alike(decoded.parentRouteScopeHash, parentRouteScopeHash)
  t.alike(admissionContext.parentRouteScopeHash, parentRouteScopeHash)
  t.alike(created.requestCommitment, forwardOpenRequestCommitment({ previousRelayKey, ...decoded }))
})

test('Forward OPEN result verifies both independently qualified relay bindings and signatures', async t => {
  const previousKeys = keyPair(0x58)
  const nextKeys = keyPair(0x59)
  const previousDescriptorHash = b4a.alloc(32, 0x5a)
  const rawEndpoint = {
    endpointId: 1,
    transportId: 1,
    envelopeClassBits: 0x007e,
    canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/describe')
  }
  const previousEndpoint = verifiedEndpointFixture(rawEndpoint, FAMILY.FORWARD, OPERATION.FORWARD.OPEN, {
    relayPublicKey: previousKeys.publicKey,
    descriptorSequence: 3n,
    descriptorHash: previousDescriptorHash,
    storeId: b4a.alloc(32, 0x5b)
  })
  const nextEndpoint = verifiedEndpointFixture(rawEndpoint, FAMILY.FORWARD, OPERATION.FORWARD.OPEN, {
    relayPublicKey: nextKeys.publicKey,
    descriptorSequence: 8n,
    descriptorHash: nextDescriptorHash,
    storeId: b4a.alloc(32, 0x5c)
  })
  const previousContext = verifiedEndpointContext(previousEndpoint)
  const nextContext = verifiedEndpointContext(nextEndpoint)
  const created = await createForwardOpenRequest({
    runtime,
    previousRelayKey: previousKeys.publicKey,
    routeId,
    nextDescriptorSequence: 8n,
    nextDescriptorHash,
    requestedWireClass: 1,
    circuitClass: 1,
    circuitNonce,
    innerHandshake: b4a.alloc(32, 0x5d),
    admission
  })
  const tuple = FORWARD_CIRCUIT_CLASS[1]
  const acceptedRouteScopeHash = b4a.alloc(32, 0x6a)
  const nextAccept = signFinalField(blindForwardHopAcceptV1, {
    version: 1,
    previousRelayKey: previousKeys.publicKey,
    previousDescriptorSequence: previousContext.descriptorSequence,
    previousDescriptorHash,
    nextRelayKey: nextKeys.publicKey,
    nextDescriptorSequence: nextContext.descriptorSequence,
    nextDescriptorHash,
    nextRelayBinding: relayBinding(nextContext),
    routeId,
    circuitNonce,
    nextStreamId: 9n,
    grantedWireClass: 1,
    circuitClass: 1,
    grantedInitialWindow: tuple.grantedInitialWindow,
    maxDataBytes: STREAM_WIRE_CLASS[1],
    maxCircuitBytes: BigInt(tuple.maxCircuitBytes),
    idleMillis: tuple.idleMillis,
    lifetimeMillis: tuple.lifetimeMillis,
    openedAtEpoch: 101,
    hopOpenCommitment: b4a.alloc(32, 0x5e),
    acceptedRouteScopeHash,
    acceptedRelayCount: 1,
    handshakeFlight2: b4a.alloc(96, 0x5f),
    nextSignature: b4a.alloc(64)
  }, AUXILIARY_SIGNATURE_DOMAIN_ID.FORWARD_HOP_ACCEPT,
  nextKeys.secretKey, 'nextSignature', auxiliarySignaturePayload)
  const result = {
    version: 1,
    relayBinding: relayBinding(previousContext),
    routeId,
    nextDescriptorSequence: 8n,
    nextDescriptorHash,
    circuitNonce,
    grantedWireClass: 1,
    circuitClass: 1,
    streamId: 5n,
    grantedInitialWindow: tuple.grantedInitialWindow,
    maxDataBytes: STREAM_WIRE_CLASS[1],
    maxCircuitBytes: BigInt(tuple.maxCircuitBytes),
    idleMillis: tuple.idleMillis,
    lifetimeMillis: tuple.lifetimeMillis,
    openedAtEpoch: 101,
    requestCommitment: created.requestCommitment,
    acceptedRouteScopeHash,
    acceptedRelayCount: 1,
    nextHopAccept: nextAccept,
    signature: b4a.alloc(64)
  }
  signFinalField(blindForwardOpenResultV1, result,
    RESULT_SIGNATURE_DOMAIN_ID.FORWARD_OPEN_RESULT,
    previousKeys.secretKey, 'signature', resultSignaturePayload)
  const resultBytes = encodeCanonical(blindForwardOpenResultV1, result)
  const verified = verifyOperationResult({
    endpoint: previousEndpoint,
    nextHopEndpoint: nextEndpoint,
    request: created.request,
    requestCommitment: created.requestCommitment,
    resultBytes,
    nextHopVerifier: () => true
  })
  t.alike(verified.snapshotBytes(), resultBytes)

  const forged = {
    ...result,
    nextHopAccept: { ...nextAccept, nextSignature: b4a.alloc(64, 0x60) },
    signature: b4a.alloc(64)
  }
  signFinalField(blindForwardOpenResultV1, forged,
    RESULT_SIGNATURE_DOMAIN_ID.FORWARD_OPEN_RESULT,
    previousKeys.secretKey, 'signature', resultSignaturePayload)
  t.exception(() => verifyOperationResult({
    endpoint: previousEndpoint,
    nextHopEndpoint: nextEndpoint,
    request: created.request,
    requestCommitment: created.requestCommitment,
    resultBytes: encodeCanonical(blindForwardOpenResultV1, forged),
    nextHopVerifier: () => true
  }), /next-hop accept signature is invalid/)
})

test('Forward circuit enforces flight, offset, sequence, credit and window flow end to end', t => {
  const left = circuit()
  const right = circuit()
  const flight3 = b4a.alloc(64, 0x61)
  const firstFrame = left.encodeData(flight3)
  const firstDispatch = decodeDispatchFrame(firstFrame, { copyBody: true })
  t.is(firstDispatch.frameKind, FRAME_KIND.STREAM)
  t.is(firstDispatch.operationId, OPERATION.FORWARD.DATA)
  t.is(firstDispatch.sequence, 0n)
  const receivedFlight = right.accept(firstFrame)
  t.is(receivedFlight.type, 'data')
  t.is(receivedFlight.offset, 0n)
  t.alike(receivedFlight.bytes, flight3)

  const initialWindow = right.encodeWindow(64n, 64)
  const granted = left.accept(initialWindow)
  t.is(granted.type, 'window')
  t.is(granted.consumedThrough, 64n)
  t.is(left.snapshot().sendCredit, BigInt(FORWARD_CIRCUIT_CLASS[1].grantedInitialWindow))

  const packet = b4a.alloc(STREAM_WIRE_CLASS[1], 0x62)
  const packetFrame = left.encodeData(packet)
  const receivedPacket = right.accept(packetFrame)
  t.is(receivedPacket.offset, 64n)
  t.alike(receivedPacket.bytes, packet)
  t.is(left.snapshot().sendSequence, 1n)
  t.is(right.snapshot().receiveSequence, 1n)

  const packetWindow = right.encodeWindow(64n + BigInt(packet.byteLength), packet.byteLength)
  left.accept(packetWindow)
  t.is(left.snapshot().sendCredit, BigInt(FORWARD_CIRCUIT_CLASS[1].grantedInitialWindow))

  const leftClose = left.encodeClose()
  const receivedLeftClose = right.accept(leftClose)
  t.is(receivedLeftClose.closeKind, FORWARD_CLOSE_KIND.FIN)
  t.is(receivedLeftClose.finalSendOffset, 64n + BigInt(packet.byteLength))
  const rightClose = right.encodeClose()
  left.accept(rightClose)
  t.is(left.snapshot().sendFinished, true)
  t.is(left.snapshot().receiveFinished, true)
  t.is(right.snapshot().sendFinished, true)
  t.is(right.snapshot().receiveFinished, true)
})

test('Forward circuit rejects wrong sizes before state mutation and replay closes the circuit', t => {
  const sender = circuit()
  t.exception(() => sender.encodeData(b4a.alloc(63)), /exactly 64 bytes/)
  t.is(sender.snapshot().sendSequence, -1n)
  t.is(sender.snapshot().sendOffset, 0n)
  const first = sender.encodeData(b4a.alloc(64))
  t.exception(() => sender.encodeData(b4a.alloc(STREAM_WIRE_CLASS[1] - 1)), /exactly 4096 bytes/)
  t.is(sender.snapshot().sendSequence, 0n)

  const receiver = circuit()
  receiver.accept(first)
  t.exception(() => receiver.accept(first), /sequence is invalid/)
  t.is(receiver.snapshot().aborted, true)
  t.exception(() => receiver.encodeClose(), /aborted/)
})

test('Forward circuit rejects gaps, nonce substitution and excess credit as terminal violations', t => {
  const wrongOffset = circuit()
  const offsetBody = encodeCanonical(blindForwardDataV1, {
    version: 1,
    circuitNonce,
    offset: 1n,
    bytes: b4a.alloc(64)
  })
  const offsetFrame = encodeDispatchFrame({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: b4a.alloc(16),
    streamId: 5n,
    sequence: 0n,
    body: offsetBody
  })
  t.exception(() => wrongOffset.accept(offsetFrame), /not contiguous/)
  t.is(wrongOffset.snapshot().aborted, true)

  const wrongNonce = circuit()
  const nonceBody = encodeCanonical(blindForwardDataV1, {
    version: 1,
    circuitNonce: b4a.alloc(32, 0x77),
    offset: 0n,
    bytes: b4a.alloc(64)
  })
  const nonceFrame = encodeDispatchFrame({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: b4a.alloc(16),
    streamId: 5n,
    sequence: 0n,
    body: nonceBody
  })
  t.exception(() => wrongNonce.accept(nonceFrame), /nonce does not match/)

  const excess = circuit()
  excess.encodeData(b4a.alloc(64))
  const windowBody = encodeCanonical(blindForwardWindowV1, {
    version: 1,
    circuitNonce,
    consumedThrough: 64n,
    creditIncrement: 1024 * 1024
  })
  const windowFrame = encodeDispatchFrame({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.WINDOW,
    requestId: b4a.alloc(16),
    streamId: 5n,
    sequence: 0n,
    body: windowBody
  })
  t.exception(() => excess.accept(windowFrame), /consumed bytes/)
})

test('Forward circuit accepts descriptor genesis zero and rejects a first-frame sequence gap', async t => {
  const created = await createForwardOpenRequest({
    runtime,
    previousRelayKey,
    routeId,
    nextDescriptorSequence: 0n,
    nextDescriptorHash,
    requestedWireClass: 1,
    circuitClass: 1,
    circuitNonce,
    innerHandshake: b4a.alloc(32, 0x58),
    admission
  })
  t.is(created.request.nextDescriptorSequence, 0n)

  const receiver = circuit()
  const body = encodeCanonical(blindForwardDataV1, {
    version: 1,
    circuitNonce,
    offset: 0n,
    bytes: b4a.alloc(64)
  })
  const gap = encodeDispatchFrame({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: b4a.alloc(16),
    streamId: 5n,
    sequence: 1n,
    body
  })
  t.exception(() => receiver.accept(gap), /sequence is invalid/)
})

test('Forward circuit constructor rejects class tuple drift', t => {
  t.exception(() => new ForwardClientCircuit({
    streamId: 5n,
    circuitNonce,
    grantedWireClass: 1,
    circuitClass: 1,
    grantedInitialWindow: 1
  }), BlindClientError)
})
