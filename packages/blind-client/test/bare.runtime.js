import b4a from 'b4a'
import test from 'brittle'
import { INBOX_FRAME_CLASS } from '@hiverelay/blind-protocol/registry'
import {
  createAppendInboxRequest,
  createCoreMirrorRequest,
  createForwardOpenRequest,
  createInboxReplica,
  ForwardClientCircuit,
  openCell,
  sealCell,
  verifyCapabilitySignature
} from '../index.js'
import { createBareCryptoRuntime } from '../runtime/bare.js'
import { decodeBlindExternalProfileValueV1 } from '../control.js'

test('Bare runtime produces the same mandatory AES-256-GCM cell profile', async t => {
  const runtime = createBareCryptoRuntime()
  const storageSlot = b4a.alloc(32, 17)
  const content = b4a.from('runtime-neutral opaque record')
  const sealed = await sealCell({ runtime, storageSlot, sizeClass: 1, structuredContent: content })
  t.is(sealed.cellBlob.byteLength, 4096)
  t.alike(await openCell({ runtime, storageSlot, sizeClass: 1, cellKey: sealed.cellKey, cellBlob: sealed.cellBlob }), content)
})

test('Bare runtime builds the native Core and Forward control compositions', async t => {
  const runtime = createBareCryptoRuntime()
  const relayPublicKey = b4a.alloc(32, 31)
  const admission = {
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32, 32),
    token: b4a.from([33])
  }
  const mirror = await createCoreMirrorRequest({
    runtime,
    relayPublicKey,
    corePublicKey: b4a.alloc(32, 34),
    fork: 0n,
    length: 1n,
    signedHeadHash: b4a.alloc(32, 35),
    leaseClass: 1,
    admission
  })
  const opened = await createForwardOpenRequest({
    runtime,
    previousRelayKey: relayPublicKey,
    routeId: b4a.alloc(16, 36),
    nextDescriptorSequence: 1n,
    nextDescriptorHash: b4a.alloc(32, 37),
    requestedWireClass: 1,
    circuitClass: 1,
    innerHandshake: b4a.alloc(32, 38),
    expectedInnerHandshakeBytes: 32,
    admission
  })
  const circuit = new ForwardClientCircuit({
    streamId: 1n,
    circuitNonce: opened.circuitNonce,
    grantedWireClass: 1,
    circuitClass: 1
  })
  t.is(mirror.requestBytes.byteLength > 0, true)
  t.is(opened.requestBytes.byteLength > 0, true)
  t.is(circuit.encodeData(b4a.alloc(64)).byteLength > 0, true)
})

test('Bare runtime creates the same canonical opaque signed-inbox composition', async t => {
  const runtime = createBareCryptoRuntime()
  const relayPublicKey = b4a.alloc(32, 27)
  const admission = {
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32, 28),
    token: b4a.from([29])
  }
  const created = await createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 500,
    frameClassBits: 1,
    retentionClass: 1,
    leaseClass: 1,
    admission
  })
  const append = await createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frameClass: 1,
    frame: b4a.alloc(INBOX_FRAME_CLASS[1], 30),
    admission
  })
  t.is(created.requestBytes.byteLength > 0, true)
  t.is(append.request.frame.byteLength, INBOX_FRAME_CLASS[1])
  t.ok(verifyCapabilitySignature(created.readCap.appendPublicKey, append.requestCommitment, append.request.appendSignature))
})

test('Bare runtime executes the closed external-profile decoder', t => {
  const readCap = b4a.concat([
    b4a.from([1]),
    b4a.alloc(32, 0x41),
    b4a.alloc(32, 0x42),
    b4a.alloc(32, 0x43),
    b4a.from([1, 1]),
    b4a.alloc(32, 0x44)
  ])
  const decoded = decodeBlindExternalProfileValueV1('ReadCellCapV1', readCap)
  t.is(decoded.sizeClass, 1)
  t.ok(Object.isFrozen(decoded))
  t.exception(() => decodeBlindExternalProfileValueV1('WriteCellCapV1', readCap), /closed inventory/)
})
