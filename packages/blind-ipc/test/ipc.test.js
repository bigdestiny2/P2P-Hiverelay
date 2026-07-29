import test from 'brittle'
import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  FAMILY,
  OUTER_CLASS,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT
} from '@hiverelay/blind-protocol'
import {
  LOCAL_ABORT_CODE,
  LOCAL_BROKER_ERROR,
  LOCAL_CIPHERTEXT_PHASE,
  LOCAL_DISPATCH_ADJACENT_HEADER_BYTES,
  LOCAL_DISPATCH_BASE_HEADER_BYTES,
  LOCAL_READY_ACK_BODY_BYTES,
  LOCAL_READY_PROBE_BODY_BYTES,
  LOCAL_RESPONSE_KIND,
  LOCAL_STREAM_CONTEXT_KIND,
  LOCAL_STREAM_CONTROL_KIND,
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LOCAL_STREAM_MODE,
  LOCAL_STREAM_OPEN_KIND,
  LocalLengthPrefixedReassembler,
  LocalStreamSequenceGuard,
  OneUseLocalStreamTickets,
  PRIVATE_IPC_LIMITS,
  PRIVATE_IPC_STATUS,
  createLocalAuthenticatedChannelContext,
  decodeLocalAuthenticatedChannelContext,
  decodeLocalReadyAckBody,
  decodeLocalReadyProbeBody,
  decodeLocalRequest,
  decodeLocalResponse,
  decodeLocalStreamAttachContext,
  decodeLocalStreamControl,
  decodeLocalStreamFrame,
  decodeLocalStreamOpen,
  encodeLocalReadyAck,
  encodeLocalReadyAckBody,
  encodeLocalReadyProbe,
  encodeLocalReadyProbeBody,
  encodeLocalRequest,
  encodeLocalResponse,
  encodeLocalStreamAttachContext,
  encodeLocalStreamControl,
  encodeLocalStreamFrame,
  encodeLocalStreamOpen,
  fragmentLocalContent,
  localAuthenticatedChannelAuthority,
  localRequestFrameLength,
  localResponseFrameLength,
  localStreamAttachmentAuthority,
  validateLocalStreamFrameForOpen,
  verifyLocalAuthenticatedChannelContext
} from '../index.js'

const fixed = (length, byte) => b4a.alloc(length, byte)

function publicOpen (overrides = {}) {
  return {
    openKind: LOCAL_STREAM_OPEN_KIND.PUBLIC_CONTENT_CHANNEL,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
    endpointId: 2,
    streamMode: LOCAL_STREAM_MODE.DISPATCH_CONTENT,
    channelClass: 3,
    acceptedMonotonicMillis: 2_000n,
    openDeadlineMonotonicMillis: 17_000n,
    ...overrides
  }
}

function channelContextInput () {
  return {
    launchTopologyHash: fixed(32, 0x61),
    edgeProcessNonce: fixed(32, 0x62),
    localChannelNonce: fixed(32, 0x63),
    transportProfileHash: fixed(32, 0x64),
    finalNoiseHandshakeHash: fixed(64, 0x65)
  }
}

function attachValue (overrides = {}) {
  return {
    ticket: fixed(32, 0x71),
    parentSessionId: fixed(32, 0x72),
    descriptorSequence: 9n,
    descriptorHash: fixed(32, 0x73),
    bindingHash: fixed(32, 0x74),
    ...overrides
  }
}

test('private IPC unary dispatch carries explicit one-hot transport support', t => {
  const body = fixed(OUTER_CLASS[1], 0x11)
  const encoded = encodeLocalRequest({
    family: FAMILY.CELL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 7,
    outerClass: 1,
    acceptedMonotonicMillis: 1_000n,
    absoluteDeadlineMonotonicMillis: 16_000n,
    body
  })
  t.is(encoded.byteLength, LOCAL_DISPATCH_BASE_HEADER_BYTES + body.byteLength)
  t.is(b4a.readUInt32BE(encoded, 0), encoded.byteLength - 4)
  t.is(localRequestFrameLength(encoded.subarray(0, 3)), null)
  t.is(localRequestFrameLength(encoded), encoded.byteLength)
  const decoded = decodeLocalRequest(encoded)
  t.is(decoded.transportId, TRANSPORT_ID.HTTPS_DIRECT)
  t.is(decoded.transportSupportBit, TRANSPORT_SUPPORT.DIRECT_HTTP)
  t.is(decoded.endpointId, 7)
  t.is(decoded.acceptedMonotonicMillis, 1_000n)
  t.is(decoded.absoluteDeadlineMonotonicMillis, 16_000n)
  t.is(decoded.adjacentRelayKey, null)
  t.ok(b4a.equals(decoded.externalCanonicalBytes, body))
  t.alike(Object.keys(decoded).sort(), [
    'absoluteDeadlineMonotonicMillis',
    'acceptedMonotonicMillis',
    'adjacentRelayKey',
    'endpointId',
    'externalCanonicalBytes',
    'family',
    'outerClass',
    'transportId',
    'transportSupportBit',
    'version'
  ])

  const base = {
    family: FAMILY.DESCRIBE,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    endpointId: 1,
    outerClass: 1,
    acceptedMonotonicMillis: 1_000n,
    absoluteDeadlineMonotonicMillis: 16_000n,
    body
  }
  t.exception(() => encodeLocalRequest(base), /explicit registered one-hot bit/)
  t.exception(() => encodeLocalRequest({
    ...base,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE
  }), /one-hot bit/)
  t.exception(() => encodeLocalRequest({ ...base, transportSupportBit: 0x8000 }), /registered one-hot bit/)
})

test('private IPC unary dispatch binds adjacent relay keys and rejects shape drift', t => {
  const body = fixed(OUTER_CLASS[1], 0x22)
  const adjacentRelayKey = fixed(32, 0x33)
  const base = {
    family: FAMILY.FORWARD,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
    endpointId: 1,
    outerClass: 1,
    acceptedMonotonicMillis: 1_000n,
    absoluteDeadlineMonotonicMillis: 16_000n,
    body
  }
  const encoded = encodeLocalRequest({ ...base, adjacentRelayKey })
  t.is(encoded.byteLength, LOCAL_DISPATCH_ADJACENT_HEADER_BYTES + body.byteLength)
  t.ok(b4a.equals(decodeLocalRequest(encoded).adjacentRelayKey, adjacentRelayKey))
  t.exception(() => encodeLocalRequest({ ...base, adjacentRelayKey: b4a.alloc(31) }), /exactly 32/)
  t.exception(() => encodeLocalRequest({ ...base, adjacentRelayKey: b4a.alloc(32) }), /must be nonzero/)
  t.exception(() => encodeLocalRequest({ ...base, family: 99 }), /family is not registered/)
  t.exception(() => encodeLocalRequest({ ...base, transportId: 99 }), /transportId is not registered/)
  t.exception(() => encodeLocalRequest({ ...base, endpointId: 0 }), /outside 1..255/)
  t.exception(() => encodeLocalRequest({ ...base, outerClass: 2 }), /does not match outerClass/)
  t.exception(() => decodeLocalRequest(encoded.subarray(0, encoded.length - 1)), /truncated|length mismatch/)
  t.exception(() => decodeLocalRequest(b4a.concat([encoded, b4a.from([0])])), /trailing bytes/)

  const badPresence = b4a.from(encoded)
  badPresence[27] = 2
  t.exception(() => decodeLocalRequest(badPresence), /presence tag/)
  const badSupport = b4a.from(encoded)
  badSupport[7] = 0
  badSupport[8] = 0
  t.exception(() => decodeLocalRequest(badSupport), /control tuple/)
  const badVersion = b4a.from(encoded)
  badVersion[4] = 2
  t.is(localRequestFrameLength(badVersion.subarray(0, 9)), null)
  t.exception(() => localRequestFrameLength(badVersion.subarray(0, LOCAL_DISPATCH_ADJACENT_HEADER_BYTES)), /version must be 1/)
})

test('private IPC unary response and readiness variants remain exact and bounded', t => {
  const body = fixed(OUTER_CLASS[1], 0x44)
  const response = encodeLocalResponse(body)
  t.is(localResponseFrameLength(response.subarray(0, 3)), null)
  t.is(localResponseFrameLength(response), response.byteLength)
  t.ok(b4a.equals(decodeLocalResponse(response).externalCanonicalBytes, body))
  t.exception(() => decodeLocalResponse(response.subarray(0, response.length - 1)), /truncated|length mismatch/)
  t.exception(() => decodeLocalResponse(b4a.concat([response, b4a.from([0])])), /trailing bytes/)

  for (const localBrokerError of Object.values(LOCAL_BROKER_ERROR)) {
    const encoded = encodeLocalResponse({ responseKind: LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR, localBrokerError })
    const decoded = decodeLocalResponse(encoded)
    t.is(decoded.responseKind, LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR)
    t.is(decoded.localBrokerError, localBrokerError)
    t.is(decoded.externalCanonicalBytes.byteLength, 0)
  }
  t.exception(() => encodeLocalResponse({
    responseKind: LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR,
    localBrokerError: 7
  }), /not registered/)

  const edgeInstanceNonce = fixed(32, 0x51)
  const launchTopologyHash = fixed(32, 0x52)
  const descriptorHash = fixed(32, 0x53)
  const acceptedMonotonicMillis = 50_000n
  const probe = encodeLocalReadyProbe({
    endpointId: 7,
    acceptedMonotonicMillis,
    edgeInstanceNonce,
    launchTopologyHash
  })
  t.is(probe.byteLength, LOCAL_DISPATCH_BASE_HEADER_BYTES + LOCAL_READY_PROBE_BODY_BYTES)
  const decodedProbe = decodeLocalRequest(probe, { copyBody: true })
  t.is(decodedProbe.transportId, 0)
  t.is(decodedProbe.transportSupportBit, 0)
  t.is(decodedProbe.outerClass, 0)
  t.alike(decodedProbe.readyProbe, { controlKind: 1, edgeInstanceNonce, launchTopologyHash })
  t.alike(decodeLocalReadyProbeBody(encodeLocalReadyProbeBody({ edgeInstanceNonce, launchTopologyHash })), decodedProbe.readyProbe)

  const ackValue = {
    edgeInstanceNonce,
    launchTopologyHash,
    endpointId: 7,
    descriptorSequence: 11n,
    descriptorHash,
    readyRoleBits: 0x21,
    readyOperationBits: 0x00000007,
    expiresMonotonicMillis: acceptedMonotonicMillis + 4_000n
  }
  const ack = encodeLocalReadyAck(ackValue)
  t.is(ack.byteLength, 11 + LOCAL_READY_ACK_BODY_BYTES)
  t.alike(decodeLocalResponse(ack, { copyBody: true }).readyAck, { controlKind: 1, ...ackValue })
  t.alike(decodeLocalReadyAckBody(encodeLocalReadyAckBody(ackValue)), { controlKind: 1, ...ackValue })
})

test('private IPC readiness cannot be substituted for an external dispatch', t => {
  const edgeInstanceNonce = fixed(32, 0x51)
  const launchTopologyHash = fixed(32, 0x52)
  const base = {
    family: FAMILY.DESCRIBE,
    transportId: 0,
    transportSupportBit: 0,
    endpointId: 1,
    outerClass: 0,
    acceptedMonotonicMillis: 1_000n,
    absoluteDeadlineMonotonicMillis: 3_000n,
    body: encodeLocalReadyProbeBody({ edgeInstanceNonce, launchTopologyHash })
  }
  t.exception(() => encodeLocalRequest({ ...base, family: FAMILY.CELL }), /control tuple/)
  t.exception(() => encodeLocalRequest({
    ...base,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  }), /control tuple/)
  t.exception(() => encodeLocalRequest({ ...base, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP }), /control tuple/)
  t.exception(() => encodeLocalRequest({ ...base, outerClass: 1 }), /control tuple/)
  t.exception(() => encodeLocalRequest({ ...base, absoluteDeadlineMonotonicMillis: 3_001n }), /exactly two seconds/)
  t.exception(() => encodeLocalRequest({ ...base, adjacentRelayKey: b4a.alloc(32, 1) }), /control tuple/)
  t.exception(() => encodeLocalRequest({ ...base, body: b4a.alloc(65) }), /control shape/)
  t.exception(() => encodeLocalReadyProbe({
    endpointId: 1,
    acceptedMonotonicMillis: (1n << 64n) - 1n,
    edgeInstanceNonce,
    launchTopologyHash
  }), /overflows/)
})

test('private IPC decoders snapshot caller-owned bytes before returning validated fields', t => {
  const body = fixed(OUTER_CLASS[1], 0x58)
  const requestBytes = encodeLocalRequest({
    family: FAMILY.CELL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 1,
    outerClass: 1,
    acceptedMonotonicMillis: 1_000n,
    absoluteDeadlineMonotonicMillis: 16_000n,
    body
  })
  const request = decodeLocalRequest(requestBytes)
  requestBytes[LOCAL_DISPATCH_BASE_HEADER_BYTES] ^= 0xff
  t.is(request.externalCanonicalBytes[0], 0x58)

  const responseBytes = encodeLocalResponse(body)
  const response = decodeLocalResponse(responseBytes)
  responseBytes[PRIVATE_IPC_LIMITS.UNARY_RESPONSE_HEADER_BYTES] ^= 0xff
  t.is(response.externalCanonicalBytes[0], 0x58)

  const openInput = publicOpen()
  const context = createLocalAuthenticatedChannelContext(channelContextInput(), openInput)
  const openBytes = encodeLocalStreamOpen({ ...openInput, context })
  const open = decodeLocalStreamOpen(openBytes)
  openBytes[PRIVATE_IPC_LIMITS.STREAM_OPEN_BASE_HEADER_BYTES] ^= 0xff
  t.is(open.contextBytes[0], 1)

  const frameBytes = encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    sequence: 0n,
    wireClass: 1,
    body: b4a.from([0x59])
  })
  const frame = decodeLocalStreamFrame(frameBytes)
  frameBytes[PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES] ^= 0xff
  t.is(frame.bytes[0], 0x59)

  let bodyReads = 0
  const accessorInput = {
    family: FAMILY.CELL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 1,
    outerClass: 1,
    acceptedMonotonicMillis: 1_000n,
    absoluteDeadlineMonotonicMillis: 16_000n,
    get body () { bodyReads++; return body }
  }
  encodeLocalRequest(accessorInput)
  t.is(bodyReads, 1)
})

test('authenticated stream-open context is canonical and authority is branded', t => {
  const openInput = publicOpen()
  const channelInput = channelContextInput()
  const contextBytes = createLocalAuthenticatedChannelContext(channelInput, openInput)
  t.is(contextBytes.byteLength, PRIVATE_IPC_LIMITS.AUTHENTICATED_CHANNEL_CONTEXT_BYTES)
  const context = decodeLocalAuthenticatedChannelContext(contextBytes)
  const encoded = encodeLocalStreamOpen({ ...openInput, context: contextBytes })
  t.is(encoded.byteLength, PRIVATE_IPC_LIMITS.STREAM_OPEN_BASE_HEADER_BYTES + contextBytes.byteLength)
  const open = decodeLocalStreamOpen(encoded, { copyContext: true })
  t.is(open.contextKind, LOCAL_STREAM_CONTEXT_KIND.AUTHENTICATED_CHANNEL)
  t.is(open.transportSupportBit, TRANSPORT_SUPPORT.DIRECT_NATIVE)
  t.ok(b4a.equals(open.contextBytes, contextBytes))

  const handle = verifyLocalAuthenticatedChannelContext(open.contextBytes, open, {
    launchTopologyHash: channelInput.launchTopologyHash,
    transportProfileHash: channelInput.transportProfileHash
  })
  const authority = localAuthenticatedChannelAuthority(handle)
  t.is(authority.endpointId, open.endpointId)
  t.is(authority.transportId, open.transportId)
  t.is(authority.transportSupportBit, open.transportSupportBit)
  t.ok(b4a.equals(authority.parentSessionId, context.parentSessionId))
  t.exception(() => localAuthenticatedChannelAuthority(open.contextBytes), /verified branded handle/)
  t.exception(() => localAuthenticatedChannelAuthority(context), /verified branded handle/)

  const changed = b4a.from(contextBytes)
  changed[224] ^= 1
  t.exception(() => verifyLocalAuthenticatedChannelContext(changed, openInput, {
    launchTopologyHash: channelInput.launchTopologyHash,
    transportProfileHash: channelInput.transportProfileHash
  }), /binding MAC/)
  t.exception(() => verifyLocalAuthenticatedChannelContext(contextBytes, {
    ...openInput,
    endpointId: 3
  }, {
    launchTopologyHash: channelInput.launchTopologyHash,
    transportProfileHash: channelInput.transportProfileHash
  }), /binding MAC/)
  t.exception(() => verifyLocalAuthenticatedChannelContext(contextBytes, openInput, {
    launchTopologyHash: channelInput.launchTopologyHash
  }), /expected transportProfileHash/)
})

test('stream-open kind, mode, class, adjacent key and context form a closed table', t => {
  const attachContext = encodeLocalStreamAttachContext(attachValue())
  t.is(attachContext.byteLength, PRIVATE_IPC_LIMITS.ATTACH_CONTEXT_BYTES)
  t.alike(decodeLocalStreamAttachContext(attachContext).descriptorSequence, 9n)

  const egress = {
    openKind: LOCAL_STREAM_OPEN_KIND.AUTHORIZED_EGRESS_CHANNEL,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
    endpointId: 3,
    streamMode: LOCAL_STREAM_MODE.FORWARD_HOP_CONTENT,
    channelClass: 3,
    acceptedMonotonicMillis: 2_000n,
    openDeadlineMonotonicMillis: 17_000n,
    adjacentRelayKey: fixed(32, 0x75),
    context: attachContext
  }
  const encodedEgress = encodeLocalStreamOpen(egress)
  t.is(encodedEgress.byteLength, PRIVATE_IPC_LIMITS.STREAM_OPEN_ADJACENT_HEADER_BYTES + attachContext.byteLength)
  t.is(decodeLocalStreamOpen(encodedEgress).contextKind, LOCAL_STREAM_CONTEXT_KIND.ONE_USE_ATTACH)

  const coreRaw = encodeLocalStreamOpen({
    openKind: LOCAL_STREAM_OPEN_KIND.CORE_RAW_CHILD,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
    endpointId: 2,
    streamMode: LOCAL_STREAM_MODE.CORE_RAW,
    channelClass: 0,
    acceptedMonotonicMillis: 2_000n,
    openDeadlineMonotonicMillis: 17_000n,
    context: attachContext
  })
  t.is(decodeLocalStreamOpen(coreRaw).channelClass, 0)

  t.exception(() => encodeLocalStreamOpen({ ...egress, adjacentRelayKey: null }), /requires an adjacent/)
  t.exception(() => encodeLocalStreamOpen({ ...egress, streamMode: LOCAL_STREAM_MODE.CORE_RAW }), /combination is not registered/)
  t.exception(() => encodeLocalStreamOpen({ ...egress, channelClass: 0 }), /combination is not registered/)
  t.exception(() => encodeLocalStreamOpen({ ...egress, transportSupportBit: 3 }), /one-hot bit/)
  t.exception(() => encodeLocalStreamOpen({ ...egress, openDeadlineMonotonicMillis: 17_001n }), /15000 ms cap/)
  t.exception(() => encodeLocalStreamOpen({
    ...publicOpen(),
    context: attachContext
  }), /context length/)
  t.exception(() => encodeLocalStreamOpen({
    ...publicOpen(),
    context: createLocalAuthenticatedChannelContext(channelContextInput(), publicOpen()),
    adjacentRelayKey: b4a.alloc(32)
  }), /nonzero|binding/)
})

test('child stream tickets are short-lived, bound, one-use and return branded authority', t => {
  let now = 1_000n
  let ticketByte = 1
  const tickets = new OneUseLocalStreamTickets({
    monotonicMillis: () => now,
    randomBytes: length => fixed(length, ticketByte++),
    ttlMillis: 2_000,
    maxTickets: 4
  })
  const value = attachValue({ ticket: undefined })
  const wrong = tickets.issue(value)
  t.is(tickets.size, 1)
  t.exception(() => tickets.consume(wrong.context, { descriptorHash: fixed(32, 0x7f) }), /does not match/)
  t.is(tickets.size, 0)
  t.exception(() => tickets.consume(wrong.context), /unknown or already consumed/)

  const issued = tickets.issue(value)
  const handle = tickets.consume(issued.context, {
    parentSessionId: value.parentSessionId,
    descriptorSequence: value.descriptorSequence,
    descriptorHash: value.descriptorHash,
    bindingHash: value.bindingHash
  })
  const authority = localStreamAttachmentAuthority(handle)
  t.is(authority.descriptorSequence, value.descriptorSequence)
  t.ok(b4a.equals(authority.bindingHash, value.bindingHash))
  t.exception(() => localStreamAttachmentAuthority(issued.context), /consumed branded handle/)
  t.exception(() => tickets.consume(issued.context), /unknown or already consumed/)

  const expired = tickets.issue(value)
  now += 2_001n
  t.exception(() => tickets.consume(expired.context), /expired or bound/)
  t.is(tickets.size, 0)

  const overflow = new OneUseLocalStreamTickets({
    monotonicMillis: () => (1n << 64n) - 1n,
    randomBytes: length => fixed(length, 0xa1)
  })
  t.exception(() => overflow.issue(value), /expiry overflows u64/)
  t.is(overflow.size, 0)
})

test('CONTENT fragmentation uses variable frames, exact physical sequences and bounded reassembly', t => {
  const canonical = fixed(65_624, 0x31)
  b4a.writeUInt32BE(canonical, canonical.byteLength - 4, 0)
  const encodedFrames = fragmentLocalContent(canonical, {
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    wireClass: 3,
    sequence: 0n,
    fin: true
  })
  t.is(encodedFrames.length, 2)
  const frames = encodedFrames.map(frame => decodeLocalStreamFrame(frame))
  t.is(frames[0].bytes.byteLength, 65_512)
  t.is(frames[1].bytes.byteLength, 112)
  t.is(frames[0].sequence, 0n)
  t.is(frames[1].sequence, 1n)
  t.is(frames[0].flags, 0)
  t.is(frames[1].flags, LOCAL_STREAM_FLAG.FIN)

  const open = publicOpen()
  const guard = new LocalStreamSequenceGuard(open)
  guard.accept(frames[0])
  guard.accept(frames[1])
  const daemonFrame = decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    sequence: 0n,
    wireClass: 3,
    flags: 0,
    body: b4a.from([0])
  }))
  guard.accept(daemonFrame)
  t.exception(() => guard.accept({
    ...daemonFrame,
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    sequence: 2n
  }), /after FIN/)
  const repeated = new LocalStreamSequenceGuard(open)
  repeated.accept(frames[0])
  t.exception(() => repeated.accept(frames[0]), /first-zero exact \+1/)

  const reassembler = new LocalLengthPrefixedReassembler()
  t.alike(reassembler.push(frames[0]), [])
  const complete = reassembler.push(frames[1])
  t.is(complete.length, 1)
  t.ok(b4a.equals(complete[0], canonical))
  t.is(reassembler.bufferedBytes, 0)

  const incomplete = new LocalLengthPrefixedReassembler({ maxItemBytes: 100 })
  const prefix = b4a.alloc(10)
  b4a.writeUInt32BE(prefix, 20, 0)
  t.exception(() => incomplete.push({
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    wireClass: 1,
    flags: LOCAL_STREAM_FLAG.FIN,
    bytes: prefix
  }), /incomplete canonical item/)
  const oversize = new LocalLengthPrefixedReassembler({ maxItemBytes: 100 })
  const oversizedPrefix = b4a.alloc(4)
  b4a.writeUInt32BE(oversizedPrefix, 97, 0)
  t.exception(() => oversize.push({
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    wireClass: 1,
    flags: 0,
    bytes: oversizedPrefix
  }), /canonical cap/)
  const bounded = new LocalLengthPrefixedReassembler({ maxItemBytes: 100, maxBufferedBytes: 100 })
  t.exception(() => bounded.push({
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    wireClass: 1,
    flags: 0,
    bytes: b4a.alloc(101)
  }), /bounded buffer/)
  const first = b4a.alloc(8, 0x41)
  const second = b4a.alloc(12, 0x42)
  b4a.writeUInt32BE(first, first.byteLength - 4, 0)
  b4a.writeUInt32BE(second, second.byteLength - 4, 0)
  const multiple = new LocalLengthPrefixedReassembler({ maxItemBytes: 100, wireClass: 1 })
  const multipleItems = multiple.push({
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    wireClass: 1,
    flags: LOCAL_STREAM_FLAG.FIN,
    bytes: b4a.concat([first, second])
  })
  t.is(multipleItems.length, 2)
  t.ok(b4a.equals(multipleItems[0], first))
  t.ok(b4a.equals(multipleItems[1], second))
  t.is(DISPATCH_LIMITS.MAX_WIRE_BYTES > canonical.byteLength, true)
})

test('CONTENT fragmentation and reassembly reach the exact maximum canonical dispatch cap', t => {
  const canonical = fixed(DISPATCH_LIMITS.MAX_WIRE_BYTES, 0x35)
  b4a.writeUInt32BE(canonical, canonical.byteLength - 4, 0)
  const encodedFrames = fragmentLocalContent(canonical, {
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    wireClass: 3,
    fin: true
  })
  t.is(encodedFrames.length, Math.ceil(canonical.byteLength / 65_512))
  const reassembler = new LocalLengthPrefixedReassembler({ wireClass: 3 })
  const complete = []
  for (const encoded of encodedFrames) {
    complete.push(...reassembler.push(decodeLocalStreamFrame(encoded)))
  }
  t.is(complete.length, 1)
  t.ok(b4a.equals(complete[0], canonical))
  t.is(reassembler.bufferedBytes, 0)
})

test('stream frame kinds have exact class, phase, FIN and generic-abort shapes', t => {
  const contentCap = STREAM_WIRE_CLASS[1] - PRIVATE_IPC_LIMITS.STREAM_CONTENT_OVERHEAD_BYTES
  const content = decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    sequence: 0n,
    wireClass: 1,
    flags: LOCAL_STREAM_FLAG.FIN,
    body: fixed(contentCap, 0x41)
  }))
  t.is(content.bytes.byteLength, 4_073)
  t.exception(() => encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    sequence: 0n,
    wireClass: 1,
    body: b4a.alloc(contentCap + 1)
  }), /content cap/)
  t.exception(() => fragmentLocalContent(b4a.alloc(0), {
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    wireClass: 1,
    fin: false
  }), /requires FIN/)

  for (const [phase, length] of [
    [LOCAL_CIPHERTEXT_PHASE.FLIGHT_1, 32],
    [LOCAL_CIPHERTEXT_PHASE.FLIGHT_2, 96],
    [LOCAL_CIPHERTEXT_PHASE.FLIGHT_3, 64]
  ]) {
    const frame = encodeLocalStreamFrame({
      direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
      frameKind: LOCAL_STREAM_FRAME_KIND.CIPHERTEXT,
      sequence: BigInt(phase - 1),
      wireClass: 0,
      body: fixed(length, phase)
    }, { ciphertextPhase: phase })
    t.is(decodeLocalStreamFrame(frame, { ciphertextPhase: phase }).bytes.byteLength, length)
    t.exception(() => encodeLocalStreamFrame({
      direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
      frameKind: LOCAL_STREAM_FRAME_KIND.CIPHERTEXT,
      sequence: 0n,
      wireClass: 0,
      body: b4a.alloc(length - 1)
    }, { ciphertextPhase: phase }), /handshake frame length/)
  }
  t.is(decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CIPHERTEXT,
    sequence: 3n,
    wireClass: 1,
    body: b4a.alloc(STREAM_WIRE_CLASS[1])
  }, { ciphertextPhase: LOCAL_CIPHERTEXT_PHASE.TRANSPORT }), {
    ciphertextPhase: LOCAL_CIPHERTEXT_PHASE.TRANSPORT
  }).wireClass, 1)
  t.exception(() => encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CIPHERTEXT,
    sequence: 0n,
    wireClass: 1,
    flags: LOCAL_STREAM_FLAG.FIN,
    body: b4a.alloc(STREAM_WIRE_CLASS[1])
  }), /cannot carry.*FIN/)
  t.exception(() => encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CIPHERTEXT,
    sequence: 0n,
    wireClass: 0,
    body: b4a.alloc(32)
  }, { ciphertextPhase: LOCAL_CIPHERTEXT_PHASE.TRANSPORT }), /does not match its phase/)

  t.exception(() => encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CORE_RAW,
    sequence: 0n,
    wireClass: 0,
    body: b4a.alloc(0)
  }), /empty non-FIN/)
  const coreFin = decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CORE_RAW,
    sequence: 0n,
    wireClass: 0,
    flags: LOCAL_STREAM_FLAG.FIN,
    body: b4a.alloc(0)
  }))
  t.is(coreFin.flags, LOCAL_STREAM_FLAG.FIN)

  const abort = decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
    frameKind: LOCAL_STREAM_FRAME_KIND.ABORT,
    sequence: 0n,
    wireClass: 0,
    body: b4a.from([LOCAL_ABORT_CODE.TIMEOUT])
  }))
  t.is(abort.abortCode, LOCAL_ABORT_CODE.TIMEOUT)
  t.is(abort.bytes.byteLength, 1)
  t.exception(() => encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
    frameKind: LOCAL_STREAM_FRAME_KIND.ABORT,
    sequence: 0n,
    wireClass: 0,
    body: b4a.from([99])
  }), /registered generic code/)
  const guard = new LocalStreamSequenceGuard()
  guard.accept(abort)
  t.exception(() => guard.accept(abort), /already closed/)
})

test('stream controls are a closed exact canonical registry with no freeform payload', t => {
  const controls = [
    { controlKind: LOCAL_STREAM_CONTROL_KIND.CHANNEL_ACCEPT, controlId: 1n, bindingHash: fixed(32, 0x81) },
    { controlKind: LOCAL_STREAM_CONTROL_KIND.CHANNEL_REJECT, controlId: 2n, localBrokerError: LOCAL_BROKER_ERROR.DAEMON_DRAINING },
    {
      controlKind: LOCAL_STREAM_CONTROL_KIND.ATTACH_TICKET,
      controlId: 3n,
      ticket: fixed(32, 0x82),
      bindingHash: fixed(32, 0x83)
    },
    {
      controlKind: LOCAL_STREAM_CONTROL_KIND.EGRESS_DIAL,
      controlId: 4n,
      endpointBindingHash: fixed(32, 0x84),
      bindingTableHash: fixed(32, 0x85),
      transportProfileHash: fixed(32, 0x86),
      wireClass: 3,
      connectDeadlineMonotonicMillis: 17_000n,
      maxOpenBytes: 65_536,
      maxStreamBytes: 16_777_216n,
      idleMillis: 5_000,
      lifetimeMillis: 60_000,
      ticket: fixed(32, 0x87)
    },
    {
      controlKind: LOCAL_STREAM_CONTROL_KIND.EGRESS_RESULT,
      controlId: 5n,
      status: 0,
      endpointBindingHash: fixed(32, 0x88),
      adjacentRelayKey: fixed(32, 0x89),
      ticket: fixed(32, 0x8a)
    },
    {
      controlKind: LOCAL_STREAM_CONTROL_KIND.CORE_CHILD_OPEN,
      controlId: 6n,
      streamId: 7n,
      ticket: fixed(32, 0x8b),
      bindingHash: fixed(32, 0x8c)
    },
    {
      controlKind: LOCAL_STREAM_CONTROL_KIND.NOISE_SESSION_OPEN,
      controlId: 7n,
      endpointBindingHash: fixed(32, 0x8d),
      handshakeProfileHash: fixed(32, 0x8e),
      prologueHash: fixed(32, 0x8f),
      wireClass: 2,
      ticket: fixed(32, 0x90)
    }
  ]
  for (const control of controls) {
    const encoded = encodeLocalStreamControl(control)
    const decoded = decodeLocalStreamControl(encoded)
    t.is(decoded.controlKind, control.controlKind)
    t.ok(b4a.equals(encodeLocalStreamControl(decoded), encoded))
  }
  t.is(encodeLocalStreamControl(controls[3]).byteLength, 167)
  const failedEgress = encodeLocalStreamControl({
    controlKind: LOCAL_STREAM_CONTROL_KIND.EGRESS_RESULT,
    controlId: 8n,
    status: 1,
    endpointBindingHash: fixed(32, 0x91),
    ticket: fixed(32, 0x92)
  })
  t.is(failedEgress.byteLength, 76)
  t.is(decodeLocalStreamControl(failedEgress).adjacentRelayKey, null)
  t.exception(() => encodeLocalStreamControl({ ...controls[4], status: 1 }), /requires exactly one adjacent/)
  t.exception(() => decodeLocalStreamControl(b4a.concat([encodeLocalStreamControl(controls[0]), b4a.from([0])])), /exact length/)

  const frame = decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTROL,
    sequence: 0n,
    wireClass: 0,
    body: encodeLocalStreamControl(controls[0])
  }))
  t.is(frame.control.controlKind, LOCAL_STREAM_CONTROL_KIND.CHANNEL_ACCEPT)
  t.exception(() => encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTROL,
    sequence: 0n,
    wireClass: 0,
    body: b4a.from('freeform failure text')
  }), /invalid prefix/)
})

test('stream modes reject frame-kind and class substitutions before use', t => {
  const content = decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    sequence: 0n,
    wireClass: 1,
    body: b4a.alloc(1)
  }))
  t.exception(() => validateLocalStreamFrameForOpen(content, publicOpen()), /wireClass differs/)
  t.exception(() => validateLocalStreamFrameForOpen(content, {
    ...publicOpen(),
    streamMode: LOCAL_STREAM_MODE.CORE_RAW,
    channelClass: 1
  }), /kind is invalid/)
  t.alike(PRIVATE_IPC_STATUS.missingSchemaNames, [])
  t.is(PRIVATE_IPC_STATUS.implementedSchemaNames.length, 7)
  t.alike(PRIVATE_IPC_STATUS.releaseBlockers, [])
  t.is(PRIVATE_IPC_STATUS.importedWireAbiHash,
    'aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d')
  t.is(PRIVATE_IPC_STATUS.releaseReady, true)
})
