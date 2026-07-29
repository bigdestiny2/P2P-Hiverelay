import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import {
  FAMILY,
  OUTER_CLASS,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  encodeVectorManifest,
  hashAbi
} from '@hiverelay/blind-protocol'
import {
  LOCAL_ABORT_CODE,
  LOCAL_BROKER_ERROR,
  LOCAL_CIPHERTEXT_PHASE,
  LOCAL_RESPONSE_KIND,
  LOCAL_STREAM_CONTROL_KIND,
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LOCAL_STREAM_MODE,
  LOCAL_STREAM_OPEN_KIND,
  PRIVATE_IPC_LIMITS,
  PRIVATE_IPC_VECTOR_OUTCOME,
  PRIVATE_IPC_VECTOR_PARSER,
  createLocalAuthenticatedChannelContext,
  encodeLocalAuthenticatedChannelContext,
  encodeLocalRequest,
  encodeLocalReadyAck,
  encodeLocalReadyProbe,
  encodeLocalResponse,
  encodeLocalStreamAttachContext,
  encodeLocalStreamControl,
  encodeLocalStreamFrame,
  encodeLocalStreamOpen,
  encodePrivateIpcFramingVector,
  encodePrivateIpcRegistry,
  hashPrivateIpcRegistry,
  hashPrivateIpcVectorManifest
} from '@hiverelay/blind-ipc'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const packageRoot = path.join(root, 'packages/blind-ipc')
const registryPath = path.join(packageRoot, 'hiverelay-blind-private-ipc-v1.cenc')
const registryAliasPath = path.join(packageRoot, 'hiverelay-blind-private-ipc-v1.draft.cenc')
const vectorPath = path.join(packageRoot, 'vector-manifest-v1.cenc')
const vectorAliasPath = path.join(packageRoot, 'vectors/draft/vector-manifest-v1.draft.cenc')
const authorityPath = path.join(packageRoot, 'hiverelay-blind-private-ipc-authority-v1.json')
const wireAbiPath = path.join(root, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc')
const fixtureRoot = path.join(packageRoot, 'vectors/fixtures')
const framingRoot = path.join(packageRoot, 'vectors/framing')
const check = process.argv.includes('--check')

const hex = bytes => b4a.toString(bytes, 'hex')
const fixed = (length, byte) => b4a.alloc(length, byte)

function vector (name, schema, bytes) {
  return { name, schema, bytes: b4a.from(bytes) }
}

function changed (bytes, mutate) {
  const output = b4a.from(bytes)
  mutate(output)
  return output
}

function chunksAt (bytes, boundaries) {
  const chunks = []
  let offset = 0
  for (const end of boundaries) {
    if (!Number.isInteger(end) || end <= offset || end > bytes.byteLength) {
      throw new Error('private IPC framing vector has an invalid split boundary')
    }
    chunks.push(bytes.subarray(offset, end))
    offset = end
  }
  if (offset < bytes.byteLength) chunks.push(bytes.subarray(offset))
  return chunks
}

function framingVector (name, parser, outcome, chunks, expectedItemCount = 0) {
  return {
    path: `framing/${name}.bin`,
    bytes: encodePrivateIpcFramingVector({ parser, outcome, chunks, expectedItemCount })
  }
}

const wireAbiBytes = await fs.readFile(wireAbiPath)
const registryBytes = encodePrivateIpcRegistry(wireAbiBytes)
const accepted = 1_000_000n
const deadline = accepted + 15_000n
const classOne = fixed(OUTER_CLASS[1], 0x11)
const topologyHash = fixed(32, 0x66)
const edgeInstanceNonce = fixed(32, 0x77)
const streamOpenBinding = Object.freeze({
  openKind: LOCAL_STREAM_OPEN_KIND.PUBLIC_CONTENT_CHANNEL,
  transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
  transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
  endpointId: 2,
  streamMode: LOCAL_STREAM_MODE.DISPATCH_CONTENT,
  channelClass: 3,
  acceptedMonotonicMillis: accepted,
  openDeadlineMonotonicMillis: deadline
})
const channelContextInput = Object.freeze({
  launchTopologyHash: topologyHash,
  edgeProcessNonce: edgeInstanceNonce,
  localChannelNonce: fixed(32, 0x78),
  transportProfileHash: fixed(32, 0x79),
  finalNoiseHandshakeHash: fixed(64, 0x7a)
})
const authenticatedChannel = createLocalAuthenticatedChannelContext(channelContextInput, streamOpenBinding)
const attachContext = encodeLocalStreamAttachContext({
  ticket: fixed(32, 0x81),
  parentSessionId: fixed(32, 0x82),
  descriptorSequence: 9n,
  descriptorHash: fixed(32, 0x83),
  bindingHash: fixed(32, 0x84)
})

const controls = [
  {
    name: 'channel-accept',
    value: { controlKind: LOCAL_STREAM_CONTROL_KIND.CHANNEL_ACCEPT, controlId: 1n, bindingHash: fixed(32, 0x91) }
  },
  {
    name: 'channel-reject',
    value: { controlKind: LOCAL_STREAM_CONTROL_KIND.CHANNEL_REJECT, controlId: 2n, localBrokerError: LOCAL_BROKER_ERROR.DAEMON_DRAINING }
  },
  {
    name: 'attach-ticket',
    value: {
      controlKind: LOCAL_STREAM_CONTROL_KIND.ATTACH_TICKET,
      controlId: 3n,
      ticket: fixed(32, 0x92),
      bindingHash: fixed(32, 0x93)
    }
  },
  {
    name: 'egress-dial',
    value: {
      controlKind: LOCAL_STREAM_CONTROL_KIND.EGRESS_DIAL,
      controlId: 4n,
      endpointBindingHash: fixed(32, 0x94),
      bindingTableHash: fixed(32, 0x95),
      transportProfileHash: fixed(32, 0x96),
      wireClass: 3,
      connectDeadlineMonotonicMillis: deadline,
      maxOpenBytes: 65_536,
      maxStreamBytes: 16_777_216n,
      idleMillis: 5_000,
      lifetimeMillis: 60_000,
      ticket: fixed(32, 0x97)
    }
  },
  {
    name: 'egress-result',
    value: {
      controlKind: LOCAL_STREAM_CONTROL_KIND.EGRESS_RESULT,
      controlId: 5n,
      status: 0,
      endpointBindingHash: fixed(32, 0x98),
      adjacentRelayKey: fixed(32, 0x99),
      ticket: fixed(32, 0x9a)
    }
  },
  {
    name: 'core-child-open',
    value: {
      controlKind: LOCAL_STREAM_CONTROL_KIND.CORE_CHILD_OPEN,
      controlId: 6n,
      streamId: 7n,
      ticket: fixed(32, 0x9b),
      bindingHash: fixed(32, 0x9c)
    }
  },
  {
    name: 'noise-session-open',
    value: {
      controlKind: LOCAL_STREAM_CONTROL_KIND.NOISE_SESSION_OPEN,
      controlId: 7n,
      endpointBindingHash: fixed(32, 0x9d),
      handshakeProfileHash: fixed(32, 0x9e),
      prologueHash: fixed(32, 0x9f),
      wireClass: 2,
      ticket: fixed(32, 0xa0)
    }
  }
]

const vectors = [
  vector('unary-cell-class-1', 'LocalDispatchV1', encodeLocalRequest({
    family: FAMILY.CELL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 1,
    outerClass: 1,
    acceptedMonotonicMillis: accepted,
    absoluteDeadlineMonotonicMillis: deadline,
    body: classOne
  })),
  vector('unary-core-adjacent-class-1', 'LocalDispatchV1', encodeLocalRequest({
    family: FAMILY.CORE,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
    endpointId: 2,
    outerClass: 1,
    acceptedMonotonicMillis: accepted,
    absoluteDeadlineMonotonicMillis: deadline,
    adjacentRelayKey: fixed(32, 0x22),
    body: classOne
  })),
  vector('unary-external-response-class-1', 'LocalUnaryResponseV1', encodeLocalResponse(classOne)),
  vector('unary-ready-probe', 'LocalDispatchV1', encodeLocalReadyProbe({
    endpointId: 4,
    acceptedMonotonicMillis: accepted,
    edgeInstanceNonce,
    launchTopologyHash: topologyHash
  })),
  vector('unary-ready-ack', 'LocalUnaryResponseV1', encodeLocalReadyAck({
    edgeInstanceNonce,
    launchTopologyHash: topologyHash,
    endpointId: 4,
    descriptorSequence: 9n,
    descriptorHash: fixed(32, 0x88),
    readyRoleBits: 0x21,
    readyOperationBits: 0x00000007,
    expiresMonotonicMillis: accepted + 4_000n
  })),
  vector('authenticated-channel', 'LocalAuthenticatedChannelV1', authenticatedChannel),
  vector('stream-attach-context', 'LocalStreamAttachContextV1', attachContext),
  vector('stream-open-public-dispatch-class-3', 'LocalStreamOpenV1', encodeLocalStreamOpen({
    ...streamOpenBinding,
    context: authenticatedChannel
  })),
  vector('stream-open-egress-forward-class-3', 'LocalStreamOpenV1', encodeLocalStreamOpen({
    openKind: LOCAL_STREAM_OPEN_KIND.AUTHORIZED_EGRESS_CHANNEL,
    transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE,
    endpointId: 3,
    streamMode: LOCAL_STREAM_MODE.FORWARD_HOP_CONTENT,
    channelClass: 3,
    acceptedMonotonicMillis: accepted,
    openDeadlineMonotonicMillis: deadline,
    adjacentRelayKey: fixed(32, 0x33),
    context: attachContext
  })),
  vector('stream-content-class-3-maximum', 'LocalStreamFrameV1', encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    sequence: 0n,
    wireClass: 3,
    flags: LOCAL_STREAM_FLAG.FIN,
    body: fixed(STREAM_WIRE_CLASS[3] - PRIVATE_IPC_LIMITS.STREAM_CONTENT_OVERHEAD_BYTES, 0x44)
  })),
  vector('stream-core-raw', 'LocalStreamFrameV1', encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
    frameKind: LOCAL_STREAM_FRAME_KIND.CORE_RAW,
    sequence: 0n,
    wireClass: 0,
    flags: LOCAL_STREAM_FLAG.FIN,
    body: fixed(512, 0x45)
  })),
  vector('stream-ciphertext-flight-1', 'LocalStreamFrameV1', encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CIPHERTEXT,
    sequence: 0n,
    wireClass: 0,
    body: fixed(32, 0x46)
  }, { ciphertextPhase: LOCAL_CIPHERTEXT_PHASE.FLIGHT_1 })),
  vector('stream-ciphertext-transport-class-1', 'LocalStreamFrameV1', encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CIPHERTEXT,
    sequence: 1n,
    wireClass: 1,
    body: fixed(STREAM_WIRE_CLASS[1], 0x47)
  }, { ciphertextPhase: LOCAL_CIPHERTEXT_PHASE.TRANSPORT })),
  vector('stream-control-frame-channel-accept', 'LocalStreamFrameV1', encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTROL,
    sequence: 0n,
    wireClass: 0,
    body: encodeLocalStreamControl(controls[0].value)
  })),
  ...controls.map(control => vector(
    `stream-control-${control.name}`,
    'LocalStreamControlV1',
    encodeLocalStreamControl(control.value)
  )),
  ...Object.entries(LOCAL_ABORT_CODE).map(([name, code]) => vector(
    `stream-abort-${name.toLowerCase().replaceAll('_', '-')}`,
    'LocalStreamFrameV1',
    encodeLocalStreamFrame({
      direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
      frameKind: LOCAL_STREAM_FRAME_KIND.ABORT,
      sequence: BigInt(code - 1),
      wireClass: 0,
      body: b4a.from([code])
    })
  )),
  ...Object.entries(LOCAL_BROKER_ERROR).map(([name, code]) => vector(
    `broker-error-${name.toLowerCase().replaceAll('_', '-')}`,
    'LocalUnaryResponseV1',
    encodeLocalResponse({ responseKind: LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR, localBrokerError: code })
  )),
  vector('authenticated-channel-explicit-codec', 'LocalAuthenticatedChannelV1', encodeLocalAuthenticatedChannelContext({
    edgeProcessNonce: fixed(32, 0xb1),
    localChannelNonce: fixed(32, 0xb2),
    parentSessionId: fixed(32, 0xb3),
    transportProfileHash: fixed(32, 0xb4),
    finalNoiseHandshakeHash: fixed(64, 0xb5),
    channelBindingMac: fixed(32, 0xb6)
  }))
].sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)

const fixtureByName = name => {
  const entry = vectors.find(entry => entry.name === name)
  if (!entry) throw new Error(`missing private IPC fixture ${name}`)
  return entry.bytes
}
const request = fixtureByName('unary-cell-class-1')
const adjacentRequest = fixtureByName('unary-core-adjacent-class-1')
const readyRequest = fixtureByName('unary-ready-probe')
const response = fixtureByName('unary-external-response-class-1')
const readyResponse = fixtureByName('unary-ready-ack')
const streamOpen = fixtureByName('stream-open-public-dispatch-class-3')
const adjacentStreamOpen = fixtureByName('stream-open-egress-forward-class-3')
const streamFrame0 = encodeLocalStreamFrame({
  direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
  frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
  sequence: 0n,
  wireClass: 1,
  body: fixed(16, 0xc1)
})
const streamFrame1 = encodeLocalStreamFrame({
  direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
  frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
  sequence: 1n,
  wireClass: 1,
  flags: LOCAL_STREAM_FLAG.FIN,
  body: fixed(8, 0xc2)
})
const streamFrame2 = encodeLocalStreamFrame({
  direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
  frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
  sequence: 2n,
  wireClass: 1,
  body: fixed(8, 0xc3)
})
const streamAbort1 = encodeLocalStreamFrame({
  direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
  frameKind: LOCAL_STREAM_FRAME_KIND.ABORT,
  sequence: 1n,
  wireClass: 0,
  body: b4a.from([LOCAL_ABORT_CODE.INTERNAL_FAILURE])
})
const accept = PRIVATE_IPC_VECTOR_OUTCOME.ACCEPT
const reject = PRIVATE_IPC_VECTOR_OUTCOME.REJECT
const requestParser = PRIVATE_IPC_VECTOR_PARSER.LOCAL_REQUEST
const responseParser = PRIVATE_IPC_VECTOR_PARSER.LOCAL_RESPONSE
const openParser = PRIVATE_IPC_VECTOR_PARSER.LOCAL_STREAM_OPEN
const frameParser = PRIVATE_IPC_VECTOR_PARSER.LOCAL_STREAM_FRAMES
const framingEntries = [
  framingVector('request-split-all-fields', requestParser, accept,
    chunksAt(request, [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 19, 27, 28, 32]), 1),
  framingVector('request-adjacent-split-all-fields', requestParser, accept,
    chunksAt(adjacentRequest, [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 19, 27, 28, 60, 64]), 1),
  framingVector('request-ready-split-all-fields', requestParser, accept,
    chunksAt(readyRequest, [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 19, 27, 28, 32]), 1),
  framingVector('response-split-all-fields', responseParser, accept,
    chunksAt(response, [1, 2, 3, 4, 5, 6, 7, 11]), 1),
  framingVector('response-ready-split-all-fields', responseParser, accept,
    chunksAt(readyResponse, [1, 2, 3, 4, 5, 6, 7, 11]), 1),
  framingVector('stream-open-split-all-fields', openParser, accept,
    chunksAt(streamOpen, [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 20, 28, 29, 33]), 1),
  framingVector('stream-open-adjacent-split-all-fields', openParser, accept,
    chunksAt(adjacentStreamOpen, [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 20, 28, 29, 61, 65]), 1),
  framingVector('stream-frame-split-all-fields', frameParser, accept,
    chunksAt(streamFrame0, [1, 2, 3, 4, 5, 6, 7, 15, 16, 17, 21]), 1),
  framingVector('stream-frames-coalesced', frameParser, accept,
    [b4a.concat([streamFrame0, streamFrame1])], 2),
  framingVector('stream-frames-split-and-coalesced', frameParser, accept,
    [streamFrame0.subarray(0, 3), b4a.concat([streamFrame0.subarray(3), streamFrame1])], 2),
  framingVector('stream-fin-then-abort', frameParser, accept,
    [b4a.concat([changed(streamFrame0, bytes => { bytes[16] = LOCAL_STREAM_FLAG.FIN }), streamAbort1])], 2),

  framingVector('request-truncated-prefix', requestParser, reject, [request.subarray(0, 3)]),
  framingVector('request-truncated-header', requestParser, reject, [request.subarray(0, 31)]),
  framingVector('request-truncated-body', requestParser, reject, [request.subarray(0, request.byteLength - 1)]),
  framingVector('response-truncated-prefix', responseParser, reject, [response.subarray(0, 3)]),
  framingVector('response-truncated-header', responseParser, reject, [response.subarray(0, 10)]),
  framingVector('response-truncated-body', responseParser, reject, [response.subarray(0, response.byteLength - 1)]),
  framingVector('stream-open-truncated-prefix', openParser, reject, [streamOpen.subarray(0, 3)]),
  framingVector('stream-open-truncated-header', openParser, reject, [streamOpen.subarray(0, 32)]),
  framingVector('stream-open-truncated-context', openParser, reject, [streamOpen.subarray(0, streamOpen.byteLength - 1)]),
  framingVector('stream-frame-truncated-prefix', frameParser, reject, [streamFrame0.subarray(0, 3)]),
  framingVector('stream-frame-truncated-header', frameParser, reject, [streamFrame0.subarray(0, 20)]),
  framingVector('stream-frame-truncated-body', frameParser, reject, [streamFrame0.subarray(0, streamFrame0.byteLength - 1)]),
  framingVector('request-trailing-byte', requestParser, reject, [b4a.concat([request, b4a.from([0])])]),
  framingVector('response-trailing-byte', responseParser, reject, [b4a.concat([response, b4a.from([0])])]),
  framingVector('stream-open-trailing-byte', openParser, reject, [b4a.concat([streamOpen, b4a.from([0])])]),
  framingVector('stream-frame-trailing-byte', frameParser, reject, [b4a.concat([streamFrame0, b4a.from([0])])]),
  framingVector('request-overlong-declaration', requestParser, reject, [changed(b4a.alloc(4), bytes => {
    b4a.writeUInt32BE(bytes, PRIVATE_IPC_LIMITS.UNARY_ADJACENT_HEADER_BYTES - 4 + Math.max(...Object.values(OUTER_CLASS)) + 1, 0)
  })]),
  framingVector('response-overlong-declaration', responseParser, reject, [changed(b4a.alloc(4), bytes => {
    b4a.writeUInt32BE(bytes, PRIVATE_IPC_LIMITS.UNARY_ADJACENT_HEADER_BYTES - 4 + Math.max(...Object.values(OUTER_CLASS)) + 1, 0)
  })]),
  framingVector('stream-open-overlong-declaration', openParser, reject, [changed(b4a.alloc(4), bytes => {
    b4a.writeUInt32BE(bytes, PRIVATE_IPC_LIMITS.STREAM_OPEN_ADJACENT_HEADER_BYTES + PRIVATE_IPC_LIMITS.MAX_STREAM_CONTEXT_BYTES - 3, 0)
  })]),
  framingVector('stream-frame-overlong-declaration', frameParser, reject, [changed(b4a.alloc(4), bytes => {
    b4a.writeUInt32BE(bytes, PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES + PRIVATE_IPC_LIMITS.MAX_STREAM_FRAME_BODY_BYTES - 3, 0)
  })]),
  framingVector('request-coalesced-second-item', requestParser, reject, [b4a.concat([request, request])]),
  framingVector('response-coalesced-second-item', responseParser, reject, [b4a.concat([response, response])]),
  framingVector('stream-open-coalesced-second-item', openParser, reject, [b4a.concat([streamOpen, streamOpen])]),
  framingVector('request-unknown-version', requestParser, reject, [changed(request, bytes => { bytes[4] = 2 })]),
  framingVector('response-unknown-version', responseParser, reject, [changed(response, bytes => { bytes[4] = 2 })]),
  framingVector('stream-open-unknown-version', openParser, reject, [changed(streamOpen, bytes => { bytes[4] = 2 })]),
  framingVector('stream-frame-unknown-version', frameParser, reject, [changed(streamFrame0, bytes => { bytes[4] = 2 })]),
  framingVector('stream-sequence-gap', frameParser, reject, [b4a.concat([streamFrame0, streamFrame2])]),
  framingVector('stream-sequence-replay', frameParser, reject, [b4a.concat([streamFrame0, streamFrame0])]),
  framingVector('stream-content-after-fin', frameParser, reject,
    [b4a.concat([changed(streamFrame0, bytes => { bytes[16] = LOCAL_STREAM_FLAG.FIN }), streamFrame1])]),
  framingVector('stream-frame-after-abort', frameParser, reject,
    [b4a.concat([changed(streamAbort1, bytes => { writeSequence(bytes, 0n) }), streamFrame1])]),
  framingVector('stream-frame-reserved-flag', frameParser, reject, [changed(streamFrame0, bytes => { bytes[16] = 2 })]),
  framingVector('stream-frame-body-length-mismatch', frameParser, reject, [changed(streamFrame0, bytes => {
    b4a.writeUInt32BE(bytes, b4a.readUInt32BE(bytes, 17) + 1, 17)
  })])
]

function writeSequence (frame, sequence) {
  for (let index = 14; index >= 7; index--) {
    frame[index] = Number(sequence & 0xffn)
    sequence >>= 8n
  }
}

const fixtureEntries = vectors.map(entry => ({
  path: `fixtures/${entry.name}.bin`,
  bytes: entry.bytes
})).concat(framingEntries).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
const manifestBytes = encodeVectorManifest(fixtureEntries)
const authority = {
  profile: 'private-ipc-authority-v1',
  registryArtifact: 'packages/blind-ipc/hiverelay-blind-private-ipc-v1.cenc',
  vectorManifestArtifact: 'packages/blind-ipc/vector-manifest-v1.cenc',
  importedWireAbiHash: hex(hashAbi(wireAbiBytes)),
  privateIpcFormatHash: hex(hashPrivateIpcRegistry(registryBytes)),
  privateIpcVectorSetHash: hex(hashPrivateIpcVectorManifest(manifestBytes)),
  registryBytes: registryBytes.byteLength,
  schemaCount: 7,
  vectorCount: fixtureEntries.length
}
const authorityBytes = b4a.from(JSON.stringify(authority, null, 2) + '\n')

async function emit (file, bytes) {
  if (check) {
    let actual
    try {
      actual = await fs.readFile(file)
    } catch {
      throw new Error(`missing generated private IPC artifact: ${path.relative(root, file)}`)
    }
    if (!b4a.equals(actual, bytes)) {
      throw new Error(`generated private IPC artifact drift: ${path.relative(root, file)}`)
    }
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, bytes)
}

for (const entry of fixtureEntries) {
  await emit(path.join(packageRoot, 'vectors', ...entry.path.split('/')), entry.bytes)
}
for (const [directory, prefix] of [[fixtureRoot, 'fixtures/'], [framingRoot, 'framing/']]) {
  const expectedNames = fixtureEntries
    .filter(entry => entry.path.startsWith(prefix))
    .map(entry => path.basename(entry.path))
    .sort()
  let actualNames = []
  try {
    actualNames = (await fs.readdir(directory, { withFileTypes: true })).map(entry => {
      if (!entry.isFile()) throw new Error('private IPC vector directory contains a non-file entry')
      return entry.name
    }).sort()
  } catch (error) {
    if (check || !error || error.code !== 'ENOENT') throw error
  }
  if (actualNames.length !== expectedNames.length ||
      actualNames.some((name, index) => name !== expectedNames[index])) {
    throw new Error('private IPC vector directory contains missing or unmanifested files')
  }
}

for (const [file, bytes] of [
  [registryPath, registryBytes],
  [registryAliasPath, registryBytes],
  [vectorPath, manifestBytes],
  [vectorAliasPath, manifestBytes],
  [authorityPath, authorityBytes]
]) await emit(file, bytes)

process.stdout.write(`${check ? 'verified' : 'generated'} final private IPC authority (${fixtureEntries.length} vectors)\n`)
