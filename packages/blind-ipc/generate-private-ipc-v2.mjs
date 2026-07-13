import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import {
  CELL_RECEIPT_RESULT,
  blindErrorV1,
  blindReceiptV1,
  blake2b256,
  cellStorageSlot,
  decodeVectorManifest,
  encodeDispatchFrame,
  encodeCanonical,
  encodeOuterEnvelope,
  encodeVectorManifest,
  hashAbi,
  putCellV1
} from '@hiverelay/blind-protocol'
import { verifyPrivateIpcRegistry } from './registry.js'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  LOCAL_ABORT_CODE,
  LOCAL_IPC_CHANNEL_CLASS_V2,
  LOCAL_IPC_FEATURE_V2,
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_STAGED_FLAG_V2,
  LOCAL_STAGED_FRAME_KIND_V2,
  LOCAL_STAGED_REQUEST_KIND_V2,
  LOCAL_STAGED_RESULT_KIND_V2,
  LOCAL_TRANSPORT_AUTHORITY_KIND_V2,
  OUTER_CLASS,
  PRIVATE_IPC_V2_ADDITIONAL_SCHEMAS,
  PRIVATE_IPC_V2_CONTRACT,
  PRIVATE_IPC_V2_LIMITS,
  PRIVATE_IPC_V2_REPLAY_POLICY,
  PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
  TLS_EXPORTER_LABEL_V2,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  cellPutWorstCaseResultFitsOuterClassV2,
  decodeLocalReadyAckV2,
  decodeLocalReadyProbeV2,
  decodeLocalTransportBindingV2,
  deriveLocalStagedOpenBindingHashV2,
  derivePublicSessionBindingHashV2,
  deriveTlsExporterContextHashV2,
  encodeLocalReadyAckV2,
  encodeLocalReadyProbeV2,
  encodeLocalStagedCellPutFrameV2,
  encodeLocalStagedCellPutOpenV2,
  encodeLocalTransportBindingV2,
  encodePrivateIpcV2Registry,
  hashPrivateIpcV2Registry,
  hashPrivateIpcV2VectorManifest,
  initialStagedCellPutOuterClassSupportedV2,
  localIpcChannelClassForOuterClassV2,
  localReadyDecisionV2,
  replayTupleHashV2,
  verifyStagedCellPutPublicOuterEnvelopeV2,
  verifyLocalStagedCellPutExchangeV2,
  verifyPrivateIpcV2Registry
} from './private-ipc-v2-contract.js'

const packageRoot = path.dirname(fileURLToPath(import.meta.url))
const repositoryRoot = path.resolve(packageRoot, '../..')
const wireAbiPath = path.join(repositoryRoot, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc')
const registryPath = path.join(packageRoot, 'hiverelay-blind-private-ipc-v2.cenc')
const vectorManifestPath = path.join(packageRoot, 'vector-manifest-v2.cenc')
const authorityPath = path.join(packageRoot, 'hiverelay-blind-private-ipc-authority-v2.json')
const vectorRoot = path.join(packageRoot, 'vectors/v2')
const baseCommit = 'fa71427da4b215e20bb083daadd590fbc5ee807d'
const v1AuthorityFiles = Object.freeze([
  'hiverelay-blind-private-ipc-v1.cenc',
  'hiverelay-blind-private-ipc-v1.draft.cenc',
  'vector-manifest-v1.cenc',
  'vectors/draft/vector-manifest-v1.draft.cenc',
  'hiverelay-blind-private-ipc-authority-v1.json'
])

const args = process.argv.slice(2)
if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
  throw new Error('usage: node packages/blind-ipc/generate-private-ipc-v2.mjs [--check]')
}
const check = args.length === 1

const fixed = (length, byte) => b4a.alloc(length, byte)
const hex = bytes => b4a.toString(bytes, 'hex')
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex')

function stableValue (value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (!value || typeof value !== 'object' || b4a.isBuffer(value)) return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
}

function canonicalJson (value) {
  return b4a.from(`${JSON.stringify(stableValue(value), null, 2)}\n`, 'utf8')
}

function changed (input, mutate) {
  const output = b4a.from(input)
  mutate(output)
  return output
}

function vector (vectorPath, bytes) {
  return Object.freeze({ path: vectorPath, bytes: b4a.from(bytes) })
}

function jsonVector (vectorPath, value) {
  return vector(vectorPath, canonicalJson(value))
}

function chunkPlan (bytes, boundaries) {
  const output = []
  let previous = 0
  for (const boundary of boundaries) {
    if (!Number.isInteger(boundary) || boundary <= previous || boundary >= bytes.byteLength) {
      throw new Error('invalid deterministic chunk boundary')
    }
    output.push(boundary - previous)
    previous = boundary
  }
  output.push(bytes.byteLength - previous)
  return output
}

function relayBinding (seed) {
  return {
    version: 1,
    relayPublicKey: fixed(32, seed),
    storeId: fixed(32, seed + 1),
    descriptorSequence: 1n,
    descriptorHash: fixed(32, seed + 2),
    durabilityProfileId: 1,
    durabilityContinuityHash: fixed(32, seed + 3),
    durabilityProfileHash: fixed(32, seed + 4),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: fixed(32, 0),
    externalCommitWitness: null
  }
}

function buildFixtures (registryBytes, v1RegistryBytes) {
  const launchTopologyHash = fixed(32, 0xa1)
  const edgeProcessNonce = fixed(32, 0xa2)
  const localChannelNonce = fixed(32, 0xa3)
  const transportProfileHash = fixed(32, 0xa4)
  const tlsExporter = fixed(32, 0xa5)
  const openFields = Object.freeze({
    requestKind: LOCAL_STAGED_REQUEST_KIND_V2.STAGED_CELL_PUT_OUTER_ENVELOPE_V1,
    resultKind: LOCAL_STAGED_RESULT_KIND_V2.CELL_PUT_OUTER_RESULT_ENVELOPE_V1,
    authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 7,
    outerClass: 3,
    ipcChannelClass: LOCAL_IPC_CHANNEL_CLASS_V2.LOCAL_64K,
    acceptedMonotonicMillis: 1_000_000n,
    openDeadlineMonotonicMillis: 1_015_000n,
    requestEnvelopeBytes: OUTER_CLASS[3]
  })
  const exporterContextHash = deriveTlsExporterContextHashV2({
    open: openFields,
    launchTopologyHash,
    edgeProcessNonce,
    localChannelNonce
  })
  const publicSessionBindingHash = derivePublicSessionBindingHashV2({
    authorityKind: openFields.authorityKind,
    transportProfileHash,
    exporterContextHash,
    sessionBindingMaterial: tlsExporter
  })
  const openBindingHash = deriveLocalStagedOpenBindingHashV2({
    open: openFields,
    launchTopologyHash,
    authorityKind: openFields.authorityKind,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash,
    publicSessionBindingHash
  })
  const transportBinding = encodeLocalTransportBindingV2({
    authorityKind: openFields.authorityKind,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash,
    publicSessionBindingHash,
    openBindingHash
  })
  const open = encodeLocalStagedCellPutOpenV2({
    ...openFields,
    context: decodeLocalTransportBindingV2(transportBinding)
  })
  const allocationEpoch = 0x01020304
  const createPublicKey = fixed(32, 0x11)
  const cellBlob = fixed(4096, 0x51)
  const requestBody = encodeCanonical(putCellV1, {
    version: 1,
    storageSlot: cellStorageSlot({ allocationEpoch, createPublicKey }),
    allocationEpoch,
    sizeClass: 1,
    leaseClass: 2,
    clientNonce: fixed(32, 0x12),
    createPublicKey,
    renewPublicKey: fixed(32, 0x13),
    dropPublicKey: fixed(32, 0x14),
    declaredBlobHash: blake2b256(cellBlob),
    createSignature: fixed(64, 0x15),
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: fixed(32, 0xa0),
      token: fixed(3, 0xa1)
    },
    cellBlob
  })
  const resultBody = encodeCanonical(blindReceiptV1, {
    version: 1,
    protocol: b4a.from('hiverelay-blind-cell-v1', 'ascii'),
    relayBinding: relayBinding(0x21),
    slotCommitment: fixed(32, 0x22),
    cellBlobHash: fixed(32, 0x23),
    allocationCommitment: fixed(32, 0x24),
    requestCommitment: fixed(32, 0x25),
    sizeClass: 1,
    allocationEpoch: 10,
    leaseClass: 2,
    leaseEpoch: 11,
    stateRevision: 12n,
    receiptEpoch: 13,
    requestNonce: fixed(32, 0x26),
    result: CELL_RECEIPT_RESULT.STORED,
    signature: fixed(64, 0x27)
  })
  const errorBody = encodeCanonical(blindErrorV1, {
    version: 1,
    code: 17,
    retryable: 1,
    retryAfterEpoch: null
  })
  const requestId = fixed(16, 0xe1)
  const publicRequest = encodeOuterEnvelope({
    outerClass: 3,
    innerDispatch: encodeDispatchFrame({
      frameKind: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.requestFrameKind,
      familyId: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.familyId,
      operationId: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.operationId,
      requestId,
      body: requestBody
    })
  }, { randomFill: padding => padding.fill(0xe3) })
  const publicResult = encodeOuterEnvelope({
    outerClass: 3,
    innerDispatch: encodeDispatchFrame({
      frameKind: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.resultFrameKinds[0],
      familyId: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.familyId,
      operationId: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.operationId,
      requestId,
      body: resultBody
    })
  }, { randomFill: padding => padding.fill(0xe5) })
  const publicError = encodeOuterEnvelope({
    outerClass: 3,
    innerDispatch: encodeDispatchFrame({
      frameKind: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.resultFrameKinds[1],
      familyId: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.familyId,
      operationId: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.operationId,
      requestId,
      body: errorBody
    })
  }, { randomFill: padding => padding.fill(0xe7) })
  const requestFrame0 = encodeLocalStagedCellPutFrameV2({
    direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
    frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
    sequence: 0n,
    flags: 0,
    bytes: publicRequest.subarray(0, PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES)
  })
  const requestFrame1 = encodeLocalStagedCellPutFrameV2({
    direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
    frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
    sequence: 1n,
    flags: LOCAL_STAGED_FLAG_V2.FIN,
    bytes: publicRequest.subarray(PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES)
  })
  const resultFrame0 = encodeLocalStagedCellPutFrameV2({
    direction: LOCAL_STAGED_DIRECTION_V2.RESULT,
    frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
    sequence: 0n,
    flags: 0,
    bytes: publicResult.subarray(0, PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES)
  })
  const resultFrame1 = encodeLocalStagedCellPutFrameV2({
    direction: LOCAL_STAGED_DIRECTION_V2.RESULT,
    frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
    sequence: 1n,
    flags: LOCAL_STAGED_FLAG_V2.FIN,
    bytes: publicResult.subarray(PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES)
  })
  verifyLocalStagedCellPutExchangeV2(open, [requestFrame0, requestFrame1, resultFrame0, resultFrame1])
  const abortFrame = encodeLocalStagedCellPutFrameV2({
    direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
    frameKind: LOCAL_STAGED_FRAME_KIND_V2.ABORT,
    sequence: 0n,
    flags: 0,
    bytes: b4a.from([LOCAL_ABORT_CODE.PEER_EOF])
  })
  const probe = encodeLocalReadyProbeV2({
    endpointId: openFields.endpointId,
    edgeProcessNonce,
    launchTopologyHash,
    edgeFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
    requestedWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
    acceptedMonotonicMillis: 2_000_000n,
    absoluteDeadlineMonotonicMillis: 2_002_000n
  })
  const descriptorHash = fixed(32, 0xd1)
  const ack = encodeLocalReadyAckV2({
    endpointId: openFields.endpointId,
    edgeProcessNonce,
    launchTopologyHash,
    descriptorSequence: 9n,
    descriptorHash,
    readyRoleBits: CELL_PUT_ENDPOINT_ROLE_BIT_V2,
    readyOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyIpcFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
    expiresMonotonicMillis: 2_001_500n
  })
  const descriptor = Object.freeze({
    sequence: 9n,
    hash: descriptorHash,
    roleBits: CELL_PUT_ENDPOINT_ROLE_BIT_V2,
    enabledOperationBits: CELL_PUT_OPERATION_BIT_V2,
    expiresMonotonicMillis: 2_001_800n
  })
  const probeDeadlineAck = decodeLocalReadyAckV2(encodeLocalReadyAckV2({
    ...decodeLocalReadyAckV2(ack),
    expiresMonotonicMillis: 2_002_100n
  }))
  const readinessExpiryBoundaries = Object.freeze({
    acceptedAtProbeStart: localReadyDecisionV2(decodeLocalReadyProbeV2(probe), decodeLocalReadyAckV2(ack), descriptor, 2_000_000n),
    rejectedBeforeProbeStart: localReadyDecisionV2(decodeLocalReadyProbeV2(probe), decodeLocalReadyAckV2(ack), descriptor, 1_999_999n),
    acceptedImmediatelyBeforeAckExpiry: localReadyDecisionV2(decodeLocalReadyProbeV2(probe), decodeLocalReadyAckV2(ack), descriptor, 2_001_499n),
    rejectedAtAckExpiry: localReadyDecisionV2(decodeLocalReadyProbeV2(probe), decodeLocalReadyAckV2(ack), descriptor, 2_001_500n),
    rejectedAtProbeDeadline: localReadyDecisionV2(decodeLocalReadyProbeV2(probe), probeDeadlineAck, {
      ...descriptor,
      expiresMonotonicMillis: 2_002_200n
    }, 2_002_000n),
    rejectedAtDescriptorExpiry: localReadyDecisionV2(decodeLocalReadyProbeV2(probe), decodeLocalReadyAckV2(ack), {
      ...descriptor,
      expiresMonotonicMillis: 2_001_200n
    }, 2_001_200n)
  })
  verifyStagedCellPutPublicOuterEnvelopeV2(publicRequest, open, LOCAL_STAGED_DIRECTION_V2.REQUEST)
  verifyStagedCellPutPublicOuterEnvelopeV2(publicResult, open, LOCAL_STAGED_DIRECTION_V2.RESULT, requestId)
  verifyStagedCellPutPublicOuterEnvelopeV2(publicError, open, LOCAL_STAGED_DIRECTION_V2.RESULT, requestId)

  const openMutations = [
    ['version-v1', 4, 1, 'PRIVATE_IPC_V2_NO_FALLBACK'],
    ['unknown-request-kind', 5, 2, 'BAD_PRIVATE_IPC_V2_CONTRACT'],
    ['unknown-result-kind', 6, 2, 'BAD_PRIVATE_IPC_V2_CONTRACT'],
    ['noise-authority-on-https', 7, LOCAL_TRANSPORT_AUTHORITY_KIND_V2.NOISE_TRANSCRIPT_BY_PEERCRED_EDGE, 'BAD_PRIVATE_IPC_V2_CONTRACT'],
    ['native-transport-on-https', 8, TRANSPORT_ID.DIRECT_PROTOMUX_NOISE, 'BAD_PRIVATE_IPC_V2_CONTRACT'],
    ['endpoint-zero', 11, 0, 'BAD_PRIVATE_IPC_V2_CONTRACT'],
    ['outer-class-zero', 12, 0, 'BAD_PRIVATE_IPC_V2_CONTRACT'],
    ['outer-class-seven', 12, 7, 'BAD_PRIVATE_IPC_V2_CONTRACT'],
    ['ipc-class-zero', 13, 0, 'BAD_PRIVATE_IPC_V2_CONTRACT']
  ]
  const vectors = [
    vector('accepted/private-ipc-v2-registry.cenc', registryBytes),
    vector('accepted/transport-binding-tls.bin', transportBinding),
    vector('accepted/staged-cell-put-open-class-3.bin', open),
    vector('accepted/request-frame-0-max.bin', requestFrame0),
    vector('accepted/request-frame-1-fin.bin', requestFrame1),
    vector('accepted/result-frame-0-max.bin', resultFrame0),
    vector('accepted/result-frame-1-fin.bin', resultFrame1),
    vector('accepted/request-abort.bin', abortFrame),
    vector('accepted/ready-probe.bin', probe),
    vector('accepted/ready-ack.bin', ack),
    vector('accepted/public-request-outer-envelope-class-3.bin', publicRequest),
    vector('accepted/public-result-outer-envelope-class-3.bin', publicResult),
    vector('accepted/public-error-outer-envelope-class-3.bin', publicError)
  ]
  for (const [name, offset, value, code] of openMutations) {
    vectors.push(vector(`negative/open-${name}.bin`, changed(open, output => { output[offset] = value })))
    vectors.push(jsonVector(`negative/open-${name}.expectation.json`, { decoder: 'decodeLocalStagedCellPutOpenV2', errorCode: code, outcome: 'reject' }))
  }
  vectors.push(
    vector('negative/open-direct-native-support.bin', changed(open, output => {
      output[9] = 0
      output[10] = TRANSPORT_SUPPORT.DIRECT_NATIVE
    })),
    jsonVector('negative/open-direct-native-support.expectation.json', { decoder: 'decodeLocalStagedCellPutOpenV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/open-request-envelope-length.bin', changed(open, output => { b4a.writeUInt32BE(output, OUTER_CLASS[3] - 1, 30) })),
    jsonVector('negative/open-request-envelope-length.expectation.json', { decoder: 'decodeLocalStagedCellPutOpenV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/open-context-length.bin', changed(open, output => { b4a.writeUInt32BE(output, 161, 34) })),
    jsonVector('negative/open-context-length.expectation.json', { decoder: 'decodeLocalStagedCellPutOpenV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/open-context-authority-mismatch.bin', changed(open, output => { output[39] = LOCAL_TRANSPORT_AUTHORITY_KIND_V2.NOISE_TRANSCRIPT_BY_PEERCRED_EDGE })),
    jsonVector('negative/open-context-authority-mismatch.expectation.json', { decoder: 'decodeLocalStagedCellPutOpenV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/open-truncated.bin', open.subarray(0, open.byteLength - 1)),
    jsonVector('negative/open-truncated.expectation.json', { decoder: 'decodeLocalStagedCellPutOpenV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/open-trailing.bin', b4a.concat([open, b4a.from([0])])),
    jsonVector('negative/open-trailing.expectation.json', { decoder: 'decodeLocalStagedCellPutOpenV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/frame-version-v1.bin', changed(requestFrame1, output => { output[4] = 1 })),
    jsonVector('negative/frame-version-v1.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'PRIVATE_IPC_V2_NO_FALLBACK', outcome: 'reject' }),
    vector('negative/frame-direction-zero.bin', changed(requestFrame1, output => { output[5] = 0 })),
    jsonVector('negative/frame-direction-zero.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/frame-kind-zero.bin', changed(requestFrame1, output => { output[6] = 0 })),
    jsonVector('negative/frame-kind-zero.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/frame-reserved-flag.bin', changed(requestFrame1, output => { output[15] = 2 })),
    jsonVector('negative/frame-reserved-flag.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/frame-body-length-mismatch.bin', changed(requestFrame1, output => { b4a.writeUInt32BE(output, 20, 16) })),
    jsonVector('negative/frame-body-length-mismatch.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/frame-abort-fin.bin', changed(abortFrame, output => { output[15] = LOCAL_STAGED_FLAG_V2.FIN })),
    jsonVector('negative/frame-abort-fin.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/frame-abort-unknown-code.bin', changed(abortFrame, output => { output[20] = 0xff })),
    jsonVector('negative/frame-abort-unknown-code.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/frame-empty-content-without-fin.bin', encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
      sequence: 0n,
      flags: LOCAL_STAGED_FLAG_V2.FIN,
      bytes: b4a.alloc(0)
    }).map((byte, index) => index === 15 ? 0 : byte)),
    jsonVector('negative/frame-empty-content-without-fin.expectation.json', { decoder: 'decodeLocalStagedCellPutFrameV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/probe-version-v1.bin', changed(probe, output => { output[4] = 1 })),
    jsonVector('negative/probe-version-v1.expectation.json', { decoder: 'decodeLocalReadyProbeV2', errorCode: 'PRIVATE_IPC_V2_NO_FALLBACK', outcome: 'reject' }),
    vector('negative/probe-missing-feature.bin', changed(probe, output => { b4a.writeUInt32BE(output, REQUIRED_LOCAL_IPC_FEATURE_BITS_V2 & ~LOCAL_IPC_FEATURE_V2.OUTER_RESULT_ENVELOPE, 71) })),
    jsonVector('negative/probe-missing-feature.expectation.json', { decoder: 'decodeLocalReadyProbeV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/probe-missing-write-bit.bin', changed(probe, output => { b4a.writeUInt32BE(output, 0, 75) })),
    jsonVector('negative/probe-missing-write-bit.expectation.json', { decoder: 'decodeLocalReadyProbeV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/probe-deadline-not-exact.bin', changed(probe, output => { output[94] ^= 1 })),
    jsonVector('negative/probe-deadline-not-exact.expectation.json', { decoder: 'decodeLocalReadyProbeV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/ack-version-v1.bin', changed(ack, output => { output[4] = 1 })),
    jsonVector('negative/ack-version-v1.expectation.json', { decoder: 'decodeLocalReadyAckV2', errorCode: 'PRIVATE_IPC_V2_NO_FALLBACK', outcome: 'reject' }),
    vector('negative/ack-missing-feature.bin', changed(ack, output => { b4a.writeUInt32BE(output, REQUIRED_LOCAL_IPC_FEATURE_BITS_V2 & ~LOCAL_IPC_FEATURE_V2.PRECOMMIT_OUTER_CLASS_AUTHORITY, 121) })),
    jsonVector('negative/ack-missing-feature.expectation.json', { decoder: 'decodeLocalReadyAckV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/ack-missing-write-bit.bin', changed(ack, output => { b4a.writeUInt32BE(output, 0, 117) })),
    jsonVector('negative/ack-missing-write-bit.expectation.json', { decoder: 'decodeLocalReadyAckV2', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-request-wrong-kind.bin', changed(publicRequest, output => { output[11] = 2 })),
    jsonVector('negative/public-request-wrong-kind.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.request', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-request-wrong-family.bin', changed(publicRequest, output => { output[12] = 1 })),
    jsonVector('negative/public-request-wrong-family.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.request', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-request-wrong-operation.bin', changed(publicRequest, output => { output[13] = 2 })),
    jsonVector('negative/public-request-wrong-operation.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.request', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-request-nonzero-flags.bin', changed(publicRequest, output => { output[14] = 1 })),
    jsonVector('negative/public-request-nonzero-flags.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.request', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-request-nonzero-stream-id.bin', changed(publicRequest, output => { output[38] = 1 })),
    jsonVector('negative/public-request-nonzero-stream-id.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.request', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-request-nonzero-sequence.bin', changed(publicRequest, output => { output[46] = 1 })),
    jsonVector('negative/public-request-nonzero-sequence.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.request', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-request-malformed-put-cell-body.bin', changed(publicRequest, output => { output[51] = 2 })),
    jsonVector('negative/public-request-malformed-put-cell-body.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.request', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-result-wrong-correlation.bin', changed(publicResult, output => { output[15] ^= 1 })),
    jsonVector('negative/public-result-wrong-correlation.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.result', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-result-wrong-kind.bin', changed(publicResult, output => {
      output[11] = PRIVATE_IPC_V2_CONTRACT.publicWireOperation.requestFrameKind
    })),
    jsonVector('negative/public-result-wrong-kind.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.result', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-result-nonzero-flags.bin', changed(publicResult, output => { output[14] = 1 })),
    jsonVector('negative/public-result-nonzero-flags.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.result', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-result-nonzero-stream-id.bin', changed(publicResult, output => { output[38] = 1 })),
    jsonVector('negative/public-result-nonzero-stream-id.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.result', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-result-nonzero-sequence.bin', changed(publicResult, output => { output[46] = 1 })),
    jsonVector('negative/public-result-nonzero-sequence.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.result', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-result-malformed-receipt-body.bin', changed(publicResult, output => { output[51] = 2 })),
    jsonVector('negative/public-result-malformed-receipt-body.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.result', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/public-error-malformed-error-body.bin', changed(publicError, output => { output[51] = 2 })),
    jsonVector('negative/public-error-malformed-error-body.expectation.json', { decoder: 'verifyStagedCellPutPublicOuterEnvelopeV2.result', errorCode: 'BAD_PRIVATE_IPC_V2_CONTRACT', outcome: 'reject' }),
    vector('negative/v1-private-ipc-registry.cenc', v1RegistryBytes),
    jsonVector('negative/v1-private-ipc-registry.expectation.json', { decoder: 'decodePrivateIpcV2Registry', errorCode: 'PRIVATE_IPC_V2_NO_FALLBACK', outcome: 'reject', rule: 'V1 and V2 never fall back or downgrade' })
  )

  const allFrames = b4a.concat([requestFrame0, requestFrame1, resultFrame0, resultFrame1])
  vectors.push(
    jsonVector('conformance/exact-lengths.json', {
      ack: ack.byteLength,
      frameHeader: PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES,
      frameMaximum: requestFrame0.byteLength,
      open: open.byteLength,
      openHeader: PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_HEADER_BYTES,
      probe: probe.byteLength,
      transportBinding: transportBinding.byteLength
    }),
    jsonVector('conformance/declared-record-readers.json', {
      ack: { exactBytes: PRIVATE_IPC_V2_LIMITS.READY_ACK_BYTES, reader: 'readLocalReadyAckLengthV2', requiredDiscriminantBytes: 7 },
      frame: { maximumBytes: PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES, minimumHeaderBytes: PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES, reader: 'readLocalStagedCellPutFrameLengthV2' },
      open: { exactBytes: PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_BYTES, requiredHeaderBytes: PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_HEADER_BYTES, reader: 'readLocalStagedCellPutOpenLengthV2' },
      probe: { exactBytes: PRIVATE_IPC_V2_LIMITS.READY_PROBE_BYTES, reader: 'readLocalReadyProbeLengthV2', requiredDiscriminantBytes: 7 },
      rule: 'return null until prefix/header or discriminant is complete; reject impossible declaration or non-v2 version before body allocation'
    }),
    jsonVector('conformance/framing-split-coalesce.json', {
      coalescedBytes: allFrames.byteLength,
      expectedItemCount: 4,
      splitAllOpenFields: chunkPlan(open, [1, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 22, 30, 34, 38, 39, 40, 70, 102, 134, 166, 199]),
      splitAndCoalescedFrames: chunkPlan(allFrames, [1, 4, 19, requestFrame0.byteLength - 1, requestFrame0.byteLength, requestFrame0.byteLength + 1, requestFrame0.byteLength + requestFrame1.byteLength + 7]),
      stateRules: ['request-sequence-first-zero-exact-plus-one', 'request-fin-before-result', 'result-sequence-first-zero-exact-plus-one', 'same-class-result-fin', 'abort-terminal', 'no-frame-after-terminal']
    }),
    jsonVector('conformance/readiness-matrix.json', {
      accepted: ['exact-echo', 'fresh-descriptor-tuple', 'storage-role', 'ready-operation-cell-put', 'ready-write-cell-put', 'all-six-features', 'not-expired'],
      rejected: ['before-probe-accepted', 'missing-write-bit', 'missing-any-feature', 'unknown-feature', 'write-not-ready-subset', 'role-not-descriptor-subset', 'operation-not-descriptor-subset', 'descriptor-sequence-mismatch', 'descriptor-hash-mismatch', 'descriptor-expiry-mismatch', 'descriptor-expired-at-equality', 'endpoint-mismatch', 'nonce-mismatch', 'topology-mismatch', 'probe-expired-at-deadline-equality', 'ack-expired-at-equality']
    }),
    jsonVector('conformance/readiness-expiry-boundaries.json', readinessExpiryBoundaries),
    jsonVector('conformance/class-mapping.json', {
      localIpcChannelClass: LOCAL_IPC_CHANNEL_CLASS_V2.LOCAL_64K,
      mapping: Object.fromEntries(Object.keys(OUTER_CLASS).map(key => [key, localIpcChannelClassForOuterClassV2(Number(key))])),
      maxFrameBytes: PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES,
      maxFrameContentBytes: PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES
    }),
    jsonVector('conformance/transport-authority-mapping.json', {
      https: { authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE, supportBit: TRANSPORT_SUPPORT.DIRECT_HTTP, transportId: TRANSPORT_ID.HTTPS_DIRECT },
      nativeNoise: { authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.NOISE_TRANSCRIPT_BY_PEERCRED_EDGE, supportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE, transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE },
      callerPeerCredentialAssertionAccepted: false,
      contractValidationIsAuthoritative: false,
      rule: 'the pure contract validates binding bytes only; the runtime must observe native peer credentials before minting process-private authority',
      runtimeMustObserveNativePeerCredentials: true,
      tlsExporterBytes: PRIVATE_IPC_V2_LIMITS.TLS_EXPORTER_BYTES,
      tlsExporterLabel: TLS_EXPORTER_LABEL_V2
    }),
    jsonVector('conformance/public-cell-put-body-mapping.json', {
      error: { frameKind: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.resultFrameKinds[1], schema: 'BlindErrorV1', canonicalBodyBytes: errorBody.byteLength },
      request: { frameKind: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.requestFrameKind, schema: 'PutCellV1', canonicalBodyBytes: requestBody.byteLength },
      response: { frameKind: PRIVATE_IPC_V2_CONTRACT.publicWireOperation.resultFrameKinds[0], schema: 'BlindReceiptV1', canonicalBodyBytes: resultBody.byteLength },
      rule: 'each body is strict canonical closed-schema bytes; decode failures normalize to BAD_PRIVATE_IPC_V2_CONTRACT'
    }),
    jsonVector('conformance/replay-tuple.json', {
      antiPoisoningBeforeConsume: [
        'native-peer-credentials', 'exact-v2-open', 'transport-profile', 'launch-topology',
        'endpoint', 'open-deadline', 'initial-cell-put-outer-class-3-through-6',
        'open-binding', 'branded-persisted-descriptor-floor-readiness-sequence-at-least-1',
        'counter-only-memory-reservation'
      ],
      consumeBefore: [
        'first-request-body-pull', 'outer-envelope-reassembly',
        'admission-preflight', 'ephemeral-staging', 'publish', 'wal', 'spend', 'sign'
      ],
      hash: hex(replayTupleHashV2(decodeLocalTransportBindingV2(transportBinding))),
      policy: PRIVATE_IPC_V2_REPLAY_POLICY,
      tuple: ['edgeProcessNonce', 'localChannelNonce', 'publicSessionBindingHash']
    }),
    jsonVector('conformance/precommit-response-fit.json', {
      class2Bytes: OUTER_CLASS[2],
      class2Fits: cellPutWorstCaseResultFitsOuterClassV2(2),
      class2AuthorizedForInitialStagedCellPut: initialStagedCellPutOuterClassSupportedV2(2),
      class3Bytes: OUTER_CLASS[3],
      class3Fits: cellPutWorstCaseResultFitsOuterClassV2(3),
      dispatchHeaderBytes: PRIVATE_IPC_V2_LIMITS.DISPATCH_HEADER_BYTES,
      fixedMaximumResultBodyBytes: PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.fixedMaximumResultBodyBytes,
      fixedRequiredResultEnvelopeBytes: PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.fixedRequiredResultEnvelopeBytes,
      minimumWorstCaseOuterClass: PRIVATE_IPC_V2_LIMITS.CELL_PUT_WORST_CASE_MINIMUM_OUTER_CLASS,
      outerHeaderBytes: PRIVATE_IPC_V2_LIMITS.OUTER_HEADER_BYTES,
      resultBodyBytes: PRIVATE_IPC_V2_LIMITS.CELL_PUT_MAX_RESULT_BODY_BYTES,
      initialAuthorizedOuterClasses: PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.initialOuterClasses,
      resultSizingAuthority: PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.resultSizingAuthority,
      rule: 'private IPC v2 uses only the generated 16384-byte maximum result body and 16435-byte required envelope; classes 3..6 are authorized and no predicted-result input exists',
      worstCaseEnvelopeBytes: PRIVATE_IPC_V2_LIMITS.CELL_PUT_WORST_CASE_RESULT_ENVELOPE_BYTES
    }),
    jsonVector('conformance/staged-cell-put-runtime-policy.json', {
      nonceLifecycle: PRIVATE_IPC_V2_CONTRACT.nonceLifecycle,
      order: PRIVATE_IPC_V2_CONTRACT.precommitOrder,
      replay: PRIVATE_IPC_V2_REPLAY_POLICY,
      requestCompletion: PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion,
      stagedCellPut: PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY
    }),
    jsonVector('conformance/contract.json', PRIVATE_IPC_V2_CONTRACT)
  )

  return { vectors, fixtures: { ack, descriptorHash, edgeProcessNonce, launchTopologyHash, open, probe, publicError, publicRequest, publicResult, registryBytes, requestId, transportBinding } }
}

async function readV1Hashes () {
  const entries = []
  for (const relative of v1AuthorityFiles) {
    const bytes = await fs.readFile(path.join(packageRoot, ...relative.split('/')))
    entries.push([relative, sha256(bytes)])
  }
  return Object.fromEntries(entries)
}

async function build () {
  const wireAbiBytes = await fs.readFile(wireAbiPath)
  const v1RegistryBytes = await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-v1.cenc'))
  const registryBytes = encodePrivateIpcV2Registry(wireAbiBytes)
  verifyPrivateIpcV2Registry(registryBytes, wireAbiBytes)
  const { vectors } = buildFixtures(registryBytes, v1RegistryBytes)
  vectors.sort((left, right) => b4a.compare(b4a.from(left.path), b4a.from(right.path)))
  for (let index = 1; index < vectors.length; index++) {
    if (vectors[index - 1].path === vectors[index].path) throw new Error(`duplicate V2 vector path: ${vectors[index].path}`)
  }
  const vectorManifestBytes = encodeVectorManifest(vectors)
  const decoded = decodeVectorManifest(vectorManifestBytes)
  if (decoded.length !== vectors.length) throw new Error('V2 vector manifest count mismatch')
  for (let index = 0; index < decoded.length; index++) {
    const expected = vectors[index]
    const actual = decoded[index]
    if (actual.path !== expected.path || actual.vectorLength !== BigInt(expected.bytes.byteLength) ||
        !b4a.equals(actual.vectorHash, blake2b256(expected.bytes))) throw new Error(`V2 vector manifest mismatch: ${expected.path}`)
  }
  const v1FileSha256 = await readV1Hashes()
  const authority = {
    authorityVersion: 2,
    authorizesRelease: false,
    baseCommit,
    contractReady: true,
    importedWireAbiHash: hex(hashAbi(wireAbiBytes)),
    privateIpcFormatHash: hex(hashPrivateIpcV2Registry(registryBytes)),
    privateIpcRegistrySha256: sha256(registryBytes),
    privateIpcVectorManifestSha256: sha256(vectorManifestBytes),
    privateIpcVectorSetHash: hex(hashPrivateIpcV2VectorManifest(vectorManifestBytes)),
    releaseBlockers: [
      'the contract deliberately does not observe native peer credentials or mint runtime authority; daemon integration remains external',
      'a branded fsync-backed replay journal, persisted descriptor floor, sequence-1 activation and startup write quarantine remain external',
      'TLS exporter binding requires a real TLSSocket integration test',
      'edge write-half-close, authenticated daemon-observed EOF, post-EOF PUT_ATOMIC_COMMITTED storage/coordinator and crash/retrieval proof remain external',
      'signed descriptor readiness and public multi-relay evidence remain external'
    ],
    runtimeReleaseReady: false,
    schemaCount: 7 + PRIVATE_IPC_V2_ADDITIONAL_SCHEMAS.length,
    v1FileSha256,
    v1SchemaCount: 7,
    v2SchemaCount: PRIVATE_IPC_V2_ADDITIONAL_SCHEMAS.length,
    vectorCount: vectors.length
  }
  return {
    authorityBytes: canonicalJson(authority),
    registryBytes,
    vectorManifestBytes,
    vectors
  }
}

function buildMap (buildOutput) {
  return new Map([
    [path.relative(packageRoot, registryPath), buildOutput.registryBytes],
    [path.relative(packageRoot, vectorManifestPath), buildOutput.vectorManifestBytes],
    [path.relative(packageRoot, authorityPath), buildOutput.authorityBytes],
    ...buildOutput.vectors.map(entry => [`vectors/v2/${entry.path}`, entry.bytes])
  ])
}

function compareBuilds (left, right) {
  const leftMap = buildMap(left)
  const rightMap = buildMap(right)
  if (leftMap.size !== rightMap.size) throw new Error('V2 generator double build inventory differs')
  for (const [relative, bytes] of leftMap) {
    const other = rightMap.get(relative)
    if (!other || !b4a.equals(bytes, other)) throw new Error(`V2 generator double build differs: ${relative}`)
  }
}

async function atomicWrite (file, bytes) {
  await fs.mkdir(path.dirname(file), { recursive: true })
  const temporary = `${file}.tmp-${process.pid}`
  await fs.writeFile(temporary, bytes)
  await fs.rename(temporary, file)
}

async function listFiles (root, prefix = '') {
  const output = []
  let entries
  try {
    entries = await fs.readdir(root, { withFileTypes: true })
  } catch (error) {
    if (error && error.code === 'ENOENT') return output
    throw error
  }
  entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) output.push(...await listFiles(path.join(root, entry.name), relative))
    else if (entry.isFile()) output.push(relative)
    else throw new Error(`V2 vector inventory contains a non-file: ${relative}`)
  }
  return output
}

async function assertExactFile (file, expected) {
  let actual
  try {
    actual = await fs.readFile(file)
  } catch (error) {
    if (error && error.code === 'ENOENT') throw new Error(`missing generated V2 artifact: ${path.relative(packageRoot, file)}`)
    throw error
  }
  if (!b4a.equals(actual, expected)) throw new Error(`stale generated V2 artifact: ${path.relative(packageRoot, file)}`)
}

async function verifyV1AuthorityStillCanonical () {
  const wireAbiBytes = await fs.readFile(wireAbiPath)
  const registry = await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-v1.cenc'))
  verifyPrivateIpcRegistry(registry, wireAbiBytes)
}

const first = await build()
const second = await build()
compareBuilds(first, second)
await verifyV1AuthorityStillCanonical()

if (check) {
  await assertExactFile(registryPath, first.registryBytes)
  await assertExactFile(vectorManifestPath, first.vectorManifestBytes)
  await assertExactFile(authorityPath, first.authorityBytes)
  const expectedInventory = first.vectors.map(entry => entry.path).sort()
  const actualInventory = await listFiles(vectorRoot)
  if (JSON.stringify(actualInventory) !== JSON.stringify(expectedInventory)) {
    throw new Error(`V2 vector inventory differs\nexpected=${JSON.stringify(expectedInventory)}\nactual=${JSON.stringify(actualInventory)}`)
  }
  for (const entry of first.vectors) await assertExactFile(path.join(vectorRoot, ...entry.path.split('/')), entry.bytes)
} else {
  await fs.rm(vectorRoot, { recursive: true, force: true })
  for (const entry of first.vectors) await atomicWrite(path.join(vectorRoot, ...entry.path.split('/')), entry.bytes)
  await atomicWrite(registryPath, first.registryBytes)
  await atomicWrite(vectorManifestPath, first.vectorManifestBytes)
  await atomicWrite(authorityPath, first.authorityBytes)
}

console.log(`${check ? 'verified' : 'generated'} private IPC v2: ${first.vectors.length} vectors, ${PRIVATE_IPC_V2_ADDITIONAL_SCHEMAS.length} additive schemas`)
