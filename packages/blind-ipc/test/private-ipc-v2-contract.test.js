import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import test from 'brittle'
import {
  blindErrorV1,
  blindReceiptV1,
  blake2b256,
  decodeCanonical,
  decodeVectorManifest,
  hashAbi,
  putCellV1
} from '@hiverelay/blind-protocol'
import {
  PRIVATE_IPC_SCHEMAS,
  verifyPrivateIpcRegistry
} from '../registry.js'
import * as contract from '../private-ipc-v2-contract.js'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = path.resolve(packageRoot, '../..')
const vectorRoot = path.join(packageRoot, 'vectors/v2')
const baseCommit = '9a33c3c1198442dda65d0eef9927c58c132d2c22'
const fixed = (length, byte) => b4a.alloc(length, byte)
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex')

function capture (t, operation, message) {
  let error = null
  try {
    operation()
  } catch (caught) {
    error = caught
  }
  t.ok(error, message)
  return error
}

function mutate (input, operation) {
  const output = b4a.from(input)
  operation(output)
  return output
}

async function artifact (relative) {
  return fs.readFile(path.join(packageRoot, ...relative.split('/')))
}

test('private IPC v2 registry and vectors are deterministic while V1 stays byte-identical', async t => {
  const wireAbi = await fs.readFile(path.join(repositoryRoot, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc'))
  const registry = await artifact('hiverelay-blind-private-ipc-v2.cenc')
  const manifest = await artifact('vector-manifest-v2.cenc')
  const authority = JSON.parse(await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-authority-v2.json'), 'utf8'))
  const value = contract.verifyPrivateIpcV2Registry(registry, wireAbi)

  t.ok(b4a.equals(contract.encodePrivateIpcV2Registry(wireAbi), registry), 'V2 registry reproduces')
  t.is(value.magic, contract.PRIVATE_IPC_V2_MAGIC)
  t.is(value.formatVersion, 2)
  t.is(value.schemas.length, 12)
  t.alike(value.schemas.slice(0, 7), PRIVATE_IPC_SCHEMAS, 'V1 rows are retained exactly')
  t.alike(value.schemas.slice(7).map(schema => [schema.schemaId, schema.schemaName]), [
    [8, 'LocalTransportBindingV2'],
    [9, 'LocalStagedCellPutOpenV2'],
    [10, 'LocalStagedCellPutFrameV2'],
    [11, 'LocalReadyProbeV2'],
    [12, 'LocalReadyAckV2']
  ])
  t.is(b4a.toString(contract.hashPrivateIpcV2Registry(registry), 'hex'), authority.privateIpcFormatHash)
  t.is(b4a.toString(contract.hashPrivateIpcV2VectorManifest(manifest), 'hex'), authority.privateIpcVectorSetHash)
  t.is(b4a.toString(hashAbi(wireAbi), 'hex'), authority.importedWireAbiHash)
  t.is(sha256(registry), authority.privateIpcRegistrySha256)
  t.is(sha256(manifest), authority.privateIpcVectorManifestSha256)
  t.is(authority.schemaCount, 12)
  t.is(authority.v1SchemaCount, 7)
  t.is(authority.v2SchemaCount, 5)
  t.ok(authority.vectorCount >= 104)
  t.is(authority.contractReady, true)
  t.is(authority.runtimeReleaseReady, false)
  t.is(authority.authorizesRelease, false)

  const entries = decodeVectorManifest(manifest)
  t.is(entries.length, authority.vectorCount)
  for (const entry of entries) {
    const bytes = await fs.readFile(path.join(vectorRoot, ...entry.path.split('/')))
    t.is(BigInt(bytes.byteLength), entry.vectorLength, `${entry.path} length`)
    t.ok(b4a.equals(blake2b256(bytes), entry.vectorHash), `${entry.path} hash`)
  }

  for (const relative of Object.keys(authority.v1FileSha256)) {
    const current = await artifact(relative)
    const atBase = execFileSync('git', ['show', `${baseCommit}:packages/blind-ipc/${relative}`], { cwd: repositoryRoot })
    t.ok(b4a.equals(current, atBase), `${relative} is byte-identical to ${baseCommit}`)
    t.is(sha256(current), authority.v1FileSha256[relative], `${relative} frozen SHA-256`)
  }

  const v1Registry = await artifact('hiverelay-blind-private-ipc-v1.cenc')
  t.ok(verifyPrivateIpcRegistry(v1Registry, wireAbi), 'V1 verifier still accepts V1')
  t.is(capture(t, () => verifyPrivateIpcRegistry(registry, wireAbi), 'V1 verifier rejects V2').code, 'BAD_PRIVATE_IPC_REGISTRY')
  t.is(capture(t, () => contract.decodePrivateIpcV2Registry(v1Registry), 'V2 decoder rejects V1').code, 'PRIVATE_IPC_V2_NO_FALLBACK')
})

test('private IPC v2 codecs freeze exact lengths and expose only non-authoritative binding validation', async t => {
  const bindingBytes = await artifact('vectors/v2/accepted/transport-binding-tls.bin')
  const openBytes = await artifact('vectors/v2/accepted/staged-cell-put-open-class-3.bin')
  const requestFrame = await artifact('vectors/v2/accepted/request-frame-0-max.bin')
  const abortFrame = await artifact('vectors/v2/accepted/request-abort.bin')
  const probeBytes = await artifact('vectors/v2/accepted/ready-probe.bin')
  const ackBytes = await artifact('vectors/v2/accepted/ready-ack.bin')

  t.is(bindingBytes.byteLength, 162)
  t.is(openBytes.byteLength, 200)
  t.is(requestFrame.byteLength, 65_535)
  t.is(abortFrame.byteLength, 21)
  t.is(probeBytes.byteLength, 95)
  t.is(ackBytes.byteLength, 133)
  t.is(contract.PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_HEADER_BYTES, 38)
  t.is(contract.PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES, 20)
  t.is(contract.PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES, 65_515)
  t.is(contract.CELL_PUT_OPERATION_BIT_V2, 8)
  t.is(contract.CELL_PUT_ENDPOINT_ROLE_BIT_V2, 1)
  t.is(contract.REQUIRED_LOCAL_IPC_FEATURE_BITS_V2, 0x3f)

  const binding = contract.decodeLocalTransportBindingV2(bindingBytes)
  const open = contract.decodeLocalStagedCellPutOpenV2(openBytes)
  const probe = contract.decodeLocalReadyProbeV2(probeBytes)
  const ack = contract.decodeLocalReadyAckV2(ackBytes)
  t.is(binding.authorityKind, contract.LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE)
  t.is(open.context.authorityKind, open.authorityKind)
  t.is(open.transportId, contract.TRANSPORT_ID.HTTPS_DIRECT)
  t.is(open.transportSupportBit, contract.TRANSPORT_SUPPORT.DIRECT_HTTP)
  t.is(open.requestEnvelopeBytes, contract.OUTER_CLASS[3])
  t.is(probe.absoluteDeadlineMonotonicMillis - probe.acceptedMonotonicMillis, 2_000n)
  t.is(ack.readyWriteOperationBits, contract.CELL_PUT_OPERATION_BIT_V2)
  t.is(ack.readyIpcFeatureBits, 0x3f)

  const readers = [
    [contract.readLocalStagedCellPutOpenLengthV2, openBytes, 38, 200],
    [contract.readLocalStagedCellPutFrameLengthV2, requestFrame, 20, 65_535],
    [contract.readLocalReadyProbeLengthV2, probeBytes, 7, 95],
    [contract.readLocalReadyAckLengthV2, ackBytes, 7, 133]
  ]
  for (const [reader, bytes, required, exact] of readers) {
    t.is(reader(bytes.subarray(0, 3)), null, 'reader waits for prefix')
    t.is(reader(bytes.subarray(0, 4)), null, 'reader waits for version')
    t.is(reader(bytes.subarray(0, required - 1)), null, 'reader waits for bounded header/discriminant')
    t.is(reader(bytes.subarray(0, required)), exact, 'reader returns exact declared record length')
    t.is(reader(bytes), exact, 'reader accepts complete record')
    t.exception(() => reader(mutate(bytes.subarray(0, 4), value => { value.fill(0) })), 'reader rejects impossible declaration')
    t.is(capture(t, () => reader(mutate(bytes.subarray(0, 5), value => { value[4] = 1 })), 'reader rejects V1').code,
      'PRIVATE_IPC_V2_NO_FALLBACK')
  }
  t.exception(() => contract.readLocalStagedCellPutOpenLengthV2(
    mutate(openBytes.subarray(0, 38), value => { b4a.writeUInt32BE(value, 161, 34) })), 'open reader rejects context contradiction')
  t.exception(() => contract.readLocalStagedCellPutFrameLengthV2(
    mutate(requestFrame.subarray(0, 20), value => { b4a.writeUInt32BE(value, 1, 16) })), 'frame reader rejects body contradiction')

  const validation = contract.validateLocalStagedCellPutOpenBindingV2(open, {
    launchTopologyHash: fixed(32, 0xa1),
    transportProfileHash: fixed(32, 0xa4)
  })
  t.is(Object.isFrozen(validation), true)
  t.is(validation.validationKind, 'NON_AUTHORITATIVE_BINDING_VALIDATION_V2')
  t.is(validation.authorityGranted, false)
  t.is(validation.peerCredentialsObserved, false)
  t.is(validation.endpointId, 7)
  t.ok(b4a.equals(validation.replayTupleHash, contract.replayTupleHashV2(binding)))
  const validationProfileByte = validation.transportProfileHash[0]
  open.context.transportProfileHash[0] ^= 1
  t.is(validation.transportProfileHash[0], validationProfileByte, 'validation record snapshots caller bytes')
  open.context.transportProfileHash[0] ^= 1
  t.exception(() => contract.validateLocalStagedCellPutOpenBindingV2(open, {
    launchTopologyHash: fixed(32, 0xa1),
    transportProfileHash: fixed(32, 0xff)
  }), 'profile mismatch rejects without minting authority')
  t.exception(() => contract.validateLocalStagedCellPutOpenBindingV2(open, {
    launchTopologyHash: fixed(32, 0xa1),
    transportProfileHash: fixed(32, 0xa4),
    peerCredentialAuthenticated: true
  }), 'caller peer-credential assertions are rejected as unknown options')
  t.alike(Object.keys(contract).filter(name => /(?:raw|random|test).*authority/i.test(name)), [], 'no raw/random/test authority constructor is exported')
  t.alike(Object.entries(contract)
    .filter(([name, value]) => typeof value === 'function' && /(?:peercred|authority)/i.test(name))
    .map(([name]) => name), [], 'contract exports no peercred/runtime-authority function')
  const source = await fs.readFile(path.join(packageRoot, 'private-ipc-v2-contract.js'), 'utf8')
  for (const forbidden of [
    'peerCredentialAuthenticated',
    'VERIFIED_STAGED_OPEN_AUTHORITIES',
    'verifyLocalStagedCellPutOpenBindingV2',
    'localStagedCellPutAuthorityV2'
  ]) t.is(source.includes(forbidden), false, `source omits ${forbidden}`)
})

test('private IPC v2 negative fixture expectations reject exact enum, bit, length and downgrade errors', async t => {
  const open = await artifact('vectors/v2/accepted/staged-cell-put-open-class-3.bin')
  const requestId = fixed(16, 0xe1)
  const names = (await fs.readdir(path.join(vectorRoot, 'negative')))
    .filter(name => name.endsWith('.expectation.json'))
    .sort()
  t.ok(names.length >= 35)
  for (const expectationName of names) {
    const expectation = JSON.parse(await fs.readFile(path.join(vectorRoot, 'negative', expectationName), 'utf8'))
    const vectorName = expectationName.startsWith('v1-private-ipc-registry.')
      ? 'v1-private-ipc-registry.cenc'
      : expectationName.replace('.expectation.json', '.bin')
    const bytes = await fs.readFile(path.join(vectorRoot, 'negative', vectorName))
    let operation
    if (expectation.decoder === 'decodeLocalStagedCellPutOpenV2') operation = () => contract.decodeLocalStagedCellPutOpenV2(bytes)
    else if (expectation.decoder === 'decodeLocalStagedCellPutFrameV2') operation = () => contract.decodeLocalStagedCellPutFrameV2(bytes)
    else if (expectation.decoder === 'decodeLocalReadyProbeV2') operation = () => contract.decodeLocalReadyProbeV2(bytes)
    else if (expectation.decoder === 'decodeLocalReadyAckV2') operation = () => contract.decodeLocalReadyAckV2(bytes)
    else if (expectation.decoder === 'decodePrivateIpcV2Registry') operation = () => contract.decodePrivateIpcV2Registry(bytes)
    else if (expectation.decoder === 'verifyStagedCellPutPublicOuterEnvelopeV2.request') {
      operation = () => contract.verifyStagedCellPutPublicOuterEnvelopeV2(bytes, open, contract.LOCAL_STAGED_DIRECTION_V2.REQUEST)
    } else if (expectation.decoder === 'verifyStagedCellPutPublicOuterEnvelopeV2.result') {
      operation = () => contract.verifyStagedCellPutPublicOuterEnvelopeV2(bytes, open, contract.LOCAL_STAGED_DIRECTION_V2.RESULT, requestId)
    } else throw new Error(`unknown negative vector decoder ${expectation.decoder}`)
    const error = capture(t, operation, `${vectorName} rejects`)
    t.is(error.code, expectation.errorCode, `${vectorName} error code`)
  }
})

test('private IPC v2 fragmented exchange is split/coalesce safe and state sequenced', async t => {
  const open = await artifact('vectors/v2/accepted/staged-cell-put-open-class-3.bin')
  const request0 = await artifact('vectors/v2/accepted/request-frame-0-max.bin')
  const request1 = await artifact('vectors/v2/accepted/request-frame-1-fin.bin')
  const result0 = await artifact('vectors/v2/accepted/result-frame-0-max.bin')
  const result1 = await artifact('vectors/v2/accepted/result-frame-1-fin.bin')
  const abort = await artifact('vectors/v2/accepted/request-abort.bin')
  const all = b4a.concat([request0, request1, result0, result1])

  const decoded = contract.decodeLocalStagedCellPutFramesV2(all)
  t.is(decoded.frames.length, 4)
  t.is(decoded.remainder.byteLength, 0)
  const complete = contract.verifyLocalStagedCellPutExchangeV2(open, decoded.frames)
  t.is(complete.requestBytes, contract.OUTER_CLASS[3])
  t.is(complete.resultBytes, contract.OUTER_CLASS[3])
  t.is(complete.requestFinished, true)
  t.is(complete.resultFinished, true)
  t.ok(b4a.equals(
    b4a.concat(decoded.frames.slice(0, 2).map(frame => frame.bytes)),
    await artifact('vectors/v2/accepted/public-request-outer-envelope-class-3.bin')
  ), 'staged request frames reconstruct the exact canonical public request envelope')
  t.ok(b4a.equals(
    b4a.concat(decoded.frames.slice(2).map(frame => frame.bytes)),
    await artifact('vectors/v2/accepted/public-result-outer-envelope-class-3.bin')
  ), 'staged result frames reconstruct the exact canonical public result envelope')

  const scenario = JSON.parse(await fs.readFile(path.join(vectorRoot, 'conformance/framing-split-coalesce.json'), 'utf8'))
  let pending = b4a.alloc(0)
  let offset = 0
  const splitFrames = []
  for (const length of scenario.splitAndCoalescedFrames) {
    pending = b4a.concat([pending, all.subarray(offset, offset + length)])
    offset += length
    const partial = contract.decodeLocalStagedCellPutFramesV2(pending, { allowIncomplete: true })
    splitFrames.push(...partial.frames)
    pending = partial.remainder
  }
  t.is(offset, all.byteLength)
  t.is(pending.byteLength, 0)
  t.is(splitFrames.length, 4)
  contract.verifyLocalStagedCellPutExchangeV2(open, splitFrames)

  const abortResult = contract.verifyLocalStagedCellPutExchangeV2(open, [abort])
  t.is(abortResult.aborted, true)
  t.exception(() => contract.verifyLocalStagedCellPutExchangeV2(open, [result0]), 'result cannot precede request FIN')
  t.exception(() => contract.verifyLocalStagedCellPutExchangeV2(open, [request0, result0]), 'result cannot replace request continuation')
  const replayedRequest1 = contract.encodeLocalStagedCellPutFrameV2({
    direction: contract.LOCAL_STAGED_DIRECTION_V2.REQUEST,
    frameKind: contract.LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
    sequence: 0n,
    flags: contract.LOCAL_STAGED_FLAG_V2.FIN,
    bytes: request1.subarray(contract.PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES)
  })
  t.exception(() => contract.verifyLocalStagedCellPutExchangeV2(open, [request0, replayedRequest1]), 'sequence replay rejects')
  t.exception(() => contract.verifyLocalStagedCellPutExchangeV2(open, [abort, request0]), 'frame after ABORT rejects')
  t.exception(() => contract.verifyLocalStagedCellPutExchangeV2(open, [...decoded.frames, result1]), 'frame after result FIN rejects')

  let openOffset = 0
  let accumulatedOpen = b4a.alloc(0)
  for (const length of scenario.splitAllOpenFields) {
    accumulatedOpen = b4a.concat([accumulatedOpen, open.subarray(openOffset, openOffset + length)])
    openOffset += length
    if (openOffset < open.byteLength) t.exception(() => contract.decodeLocalStagedCellPutOpenV2(accumulatedOpen))
  }
  t.is(contract.decodeLocalStagedCellPutOpenV2(accumulatedOpen).outerClass, 3)
})

test('private IPC v2 readiness is a write-specific descriptor-bound fail-closed gate', async t => {
  const probe = contract.decodeLocalReadyProbeV2(await artifact('vectors/v2/accepted/ready-probe.bin'))
  const ack = contract.decodeLocalReadyAckV2(await artifact('vectors/v2/accepted/ready-ack.bin'))
  const descriptor = {
    sequence: 9n,
    hash: fixed(32, 0xd1),
    roleBits: contract.CELL_PUT_ENDPOINT_ROLE_BIT_V2,
    enabledOperationBits: contract.CELL_PUT_OPERATION_BIT_V2,
    expiresMonotonicMillis: 2_001_800n
  }
  t.alike(contract.localReadyDecisionV2(probe, ack, descriptor, 2_000_000n), { ready: true, reasons: [] })
  t.ok(contract.localReadyDecisionV2(probe, ack, descriptor, 1_999_999n).reasons.includes('not-yet-valid'))
  t.alike(contract.localReadyDecisionV2(probe, ack, descriptor, 2_001_000n), { ready: true, reasons: [] })
  t.ok(contract.localReadyDecisionV2(probe, ack, { ...descriptor, sequence: 10n }, 2_001_000n).reasons.includes('descriptor-freshness-mismatch'))
  t.ok(contract.localReadyDecisionV2(probe, ack, { ...descriptor, hash: fixed(32, 0xd2) }, 2_001_000n).reasons.includes('descriptor-freshness-mismatch'))
  t.ok(contract.localReadyDecisionV2(probe, ack, { ...descriptor, roleBits: 0 }, 2_001_000n).reasons.includes('descriptor-role-subset-mismatch'))
  t.ok(contract.localReadyDecisionV2(probe, ack, { ...descriptor, enabledOperationBits: 0 }, 2_001_000n).reasons.includes('descriptor-operation-subset-mismatch'))
  const descriptorExpiry = contract.localReadyDecisionV2(
    probe, ack, { ...descriptor, expiresMonotonicMillis: 2_001_000n }, 2_001_000n)
  t.ok(descriptorExpiry.reasons.includes('descriptor-expiry-mismatch'))
  t.ok(descriptorExpiry.reasons.includes('descriptor-expired'))
  t.alike(contract.localReadyDecisionV2(probe, ack, descriptor, 2_001_499n), { ready: true, reasons: [] })
  t.ok(contract.localReadyDecisionV2(probe, ack, descriptor, 2_001_500n).reasons.includes('expired'))
  t.ok(contract.localReadyDecisionV2(probe, ack, descriptor, 2_002_000n).reasons.includes('expired'))
  t.ok(contract.localReadyDecisionV2(probe, ack, descriptor, 2_001_800n).reasons.includes('descriptor-expired'))

  const boundaries = JSON.parse(await fs.readFile(
    path.join(vectorRoot, 'conformance/readiness-expiry-boundaries.json'), 'utf8'))
  t.is(boundaries.acceptedAtProbeStart.ready, true)
  t.ok(boundaries.rejectedBeforeProbeStart.reasons.includes('not-yet-valid'))
  t.ok(boundaries.rejectedAtAckExpiry.reasons.includes('expired'))
  t.ok(boundaries.rejectedAtProbeDeadline.reasons.includes('expired'))
  t.ok(boundaries.rejectedAtDescriptorExpiry.reasons.includes('descriptor-expired'))

  const extraReadyOperationAck = contract.decodeLocalReadyAckV2(contract.encodeLocalReadyAckV2({
    ...ack,
    readyOperationBits: ack.readyOperationBits | 1
  }))
  t.ok(contract.localReadyDecisionV2(probe, extraReadyOperationAck, descriptor, 2_001_000n).reasons.includes('descriptor-operation-subset-mismatch'))
  const extraRoleAck = contract.decodeLocalReadyAckV2(contract.encodeLocalReadyAckV2({
    ...ack,
    readyRoleBits: ack.readyRoleBits | 2
  }))
  t.ok(contract.localReadyDecisionV2(probe, extraRoleAck, descriptor, 2_001_000n).reasons.includes('descriptor-role-subset-mismatch'))
})

test('private IPC v2 freezes transport/class/replay mapping and precommit result fit', async t => {
  const open = await artifact('vectors/v2/accepted/staged-cell-put-open-class-3.bin')
  const publicRequest = await artifact('vectors/v2/accepted/public-request-outer-envelope-class-3.bin')
  const publicResult = await artifact('vectors/v2/accepted/public-result-outer-envelope-class-3.bin')
  const publicError = await artifact('vectors/v2/accepted/public-error-outer-envelope-class-3.bin')
  const requestId = fixed(16, 0xe1)
  const callerRequest = b4a.from(publicRequest)
  const request = contract.verifyStagedCellPutPublicOuterEnvelopeV2(
    callerRequest, open, contract.LOCAL_STAGED_DIRECTION_V2.REQUEST)
  const verifiedRequestId = b4a.from(request.frame.requestId)
  const verifiedRequestBody = b4a.from(request.frame.body)
  callerRequest[15] ^= 1
  callerRequest[51] = 2
  t.is(Object.isFrozen(request.frame), true, 'verified frame record is frozen')
  t.ok(b4a.equals(request.frame.requestId, verifiedRequestId), 'caller mutation cannot change verified requestId')
  t.ok(b4a.equals(request.frame.body, verifiedRequestBody), 'caller mutation cannot change verified canonical body')
  t.is(decodeCanonical(putCellV1, request.frame.body).version, 1, 'owned verified body remains canonical')
  const mutatedCallerError = capture(t, () => contract.verifyStagedCellPutPublicOuterEnvelopeV2(
    callerRequest, open, contract.LOCAL_STAGED_DIRECTION_V2.REQUEST), 'fresh verification observes caller mutation')
  t.is(mutatedCallerError.code, 'BAD_PRIVATE_IPC_V2_CONTRACT')
  const result = contract.verifyStagedCellPutPublicOuterEnvelopeV2(
    publicResult, open, contract.LOCAL_STAGED_DIRECTION_V2.RESULT, requestId)
  const error = contract.verifyStagedCellPutPublicOuterEnvelopeV2(
    publicError, open, contract.LOCAL_STAGED_DIRECTION_V2.RESULT, requestId)
  t.is(request.bodySchemaName, 'PutCellV1')
  t.is(result.bodySchemaName, 'BlindReceiptV1')
  t.is(error.bodySchemaName, 'BlindErrorV1')
  t.is(decodeCanonical(putCellV1, request.frame.body).version, 1)
  t.is(decodeCanonical(blindReceiptV1, result.frame.body).result, 1)
  t.is(decodeCanonical(blindErrorV1, error.frame.body).code, 17)
  t.is(request.frame.frameKind, contract.PRIVATE_IPC_V2_CONTRACT.publicWireOperation.requestFrameKind)
  t.ok(contract.PRIVATE_IPC_V2_CONTRACT.publicWireOperation.resultFrameKinds.includes(result.frame.frameKind))
  t.ok(contract.PRIVATE_IPC_V2_CONTRACT.publicWireOperation.resultFrameKinds.includes(error.frame.frameKind))
  t.ok(b4a.equals(request.frame.requestId, result.frame.requestId), 'result requestId is correlated')
  t.ok(b4a.equals(request.frame.requestId, error.frame.requestId), 'error requestId is correlated')

  for (let outerClass = 1; outerClass <= 6; outerClass++) {
    t.is(contract.localIpcChannelClassForOuterClassV2(outerClass), contract.LOCAL_IPC_CHANNEL_CLASS_V2.LOCAL_64K)
  }
  t.is(contract.PRIVATE_IPC_V2_LIMITS.CELL_PUT_WORST_CASE_RESULT_ENVELOPE_BYTES, 16_435)
  t.is(contract.cellPutWorstCaseResultFitsOuterClassV2(2), false)
  t.is(contract.cellPutWorstCaseResultFitsOuterClassV2(3), true)
  t.is(contract.cellPutPredictedResultFitsOuterClassV2, undefined,
    'V2 exports no predicted-result sizing authority')
  t.is(contract.initialStagedCellPutOuterClassSupportedV2(2), false)
  t.is(contract.initialStagedCellPutOuterClassSupportedV2(3), true)
  t.is(capture(t, () => contract.assertPrecommitCellPutResultFitV2(2), 'class 2 worst case rejects').code,
    'PRIVATE_IPC_V2_PRECOMMIT_RESULT_CLASS')
  t.is(capture(t, () => contract.assertPrecommitCellPutResultFitV2(3, 104),
    'predicted-result input rejects').code, 'PRIVATE_IPC_V2_FIXED_RESULT_SIZING')
  t.is(contract.assertPrecommitCellPutResultFitV2(3), 3)
  t.alike(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.initialOuterClasses, [3, 4, 5, 6])
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.resultSizingAuthority,
    'fixed-generated-worst-case-only')
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.fixedMaximumResultBodyBytes, 16_384)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.fixedRequiredResultEnvelopeBytes, 16_435)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.minimumReadyDescriptorSequence, 1)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.atomicCommitRecordKind, 'PUT_ATOMIC_COMMITTED')
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.v2EmitsLegacyReservationWal, false)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.cancellationFence,
    'under-canonical-locks-immediately-before-non-cancellable-publish-and-commit-unit')
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.nonCancellableCommitUnit,
    'publish-through-put-atomic-committed-fsync-and-apply')
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.walPrewriteFence,
    'internal-writer-and-commit-invariants-only-never-caller-cancellation')
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.capacity, 4096)
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.acceptedRecordMaximumTtlMillis, 15_000)
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.freshEntryExpiry, 'exact-open-deadline')
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.recoveredEntryMinimumRetentionMillis, 15_000)
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.recoveredRetentionBasis,
    'conservative-startup-fence-not-accepted-record-ttl')
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.startupWriteQuarantineMillis, 15_000)
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.quarantineReadyAck, 'suppress-or-refuse')
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.quarantineReadinessBrand, 'withheld')
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.quarantineZeroWriteBitsAckPermitted, false)
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.maximumHorizonMillis, undefined,
    'accepted-record TTL is not conflated with recovered retention')
  t.is(contract.PRIVATE_IPC_V2_REPLAY_POLICY.liveEntryEvictionPermitted, false)
  t.is(contract.PRIVATE_IPC_V2_CONTRACT.precommitOrder.indexOf('open-binding') <
    contract.PRIVATE_IPC_V2_CONTRACT.precommitOrder.indexOf('durable-replay-consume'), true)
  t.is(contract.PRIVATE_IPC_V2_CONTRACT.precommitOrder.indexOf('durable-replay-consume') <
    contract.PRIVATE_IPC_V2_CONTRACT.precommitOrder.indexOf('first-request-body-pull'), true)
  const completionOrder = contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion.sequence
  t.alike(completionOrder, [
    'exact-outer-request-fin',
    'edge-write-half-close',
    'daemon-observed-authenticated-peer-eof',
    'canonical-post-eof-revalidation'
  ])
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion.edgeResponseHalfReadableUntilTerminal, true)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion.daemonEofAuthority,
    'module-private-same-native-peercred-authenticated-stream-eof-after-request-fin')
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion.callerEofAssertionPermitted, false)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion.frameVerifierMintsEofAuthority, false)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion.commitBeforeDaemonObservedEofPermitted, false)
  t.is(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.publicResultRequires,
    'exact-outer-plus-request-fin-plus-edge-write-half-close-plus-daemon-observed-authenticated-peer-eof-plus-canonical-revalidation')
  t.alike(contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion.negativeSemantics, {
    eofBeforeFin: 'generic-local-abort-no-public-error-no-commit',
    finWithoutEof: 'caller-cancellation-or-deadline-then-generic-local-abort-no-public-error-no-commit',
    requestDataAfterFin: 'generic-local-abort-no-public-error-no-commit',
    resultBeforeDaemonObservedEof: 'forbidden-runtime-conformance-failure',
    responseHalfClosedBeforeTerminal: 'caller-cancelled-pre-boundary-discards-post-boundary-commit-completes-without-result'
  })
  const order = contract.PRIVATE_IPC_V2_CONTRACT.precommitOrder
  t.is(order.indexOf('exact-outer-request-fin') < order.indexOf('edge-write-half-close-response-half-readable'), true)
  t.is(order.indexOf('edge-write-half-close-response-half-readable') <
    order.indexOf('daemon-observed-authenticated-peer-eof'), true)
  t.is(order.indexOf('daemon-observed-authenticated-peer-eof') < order.indexOf('canonical-post-eof-revalidation'), true)
  t.is(order.indexOf('canonical-post-eof-revalidation') <
    order.indexOf('final-caller-cancellation-and-lifecycle-fence-before-publish'), true)
  const runtimePolicy = JSON.parse(await artifact('vectors/v2/conformance/staged-cell-put-runtime-policy.json'))
  t.alike(runtimePolicy.requestCompletion, contract.PRIVATE_IPC_V2_STAGED_CELL_PUT_POLICY.requestCompletion)
  t.alike(runtimePolicy.replay, contract.PRIVATE_IPC_V2_REPLAY_POLICY)
  t.is(runtimePolicy.stagedCellPut.resultSizingAuthority, 'fixed-generated-worst-case-only')

  const binding = contract.decodeLocalTransportBindingV2(await artifact('vectors/v2/accepted/transport-binding-tls.bin'))
  const replay = contract.replayTupleHashV2(binding)
  for (const field of ['edgeProcessNonce', 'localChannelNonce', 'publicSessionBindingHash']) {
    const changed = { ...binding, [field]: mutate(binding[field], bytes => { bytes[0] ^= 1 }) }
    t.not(b4a.toString(contract.replayTupleHashV2(changed), 'hex'), b4a.toString(replay, 'hex'), `${field} binds replay tuple`)
  }
  t.is(contract.PRIVATE_IPC_V2_CONTRACT.httpsTransport.authorityKind,
    contract.LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE)
  t.is(contract.PRIVATE_IPC_V2_TRANSPORT_BINDING_RULES[contract.TRANSPORT_ID.DIRECT_PROTOMUX_NOISE].authorityKind,
    contract.LOCAL_TRANSPORT_AUTHORITY_KIND_V2.NOISE_TRANSCRIPT_BY_PEERCRED_EDGE)
  t.is(contract.PRIVATE_IPC_V2_CONTRACT.v1FallbackPermitted, false)
})
