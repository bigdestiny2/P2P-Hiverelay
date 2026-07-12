import b4a from 'b4a'
import { encodeDispatchFrame } from './dispatch.js'
import {
  cellPutRequestCommitment,
  encodeVectorManifest,
  hashAbi,
  hashSpec,
  hashVectorSet,
  inboxReadRequestCommitment,
  resultSignaturePayload
} from './hashes.js'
import { encodeOuterEnvelope } from './outer-envelope.js'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID
} from './registry.js'

const hex = bytes => b4a.toString(bytes, 'hex')
const fixed = (length, value) => b4a.alloc(length, value)

export function computeWireRuntimeVectors () {
  const cellGet = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: b4a.from('00112233445566778899aabbccddeeff', 'hex'),
    body: b4a.from('01020304', 'hex')
  })
  const forwardData = encodeDispatchFrame({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: b4a.alloc(16),
    streamId: 0x0102030405060708n,
    sequence: 9n,
    body: b4a.from('a0a1a2a3', 'hex')
  })
  const outer = encodeOuterEnvelope({ outerClass: 1, innerDispatch: cellGet }, {
    randomFill: padding => padding.fill(0xa5)
  })
  const manifest = encodeVectorManifest([
    { path: 'outer/z.bin', bytes: b4a.from('z') },
    { path: 'dispatch/a.bin', bytes: b4a.from('a') }
  ])
  const cellCommitment = cellPutRequestCommitment({
    allocationCommitment: fixed(32, 0x16),
    clientNonce: fixed(32, 0x12)
  })
  const inboxCommitment = inboxReadRequestCommitment({
    relayPublicKey: fixed(32, 0x34),
    physicalTopic: fixed(32, 0x31),
    cursor: b4a.from('a0a1a2', 'hex'),
    limit: 64,
    clientNonce: fixed(32, 0x35)
  })
  const signedPayload = resultSignaturePayload(
    RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT,
    b4a.from('01020304', 'hex')
  )
  return Object.freeze({
    cellGet: hex(cellGet),
    forwardData: hex(forwardData),
    outer: hex(outer),
    cellCommitment: hex(cellCommitment),
    inboxCommitment: hex(inboxCommitment),
    resultSignaturePayload: hex(signedPayload),
    manifest: hex(manifest),
    specHash: hex(hashSpec(b4a.from('wire-runtime-spec-vector-v1'))),
    abiHash: hex(hashAbi(b4a.from('wire-runtime-abi-vector-v1'))),
    vectorSetHash: hex(hashVectorSet(manifest))
  })
}
