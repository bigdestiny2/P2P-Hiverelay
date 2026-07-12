import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  FRAME_KIND,
  PROTOCOL,
  operationProfile
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { blindErrorV1 } from '@hiverelay/blind-protocol/schemas'
import { decodeCanonical } from '@hiverelay/blind-protocol/codec'
import {
  decodeOuterEnvelope,
  encodeOuterEnvelope,
  smallestOuterClass
} from '@hiverelay/blind-protocol/outer-envelope'
import { encodeDispatchFrame } from '@hiverelay/blind-protocol/dispatch'
import { asBytes, randomBytes } from './bytes.js'
import { fail } from './errors.js'

function isAllZero (bytes) {
  for (const byte of bytes) if (byte !== 0) return false
  return true
}

function requestId (runtime, value) {
  if (value != null) {
    const bytes = b4a.from(asBytes(value, 'requestId', 16))
    if (isAllZero(bytes)) fail('BAD_CLIENT_INPUT', 'requestId must be nonzero')
    return bytes
  }
  for (let attempt = 0; attempt < 8; attempt++) {
    const bytes = randomBytes(runtime, 16, 'requestId')
    if (!isAllZero(bytes)) return bytes
  }
  fail('RNG_FAILURE', 'could not generate a nonzero requestId')
}

function sameBytes (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

export function encodeUnaryRequest (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'unary request options are required')
  const id = requestId(options.runtime, options.requestId)
  const body = asBytes(options.body, 'canonical operation body')
  const dispatch = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: options.familyId,
    operationId: options.operationId,
    requestId: id,
    body
  })
  const profile = operationProfile(options.familyId, options.operationId)
  if (!profile) fail('BAD_CLIENT_INPUT', 'family/operation pair has no frozen profile')
  const expectedResultBodyBytes = options.expectedResultBodyBytes == null
    ? profile.maxResultBodyBytes
    : options.expectedResultBodyBytes
  if (!Number.isSafeInteger(expectedResultBodyBytes) || expectedResultBodyBytes < 0 ||
      expectedResultBodyBytes > profile.maxResultBodyBytes) {
    fail('BAD_CLIENT_INPUT', 'expectedResultBodyBytes exceeds the operation profile')
  }
  const resultDispatchBytes = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES + expectedResultBodyBytes
  const requiredOuterClass = smallestOuterClass(Math.max(dispatch.byteLength, resultDispatchBytes))
  if (options.outerClass != null && options.outerClass < requiredOuterClass) {
    fail('BAD_CLIENT_INPUT', 'selected outerClass cannot carry the expected response')
  }
  const envelope = encodeOuterEnvelope({
    innerDispatch: dispatch,
    outerClass: options.outerClass == null ? requiredOuterClass : options.outerClass
  }, {
    randomFill (padding) {
      if (padding.byteLength > 0) b4a.copy(randomBytes(options.runtime, padding.byteLength, 'outer padding'), padding)
    }
  })
  return {
    mediaType: PROTOCOL.mediaType,
    familyId: options.familyId,
    operationId: options.operationId,
    requestId: id,
    outerClass: envelope[1],
    expectedResultBodyBytes,
    body: envelope
  }
}

export function decodeUnaryResponse (bytes, expected) {
  if (!expected || typeof expected !== 'object') fail('BAD_CLIENT_INPUT', 'expected unary correlation is required')
  let envelope
  try {
    envelope = decodeOuterEnvelope(asBytes(bytes, 'unary response'), { copyInner: true, copyBody: true })
  } catch (error) {
    fail('RELAY_PROTOCOL_VIOLATION', 'relay response envelope is invalid', { cause: error })
  }
  const frame = envelope.frame
  if (expected.outerClass != null && envelope.outerClass !== expected.outerClass) {
    fail('RELAY_PROTOCOL_VIOLATION', 'relay changed the selected outer class')
  }
  if (frame.familyId !== expected.familyId || frame.operationId !== expected.operationId ||
      !sameBytes(frame.requestId, asBytes(expected.requestId, 'expected requestId', 16))) {
    fail('RELAY_PROTOCOL_VIOLATION', 'relay response correlation does not match the request')
  }
  if (frame.frameKind === FRAME_KIND.ERROR) {
    let remoteError
    try {
      remoteError = decodeCanonical(blindErrorV1, frame.body, { copyBytes: true })
    } catch (error) {
      fail('RELAY_PROTOCOL_VIOLATION', 'relay error body is invalid', { cause: error })
    }
    return {
      ok: false,
      outerClass: envelope.outerClass,
      frame,
      error: remoteError
    }
  }
  if (frame.frameKind !== FRAME_KIND.RESPONSE) {
    fail('RELAY_PROTOCOL_VIOLATION', 'unary relay response is not RESPONSE or ERROR')
  }
  if (!Number.isSafeInteger(expected.expectedResultBodyBytes) || expected.expectedResultBodyBytes < 0) {
    fail('BAD_CLIENT_INPUT', 'expected result body bound is required')
  }
  if (frame.body.byteLength > expected.expectedResultBodyBytes) {
    fail('RELAY_PROTOCOL_VIOLATION', 'relay success body exceeds the operation-specific result bound')
  }
  return { ok: true, outerClass: envelope.outerClass, frame, body: frame.body }
}
