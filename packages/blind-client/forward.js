import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  FAMILY,
  FORWARD_CIRCUIT_CLASS,
  FORWARD_CLOSE_KIND,
  FRAME_KIND,
  OPERATION,
  STREAM_WIRE_CLASS,
  operationProfile
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { forwardOpenRequestCommitment } from '@hiverelay/blind-protocol/hashes'
import {
  blindErrorV1,
  blindForwardCloseV1,
  blindForwardDataV1,
  blindForwardOpenV1,
  blindForwardWindowV1
} from '@hiverelay/blind-protocol/schemas'
import { decodeCanonical, encodeCanonical } from '@hiverelay/blind-protocol/codec'
import { decodeDispatchFrame, encodeDispatchFrame } from '@hiverelay/blind-protocol/dispatch'
import { asBytes, randomBytes } from './bytes.js'
import { fail } from './errors.js'
import { resolveAdmission } from './provider.js'

const MAX_U64 = (1n << 64n) - 1n
const ZERO_REQUEST_ID = b4a.alloc(16)
const FIRST_NOISE_FLIGHT_BYTES = 64

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('BAD_CLIENT_INPUT', `${field} must be within ${minimum}..${maximum}`)
  }
  return value
}

function u64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_CLIENT_INPUT', `${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) {
    fail('BAD_CLIENT_INPUT', `${field} is outside its u64 bounds`)
  }
  return value
}

function fixed (value, length, field, nonzero = false) {
  const bytes = b4a.from(asBytes(value, field, length))
  if (nonzero && bytes.every(byte => byte === 0)) fail('BAD_CLIENT_INPUT', `${field} must be nonzero`)
  return bytes
}

function randomNonzero (runtime, length, field) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const bytes = randomBytes(runtime, length, field)
    if (!bytes.every(byte => byte === 0)) return bytes
  }
  fail('RNG_FAILURE', `${field} remained zero`)
}

async function admission (options, context) {
  return resolveAdmission(options, context, true,
    'forward open requires an admission provider or admission value')
}

function sameBytes (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

export async function createForwardOpenRequest (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'forward open options are required')
  const previousRelayKey = fixed(options.previousRelayKey, 32, 'previousRelayKey', true)
  const routeId = fixed(options.routeId, 16, 'routeId', true)
  const nextDescriptorSequence = u64(options.nextDescriptorSequence, 'nextDescriptorSequence')
  const nextDescriptorHash = fixed(options.nextDescriptorHash, 32, 'nextDescriptorHash', true)
  const requestedWireClass = integer(options.requestedWireClass, 1, 3, 'requestedWireClass')
  const circuitClass = integer(options.circuitClass, 1, 3, 'circuitClass')
  const circuitNonce = options.circuitNonce == null
    ? randomNonzero(options.runtime, 32, 'circuitNonce')
    : fixed(options.circuitNonce, 32, 'circuitNonce', true)
  const innerHandshake = fixed(options.innerHandshake, 32, 'innerHandshake')
  if (options.expectedInnerHandshakeBytes != null) {
    integer(options.expectedInnerHandshakeBytes, 32, 32, 'expectedInnerHandshakeBytes')
  }
  const requestCommitment = forwardOpenRequestCommitment({
    previousRelayKey,
    routeId,
    nextDescriptorSequence,
    nextDescriptorHash,
    requestedWireClass,
    circuitClass,
    circuitNonce,
    innerHandshake
  })
  const hopAdmission = await admission(options, {
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.OPEN,
    requestCommitment,
    relayPublicKey: previousRelayKey,
    routeId,
    requestedWireClass,
    circuitClass
  })
  const request = {
    version: 1,
    routeId,
    nextDescriptorSequence,
    nextDescriptorHash,
    requestedWireClass,
    circuitClass,
    circuitNonce,
    hopAdmission,
    innerHandshake
  }
  const profile = operationProfile(FAMILY.FORWARD, OPERATION.FORWARD.OPEN)
  return {
    request,
    requestBytes: encodeCanonical(blindForwardOpenV1, request),
    requestCommitment,
    circuitNonce: b4a.from(circuitNonce),
    wire: Object.freeze({
      familyId: FAMILY.FORWARD,
      operationId: OPERATION.FORWARD.OPEN,
      expectedResultBodyBytes: profile.maxResultBodyBytes,
      requiresAuthenticatedStream: true
    })
  }
}

export class ForwardClientCircuit {
  constructor (options) {
    if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'forward circuit options are required')
    this.streamId = u64(options.streamId, 'streamId', true)
    this.circuitNonce = fixed(options.circuitNonce, 32, 'circuitNonce', true)
    this.wireClass = integer(options.grantedWireClass, 1, 3, 'grantedWireClass')
    this.circuitClass = integer(options.circuitClass, 1, 3, 'circuitClass')
    const circuit = FORWARD_CIRCUIT_CLASS[this.circuitClass]
    this.maxDataBytes = STREAM_WIRE_CLASS[this.wireClass]
    this.maxCircuitBytes = BigInt(circuit.maxCircuitBytes)
    this.maximumCredit = BigInt(DISPATCH_LIMITS.MAX_FORWARD_WINDOW_BYTES)
    if (options.grantedInitialWindow != null && options.grantedInitialWindow !== circuit.grantedInitialWindow) {
      fail('BAD_CLIENT_INPUT', 'grantedInitialWindow does not match circuitClass')
    }
    if (options.maxDataBytes != null && options.maxDataBytes !== this.maxDataBytes) {
      fail('BAD_CLIENT_INPUT', 'maxDataBytes does not match grantedWireClass')
    }
    if (options.maxCircuitBytes != null && u64(options.maxCircuitBytes, 'maxCircuitBytes') !== this.maxCircuitBytes) {
      fail('BAD_CLIENT_INPUT', 'maxCircuitBytes does not match circuitClass')
    }
    this.sendCredit = BigInt(circuit.grantedInitialWindow)
    this.receiveCredit = BigInt(circuit.grantedInitialWindow)
    this.sendOffset = 0n
    this.receiveOffset = 0n
    this.peerConsumedThrough = 0n
    this.localConsumedThrough = 0n
    this.sendSequence = -1n
    this.receiveSequence = -1n
    this.sentFrames = 0
    this.receivedFrames = 0
    this.sendFinished = false
    this.receiveFinished = false
    this.aborted = false
  }

  _assertActive () {
    if (this.aborted) fail('CIRCUIT_CLOSED', 'forward circuit is aborted')
  }

  _encode (operationId, encoding, value) {
    const sequence = this.sendSequence + 1n
    if (sequence > MAX_U64) fail('CIRCUIT_CLOSED', 'forward send sequence exhausted')
    const body = encodeCanonical(encoding, value)
    const frame = encodeDispatchFrame({
      frameKind: FRAME_KIND.STREAM,
      familyId: FAMILY.FORWARD,
      operationId,
      requestId: ZERO_REQUEST_ID,
      streamId: this.streamId,
      sequence,
      body
    })
    this.sendSequence = sequence
    this.sentFrames++
    return frame
  }

  encodeData (value) {
    this._assertActive()
    if (this.sendFinished) fail('CIRCUIT_CLOSED', 'forward send side is finished')
    const bytes = b4a.from(asBytes(value, 'forward data'))
    const expectedBytes = this.sendOffset === 0n ? FIRST_NOISE_FLIGHT_BYTES : this.maxDataBytes
    if (bytes.byteLength !== expectedBytes) {
      fail('BAD_CLIENT_INPUT', `forward data must contain exactly ${expectedBytes} bytes at this offset`)
    }
    const length = BigInt(bytes.byteLength)
    if (length > this.sendCredit) fail('BACKPRESSURE', 'forward data exceeds granted send credit')
    if (this.sendOffset + length > this.maxCircuitBytes) fail('CIRCUIT_LIMIT', 'forward data exceeds circuit byte cap')
    const offset = this.sendOffset
    const frame = this._encode(OPERATION.FORWARD.DATA, blindForwardDataV1, {
      version: 1,
      circuitNonce: this.circuitNonce,
      offset,
      bytes
    })
    this.sendOffset += length
    this.sendCredit -= length
    return frame
  }

  encodeWindow (consumedThrough, creditIncrement) {
    this._assertActive()
    consumedThrough = u64(consumedThrough, 'consumedThrough')
    creditIncrement = integer(creditIncrement, 1, DISPATCH_LIMITS.MAX_FORWARD_WINDOW_BYTES, 'creditIncrement')
    if (consumedThrough <= this.localConsumedThrough || consumedThrough > this.receiveOffset) {
      fail('BAD_CLIENT_INPUT', 'consumedThrough must advance within received bytes')
    }
    const consumedDelta = consumedThrough - this.localConsumedThrough
    if (BigInt(creditIncrement) > consumedDelta) {
      fail('BAD_CLIENT_INPUT', 'creditIncrement exceeds newly consumed bytes')
    }
    const nextCredit = this.receiveCredit + BigInt(creditIncrement)
    const outstanding = this.receiveOffset - consumedThrough
    if (nextCredit + outstanding > this.maximumCredit) {
      fail('BAD_CLIENT_INPUT', 'receive available plus outstanding credit would exceed the protocol cap')
    }
    const frame = this._encode(OPERATION.FORWARD.WINDOW, blindForwardWindowV1, {
      version: 1,
      circuitNonce: this.circuitNonce,
      consumedThrough,
      creditIncrement
    })
    this.localConsumedThrough = consumedThrough
    this.receiveCredit = nextCredit
    return frame
  }

  encodeClose (options = {}) {
    this._assertActive()
    const closeKind = options.closeKind == null ? FORWARD_CLOSE_KIND.FIN : options.closeKind
    integer(closeKind, FORWARD_CLOSE_KIND.FIN, FORWARD_CLOSE_KIND.ABORT, 'closeKind')
    const reasonCode = options.reasonCode == null ? 0 : integer(options.reasonCode, 0, 255, 'reasonCode')
    if (this.sendFinished) fail('CIRCUIT_CLOSED', 'forward send side is already finished')
    const frame = this._encode(OPERATION.FORWARD.CLOSE, blindForwardCloseV1, {
      version: 1,
      circuitNonce: this.circuitNonce,
      closeKind,
      finalSendOffset: this.sendOffset,
      reasonCode
    })
    this.sendFinished = true
    if (closeKind === FORWARD_CLOSE_KIND.ABORT) {
      this.aborted = true
      this.receiveFinished = true
    }
    return frame
  }

  accept (input) {
    this._assertActive()
    try {
      return this._acceptFrame(input)
    } catch (error) {
      this.aborted = true
      this.sendFinished = true
      this.receiveFinished = true
      throw error
    }
  }

  _acceptFrame (input) {
    let frame
    try {
      frame = decodeDispatchFrame(asBytes(input, 'forward dispatch frame'), { copyBody: true })
    } catch (error) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward dispatch frame is invalid', { cause: error })
    }
    if (frame.familyId !== FAMILY.FORWARD || frame.streamId !== this.streamId ||
        frame.sequence !== this.receiveSequence + 1n) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward stream correlation or sequence is invalid')
    }
    if (frame.frameKind === FRAME_KIND.ERROR) {
      let errorValue
      try {
        errorValue = decodeCanonical(blindErrorV1, frame.body, { copyBytes: true })
      } catch (error) {
        fail('RELAY_PROTOCOL_VIOLATION', 'forward stream error is invalid', { cause: error })
      }
      this.receiveSequence = frame.sequence
      this.aborted = true
      this.sendFinished = true
      this.receiveFinished = true
      return { type: 'error', error: errorValue }
    }
    if (frame.frameKind !== FRAME_KIND.STREAM) fail('RELAY_PROTOCOL_VIOLATION', 'forward frame is not stream data')
    let value
    try {
      if (frame.operationId === OPERATION.FORWARD.DATA) value = decodeCanonical(blindForwardDataV1, frame.body, { copyBytes: true })
      else if (frame.operationId === OPERATION.FORWARD.WINDOW) value = decodeCanonical(blindForwardWindowV1, frame.body, { copyBytes: true })
      else if (frame.operationId === OPERATION.FORWARD.CLOSE) value = decodeCanonical(blindForwardCloseV1, frame.body, { copyBytes: true })
      else fail('RELAY_PROTOCOL_VIOLATION', 'unknown forward stream operation')
    } catch (error) {
      if (error && error.code === 'RELAY_PROTOCOL_VIOLATION') throw error
      fail('RELAY_PROTOCOL_VIOLATION', 'forward stream body is invalid', { cause: error })
    }
    if (!sameBytes(value.circuitNonce, this.circuitNonce)) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward circuit nonce does not match')
    }
    let output
    if (frame.operationId === OPERATION.FORWARD.DATA) output = this._acceptData(value)
    else if (frame.operationId === OPERATION.FORWARD.WINDOW) output = this._acceptWindow(value)
    else output = this._acceptClose(value)
    this.receiveSequence = frame.sequence
    this.receivedFrames++
    return output
  }

  _acceptData (value) {
    if (this.receiveFinished) fail('RELAY_PROTOCOL_VIOLATION', 'received DATA after peer close')
    const offset = u64(value.offset, 'offset')
    if (offset !== this.receiveOffset) fail('RELAY_PROTOCOL_VIOLATION', 'forward DATA offset is not contiguous')
    const expectedBytes = offset === 0n ? FIRST_NOISE_FLIGHT_BYTES : this.maxDataBytes
    if (value.bytes.byteLength !== expectedBytes) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward DATA does not match its negotiated wire class')
    }
    const length = BigInt(value.bytes.byteLength)
    if (length > this.receiveCredit || this.receiveOffset + length > this.maxCircuitBytes) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward DATA exceeds credit or circuit byte cap')
    }
    this.receiveOffset += length
    this.receiveCredit -= length
    return { type: 'data', offset, bytes: value.bytes }
  }

  _acceptWindow (value) {
    const consumedThrough = u64(value.consumedThrough, 'consumedThrough')
    if (consumedThrough <= this.peerConsumedThrough || consumedThrough > this.sendOffset) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward WINDOW does not advance within sent bytes')
    }
    const consumedDelta = consumedThrough - this.peerConsumedThrough
    if (BigInt(value.creditIncrement) > consumedDelta) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward WINDOW credit exceeds newly consumed bytes')
    }
    const nextCredit = this.sendCredit + BigInt(value.creditIncrement)
    const outstanding = this.sendOffset - consumedThrough
    if (nextCredit + outstanding > this.maximumCredit) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward WINDOW available plus outstanding credit exceeds cap')
    }
    this.peerConsumedThrough = consumedThrough
    this.sendCredit = nextCredit
    return { type: 'window', consumedThrough, creditIncrement: value.creditIncrement }
  }

  _acceptClose (value) {
    const finalSendOffset = u64(value.finalSendOffset, 'finalSendOffset')
    if (finalSendOffset !== this.receiveOffset) {
      fail('RELAY_PROTOCOL_VIOLATION', 'forward CLOSE final offset does not match received bytes')
    }
    this.receiveFinished = true
    if (value.closeKind === FORWARD_CLOSE_KIND.ABORT) {
      this.aborted = true
      this.sendFinished = true
    }
    return { type: 'close', closeKind: value.closeKind, finalSendOffset, reasonCode: value.reasonCode }
  }

  snapshot () {
    return Object.freeze({
      streamId: this.streamId,
      sendSequence: this.sendSequence,
      receiveSequence: this.receiveSequence,
      sendOffset: this.sendOffset,
      receiveOffset: this.receiveOffset,
      sendCredit: this.sendCredit,
      receiveCredit: this.receiveCredit,
      sendFinished: this.sendFinished,
      receiveFinished: this.receiveFinished,
      aborted: this.aborted
    })
  }
}
