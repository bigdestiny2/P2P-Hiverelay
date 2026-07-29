import { randomFillSync } from 'node:crypto'
import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  OUTER_CLASS,
  blindErrorV1,
  blindReceiptV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  encodeDispatchFrame
} from '@hiverelay/blind-protocol'
import {
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_STAGED_FLAG_V2,
  LOCAL_STAGED_FRAME_KIND_V2,
  PRIVATE_IPC_V2_LIMITS,
  encodeLocalStagedCellPutFrameV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { StagedCellPutDispatchIngestor } from './staged-put.js'

const OUTER_HEADER_BYTES = 6
const MINIMUM_DISPATCH_BYTES = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES
const MAX_U64 = (1n << 64n) - 1n

export const STAGED_CELL_PUT_FRAME_READER_MAX_BUFFERED_BYTES_V2 =
  PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES
export const STAGED_CELL_PUT_FRAME_DECODER_MAX_BUFFERED_BYTES_V2 =
  (3 * PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES) +
  (2 * PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES)
export const STAGED_CELL_PUT_RESULT_ENCODER_MAX_BUFFERED_BYTES_V2 =
  (2 * (PRIVATE_IPC_V2_LIMITS.DISPATCH_HEADER_BYTES +
    PRIVATE_IPC_V2_LIMITS.CELL_PUT_MAX_RESULT_BODY_BYTES)) +
  OUTER_HEADER_BYTES +
  (2 * PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES) +
  PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function bytes (input, field) {
  if (!input || typeof input.byteLength !== 'number') fail('BAD_ENCODING', `${field} must be bytes`)
  if (b4a.isBuffer(input)) return input
  if (ArrayBuffer.isView(input)) return b4a.from(input.buffer, input.byteOffset, input.byteLength)
  return b4a.from(input)
}

function monotonic (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_ENCODING', `${field} must be a u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    fail('BAD_ENCODING', `${field} must be a u64`)
  }
  return value
}

function replayKey (input) {
  if (typeof input === 'string' && input.length > 0) {
    return input
  }
  const value = bytes(input, 'replay key')
  if (value.byteLength < 1 || value.byteLength > 512) fail('BAD_ENCODING', 'replay key is outside 1..512 bytes')
  return b4a.toString(value, 'hex')
}

function canonicalStagedCellPutResultDispatch (input, requestIdInput) {
  const source = b4a.from(bytes(input, 'staged CELL.PUT result dispatch'))
  const requestId = b4a.from(bytes(requestIdInput, 'staged CELL.PUT requestId'))
  if (requestId.byteLength !== DISPATCH_LIMITS.REQUEST_ID_BYTES) {
    fail('BAD_LOCAL_STREAM', 'staged CELL.PUT requestId must be exactly 16 bytes')
  }
  let frame
  let canonicalBody
  try {
    frame = decodeDispatchFrame(source, { copyBody: true })
    if ((frame.frameKind !== FRAME_KIND.RESPONSE && frame.frameKind !== FRAME_KIND.ERROR) ||
        frame.familyId !== FAMILY.CELL || frame.operationId !== OPERATION.CELL.PUT ||
        frame.flags !== 0 || frame.streamId !== 0n || frame.sequence !== 0n ||
        !b4a.equals(frame.requestId, requestId)) {
      throw new Error('result correlation mismatch')
    }
    const schema = frame.frameKind === FRAME_KIND.RESPONSE ? blindReceiptV1 : blindErrorV1
    canonicalBody = encodeCanonical(schema, decodeCanonical(schema, frame.body, { copyBytes: true }))
    if (!b4a.equals(canonicalBody, frame.body)) throw new Error('non-canonical result body')
    const canonicalDispatch = encodeDispatchFrame({ ...frame, body: canonicalBody })
    if (!b4a.equals(canonicalDispatch, source)) throw new Error('non-canonical result dispatch')
  } catch {
    fail('BAD_LOCAL_STREAM', 'staged CELL.PUT dispatcher returned a non-canonical or uncorrelated result')
  }
  return source
}

// Builds the same-class public outer envelope lazily. Only the canonical
// dispatch snapshot, six-byte header, one content chunk and its encoded frame
// coexist; class-sized padding is generated with the OS CSPRNG as it is sent.
export class StagedCellPutResultEncoderV2 {
  constructor (options = {}) {
    const classBytes = OUTER_CLASS[options.outerClass]
    if (!classBytes) fail('BAD_ENCODING', 'staged CELL.PUT result outer class is not registered')
    const dispatch = canonicalStagedCellPutResultDispatch(options.dispatch, options.requestId)
    if (OUTER_HEADER_BYTES + dispatch.byteLength > classBytes) {
      fail('TOO_LARGE', 'staged CELL.PUT result dispatch does not fit its authenticated outer class')
    }
    const randomFill = options.randomFill == null ? randomFillSync : options.randomFill
    if (typeof randomFill !== 'function') throw new TypeError('randomFill must be a function')
    const header = b4a.alloc(OUTER_HEADER_BYTES)
    header[0] = 1
    header[1] = options.outerClass
    b4a.writeUInt32BE(header, dispatch.byteLength, 2)
    this.outerClass = options.outerClass
    this.classBytes = classBytes
    this.dispatch = dispatch
    this.header = header
    this.randomFill = randomFill
    this.sequence = 0n
    this.emittedOuterBytes = 0
    this.frameCount = 0
    this.maximumBufferedBytes = dispatch.byteLength + header.byteLength
  }

  [Symbol.iterator] () {
    return this
  }

  return () {
    this.emittedOuterBytes = this.classBytes
    this.header = null
    this.dispatch = null
    this.randomFill = null
    return { done: true, value: undefined }
  }

  next () {
    if (this.emittedOuterBytes === this.classBytes) return { done: true, value: undefined }
    const contentLength = Math.min(
      PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES,
      this.classBytes - this.emittedOuterBytes
    )
    const content = b4a.alloc(contentLength)
    const start = this.emittedOuterBytes
    let cursor = 0
    if (start < OUTER_HEADER_BYTES) {
      const take = Math.min(contentLength, OUTER_HEADER_BYTES - start)
      b4a.copy(this.header, content, 0, start, start + take)
      cursor += take
    }
    const dispatchStart = Math.max(0, start + cursor - OUTER_HEADER_BYTES)
    if (dispatchStart < this.dispatch.byteLength && cursor < contentLength) {
      const take = Math.min(contentLength - cursor, this.dispatch.byteLength - dispatchStart)
      b4a.copy(this.dispatch, content, cursor, dispatchStart, dispatchStart + take)
      cursor += take
    }
    if (cursor < contentLength) this.randomFill(content.subarray(cursor))
    const final = start + contentLength === this.classBytes
    const frame = encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.RESULT,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
      sequence: this.sequence++,
      flags: final ? LOCAL_STAGED_FLAG_V2.FIN : 0,
      bytes: content
    })
    this.maximumBufferedBytes = Math.max(this.maximumBufferedBytes,
      this.header.byteLength + this.dispatch.byteLength + content.byteLength + frame.byteLength)
    this.emittedOuterBytes += contentLength
    this.frameCount++
    if (final) {
      this.header = null
      this.dispatch = null
      this.randomFill = null
    }
    return { done: false, value: frame }
  }
}

// One timer covers generator work and every frame write. A stalled later frame
// cannot obtain a fresh timeout after earlier frames consumed most of the
// response budget.
export async function writeSocketFramesWithinDeadlineV2 (socket, frames, timeoutMillis, options = {}) {
  if (!socket || typeof socket.write !== 'function' || typeof socket.destroy !== 'function') {
    throw new TypeError('writable socket is required')
  }
  const end = options.end === true
  if (end && typeof socket.end !== 'function') throw new TypeError('ending writable socket is required')
  if (!Number.isSafeInteger(timeoutMillis) || timeoutMillis < 1) {
    throw new TypeError('timeoutMillis must be a positive safe integer')
  }
  const iterator = frames && typeof frames[Symbol.asyncIterator] === 'function'
    ? frames[Symbol.asyncIterator]()
    : frames && typeof frames[Symbol.iterator] === 'function'
      ? frames[Symbol.iterator]()
      : null
  if (!iterator || typeof iterator.next !== 'function') throw new TypeError('frame iterable is required')
  let rejectDeadline
  const timeoutError = Object.assign(new Error('private stream response write timed out'), {
    code: 'IPC_WRITE_TIMEOUT'
  })
  const deadline = new Promise((_resolve, reject) => { rejectDeadline = reject })
  const timer = setTimeout(() => {
    rejectDeadline(timeoutError)
    if (!socket.destroyed) socket.destroy()
  }, timeoutMillis)
  if (timer.unref) timer.unref()
  try {
    for (;;) {
      const item = await Promise.race([
        Promise.resolve().then(() => iterator.next()),
        deadline
      ])
      if (!item || item.done) break
      if (socket.destroyed) throw new Error('private stream closed before response write')
      const written = new Promise((resolve, reject) => {
        socket.write(item.value, error => error ? reject(error) : resolve())
      })
      await Promise.race([written, deadline])
    }
    if (end) {
      if (socket.destroyed) throw new Error('private stream closed before response half-close')
      const ended = new Promise(resolve => socket.end(resolve))
      await Promise.race([ended, deadline])
    }
  } finally {
    clearTimeout(timer)
    if (typeof iterator.return === 'function') {
      try {
        const returned = iterator.return()
        if (returned && typeof returned.catch === 'function') returned.catch(() => {})
      } catch {}
    }
  }
}

// A replay reservation is deliberately not releasable. Once an authenticated
// edge has presented a tuple, an aborted or malformed body cannot make that
// tuple fresh again. Expiry is the only removal path.
export class BoundedReplayGuardV2 {
  constructor (options = {}) {
    this.capacity = options.capacity == null ? 4096 : options.capacity
    this.maximumTtlMillis = options.maximumTtlMillis == null
      ? 15_000n
      : monotonic(options.maximumTtlMillis, 'maximumTtlMillis')
    if (!Number.isSafeInteger(this.capacity) || this.capacity < 1 || this.capacity > 1_000_000) {
      throw new TypeError('replay capacity is outside 1..1000000')
    }
    if (this.maximumTtlMillis < 1n) throw new TypeError('maximumTtlMillis must be positive')
    this.entries = new Map()
  }

  reserve (keyInput, expiresMonotonicMillis, nowMonotonicMillis) {
    const key = replayKey(keyInput)
    const now = monotonic(nowMonotonicMillis, 'nowMonotonicMillis')
    const expires = monotonic(expiresMonotonicMillis, 'expiresMonotonicMillis')
    if (expires <= now || expires - now > this.maximumTtlMillis) {
      fail('PRIVATE_IPC_V2_EXPIRED', 'replay reservation expiry is not live and bounded')
    }
    this.prune(now)
    if (this.entries.has(key)) fail('PRIVATE_IPC_V2_REPLAY', 'staged CELL.PUT replay tuple is already reserved')
    // Never evict a live reservation to admit a new request.
    if (this.entries.size >= this.capacity) {
      fail('BLIND_STREAM_BUSY', 'staged CELL.PUT replay guard is at live capacity')
    }
    this.entries.set(key, expires)
    return Object.freeze({ key, expiresMonotonicMillis: expires })
  }

  prune (nowMonotonicMillis) {
    const now = monotonic(nowMonotonicMillis, 'nowMonotonicMillis')
    for (const [key, expires] of this.entries) {
      if (expires <= now) this.entries.delete(key)
    }
  }

  has (keyInput, nowMonotonicMillis) {
    this.prune(nowMonotonicMillis)
    return this.entries.has(replayKey(keyInput))
  }

  get size () {
    return this.entries.size
  }
}

// Mechanism only: this parser cannot grant peer, topology, profile, readiness,
// or replay authority. BlindDaemon constructs it only after those gates pass.
// It strips the six-byte public envelope header, streams exactly innerLength
// bytes into the existing bounded CELL.PUT ingestor, and counts padding without
// retaining it.
export class StagedCellPutOuterEnvelopeIngestorV2 {
  constructor (options = {}) {
    const open = options.open
    if (!open || typeof open !== 'object' || open.version !== 2) {
      throw new TypeError('decoded private IPC V2 open is required')
    }
    const classBytes = OUTER_CLASS[open.outerClass]
    if (!classBytes || open.requestEnvelopeBytes !== classBytes) {
      throw new TypeError('V2 open does not select one exact public outer class')
    }
    this.open = open
    this.ingestor = options.ingestor || new StagedCellPutDispatchIngestor(options)
    this.ready = this.ingestor.ready
    this.expectedBytes = classBytes
    this.outerHeader = b4a.alloc(OUTER_HEADER_BYTES)
    this.outerHeaderBytes = 0
    this.innerLength = null
    this.innerBytes = 0
    this.paddingBytes = 0
    this.receivedBytes = 0
    this.finished = false
    this.failed = null
  }

  #acceptHeader () {
    if (this.outerHeaderBytes !== OUTER_HEADER_BYTES || this.innerLength != null) return
    if (this.outerHeader[0] !== 1) fail('BAD_VERSION', 'public outer envelope version must be 1')
    if (this.outerHeader[1] !== this.open.outerClass) {
      fail('BAD_ENCODING', 'public outer envelope class differs from authenticated V2 open')
    }
    const innerLength = b4a.readUInt32BE(this.outerHeader, 2)
    if (innerLength < MINIMUM_DISPATCH_BYTES || OUTER_HEADER_BYTES + innerLength > this.expectedBytes) {
      fail('BAD_ENCODING', 'public outer envelope inner length is outside its selected class')
    }
    this.innerLength = innerLength
  }

  async push (input) {
    if (this.failed) throw this.failed
    if (this.finished) fail('BAD_ENCODING', 'V2 staged CELL.PUT received bytes after terminal completion')
    let chunk = bytes(input, 'V2 staged CELL.PUT outer bytes')
    if (chunk.byteLength === 0) return
    if (this.receivedBytes + chunk.byteLength > this.expectedBytes) {
      return this.abort(Object.assign(new Error('V2 staged CELL.PUT exceeds its exact outer class'), {
        code: 'BAD_ENCODING'
      }))
    }
    this.receivedBytes += chunk.byteLength
    try {
      if (this.outerHeaderBytes < OUTER_HEADER_BYTES) {
        const take = Math.min(chunk.byteLength, OUTER_HEADER_BYTES - this.outerHeaderBytes)
        b4a.copy(chunk, this.outerHeader, this.outerHeaderBytes, 0, take)
        this.outerHeaderBytes += take
        chunk = chunk.subarray(take)
        this.#acceptHeader()
      }
      if (this.innerLength != null && this.innerBytes < this.innerLength && chunk.byteLength > 0) {
        const take = Math.min(chunk.byteLength, this.innerLength - this.innerBytes)
        await this.ingestor.push(chunk.subarray(0, take))
        this.innerBytes += take
        chunk = chunk.subarray(take)
      }
      if (chunk.byteLength > 0) this.paddingBytes += chunk.byteLength
    } catch (error) {
      return this.abort(error)
    }
  }

  finishRequest () {
    if (this.failed) throw this.failed
    if (this.finished) fail('BAD_ENCODING', 'V2 staged CELL.PUT completion is duplicated')
    this.finished = true
    try {
      this.#acceptHeader()
      if (this.receivedBytes !== this.expectedBytes || this.outerHeaderBytes !== OUTER_HEADER_BYTES ||
          this.innerLength == null || this.innerBytes !== this.innerLength ||
          this.paddingBytes !== this.expectedBytes - OUTER_HEADER_BYTES - this.innerLength) {
        fail('BAD_ENCODING', 'V2 staged CELL.PUT ended before one exact full outer envelope')
      }
      this.ingestor.finish()
    } catch (error) {
      this.failed = error
      try { this.ingestor.abort(error) } catch {}
      throw error
    }
  }

  abort (error) {
    if (this.failed) throw this.failed
    this.failed = error instanceof Error ? error : new Error('V2 staged CELL.PUT ingress failed')
    try { this.ingestor.abort(this.failed) } catch {}
    throw this.failed
  }

  get maximumBufferedBytes () {
    return OUTER_HEADER_BYTES + this.ingestor.bufferedBytes
  }
}
