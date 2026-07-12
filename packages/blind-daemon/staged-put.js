import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CELL_SIZE_CLASS,
  DISPATCH_LIMITS,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  cellStorageSlot,
  operationProfile,
  readDispatchLengthPrefix
} from '@hiverelay/blind-protocol'

const DISPATCH_WIRE_HEADER_BYTES = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES
const PUT_FIXED_PREFIX_BYTES = 263
const ADMISSION_FIXED_PREFIX_BYTES = 36
const MAX_ADMISSION_TOKEN_BYTES = 4096
const MAX_COMPACT_TOKEN_PREFIX_BYTES = 3
const CELL_PUT_MAX_REQUEST_BODY_BYTES = operationProfile(FAMILY.CELL, OPERATION.CELL.PUT).maxRequestBodyBytes
export const STAGED_CELL_PUT_MAX_PREFIX_BYTES = DISPATCH_WIRE_HEADER_BYTES + PUT_FIXED_PREFIX_BYTES +
  ADMISSION_FIXED_PREFIX_BYTES + MAX_COMPACT_TOKEN_PREFIX_BYTES + MAX_ADMISSION_TOKEN_BYTES
export const STAGED_CELL_PUT_DEFAULT_QUEUE_BYTES = 65_535
const STAGED_AUTHORITIES = new WeakMap()

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

function isZero (input) {
  for (const byte of input) if (byte !== 0) return false
  return true
}

function u16 (input, offset) {
  return (input[offset] << 8) | input[offset + 1]
}

function u32 (input, offset) {
  return b4a.readUInt32BE(input, offset)
}

function copy (input, start, end) {
  return b4a.from(input.subarray(start, end))
}

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => { resolve = _resolve; reject = _reject })
  // The producer can fail before the runtime starts awaiting metadata. Attach a
  // sink immediately while preserving rejection for the eventual consumer.
  promise.catch(() => {})
  return { promise, resolve, reject }
}

class BoundedAsyncByteQueue {
  constructor (maximum) {
    this.maximum = maximum
    this.items = []
    this.bufferedBytes = 0
    this.waitingConsumer = null
    this.waitingDrain = []
    this.closed = false
    this.failure = null
    this.claimed = false
    this.discarding = false
    this.pullCount = 0
  }

  async push (input) {
    const value = b4a.from(bytes(input, 'opaque PUT body chunk'))
    if (value.byteLength === 0) return
    if (this.discarding) return
    if (value.byteLength > this.maximum) {
      for (let offset = 0; offset < value.byteLength; offset += this.maximum) {
        await this.push(value.subarray(offset, Math.min(value.byteLength, offset + this.maximum)))
      }
      return
    }
    while (!this.failure && !this.closed && this.waitingConsumer == null &&
      this.bufferedBytes + value.byteLength > this.maximum) {
      await new Promise((resolve, reject) => this.waitingDrain.push({ resolve, reject }))
    }
    if (this.failure) throw this.failure
    if (this.discarding) return
    if (this.closed) fail('BAD_ENCODING', 'opaque PUT source received bytes after close')
    if (this.waitingConsumer) {
      const waiter = this.waitingConsumer
      this.waitingConsumer = null
      waiter.resolve({ done: false, value })
      return
    }
    this.items.push(value)
    this.bufferedBytes += value.byteLength
  }

  close () {
    if (this.closed || this.failure) return
    this.closed = true
    if (this.waitingConsumer) {
      const waiter = this.waitingConsumer
      this.waitingConsumer = null
      waiter.resolve({ done: true, value: undefined })
    }
    this.#wakeDrain()
  }

  discard () {
    if (this.failure || this.closed || this.discarding) return
    this.discarding = true
    this.items = []
    this.bufferedBytes = 0
    if (this.waitingConsumer) {
      const waiter = this.waitingConsumer
      this.waitingConsumer = null
      waiter.resolve({ done: true, value: undefined })
    }
    this.#wakeDrain()
  }

  fail (error) {
    if (this.failure) return
    this.failure = error instanceof Error ? error : new Error('opaque PUT source failed')
    if (this.waitingConsumer) {
      const waiter = this.waitingConsumer
      this.waitingConsumer = null
      waiter.reject(this.failure)
    }
    for (const waiter of this.waitingDrain.splice(0)) waiter.reject(this.failure)
  }

  #wakeDrain () {
    for (const waiter of this.waitingDrain.splice(0)) waiter.resolve()
  }

  source () {
    if (this.claimed) fail('BAD_ENCODING', 'opaque PUT source may only be consumed once')
    this.claimed = true
    const queue = this
    return Object.freeze({
      [Symbol.asyncIterator] () { return this },
      next () {
        queue.pullCount++
        if (queue.failure) return Promise.reject(queue.failure)
        if (queue.discarding) return Promise.resolve({ done: true, value: undefined })
        if (queue.items.length > 0) {
          const value = queue.items.shift()
          queue.bufferedBytes -= value.byteLength
          queue.#wakeDrain()
          return Promise.resolve({ done: false, value })
        }
        if (queue.closed) return Promise.resolve({ done: true, value: undefined })
        if (queue.waitingConsumer) return Promise.reject(new Error('opaque PUT source has concurrent consumers'))
        return new Promise((resolve, reject) => { queue.waitingConsumer = { resolve, reject } })
      },
      return () {
        const error = new Error('opaque PUT source consumer stopped before ingress completed')
        error.code = 'ABORT_ERR'
        queue.fail(error)
        return Promise.resolve({ done: true, value: undefined })
      }
    })
  }
}

function parseDispatchHeader (prefix) {
  if (prefix.byteLength < DISPATCH_WIRE_HEADER_BYTES) return null
  const frameLength = readDispatchLengthPrefix(prefix)
  const bodyLength = u32(prefix, 41)
  if (frameLength !== DISPATCH_LIMITS.HEADER_BYTES + bodyLength) {
    fail('BAD_ENCODING', 'staged dispatch body length does not match its frame length')
  }
  if (prefix[4] !== 1) fail('BAD_VERSION', 'dispatch version must be 1')
  if (prefix[5] !== FRAME_KIND.REQUEST || prefix[6] !== FAMILY.CELL || prefix[7] !== OPERATION.CELL.PUT ||
      prefix[8] !== 0 || isZero(prefix.subarray(9, 25)) || !isZero(prefix.subarray(25, 41))) {
    fail('BAD_ENCODING', 'staged stream is not one canonical CELL.PUT request')
  }
  if (bodyLength > CELL_PUT_MAX_REQUEST_BODY_BYTES) fail('TOO_LARGE', 'CELL.PUT body exceeds its operation cap')
  return Object.freeze({
    version: 1,
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    flags: 0,
    requestId: copy(prefix, 9, 25),
    streamId: 0n,
    sequence: 0n,
    bodyLength,
    dispatchBytes: DISPATCH_LIMITS.PREFIX_BYTES + frameLength
  })
}

function compactTokenLength (prefix, offset) {
  if (offset >= prefix.byteLength) return null
  const marker = prefix[offset]
  if (marker <= 0xfc) {
    if (marker < 1) fail('BAD_ENCODING', 'admission token length is outside 1..4096')
    return { value: marker, bytes: 1 }
  }
  if (marker !== 0xfd) fail('BAD_ENCODING', 'admission token length exceeds its canonical bound')
  if (offset + 3 > prefix.byteLength) return null
  const value = prefix[offset + 1] | (prefix[offset + 2] << 8)
  if (value <= 0xfc) fail('BAD_ENCODING', 'admission token length is not canonical')
  if (value > MAX_ADMISSION_TOKEN_BYTES) fail('BAD_ENCODING', 'admission token length is outside 1..4096')
  return { value, bytes: 3 }
}

function parsePutMetadata (prefix, header) {
  const bodyOffset = DISPATCH_WIRE_HEADER_BYTES
  const tokenLengthOffset = bodyOffset + PUT_FIXED_PREFIX_BYTES + ADMISSION_FIXED_PREFIX_BYTES
  const tokenLength = compactTokenLength(prefix, tokenLengthOffset)
  if (!tokenLength) return null
  const metadataBytes = PUT_FIXED_PREFIX_BYTES + ADMISSION_FIXED_PREFIX_BYTES + tokenLength.bytes + tokenLength.value
  const metadataEnd = bodyOffset + metadataBytes
  if (metadataEnd > STAGED_CELL_PUT_MAX_PREFIX_BYTES) fail('BAD_ENCODING', 'CELL.PUT metadata exceeds its staged bound')
  const version = prefix[bodyOffset]
  if (version !== 1) fail('BAD_VERSION', 'operation body version must be 1')
  const sizeClass = prefix[bodyOffset + 37]
  const leaseClass = prefix[bodyOffset + 38]
  const cellBytes = CELL_SIZE_CLASS[sizeClass]
  if (!cellBytes) fail('BAD_ENCODING', 'CELL.PUT sizeClass is outside 1..5')
  if (leaseClass < 1 || leaseClass > 4) fail('BAD_ENCODING', 'CELL.PUT leaseClass is outside 1..4')
  if (header.bodyLength !== metadataBytes + cellBytes) {
    fail('BAD_ENCODING', 'CELL.PUT declared dispatch length does not match metadata plus its exact cell class')
  }
  const profileId = u16(prefix, bodyOffset + PUT_FIXED_PREFIX_BYTES)
  const schemeId = u16(prefix, bodyOffset + PUT_FIXED_PREFIX_BYTES + 2)
  if (profileId === 0 || schemeId === 0) fail('BAD_ENCODING', 'CELL.PUT admission identifiers must be nonzero')
  const allocationEpoch = u32(prefix, bodyOffset + 33)
  const createPublicKey = copy(prefix, bodyOffset + 71, bodyOffset + 103)
  const storageSlot = copy(prefix, bodyOffset + 1, bodyOffset + 33)
  if (!b4a.equals(cellStorageSlot({ allocationEpoch, createPublicKey }), storageSlot)) {
    fail('BAD_ENCODING', 'CELL.PUT storageSlot is not self-certifying')
  }
  // Everything above is fixed-size or a bounded canonical length marker. It is
  // deliberately authoritative before any admission-token byte or opaque cell
  // body is buffered, hashed, queued, or exposed to a verifier.
  if (prefix.byteLength < metadataEnd) return null
  const admissionOffset = bodyOffset + PUT_FIXED_PREFIX_BYTES
  const tokenOffset = tokenLengthOffset + tokenLength.bytes
  const request = Object.freeze({
    version: 1,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    clientNonce: copy(prefix, bodyOffset + 39, bodyOffset + 71),
    createPublicKey,
    renewPublicKey: copy(prefix, bodyOffset + 103, bodyOffset + 135),
    dropPublicKey: copy(prefix, bodyOffset + 135, bodyOffset + 167),
    declaredBlobHash: copy(prefix, bodyOffset + 167, bodyOffset + 199),
    createSignature: copy(prefix, bodyOffset + 199, bodyOffset + 263),
    admission: Object.freeze({
      profileId,
      schemeId,
      parameterHash: copy(prefix, admissionOffset + 4, admissionOffset + 36),
      token: copy(prefix, tokenOffset, tokenOffset + tokenLength.value)
    })
  })
  return Object.freeze({
    request,
    metadataBytes,
    metadataEnd,
    cellBytes,
    canonicalRequestPrefixBytes: copy(prefix, bodyOffset, metadataEnd),
    canonicalDispatchPrefixBytes: copy(prefix, 0, metadataEnd)
  })
}

export class StagedCellPutDispatchIngestor {
  constructor (options = {}) {
    const queueBytes = options.maxQueuedBodyBytes == null
      ? STAGED_CELL_PUT_DEFAULT_QUEUE_BYTES
      : options.maxQueuedBodyBytes
    if (!Number.isSafeInteger(queueBytes) || queueBytes < 1 || queueBytes > STAGED_CELL_PUT_DEFAULT_QUEUE_BYTES) {
      throw new TypeError('maxQueuedBodyBytes is outside 1..65535')
    }
    this.queue = new BoundedAsyncByteQueue(queueBytes)
    this.prefix = b4a.alloc(0)
    this.header = null
    this.metadata = null
    this.receivedBytes = 0
    this.bodyReceivedBytes = 0
    this.finished = false
    this.failed = null
    this.metadataDeferred = deferred()
    this.validationDeferred = deferred()
    this.ready = this.metadataDeferred.promise
    this.hashState = b4a.alloc(sodium.crypto_generichash_STATEBYTES)
    sodium.crypto_generichash_init(this.hashState, null, 32)
  }

  #prefixTarget () {
    if (!this.header) return DISPATCH_WIRE_HEADER_BYTES
    const tokenLengthOffset = DISPATCH_WIRE_HEADER_BYTES + PUT_FIXED_PREFIX_BYTES + ADMISSION_FIXED_PREFIX_BYTES
    if (this.prefix.byteLength <= tokenLengthOffset) return tokenLengthOffset + 1
    const tokenLength = compactTokenLength(this.prefix, tokenLengthOffset)
    if (!tokenLength) return tokenLengthOffset + 3
    return tokenLengthOffset + tokenLength.bytes + tokenLength.value
  }

  #acceptPrefix () {
    if (!this.header && this.prefix.byteLength >= DISPATCH_WIRE_HEADER_BYTES) {
      this.header = parseDispatchHeader(this.prefix)
    }
    if (this.header && !this.metadata) {
      const metadata = parsePutMetadata(this.prefix, this.header)
      if (metadata) {
        this.metadata = metadata
        const source = this.queue.source()
        const authority = Object.freeze({
          frame: this.header,
          request: metadata.request,
          source,
          sourceByteLength: metadata.cellBytes,
          canonicalRequestPrefixBytes: metadata.canonicalRequestPrefixBytes,
          canonicalDispatchPrefixBytes: metadata.canonicalDispatchPrefixBytes,
          maximumBufferedBytes: STAGED_CELL_PUT_MAX_PREFIX_BYTES + this.queue.maximum
        })
        STAGED_AUTHORITIES.set(authority, Object.freeze({
          ...authority,
          ensureBodyValidated: async () => {
            this.queue.discard()
            return this.validationDeferred.promise
          },
          abort: error => {
            if (!this.finished && !this.failed) this.#fail(error, false)
          }
        }))
        this.metadataDeferred.resolve(authority)
      }
    }
  }

  async push (input) {
    if (this.failed) throw this.failed
    if (this.finished) fail('BAD_ENCODING', 'staged CELL.PUT received bytes after FIN')
    let chunk = bytes(input, 'staged CELL.PUT bytes')
    if (chunk.byteLength === 0) return
    if (this.receivedBytes + chunk.byteLength > DISPATCH_LIMITS.MAX_WIRE_BYTES) {
      return this.abort(Object.assign(new Error('staged dispatch exceeds its absolute cap'), { code: 'TOO_LARGE' }))
    }
    this.receivedBytes += chunk.byteLength
    if (this.header && this.receivedBytes > this.header.dispatchBytes) {
      return this.abort(Object.assign(new Error('staged dispatch has trailing bytes'), { code: 'BAD_ENCODING' }))
    }
    try {
      while (chunk.byteLength > 0 && !this.metadata) {
        const target = this.#prefixTarget()
        const take = Math.min(chunk.byteLength, target - this.prefix.byteLength)
        if (take <= 0) {
          this.#acceptPrefix()
          continue
        }
        this.prefix = b4a.concat([this.prefix, chunk.subarray(0, take)])
        chunk = chunk.subarray(take)
        if (this.prefix.byteLength > STAGED_CELL_PUT_MAX_PREFIX_BYTES) {
          fail('BAD_ENCODING', 'CELL.PUT metadata exceeds its staged bound')
        }
        this.#acceptPrefix()
      }
      if (this.header && this.receivedBytes > this.header.dispatchBytes) {
        fail('BAD_ENCODING', 'staged dispatch has trailing bytes')
      }
      if (this.metadata && chunk.byteLength > 0) {
        this.bodyReceivedBytes += chunk.byteLength
        if (this.bodyReceivedBytes > this.metadata.cellBytes) fail('BAD_ENCODING', 'CELL.PUT body exceeds its exact class')
        sodium.crypto_generichash_update(this.hashState, chunk)
        await this.queue.push(chunk)
      }
    } catch (error) {
      this.abort(error)
    }
  }

  finish () {
    if (this.failed) throw this.failed
    if (this.finished) fail('BAD_ENCODING', 'staged CELL.PUT FIN is duplicated')
    this.finished = true
    try {
      this.#acceptPrefix()
      if (!this.header || !this.metadata || this.receivedBytes !== this.header.dispatchBytes ||
          this.bodyReceivedBytes !== this.metadata.cellBytes) {
        fail('BAD_ENCODING', 'staged CELL.PUT ended before one exact dispatch and cell body')
      }
      const digest = b4a.alloc(32)
      sodium.crypto_generichash_final(this.hashState, digest)
      if (!b4a.equals(digest, this.metadata.request.declaredBlobHash)) {
        fail('BAD_ENCODING', 'CELL.PUT opaque body does not match declaredBlobHash')
      }
      this.queue.close()
      this.validationDeferred.resolve(Object.freeze({
        byteLength: this.bodyReceivedBytes,
        hash: digest
      }))
    } catch (error) {
      this.abort(error)
    }
  }

  abort (error) {
    if (this.failed) throw this.failed
    this.#fail(error, true)
    throw this.failed
  }

  #fail (error, rejectMetadata) {
    if (this.failed) return
    this.failed = error instanceof Error ? error : new Error('staged CELL.PUT ingress failed')
    this.queue.fail(this.failed)
    if (rejectMetadata) this.metadataDeferred.reject(this.failed)
    this.validationDeferred.reject(this.failed)
  }

  get bufferedBytes () {
    return this.prefix.byteLength + this.queue.bufferedBytes
  }

  get bodyPullCount () {
    return this.queue.pullCount
  }
}

export function stagedCellPutAuthority (input) {
  const authority = input && STAGED_AUTHORITIES.get(input)
  if (!authority) fail('BAD_ENCODING', 'staged CELL.PUT requires a branded ingress authority')
  return authority
}
