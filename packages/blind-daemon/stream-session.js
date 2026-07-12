import crypto from 'node:crypto'
import b4a from 'b4a'
import {
  BlindProtocolError,
  FAMILY,
  blake2b256
} from '@hiverelay/blind-protocol'

const MAX_U64 = (1n << 64n) - 1n
const DEFAULT_MAX_STREAMS = 1024
const DEFAULT_MAX_PENDING_TICKETS = 1024
const DEFAULT_MAX_BUFFERED_BYTES = 64 * 1024 * 1024
const DEFAULT_MAX_STREAM_BUFFERED_BYTES = 1024 * 1024 + 65535
const DEFAULT_TICKET_TTL_MILLIS = 2000
const TICKET_BYTES = 32
const BINDING_DOMAIN = b4a.from('hiverelay.blind.private-stream-ticket-binding.v1', 'ascii')

function fail (code, message) {
  throw new BlindProtocolError(code, message)
}

function positiveInteger (value, fallback, field) {
  if (value == null) return fallback
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${field} must be a positive safe integer`)
  return value
}

function currentMonotonic (now) {
  const value = now()
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new TypeError('monotonicMillis must return a u64 bigint')
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_ENCODING', `${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    fail('BAD_ENCODING', `${field} is outside u64`)
  }
  return value
}

function encodeU64 (value, field) {
  value = u64(value, field)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function bytes (value, field, minimum = 1, maximum = 256) {
  if (typeof value === 'string') value = b4a.from(value, 'utf8')
  if (!value || typeof value.byteLength !== 'number') fail('BAD_ENCODING', `${field} must be bytes or a string`)
  const output = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (output.byteLength < minimum || output.byteLength > maximum) {
    fail('BAD_ENCODING', `${field} must be ${minimum}..${maximum} bytes`)
  }
  return output
}

function fixed32 (value, field) {
  return bytes(value, field, 32, 32)
}

function nonzeroRandomTicket (randomBytes) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const token = bytes(randomBytes(TICKET_BYTES), 'random ticket', TICKET_BYTES, TICKET_BYTES)
    for (const byte of token) {
      if (byte !== 0) return b4a.from(token)
    }
  }
  throw new Error('ticket entropy source repeatedly returned the all-zero token')
}

function scheduleTimeout (callback, delay) {
  const timer = setTimeout(callback, delay)
  if (timer.unref) timer.unref()
  return timer
}

function normalizeReadiness (value, now) {
  if (!value || typeof value !== 'object') fail('EXPIRED', 'stream requires a readiness descriptor fence')
  const descriptorSequence = u64(value.descriptorSequence, 'descriptorSequence')
  const descriptorHash = b4a.from(fixed32(value.descriptorHash, 'descriptorHash'))
  const expiresMonotonicMillis = u64(value.expiresMonotonicMillis, 'expiresMonotonicMillis')
  if (expiresMonotonicMillis <= now) fail('EXPIRED', 'stream readiness has expired')
  return { descriptorSequence, descriptorHash, expiresMonotonicMillis }
}

function streamKey (family, streamId) {
  if (family !== FAMILY.CORE && family !== FAMILY.FORWARD) {
    fail('BAD_ENCODING', 'private stream family must be CORE or FORWARD')
  }
  streamId = u64(streamId, 'streamId')
  if (streamId === 0n) fail('BAD_ENCODING', 'streamId must be nonzero')
  return `${family}:${streamId}`
}

export function streamTicketBinding (value) {
  if (!value || typeof value !== 'object') fail('BAD_ENCODING', 'stream ticket binding must be an object')
  const family = value.family
  if (family !== FAMILY.CORE && family !== FAMILY.FORWARD) {
    fail('BAD_ENCODING', 'stream ticket family must be CORE or FORWARD')
  }
  const parentSessionId = bytes(value.parentSessionId, 'parentSessionId')
  if (parentSessionId.byteLength > 0xffff) fail('BAD_ENCODING', 'parentSessionId is too long')
  const streamId = u64(value.streamId, 'streamId')
  if (streamId === 0n) fail('BAD_ENCODING', 'streamId must be nonzero')
  const parentLength = b4a.alloc(2)
  parentLength[0] = parentSessionId.byteLength >>> 8
  parentLength[1] = parentSessionId.byteLength & 0xff
  return blake2b256(b4a.concat([
    BINDING_DOMAIN,
    b4a.from([family]),
    encodeU64(streamId, 'streamId'),
    encodeU64(value.descriptorSequence, 'descriptorSequence'),
    fixed32(value.descriptorHash, 'descriptorHash'),
    parentLength,
    parentSessionId
  ]))
}

export class OneUseStreamTickets {
  constructor (options = {}) {
    this.now = typeof options.monotonicMillis === 'function'
      ? options.monotonicMillis
      : () => process.hrtime.bigint() / 1_000_000n
    this.randomBytes = typeof options.randomBytes === 'function' ? options.randomBytes : crypto.randomBytes
    this.maxTickets = positiveInteger(options.maxTickets, DEFAULT_MAX_PENDING_TICKETS, 'maxTickets')
    this.ttlMillis = positiveInteger(options.ttlMillis, DEFAULT_TICKET_TTL_MILLIS, 'ttlMillis')
    this.records = new Map()
  }

  issue ({ binding, scopeId, payload, expiresMonotonicMillis }) {
    const now = currentMonotonic(this.now)
    this.sweep(now)
    if (this.records.size >= this.maxTickets) fail('BUSY', 'pending stream ticket capacity is exhausted')
    const bindingHash = fixed32(binding, 'binding')
    const scopeKey = String(scopeId)
    if (scopeKey.length < 1 || scopeKey.length > 128) fail('BAD_ENCODING', 'scopeId is outside its bound')
    const ttlExpiry = now + BigInt(this.ttlMillis)
    const callerExpiry = u64(expiresMonotonicMillis, 'expiresMonotonicMillis')
    const expiry = callerExpiry < ttlExpiry ? callerExpiry : ttlExpiry
    if (expiry <= now) fail('EXPIRED', 'stream ticket would already be expired')

    let token
    let key
    do {
      token = nonzeroRandomTicket(this.randomBytes)
      key = b4a.toString(token, 'hex')
    } while (this.records.has(key))
    this.records.set(key, {
      bindingHash: b4a.from(bindingHash),
      scopeId: scopeKey,
      payload,
      expiresMonotonicMillis: expiry
    })
    return token
  }

  consume (token, binding) {
    token = bytes(token, 'stream ticket', TICKET_BYTES, TICKET_BYTES)
    binding = fixed32(binding, 'binding')
    const key = b4a.toString(token, 'hex')
    const record = this.records.get(key)
    if (!record) fail('RETRY_TERMINAL', 'stream ticket is unknown or already consumed')

    // Removal deliberately precedes every check below. A guessed, stale, or
    // wrongly-bound use cannot turn a bearer ticket into a reusable oracle.
    this.records.delete(key)
    const now = currentMonotonic(this.now)
    if (record.expiresMonotonicMillis <= now) fail('RETRY_TERMINAL', 'stream ticket has expired')
    if (!b4a.equals(record.bindingHash, binding)) fail('RETRY_TERMINAL', 'stream ticket binding does not match')
    return record.payload
  }

  revokeScope (scopeId) {
    const key = String(scopeId)
    for (const [ticket, record] of this.records) {
      if (record.scopeId === key) this.records.delete(ticket)
    }
  }

  sweep (now = currentMonotonic(this.now)) {
    for (const [ticket, record] of this.records) {
      if (record.expiresMonotonicMillis <= now) this.records.delete(ticket)
    }
  }

  get size () {
    this.sweep()
    return this.records.size
  }

  clear () {
    this.records.clear()
  }
}

class StreamScope {
  constructor (plane, options) {
    this.plane = plane
    this.family = options.family
    this.streamId = u64(options.streamId, 'streamId')
    this.key = streamKey(this.family, this.streamId)
    this.maxBytes = u64(options.maxBytes, 'maxBytes')
    if (this.maxBytes === 0n) fail('BAD_ENCODING', 'maxBytes must be nonzero')
    this.maxBufferedBytes = positiveInteger(options.maxBufferedBytes,
      plane.maxPerStreamBufferedBytes, 'maxBufferedBytes')
    if (this.maxBufferedBytes > plane.maxBufferedBytes) {
      throw new TypeError('maxBufferedBytes cannot exceed the global stream buffer cap')
    }
    this.idleMillis = positiveInteger(options.idleMillis, null, 'idleMillis')
    this.lifetimeMillis = positiveInteger(options.lifetimeMillis, null, 'lifetimeMillis')
    if (this.idleMillis == null || this.lifetimeMillis == null) {
      throw new TypeError('idleMillis and lifetimeMillis are required')
    }
    const now = currentMonotonic(plane.now)
    this.readiness = normalizeReadiness(options.readiness, now)
    this.metadata = options.metadata == null ? null : options.metadata
    this.onClose = typeof options.onClose === 'function' ? options.onClose : async () => {}
    this.openedMonotonicMillis = now
    this.lastActivityMonotonicMillis = now
    this.totalBytes = 0n
    this.bufferedBytes = 0
    this.reservations = new Set()
    this.abortController = new AbortController()
    this.closed = false
    this.closeReason = null
    this.closePromise = null
    this.timer = null
    this._scheduleExpiry()
  }

  get signal () {
    return this.abortController.signal
  }

  assertActive () {
    if (this.closed) fail('RETRY_TERMINAL', `stream is terminal (${this.closeReason || 'closed'})`)
    const now = currentMonotonic(this.plane.now)
    if (!this.plane._isReady(this, now)) {
      this.close('readiness-expired').catch(this.plane.onError)
      fail('EXPIRED', 'stream readiness descriptor is no longer active')
    }
    if (now >= this.readiness.expiresMonotonicMillis) {
      this.close('readiness-expired').catch(this.plane.onError)
      fail('EXPIRED', 'stream readiness has expired')
    }
    if (now - this.openedMonotonicMillis >= BigInt(this.lifetimeMillis)) {
      this.close('lifetime-expired').catch(this.plane.onError)
      fail('EXPIRED', 'stream lifetime has expired')
    }
    if (now - this.lastActivityMonotonicMillis >= BigInt(this.idleMillis)) {
      this.close('idle-expired').catch(this.plane.onError)
      fail('EXPIRED', 'stream idle limit has expired')
    }
    return now
  }

  touch () {
    const now = this.assertActive()
    this.lastActivityMonotonicMillis = now
    this._scheduleExpiry()
  }

  countBytes (length) {
    if (!Number.isSafeInteger(length) || length < 1) fail('BAD_ENCODING', 'stream byte count must be positive')
    this.assertActive()
    const next = this.totalBytes + BigInt(length)
    if (next > this.maxBytes) {
      this.close('byte-cap').catch(this.plane.onError)
      fail('TOO_LARGE', 'stream aggregate byte cap exceeded')
    }
    this.totalBytes = next
    this.touch()
  }

  reserveBuffer (length) {
    if (!Number.isSafeInteger(length) || length < 1) fail('BAD_ENCODING', 'buffer reservation must be positive')
    this.assertActive()
    if (this.bufferedBytes + length > this.maxBufferedBytes ||
        this.plane.bufferedBytes + length > this.plane.maxBufferedBytes) {
      this.close('buffer-cap').catch(this.plane.onError)
      fail('BUSY', 'stream buffer cap exceeded')
    }
    const reservation = { active: true, length }
    this.reservations.add(reservation)
    this.bufferedBytes += length
    this.plane.bufferedBytes += length
    return () => {
      if (!reservation.active) return
      reservation.active = false
      this.reservations.delete(reservation)
      this.bufferedBytes -= length
      this.plane.bufferedBytes -= length
    }
  }

  poll () {
    if (this.closed) return false
    try {
      this.assertActive()
      return true
    } catch {
      return false
    }
  }

  _scheduleExpiry () {
    if (this.closed) return
    if (this.timer != null) this.plane.cancelSchedule(this.timer)
    const now = currentMonotonic(this.plane.now)
    const idleExpiry = this.lastActivityMonotonicMillis + BigInt(this.idleMillis)
    const lifetimeExpiry = this.openedMonotonicMillis + BigInt(this.lifetimeMillis)
    let expiry = idleExpiry < lifetimeExpiry ? idleExpiry : lifetimeExpiry
    if (this.readiness.expiresMonotonicMillis < expiry) expiry = this.readiness.expiresMonotonicMillis
    const remaining = expiry > now ? expiry - now : 0n
    const delay = Number(remaining > 0x7fffffffn ? 0x7fffffffn : remaining)
    this.timer = this.plane.schedule(() => {
      this.timer = null
      if (this.poll()) this._scheduleExpiry()
    }, Math.max(1, delay))
  }

  close (reason = 'closed') {
    if (this.closePromise) return this.closePromise
    this.closed = true
    this.closeReason = String(reason).slice(0, 64)
    if (this.timer != null) {
      this.plane.cancelSchedule(this.timer)
      this.timer = null
    }
    this.abortController.abort(this.closeReason)
    for (const reservation of this.reservations) reservation.active = false
    this.reservations.clear()
    this.plane.bufferedBytes -= this.bufferedBytes
    this.bufferedBytes = 0
    this.plane.tickets.revokeScope(this.key)
    this.plane.sessions.delete(this.key)
    this.closePromise = Promise.resolve().then(() => this.onClose(this.closeReason, this)).catch(error => {
      this.plane.onError(error)
    })
    return this.closePromise
  }
}

export class StreamSessionPlane {
  constructor (options = {}) {
    this.now = typeof options.monotonicMillis === 'function'
      ? options.monotonicMillis
      : () => process.hrtime.bigint() / 1_000_000n
    currentMonotonic(this.now)
    this.maxStreams = positiveInteger(options.maxStreams, DEFAULT_MAX_STREAMS, 'maxStreams')
    this.maxBufferedBytes = positiveInteger(options.maxBufferedBytes,
      DEFAULT_MAX_BUFFERED_BYTES, 'maxBufferedBytes')
    this.maxPerStreamBufferedBytes = positiveInteger(options.maxPerStreamBufferedBytes,
      DEFAULT_MAX_STREAM_BUFFERED_BYTES, 'maxPerStreamBufferedBytes')
    if (this.maxPerStreamBufferedBytes > this.maxBufferedBytes) {
      throw new TypeError('maxPerStreamBufferedBytes cannot exceed maxBufferedBytes')
    }
    this.schedule = typeof options.schedule === 'function' ? options.schedule : scheduleTimeout
    this.cancelSchedule = typeof options.cancelSchedule === 'function' ? options.cancelSchedule : clearTimeout
    this.isReady = typeof options.isReady === 'function' ? options.isReady : () => true
    this.onError = typeof options.onError === 'function' ? options.onError : () => {}
    this.sessions = new Map()
    this.bufferedBytes = 0
    this.closing = false
    this.tickets = new OneUseStreamTickets({
      monotonicMillis: this.now,
      randomBytes: options.randomBytes,
      maxTickets: options.maxPendingTickets,
      ttlMillis: options.ticketTtlMillis
    })
    this.unsubscribeReadinessFence = typeof options.subscribeReadinessFence === 'function'
      ? options.subscribeReadinessFence(event => this.fence(event))
      : null
    if (this.unsubscribeReadinessFence != null && typeof this.unsubscribeReadinessFence !== 'function') {
      throw new TypeError('subscribeReadinessFence must return an unsubscribe function')
    }
  }

  createSession (options) {
    if (this.closing) fail('BUSY', 'stream plane is draining')
    if (!options || typeof options !== 'object') throw new TypeError('stream session options are required')
    const key = streamKey(options.family, options.streamId)
    if (this.sessions.has(key)) fail('CONFLICT', 'streamId is already active for this family')
    if (this.sessions.size >= this.maxStreams) fail('BUSY', 'active stream capacity is exhausted')
    const scope = new StreamScope(this, options)
    this.sessions.set(key, scope)
    return scope
  }

  issueTicket (scope, parentSessionId) {
    if (!(scope instanceof StreamScope) || scope.plane !== this) throw new TypeError('scope belongs to another stream plane')
    scope.assertActive()
    const binding = streamTicketBinding({
      family: scope.family,
      streamId: scope.streamId,
      descriptorSequence: scope.readiness.descriptorSequence,
      descriptorHash: scope.readiness.descriptorHash,
      parentSessionId
    })
    return this.tickets.issue({
      binding,
      scopeId: scope.key,
      payload: scope,
      expiresMonotonicMillis: scope.readiness.expiresMonotonicMillis
    })
  }

  consumeTicket (ticket, expected) {
    const binding = streamTicketBinding(expected)
    const scope = this.tickets.consume(ticket, binding)
    if (!(scope instanceof StreamScope) || scope.plane !== this) fail('RETRY_TERMINAL', 'stream ticket payload is invalid')
    scope.assertActive()
    return scope
  }

  _isReady (scope, now) {
    try {
      return this.isReady({
        family: scope.family,
        streamId: scope.streamId,
        descriptorSequence: scope.readiness.descriptorSequence,
        descriptorHash: b4a.from(scope.readiness.descriptorHash),
        expiresMonotonicMillis: scope.readiness.expiresMonotonicMillis,
        metadata: scope.metadata,
        now
      }) === true
    } catch (error) {
      this.onError(error)
      return false
    }
  }

  async fence (event = {}) {
    const reason = event && event.reason ? `readiness-${String(event.reason)}` : 'readiness-fenced'
    let descriptorSequence = null
    let descriptorHash = null
    if (event && event.descriptorSequence != null) descriptorSequence = u64(event.descriptorSequence, 'descriptorSequence')
    if (event && event.descriptorHash != null) descriptorHash = fixed32(event.descriptorHash, 'descriptorHash')
    const closing = []
    for (const scope of this.sessions.values()) {
      if (descriptorSequence != null && scope.readiness.descriptorSequence !== descriptorSequence) continue
      if (descriptorHash != null && !b4a.equals(scope.readiness.descriptorHash, descriptorHash)) continue
      closing.push(scope.close(reason))
    }
    await Promise.allSettled(closing)
  }

  poll () {
    this.tickets.sweep()
    for (const scope of [...this.sessions.values()]) scope.poll()
  }

  async close (reason = 'daemon-shutdown') {
    if (this.closing) return
    this.closing = true
    if (this.unsubscribeReadinessFence) {
      this.unsubscribeReadinessFence()
      this.unsubscribeReadinessFence = null
    }
    this.tickets.clear()
    await Promise.allSettled([...this.sessions.values()].map(scope => scope.close(reason)))
  }

  get activeStreams () {
    return this.sessions.size
  }
}
