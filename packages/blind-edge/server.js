import http from 'node:http'
import https from 'node:https'
import { randomBytes } from 'node:crypto'
import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  FAMILY,
  FAMILY_ROUTES,
  OPERATION,
  OUTER_CLASS,
  PROTOCOL,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  assertAdvertisedOperation,
  assertReleaseReady
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { decodeOuterEnvelope } from '@hiverelay/blind-protocol'
import {
  MAX_LOCAL_BODY_BYTES,
  PRIVATE_IPC_TIMING_MILLIS,
  assertPrivateIpcReady
} from '@hiverelay/blind-ipc'
import {
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_TRANSPORT_AUTHORITY_KIND_V2,
  PRIVATE_IPC_V2_LIMITS,
  TLS_EXPORTER_LABEL_V2,
  assertPrecommitCellPutResultFitV2,
  decodeLocalStagedCellPutOpenV2,
  deriveLocalStagedOpenBindingHashV2,
  derivePublicSessionBindingHashV2,
  deriveTlsExporterContextHashV2,
  encodeLocalStagedCellPutOpenV2,
  verifyStagedCellPutPublicOuterEnvelopeV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { exchangeLocal, exchangeLocalStagedCellPutV2 } from './ipc-client.js'
import {
  EdgeReadinessError,
  performReadinessHandshake,
  performWriteReadinessHandshakeV2,
  verifyWriteStreamDialV2,
  validateReadinessTopology
} from './readiness.js'

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_PORT = 9100
const DEFAULT_MAX_IN_FLIGHT = 1024
const DEFAULT_MAX_CONNECTIONS = 256
const DEFAULT_TIMEOUT_MS = 35_000
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5_000
const DEFAULT_MAX_BUFFERED_BYTES = 64 * 1024 * 1024
const DEFAULT_CLOSE_TIMEOUT_MS = 5_000
const MAX_REQUEST_LINE_BYTES = 1_024
const MAX_HEADER_FIELDS = 32
const MAX_AGGREGATE_HEADER_BYTES = 16_384
const MAX_RAW_HTTP_HEAD_BYTES = MAX_REQUEST_LINE_BYTES + MAX_AGGREGATE_HEADER_BYTES + (MAX_HEADER_FIELDS * 4) + 4
const RESPONSE_CHUNK_BYTES = 64 * 1024
const READINESS_REFRESH_TIMER_GUARD_MS = 25
const DEFAULT_STAGE_TIMEOUTS = Object.freeze({
  headersMs: 5_000,
  firstBodyByteMs: 2_000,
  bodyIdleMs: 2_000,
  bodyCompleteMs: 10_000,
  ipcWriteMs: 2_000,
  responseFirstByteMs: 2_000,
  publicWriteIdleMs: 5_000,
  corsMs: 5_000,
  familyMs: 15_000,
  inboxFamilyMs: 35_000
})
const ROUTE_TO_FAMILY = new Map(Object.entries(FAMILY_ROUTES).map(([family, route]) => [route, Number(family)]))
const ALLOWED_HEADERS = 'content-type'

function monotonicMillis () {
  return process.hrtime.bigint() / 1_000_000n
}

class EdgeTransportError extends Error {
  constructor (status, message) {
    super(message)
    this.status = status
  }
}

function positiveInteger (value, fallback, field, allowZero = false) {
  if (value == null) return fallback
  const lower = allowZero ? 0 : 1
  if (!Number.isSafeInteger(value) || value < lower) throw new TypeError(`${field} must be an integer >= ${lower}`)
  return value
}

function stageTimeouts (input) {
  if (input == null) return { ...DEFAULT_STAGE_TIMEOUTS }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('stageTimeouts must be an object')
  for (const key of Object.keys(input)) {
    if (!(key in DEFAULT_STAGE_TIMEOUTS)) throw new TypeError(`unknown stage timeout ${key}`)
  }
  const result = {}
  for (const [key, maximum] of Object.entries(DEFAULT_STAGE_TIMEOUTS)) {
    const value = positiveInteger(input[key], maximum, `stageTimeouts.${key}`)
    if (value > maximum) throw new TypeError(`stageTimeouts.${key} may only tighten the ${maximum} ms protocol bound`)
    result[key] = value
  }
  return result
}

function minimumDeadline (...deadlines) {
  let result = deadlines[0]
  for (let i = 1; i < deadlines.length; i++) {
    if (deadlines[i] < result) result = deadlines[i]
  }
  return result
}

function deadlineElapsed (now, deadline) {
  return now > deadline
}

function armDeadline (now, deadline, onElapsed) {
  let timer = null
  let cancelled = false
  const check = () => {
    if (cancelled) return
    const remaining = deadline - now()
    if (remaining < 0n) {
      cancelled = true
      onElapsed()
      return
    }
    timer = setTimeout(check, Math.max(1, Number(remaining) + 1))
    if (timer.unref) timer.unref()
  }
  check()
  return () => {
    cancelled = true
    if (timer) clearTimeout(timer)
  }
}

function requestLineBytes (request) {
  if (typeof request.method !== 'string' || typeof request.url !== 'string' || typeof request.httpVersion !== 'string') return Number.POSITIVE_INFINITY
  return Buffer.byteLength(`${request.method} ${request.url} HTTP/${request.httpVersion}`, 'latin1')
}

function aggregateHeaderBytes (rawHeaders) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) return Number.POSITIVE_INFINITY
  let total = 0
  for (const value of rawHeaders) {
    if (typeof value !== 'string') return Number.POSITIVE_INFINITY
    total += Buffer.byteLength(value, 'latin1')
    if (total > MAX_AGGREGATE_HEADER_BYTES) return total
  }
  return total
}

function inspectOuterEnvelope (input) {
  const body = b4a.isBuffer(input) ? input : b4a.from(input)
  if (body.byteLength < 6) throw new EdgeTransportError(400, 'malformed blind envelope')
  if (body[0] !== 1) throw new EdgeTransportError(400, 'malformed blind envelope')
  const outerClass = body[1]
  const classBytes = OUTER_CLASS[outerClass]
  if (!classBytes || body.byteLength !== classBytes) throw new EdgeTransportError(400, 'malformed blind envelope')
  const innerLength = b4a.readUInt32BE(body, 2)
  const minDispatchBytes = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES
  if (innerLength < minDispatchBytes || innerLength > DISPATCH_LIMITS.MAX_WIRE_BYTES || 6 + innerLength > classBytes) {
    throw new EdgeTransportError(400, 'malformed blind envelope')
  }
  return outerClass
}

function readBoundedBody (request, maxBytes, signal, reserveBytes, timing) {
  if (request.headers['transfer-encoding'] != null) throw new EdgeTransportError(400, 'transfer encoding is forbidden')
  const declared = request.headers['content-length']
  if (declared == null) throw new EdgeTransportError(400, 'exact content length is required')
  if (typeof declared !== 'string' || !/^(0|[1-9][0-9]*)$/.test(declared)) throw new EdgeTransportError(400, 'invalid content length')
  const declaredBytes = Number(declared)
  if (declaredBytes > maxBytes) throw new EdgeTransportError(413, 'blind envelope too large')
  reserveBytes(declaredBytes)

  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    let settled = false
    let sawBodyByte = false
    let progressDeadline = timing.headersCompletedMonotonicMillis + BigInt(timing.firstBodyByteMs)
    const completeDeadline = timing.headersCompletedMonotonicMillis + BigInt(timing.bodyCompleteMs)
    let cancelTimer = null

    const cleanup = () => {
      if (cancelTimer) cancelTimer()
      request.off('data', onData)
      request.off('end', onEnd)
      request.off('aborted', onAborted)
      request.off('error', onError)
      signal.removeEventListener('abort', onSignalAbort)
    }
    const finish = (error, value) => {
      if (settled) return
      settled = true
      cleanup()
      if (error) reject(error)
      else resolve(value)
    }
    const timeoutError = () => {
      const stageDeadline = minimumDeadline(progressDeadline, completeDeadline)
      return timing.absoluteDeadlineMonotonicMillis <= stageDeadline
        ? new EdgeTransportError(503, 'absolute request deadline elapsed')
        : new EdgeTransportError(408, 'request body stage timed out')
    }
    const arm = () => {
      if (cancelTimer) cancelTimer()
      const deadline = minimumDeadline(progressDeadline, completeDeadline, timing.absoluteDeadlineMonotonicMillis)
      cancelTimer = armDeadline(timing.now, deadline, () => finish(timeoutError()))
    }
    const onData = chunk => {
      const observed = timing.now()
      if (deadlineElapsed(observed, timing.absoluteDeadlineMonotonicMillis)) return finish(new EdgeTransportError(503, 'absolute request deadline elapsed'))
      if (deadlineElapsed(observed, completeDeadline) || deadlineElapsed(observed, progressDeadline)) return finish(new EdgeTransportError(408, 'request body stage timed out'))
      if (chunk.byteLength === 0) return
      sawBodyByte = true
      total += chunk.byteLength
      if (total > declaredBytes || total > maxBytes) return finish(new EdgeTransportError(413, 'blind envelope too large'))
      chunks.push(b4a.from(chunk))
      progressDeadline = observed + BigInt(timing.bodyIdleMs)
      arm()
    }
    const onEnd = () => {
      const observed = timing.now()
      if (deadlineElapsed(observed, timing.absoluteDeadlineMonotonicMillis)) return finish(new EdgeTransportError(503, 'absolute request deadline elapsed'))
      if (deadlineElapsed(observed, completeDeadline)) return finish(new EdgeTransportError(408, 'request body stage timed out'))
      if (declaredBytes > 0 && deadlineElapsed(observed, progressDeadline)) return finish(new EdgeTransportError(408, 'request body stage timed out'))
      if (declaredBytes > 0 && !sawBodyByte) return finish(new EdgeTransportError(400, 'content length mismatch'))
      if (total !== declaredBytes) return finish(new EdgeTransportError(400, 'content length mismatch'))
      finish(null, chunks.length === 1 ? chunks[0] : b4a.concat(chunks, total))
    }
    const onAborted = () => finish(new EdgeTransportError(400, 'request aborted'))
    const onError = () => finish(new EdgeTransportError(400, 'request aborted'))
    const onSignalAbort = () => finish(signal.reason instanceof Error ? signal.reason : new EdgeTransportError(503, 'request aborted'))

    request.on('data', onData)
    request.once('end', onEnd)
    request.once('aborted', onAborted)
    request.once('error', onError)
    signal.addEventListener('abort', onSignalAbort, { once: true })
    arm()
    if (signal.aborted) return onSignalAbort()
    if (request.aborted) return onAborted()
    request.resume()
  })
}

function waitUntil (promise, now, deadline, signal, error) {
  return new Promise((resolve, reject) => {
    let settled = false
    let cancelTimer = () => {}
    const onAbort = () => finish(signal.reason instanceof Error ? signal.reason : error)
    const finish = (failure, value) => {
      if (settled) return
      settled = true
      cancelTimer()
      signal.removeEventListener('abort', onAbort)
      if (failure) reject(failure)
      else resolve(value)
    }
    cancelTimer = armDeadline(now, deadline, () => finish(error))
    if (settled) {
      cancelTimer()
      return
    }
    signal.addEventListener('abort', onAbort, { once: true })
    if (signal.aborted) return onAbort()
    Promise.resolve(promise).then(value => finish(null, value), finish)
  })
}

function writeBoundedResponse (response, body, timing) {
  return new Promise((resolve, reject) => {
    let settled = false
    let offset = 0
    let cancelTimer = null
    let progressDeadlineMonotonicMillis = null
    const payload = b4a.isBuffer(body) ? body : b4a.from(body)

    const cleanup = () => {
      if (cancelTimer) cancelTimer()
      response.off('close', onClose)
      response.off('error', onError)
      timing.signal.removeEventListener('abort', onAbort)
    }
    const finish = error => {
      if (settled) return
      settled = true
      cleanup()
      if (error) {
        if (!response.destroyed) response.destroy(error)
        reject(error)
      } else {
        resolve()
      }
    }
    const timeoutError = () => new EdgeTransportError(503, 'public response write timed out')
    const armIdle = () => {
      if (cancelTimer) cancelTimer()
      progressDeadlineMonotonicMillis = minimumDeadline(timing.now() + BigInt(timing.idleMs), timing.absoluteDeadlineMonotonicMillis)
      cancelTimer = armDeadline(timing.now, progressDeadlineMonotonicMillis, () => finish(timeoutError()))
    }
    const onClose = () => {
      if (!response.writableFinished) return finish(new EdgeTransportError(503, 'public response closed early'))
      if (progressDeadlineMonotonicMillis != null && deadlineElapsed(timing.now(), progressDeadlineMonotonicMillis)) return finish(timeoutError())
      finish()
    }
    const onError = error => finish(error)
    const onAbort = () => finish(timing.signal.reason instanceof Error ? timing.signal.reason : timeoutError())
    const writeNext = () => {
      if (settled) return
      if (deadlineElapsed(timing.now(), timing.absoluteDeadlineMonotonicMillis)) return finish(new EdgeTransportError(503, 'absolute request deadline elapsed'))
      if (offset >= payload.byteLength) {
        armIdle()
        try {
          response.end(() => {
            if (deadlineElapsed(timing.now(), progressDeadlineMonotonicMillis)) return finish(timeoutError())
            finish()
          })
        } catch (error) {
          finish(error)
        }
        return
      }
      const end = Math.min(offset + RESPONSE_CHUNK_BYTES, payload.byteLength)
      const chunk = payload.subarray(offset, end)
      offset = end
      armIdle()
      try {
        response.write(chunk, error => {
          if (error) return finish(error)
          if (deadlineElapsed(timing.now(), progressDeadlineMonotonicMillis)) return finish(timeoutError())
          armIdle()
          setImmediate(writeNext)
        })
      } catch (error) {
        finish(error)
      }
    }

    response.once('close', onClose)
    response.once('error', onError)
    timing.signal.addEventListener('abort', onAbort, { once: true })
    if (timing.signal.aborted) return onAbort()
    if (deadlineElapsed(timing.now(), timing.firstByteDeadlineMonotonicMillis) || deadlineElapsed(timing.now(), timing.absoluteDeadlineMonotonicMillis)) {
      return finish(new EdgeTransportError(503, 'public response first-byte deadline elapsed'))
    }
    try {
      response.flushHeaders()
      writeNext()
    } catch (error) {
      finish(error)
    }
  })
}

function applyCommonHeaders (response) {
  response.setHeader('Cache-Control', 'no-store')
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
  response.setHeader('Connection', 'close')
}

function applyCorsHeaders (response) {
  response.setHeader('Access-Control-Allow-Origin', '*')
  response.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  response.setHeader('Access-Control-Allow-Headers', ALLOWED_HEADERS)
  response.setHeader('Access-Control-Max-Age', '600')
}

function transportFailure (response, status) {
  if (response.headersSent) return response.destroy()
  applyCommonHeaders(response)
  response.statusCode = status
  response.setHeader('Content-Type', 'text/plain; charset=utf-8')
  response.setHeader('Content-Length', '0')
  response.end()
}

function assertExecutableReleaseReady () {
  assertReleaseReady()
  assertPrivateIpcReady()
}

function randomNonzero32 () {
  for (;;) {
    const value = b4a.from(randomBytes(32))
    for (const byte of value) {
      if (byte !== 0) return value
    }
  }
}

function stagedCellPutOpenV2 ({
  socket,
  launchTopologyHash,
  transportProfileHash,
  edgeProcessNonce,
  endpointId,
  outerClass,
  acceptedMonotonicMillis,
  openDeadlineMonotonicMillis,
  outerEnvelope
}) {
  if (!socket || socket.encrypted !== true || typeof socket.exportKeyingMaterial !== 'function') {
    throw new EdgeTransportError(503, 'staged CELL.PUT requires a live TLS exporter')
  }
  try {
    assertPrecommitCellPutResultFitV2(outerClass)
    const localChannelNonce = randomNonzero32()
    const fields = Object.freeze({
      endpointId,
      outerClass,
      acceptedMonotonicMillis,
      openDeadlineMonotonicMillis
    })
    const exporterContextHash = deriveTlsExporterContextHashV2({
      open: fields,
      launchTopologyHash,
      edgeProcessNonce,
      localChannelNonce
    })
    let exporter
    try {
      exporter = b4a.from(socket.exportKeyingMaterial(
        PRIVATE_IPC_V2_LIMITS.TLS_EXPORTER_BYTES,
        TLS_EXPORTER_LABEL_V2,
        exporterContextHash
      ))
    } catch {
      throw new EdgeTransportError(503, 'staged CELL.PUT TLS exporter is unavailable')
    }
    let publicSessionBindingHash
    try {
      publicSessionBindingHash = derivePublicSessionBindingHashV2({
        authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE,
        transportProfileHash,
        exporterContextHash,
        sessionBindingMaterial: exporter
      })
    } finally {
      // The raw exporter is a session secret. Only its domain-separated binding
      // hash crosses this function; erase the temporary bytes immediately.
      exporter.fill(0)
    }
    const openBindingHash = deriveLocalStagedOpenBindingHashV2({
      open: fields,
      launchTopologyHash,
      authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE,
      edgeProcessNonce,
      localChannelNonce,
      transportProfileHash,
      publicSessionBindingHash
    })
    const context = Object.freeze({
      authorityKind: LOCAL_TRANSPORT_AUTHORITY_KIND_V2.TLS_EXPORTER_BY_PEERCRED_EDGE,
      edgeProcessNonce,
      localChannelNonce,
      transportProfileHash,
      publicSessionBindingHash,
      openBindingHash
    })
    const openBytes = encodeLocalStagedCellPutOpenV2({ ...fields, context })
    const open = decodeLocalStagedCellPutOpenV2(openBytes)
    const request = verifyStagedCellPutPublicOuterEnvelopeV2(
      outerEnvelope,
      open,
      LOCAL_STAGED_DIRECTION_V2.REQUEST
    )
    return Object.freeze({ openBytes, open, request })
  } catch (error) {
    if (error instanceof EdgeTransportError) throw error
    throw new EdgeTransportError(400, 'malformed staged CELL.PUT envelope or V2 authority')
  }
}

export class BlindEdge {
  constructor (options = {}) {
    this.host = options.host == null ? DEFAULT_HOST : String(options.host)
    this.port = positiveInteger(options.port, DEFAULT_PORT, 'port', true)
    if (this.port > 65535) throw new TypeError('port must be <= 65535')
    this.endpointId = positiveInteger(options.endpointId, 1, 'endpointId')
    if (this.endpointId > 255) throw new TypeError('endpointId must be <= 255')
    this.maxInFlight = positiveInteger(options.maxInFlight, DEFAULT_MAX_IN_FLIGHT, 'maxInFlight')
    this.maxConnections = positiveInteger(options.maxConnections, DEFAULT_MAX_CONNECTIONS, 'maxConnections')
    this.requestTimeoutMs = positiveInteger(options.requestTimeoutMs, DEFAULT_TIMEOUT_MS, 'requestTimeoutMs')
    this.handshakeTimeoutMs = positiveInteger(options.handshakeTimeoutMs, DEFAULT_HANDSHAKE_TIMEOUT_MS, 'handshakeTimeoutMs')
    if (this.handshakeTimeoutMs > DEFAULT_HANDSHAKE_TIMEOUT_MS) throw new TypeError('handshakeTimeoutMs may only tighten the 5000 ms protocol bound')
    this.maxBufferedBytes = positiveInteger(options.maxBufferedBytes, DEFAULT_MAX_BUFFERED_BYTES, 'maxBufferedBytes')
    this.closeTimeoutMs = positiveInteger(options.closeTimeoutMs, DEFAULT_CLOSE_TIMEOUT_MS, 'closeTimeoutMs')
    this.tls = options.tls && options.tls.key && options.tls.cert ? options.tls : null
    this.allowInsecureLoopback = options.allowInsecureLoopback === true
    if (options.readinessProbe != null) throw new TypeError('readinessProbe is removed; use signed readinessTopology or the explicit unsafe test seam')
    const unsafeReadinessProbe = options.unsafeReadinessProbe
    const unsafeReadiness = unsafeReadinessProbe != null || options.allowUnsafeReadinessProbe === true
    if ((options.stageTimeouts != null || options.testHooks != null || options.monotonicMillis != null || unsafeReadiness) && !this.allowInsecureLoopback) {
      throw new TypeError('deadline/test seams require explicit insecure-loopback test mode')
    }
    if (unsafeReadiness) {
      if (options.allowUnsafeReadinessProbe !== true || typeof unsafeReadinessProbe !== 'function') {
        throw new TypeError('unsafe readiness requires allowUnsafeReadinessProbe=true and an unsafeReadinessProbe function')
      }
      const unarySocketPath = options.unarySocketPath == null ? options.socketPath : options.unarySocketPath
      if (typeof unarySocketPath !== 'string' || !unarySocketPath.startsWith('/') || unarySocketPath.includes('\0')) {
        throw new TypeError('unsafe unary socket path must be absolute')
      }
      this.readinessMode = 'unsafe-test'
      this.readinessTopology = null
      this.unsafeReadinessProbe = unsafeReadinessProbe
      this.unarySocketPath = unarySocketPath
      this.streamSocketPath = null
      this.streamTransportProfileHash = null
    } else {
      this.readinessMode = 'production'
      this.readinessTopology = validateReadinessTopology(options.readinessTopology, this.endpointId)
      this.unsafeReadinessProbe = null
      this.unarySocketPath = this.readinessTopology.unarySocketPath
      this.streamSocketPath = this.readinessTopology.streamSocketPath
      this.streamTransportProfileHash = this.readinessTopology.streamTransportProfileHash
    }
    this.socketPath = this.unarySocketPath
    this.stageTimeouts = stageTimeouts(options.stageTimeouts)
    this.now = typeof options.monotonicMillis === 'function' ? options.monotonicMillis : monotonicMillis
    if (typeof this.now() !== 'bigint') throw new TypeError('monotonicMillis must return bigint milliseconds')
    const testHooks = options.testHooks == null ? {} : options.testHooks
    if (!testHooks || typeof testHooks !== 'object' || Array.isArray(testHooks)) throw new TypeError('testHooks must be an object')
    for (const key of Object.keys(testHooks)) {
      if (key !== 'beforeResponseFirstByte') throw new TypeError(`unknown blind-edge test hook ${key}`)
    }
    if (testHooks.beforeResponseFirstByte != null && typeof testHooks.beforeResponseFirstByte !== 'function') {
      throw new TypeError('testHooks.beforeResponseFirstByte must be a function')
    }
    this.beforeResponseFirstByte = testHooks.beforeResponseFirstByte || null
    this.releaseGate = typeof options.releaseGate === 'function' ? options.releaseGate : assertExecutableReleaseReady
    this.onError = typeof options.onError === 'function' ? options.onError : () => {}
    this.server = null
    this.inFlight = 0
    this.bufferedBytes = 0
    this.sockets = new Set()
    this.abortControllers = new Set()
    this.requestStateBySocket = new WeakMap()
    this.readinessAck = null
    this.descriptorReadinessFloor = null
    this.descriptorAuthorityFloor = null
    // This is deliberately process-scoped, not request-scoped. If a process
    // object survives a fork, the PID fence regenerates it in the child before
    // that child can open a V2 write channel.
    this.edgeProcessNonce = randomNonzero32()
    this.edgeProcessNoncePid = process.pid
    this.writeDescriptorReadinessFloor = null
    this.readinessRefreshTimer = null
    this.readinessExpiryTimer = null
    this.readinessRefreshInFlight = false
    this.readinessFailure = null
    this.closing = false
    this.closePromise = null
  }

  async start () {
    if (this.server) return this
    if (this.closing) throw new Error('blind edge is closing')
    await this.releaseGate()
    const loopback = this.host === '127.0.0.1' || this.host === '::1' || this.host === 'localhost'
    if (!this.tls && !(this.allowInsecureLoopback && loopback)) {
      const error = new Error('blind edge requires owned TLS; plaintext is permitted only by an explicit loopback test seam')
      error.code = 'BLIND_TLS_REQUIRED'
      throw error
    }
    const initialReadiness = await this._establishReadiness()
    if (initialReadiness && this.now() >= initialReadiness.expiresMonotonicMillis) {
      throw new EdgeReadinessError('BLIND_READINESS_ACK', 'initial readiness ACK expired before public bind')
    }
    if (initialReadiness) this._recordReadiness(initialReadiness)
    const listener = (request, response) => this._handle(request, response)
    const serverOptions = { maxHeaderSize: MAX_RAW_HTTP_HEAD_BYTES }
    const server = this.tls
      ? https.createServer({ ...serverOptions, ...this.tls, handshakeTimeout: this.handshakeTimeoutMs }, listener)
      : http.createServer(serverOptions, listener)
    server.maxConnections = this.maxConnections
    server.dropMaxConnection = true
    server.requestTimeout = 0
    server.headersTimeout = this.stageTimeouts.headersMs
    // Do not let Node silently truncate excess fields before the exact raw-list
    // check in _handle; maxHeaderSize bounds parser allocation first.
    server.maxHeadersCount = 0
    server.keepAliveTimeout = 1
    // Node HTTP/1 does not expose a trustworthy per-request kernel first-byte
    // timestamp. Production therefore fails closed to one request per socket and
    // uses the earlier connection/secure-session time as t0. That can shorten but
    // never extend any protocol deadline.
    server.maxRequestsPerSocket = 1
    server.on('connection', socket => {
      if (!this._readinessIsCurrent()) {
        socket.destroy()
        this._failReadiness(new EdgeReadinessError('BLIND_READINESS_EXPIRED', 'public connection arrived without current daemon readiness'))
        return
      }
      this.sockets.add(socket)
      socket.once('close', () => this.sockets.delete(socket))
      if (!this.tls) this._armRequestSocket(socket)
    })
    if (this.tls) server.on('secureConnection', socket => this._armRequestSocket(socket))
    server.on('clientError', (_error, socket) => {
      const requestState = this.requestStateBySocket.get(socket)
      if (requestState && requestState.timedOut) return socket.destroy()
      const status = _error && _error.code === 'ERR_HTTP_REQUEST_TIMEOUT' ? 408 : 400
      if (socket.writable) socket.end(`HTTP/1.1 ${status} ${status === 408 ? 'Request Timeout' : 'Bad Request'}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`)
      else socket.destroy()
    })
    server.on('error', error => this.onError(error))
    await new Promise((resolve, reject) => {
      const onError = error => {
        server.off('listening', onListening)
        reject(error)
      }
      const onListening = () => {
        server.off('error', onError)
        resolve()
      }
      server.once('error', onError)
      server.once('listening', onListening)
      server.listen(this.port, this.host)
    })
    this.server = server
    if (initialReadiness) {
      if (this.now() >= initialReadiness.expiresMonotonicMillis) {
        const error = new EdgeReadinessError('BLIND_READINESS_ACK', 'initial readiness ACK expired during public bind')
        this._failReadiness(error)
        throw error
      }
      this._scheduleReadinessTimers()
    }
    return this
  }

  async _establishReadiness () {
    if (this.readinessMode === 'unsafe-test') {
      if (await this.unsafeReadinessProbe({ socketPath: this.unarySocketPath, endpointId: this.endpointId }) !== true) {
        const error = new Error('unsafe test readiness probe failed')
        error.code = 'BLIND_DAEMON_NOT_READY'
        throw error
      }
      return null
    }
    return performReadinessHandshake(this.readinessTopology, {
      now: this.now,
      previous: this.descriptorReadinessFloor
    })
  }

  _currentEdgeProcessNonce () {
    if (this.edgeProcessNoncePid !== process.pid) {
      this.edgeProcessNonce = randomNonzero32()
      this.edgeProcessNoncePid = process.pid
      this.writeDescriptorReadinessFloor = null
    }
    return this.edgeProcessNonce
  }

  async _establishStagedWriteReadiness (absoluteDeadlineMonotonicMillis, signal) {
    if (this.readinessMode !== 'production' || !this.streamSocketPath || !this.streamTransportProfileHash) {
      throw new EdgeTransportError(503, 'staged CELL.PUT is not enabled by this edge topology')
    }
    if (signal && signal.aborted) throw new EdgeTransportError(503, 'staged CELL.PUT was cancelled before V2 readiness')
    let acknowledgement
    try {
      acknowledgement = await performWriteReadinessHandshakeV2(this.readinessTopology, {
        now: this.now,
        edgeProcessNonce: this._currentEdgeProcessNonce(),
        previous: this.writeDescriptorReadinessFloor
      })
    } catch (error) {
      throw new EdgeTransportError(503, 'staged CELL.PUT V2 write readiness is unavailable')
    }
    const now = this.now()
    if ((signal && signal.aborted) || now >= absoluteDeadlineMonotonicMillis ||
        now >= acknowledgement.expiresMonotonicMillis) {
      throw new EdgeTransportError(503, 'staged CELL.PUT V2 write readiness expired')
    }
    try {
      this._recordWriteReadiness(acknowledgement)
    } catch (error) {
      if (error instanceof EdgeReadinessError && error.code === 'BLIND_READINESS_ROLLBACK') {
        this._failReadiness(error)
        throw new EdgeTransportError(503, 'staged CELL.PUT V2 write readiness rolled back or forked')
      }
      throw error
    }
    return acknowledgement
  }

  _recordDescriptorAuthorityFloor (ack) {
    const floor = this.descriptorAuthorityFloor
    if (floor && (ack.descriptorSequence < floor.descriptorSequence ||
        (ack.descriptorSequence === floor.descriptorSequence &&
         !b4a.equals(ack.descriptorHash, floor.descriptorHash)))) {
      throw new EdgeReadinessError('BLIND_READINESS_ROLLBACK',
        'daemon descriptor tuple rolled back or forked across readiness planes')
    }
    if (!floor || ack.descriptorSequence > floor.descriptorSequence) {
      this.descriptorAuthorityFloor = Object.freeze({
        descriptorSequence: ack.descriptorSequence,
        descriptorHash: b4a.from(ack.descriptorHash)
      })
    }
  }

  _recordWriteReadiness (ack) {
    // Compare against the current shared floor after the asynchronous
    // handshake. This makes out-of-order V2 completions fail closed instead of
    // allowing an older acknowledgement to overwrite a newer tuple.
    this._recordDescriptorAuthorityFloor(ack)
    const floor = this.writeDescriptorReadinessFloor
    if (!floor || ack.descriptorSequence > floor.descriptorSequence) {
      this.writeDescriptorReadinessFloor = Object.freeze({
        descriptorSequence: ack.descriptorSequence,
        descriptorHash: b4a.from(ack.descriptorHash)
      })
    }
  }

  _recordReadiness (ack) {
    this._recordDescriptorAuthorityFloor(ack)
    this.readinessAck = ack
    this.descriptorReadinessFloor = Object.freeze({
      descriptorSequence: ack.descriptorSequence,
      descriptorHash: b4a.from(ack.descriptorHash),
      expiresMonotonicMillis: ack.expiresMonotonicMillis
    })
  }

  _acceptReadiness (ack) {
    this._recordReadiness(ack)
    this._scheduleReadinessTimers()
  }

  _readinessIsCurrent () {
    if (this.readinessMode === 'unsafe-test') return true
    return !this.readinessFailure && this.readinessAck != null && this.now() < this.readinessAck.expiresMonotonicMillis
  }

  _clearReadinessTimers () {
    if (this.readinessRefreshTimer) clearTimeout(this.readinessRefreshTimer)
    if (this.readinessExpiryTimer) clearTimeout(this.readinessExpiryTimer)
    this.readinessRefreshTimer = null
    this.readinessExpiryTimer = null
  }

  _scheduleReadinessTimers () {
    this._clearReadinessTimers()
    if (this.readinessMode !== 'production' || !this.readinessAck || this.closing) return
    const now = this.now()
    const untilExpiry = this.readinessAck.expiresMonotonicMillis - now
    if (untilExpiry <= 0n) {
      this._failReadiness(new EdgeReadinessError('BLIND_READINESS_EXPIRED', 'daemon readiness ACK expired'))
      return
    }
    // Start slightly before the exact minimum lead so timer granularity and the
    // first local scheduling turn cannot make the refresh begin under one second
    // before expiry.
    const refreshAt = this.readinessAck.expiresMonotonicMillis -
      BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_ACK_REFRESH_LEAD + READINESS_REFRESH_TIMER_GUARD_MS)
    const refreshDelay = refreshAt <= now ? 0 : Number(refreshAt - now)
    this.readinessRefreshTimer = setTimeout(() => this._refreshReadiness(), refreshDelay)
    this.readinessExpiryTimer = setTimeout(() => {
      this._failReadiness(new EdgeReadinessError('BLIND_READINESS_EXPIRED', 'daemon readiness ACK expired'))
    }, Number(untilExpiry))
    if (this.readinessRefreshTimer.unref) this.readinessRefreshTimer.unref()
    if (this.readinessExpiryTimer.unref) this.readinessExpiryTimer.unref()
  }

  async _refreshReadiness () {
    if (this.readinessRefreshInFlight || this.closing || this.readinessMode !== 'production') return
    this.readinessRefreshInFlight = true
    const previous = this.readinessAck
    try {
      const ack = await this._establishReadiness()
      if (this.closing) return
      const receivedAt = this.now()
      if (!previous || this.readinessAck !== previous || receivedAt >= previous.expiresMonotonicMillis) {
        throw new EdgeReadinessError('BLIND_READINESS_EXPIRED', 'prior readiness ACK expired before refresh completed')
      }
      if (receivedAt >= ack.expiresMonotonicMillis) {
        throw new EdgeReadinessError('BLIND_READINESS_EXPIRED', 'refreshed readiness ACK expired before acceptance')
      }
      if (ack.expiresMonotonicMillis <= previous.expiresMonotonicMillis) {
        throw new EdgeReadinessError('BLIND_READINESS_ROLLBACK', 'readiness refresh did not advance expiry')
      }
      this._acceptReadiness(ack)
    } catch (error) {
      this.onError(error)
      if (error instanceof EdgeReadinessError &&
          (error.code === 'BLIND_READINESS_ACK' || error.code === 'BLIND_READINESS_PEER' ||
            error.code === 'BLIND_READINESS_ROLLBACK' || error.code === 'BLIND_READINESS_EXPIRED')) {
        this._failReadiness(error)
      } else {
        this._scheduleReadinessRetry()
      }
    } finally {
      this.readinessRefreshInFlight = false
    }
  }

  _scheduleReadinessRetry () {
    if (!this.readinessAck || this.closing) return
    const remaining = this.readinessAck.expiresMonotonicMillis - this.now()
    if (remaining <= 0n) {
      this._failReadiness(new EdgeReadinessError('BLIND_READINESS_EXPIRED', 'daemon readiness refresh failed through expiry'))
      return
    }
    if (this.readinessRefreshTimer) clearTimeout(this.readinessRefreshTimer)
    const delay = Math.max(1, Math.min(250, Math.floor(Number(remaining) / 2)))
    this.readinessRefreshTimer = setTimeout(() => this._refreshReadiness(), delay)
    if (this.readinessRefreshTimer.unref) this.readinessRefreshTimer.unref()
  }

  _failReadiness (error) {
    if (this.readinessFailure) return
    this.readinessFailure = error
    this._clearReadinessTimers()
    for (const abortController of this.abortControllers) abortController.abort(error)
    if (this.server && this.server.closeAllConnections) this.server.closeAllConnections()
    for (const socket of this.sockets) socket.destroy()
    this.close().catch(closeError => this.onError(closeError))
  }

  _armRequestSocket (socket) {
    if (this.requestStateBySocket.has(socket)) return
    const t0 = this.now()
    const headerDeadlineMonotonicMillis = t0 + BigInt(this.stageTimeouts.headersMs)
    const rawLineCaptureLimit = MAX_REQUEST_LINE_BYTES + 2
    let rawLinePrefix = b4a.alloc(0)
    const state = {
      t0,
      headerDeadlineMonotonicMillis,
      seen: false,
      timedOut: false,
      rawLineComplete: false,
      rawLineBytes: null,
      cancelHeaderTimer: null,
      stopHeaderTracking: null
    }
    const onRawData = chunk => {
      if (state.rawLineComplete) return
      const remaining = rawLineCaptureLimit - rawLinePrefix.byteLength
      if (remaining > 0) {
        const addition = b4a.from(chunk.subarray(0, Math.min(remaining, chunk.byteLength)))
        rawLinePrefix = rawLinePrefix.byteLength === 0 ? addition : b4a.concat([rawLinePrefix, addition])
      }
      const lineEnd = rawLinePrefix.indexOf('\r\n')
      if (lineEnd !== -1) {
        state.rawLineComplete = true
        state.rawLineBytes = lineEnd
        socket.off('data', onRawData)
      } else if (rawLinePrefix.byteLength >= rawLineCaptureLimit) {
        state.rawLineComplete = true
        state.rawLineBytes = MAX_REQUEST_LINE_BYTES + 1
        socket.off('data', onRawData)
      }
    }
    socket.prependListener('data', onRawData)
    state.cancelHeaderTimer = armDeadline(this.now, headerDeadlineMonotonicMillis, () => {
      state.timedOut = true
      socket.off('data', onRawData)
      if (socket.writable) socket.end('HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
      else socket.destroy()
    })
    state.stopHeaderTracking = () => {
      state.cancelHeaderTimer()
      socket.off('data', onRawData)
    }
    socket.once('close', state.stopHeaderTracking)
    this.requestStateBySocket.set(socket, state)
  }

  async _handle (request, response) {
    applyCommonHeaders(response)
    if (!this._readinessIsCurrent()) {
      this._failReadiness(new EdgeReadinessError('BLIND_READINESS_EXPIRED', 'public request reached an edge without current daemon readiness'))
      return transportFailure(response, 503)
    }
    const requestState = this.requestStateBySocket.get(request.socket)
    const headersCompletedMonotonicMillis = this.now()
    if (!requestState || requestState.seen) return transportFailure(response, 400)
    requestState.seen = true
    requestState.stopHeaderTracking()
    if (requestState.timedOut || deadlineElapsed(headersCompletedMonotonicMillis, requestState.headerDeadlineMonotonicMillis)) {
      return transportFailure(response, 408)
    }
    const url = request.url || ''
    const normalizedRequestLineBytes = requestLineBytes(request)
    if (!requestState.rawLineComplete || requestState.rawLineBytes > MAX_REQUEST_LINE_BYTES || requestState.rawLineBytes !== normalizedRequestLineBytes) {
      return transportFailure(response, 400)
    }
    if (request.rawHeaders.length / 2 > MAX_HEADER_FIELDS) return transportFailure(response, 400)
    if (aggregateHeaderBytes(request.rawHeaders) > MAX_AGGREGATE_HEADER_BYTES) return transportFailure(response, 400)
    const family = ROUTE_TO_FAMILY.get(url)
    if (!family) return transportFailure(response, 404)
    applyCorsHeaders(response)
    if (request.method === 'OPTIONS') {
      if (request.headers['transfer-encoding'] != null) return transportFailure(response, 400)
      if (request.headers['content-length'] != null && request.headers['content-length'] !== '0') return transportFailure(response, 400)
      const absoluteDeadlineMonotonicMillis = requestState.t0 + BigInt(this.stageTimeouts.corsMs)
      if (deadlineElapsed(headersCompletedMonotonicMillis, absoluteDeadlineMonotonicMillis)) return transportFailure(response, 408)
      const abortController = new AbortController()
      const cancelDeadline = armDeadline(this.now, absoluteDeadlineMonotonicMillis, () => {
        abortController.abort(new EdgeTransportError(408, 'CORS preflight deadline elapsed'))
      })
      response.statusCode = 204
      response.setHeader('Content-Length', '0')
      try {
        await writeBoundedResponse(response, b4a.alloc(0), {
          now: this.now,
          signal: abortController.signal,
          firstByteDeadlineMonotonicMillis: absoluteDeadlineMonotonicMillis,
          absoluteDeadlineMonotonicMillis,
          idleMs: this.stageTimeouts.corsMs
        })
      } catch (error) {
        transportFailure(response, error instanceof EdgeTransportError ? error.status : 408)
      } finally {
        cancelDeadline()
      }
      return
    }
    if (request.method !== 'POST') return transportFailure(response, 405)
    if (request.headers['content-type'] !== PROTOCOL.mediaType) return transportFailure(response, 400)
    if (this.inFlight >= this.maxInFlight) return transportFailure(response, 429)

    this.inFlight++
    const abortController = new AbortController()
    this.abortControllers.add(abortController)
    const familyTimeoutMs = family === FAMILY.INBOX ? this.stageTimeouts.inboxFamilyMs : this.stageTimeouts.familyMs
    const absoluteDeadlineMonotonicMillis = requestState.t0 + BigInt(Math.min(familyTimeoutMs, this.requestTimeoutMs))
    const cancelAbsoluteDeadline = armDeadline(this.now, absoluteDeadlineMonotonicMillis, () => {
      abortController.abort(new EdgeTransportError(503, 'absolute request deadline elapsed'))
    })
    let reservedBytes = 0
    const reserveBytes = bytes => {
      if (!Number.isSafeInteger(bytes) || bytes < 0) throw new EdgeTransportError(503, 'invalid memory reservation')
      if (this.bufferedBytes + bytes > this.maxBufferedBytes) throw new EdgeTransportError(429, 'blind edge memory budget exhausted')
      this.bufferedBytes += bytes
      reservedBytes += bytes
    }
    const onAborted = () => abortController.abort()
    request.once('aborted', onAborted)
    response.once('close', () => {
      if (!response.writableEnded) abortController.abort()
    })
    try {
      if (deadlineElapsed(this.now(), absoluteDeadlineMonotonicMillis)) throw new EdgeTransportError(503, 'absolute request deadline elapsed')
      const body = await readBoundedBody(request, MAX_LOCAL_BODY_BYTES, abortController.signal, reserveBytes, {
        now: this.now,
        headersCompletedMonotonicMillis,
        absoluteDeadlineMonotonicMillis,
        firstBodyByteMs: this.stageTimeouts.firstBodyByteMs,
        bodyIdleMs: this.stageTimeouts.bodyIdleMs,
        bodyCompleteMs: this.stageTimeouts.bodyCompleteMs
      })
      const outerClass = inspectOuterEnvelope(body)
      let outer
      try {
        outer = decodeOuterEnvelope(body, { copyInner: true, copyBody: false })
      } catch {
        throw new EdgeTransportError(400, 'malformed blind envelope')
      }
      try {
        assertAdvertisedOperation(outer.frame.familyId, outer.frame.operationId)
      } catch {
        throw new EdgeTransportError(400, 'operation is outside the advertised release profile')
      }
      const stagedCellPut = family === FAMILY.CELL &&
        outer.frame.familyId === FAMILY.CELL && outer.frame.operationId === OPERATION.CELL.PUT
      const acceptedMonotonicMillis = requestState.t0
      const remainingMillis = absoluteDeadlineMonotonicMillis - this.now()
      if (remainingMillis <= 0n) throw new EdgeTransportError(503, 'absolute request deadline elapsed')
      // Reserve all remaining worst-case copies before daemon dispatch so a
      // committed operation can always carry its same-class response: encoded
      // request plus response chunks, assembled frame, and decoded body.
      reserveBytes(body.byteLength * 4)
      let result
      if (stagedCellPut) {
        if (!this.streamSocketPath || !this.streamTransportProfileHash) {
          throw new EdgeTransportError(503, 'staged CELL.PUT is not enabled by this edge topology')
        }
        try {
          assertPrecommitCellPutResultFitV2(outerClass)
        } catch {
          throw new EdgeTransportError(400, 'staged CELL.PUT requires a V2 result-capable outer class')
        }
        const writeReadiness = await this._establishStagedWriteReadiness(
          absoluteDeadlineMonotonicMillis,
          abortController.signal
        )
        const openAcceptedMonotonicMillis = this.now()
        const openDeadlineMonotonicMillis = minimumDeadline(
          openAcceptedMonotonicMillis + BigInt(PRIVATE_IPC_V2_LIMITS.OPEN_DEADLINE_MILLIS),
          absoluteDeadlineMonotonicMillis,
          writeReadiness.expiresMonotonicMillis
        )
        if (openAcceptedMonotonicMillis >= openDeadlineMonotonicMillis) {
          throw new EdgeTransportError(503, 'staged CELL.PUT V2 open expired before dispatch')
        }
        const streamRemainingMillis = openDeadlineMonotonicMillis - this.now()
        if (streamRemainingMillis <= 0n) {
          throw new EdgeTransportError(503, 'staged CELL.PUT V2 stream deadline elapsed before dispatch')
        }
        const staged = stagedCellPutOpenV2({
          socket: request.socket,
          launchTopologyHash: this.readinessTopology.launchTopologyHash,
          transportProfileHash: this.streamTransportProfileHash,
          edgeProcessNonce: this._currentEdgeProcessNonce(),
          endpointId: this.endpointId,
          outerClass,
          acceptedMonotonicMillis: openAcceptedMonotonicMillis,
          openDeadlineMonotonicMillis,
          outerEnvelope: body
        })
        result = await exchangeLocalStagedCellPutV2(this.streamSocketPath, body, staged.openBytes, {
          timeoutMs: Number(streamRemainingMillis),
          writeTimeoutMs: Math.min(this.stageTimeouts.ipcWriteMs, Number(streamRemainingMillis)),
          signal: abortController.signal,
          verifyConnectedSocket: socket => verifyWriteStreamDialV2(
            this.readinessTopology,
            writeReadiness.streamSocketIdentity,
            socket
          )
        })
      } else {
        result = await exchangeLocal(this.socketPath, {
          family,
          transportId: TRANSPORT_ID.HTTPS_DIRECT,
          transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
          endpointId: this.endpointId,
          outerClass,
          acceptedMonotonicMillis,
          absoluteDeadlineMonotonicMillis,
          adjacentRelayKey: null,
          body
        }, {
          timeoutMs: Number(remainingMillis),
          writeTimeoutMs: Math.min(this.stageTimeouts.ipcWriteMs, Number(remainingMillis)),
          signal: abortController.signal
        })
        const responseOuterClass = inspectOuterEnvelope(result)
        if (responseOuterClass !== outerClass) throw new EdgeTransportError(503, 'daemon changed the selected outer class')
      }
      const frameCompleteMonotonicMillis = this.now()
      const firstByteDeadlineMonotonicMillis = minimumDeadline(
        frameCompleteMonotonicMillis + BigInt(this.stageTimeouts.responseFirstByteMs),
        absoluteDeadlineMonotonicMillis
      )
      if (this.beforeResponseFirstByte) {
        await waitUntil(
          this.beforeResponseFirstByte({ family, response, result }),
          this.now,
          firstByteDeadlineMonotonicMillis,
          abortController.signal,
          new EdgeTransportError(503, 'public response first-byte deadline elapsed')
        )
      }
      response.statusCode = 200
      response.setHeader('Content-Type', PROTOCOL.mediaType)
      response.setHeader('Content-Length', String(result.byteLength))
      await writeBoundedResponse(response, result, {
        now: this.now,
        signal: abortController.signal,
        firstByteDeadlineMonotonicMillis,
        absoluteDeadlineMonotonicMillis,
        idleMs: this.stageTimeouts.publicWriteIdleMs
      })
    } catch (error) {
      const status = error instanceof EdgeTransportError
        ? error.status
        : error && error.code === 'LOCAL_BROKER_ERROR' && error.localBrokerError === 4
          ? 413
          : 503
      if (status === 503) this.onError(error)
      transportFailure(response, status)
    } finally {
      cancelAbsoluteDeadline()
      request.off('aborted', onAborted)
      this.abortControllers.delete(abortController)
      this.bufferedBytes = Math.max(0, this.bufferedBytes - reservedBytes)
      this.inFlight--
    }
  }

  address () {
    return this.server ? this.server.address() : null
  }

  close () {
    if (this.closePromise) return this.closePromise
    this.closePromise = this._close()
    return this.closePromise
  }

  async _close () {
    this.closing = true
    this._clearReadinessTimers()
    const server = this.server
    if (server) {
      server.closeIdleConnections && server.closeIdleConnections()
      const closed = new Promise(resolve => server.close(() => resolve()))
      const timer = setTimeout(() => {
        for (const abortController of this.abortControllers) abortController.abort()
        server.closeAllConnections && server.closeAllConnections()
        for (const socket of this.sockets) socket.destroy()
      }, this.closeTimeoutMs)
      if (timer.unref) timer.unref()
      try {
        await closed
      } finally {
        clearTimeout(timer)
      }
    }
    for (const socket of this.sockets) socket.destroy()
    this.server = null
  }
}

export function createBlindEdge (options) {
  return new BlindEdge(options)
}

export {
  DEFAULT_STAGE_TIMEOUTS,
  MAX_AGGREGATE_HEADER_BYTES,
  MAX_HEADER_FIELDS,
  MAX_REQUEST_LINE_BYTES,
  aggregateHeaderBytes,
  inspectOuterEnvelope,
  requestLineBytes,
  writeBoundedResponse
}
