// Direct-HTTPS public edge for the five-route vNext runtime, reconstructed on
// the accepted base per the runtime relock activation. One exact binary HTTPS
// contract serves DESCRIBE, CELL, INBOX, CORE and the bounded one-hop FORWARD
// route: no operation-specific alternate URLs, no cookies, Authorization,
// referrer, redirect, compression, chunking or protocol fallback. The edge
// owns TLS, derives only the exporter binding, and forwards exact opaque
// bytes over peercred-authenticated private IPC; it never learns application
// schema or plaintext and never publishes a readiness or descriptor bit.

import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import b4a from 'b4a'
import { socketPeerCredentials } from '@hiverelay/blind-peercred'
import {
  FAMILY,
  FAMILY_ROUTES,
  OUTER_CLASS,
  PROTOCOL,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  assertAdvertisedOperation,
  operationProfile
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { decodeOuterEnvelope } from '@hiverelay/blind-protocol/outer-envelope'
import {
  FORWARD_HTTPS_REQUEST_ROLE_V1,
  FORWARD_HTTPS_TLS_EXPORTER_LABEL_V1,
  FORWARD_HTTPS_V3_LIMITS,
  blindForwardHttpsOriginForwardTurnRequestV1,
  decodeCanonical,
  forwardHttpsForwardedRequestCommitmentV1,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsTlsExporterBindingHashV1,
  forwardHttpsTlsExporterContextV1
} from '@hiverelay/blind-protocol'
import {
  FORWARD_HTTPS_TARGET_TLS_EXPORTER_LABEL_V4,
  LOCAL_FORWARD_HTTPS_DIRECTION_V4,
  PRIVATE_IPC_V4_LIMITS,
  assertLocalForwardHttpsResultTranscriptV4,
  createLocalForwardHttpsOriginAuthorityV4,
  createLocalForwardHttpsTargetIngressV4,
  decodeLocalForwardHttpsTurnV4,
  encodeLocalForwardHttpsSourceOriginTranscriptV4,
  encodeLocalForwardHttpsTargetIngressV4,
  forwardHttpsTargetTlsExporterBindingHashV4,
  forwardHttpsTargetTlsExporterContextV4,
  encodeLocalRequest,
  decodeLocalResponse,
  LOCAL_RESPONSE_KIND
} from '@hiverelay/blind-ipc'
import sodium from 'sodium-universal'

const REQUEST_BYTES = FORWARD_HTTPS_V3_LIMITS.EXACT_REQUEST_BYTES
const RESULT_TRANSCRIPT_BYTES = PRIVATE_IPC_V4_LIMITS.RESULT_TRANSCRIPT_BYTES
const SOURCE_ORIGIN_TRANSCRIPT_BYTES = PRIVATE_IPC_V4_LIMITS.SOURCE_ORIGIN_TRANSCRIPT_BYTES
const TARGET_INGRESS_TRANSCRIPT_BYTES = PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_TRANSCRIPT_BYTES
const MAX_DEADLINE_MILLIS = PRIVATE_IPC_V4_LIMITS.MAX_DEADLINE_MILLIS
const MAX_REQUEST_LINE_BYTES = 1024
const MAX_HEADER_FIELDS = 32
const MAX_AGGREGATE_HEADER_BYTES = 16384

const ROUTE_TO_FAMILY = Object.freeze(Object.fromEntries(
  Object.entries(FAMILY_ROUTES).map(([familyId, route]) => [route, Number(familyId)])))

export const FORWARD_HTTPS_EDGE_ROLE_VNEXT = Object.freeze({
  SOURCE: 'SOURCE',
  TARGET: 'TARGET'
})

export const FORWARD_HTTPS_EDGE_VNEXT_LIMITS = Object.freeze({
  exactRequestBytes: REQUEST_BYTES,
  exactResultBytes: FORWARD_HTTPS_V3_LIMITS.EXACT_RESULT_BYTES,
  sourceOriginTranscriptBytes: SOURCE_ORIGIN_TRANSCRIPT_BYTES,
  targetIngressTranscriptBytes: TARGET_INGRESS_TRANSCRIPT_BYTES,
  resultTranscriptBytes: RESULT_TRANSCRIPT_BYTES,
  maxExchangeDeadlineMillis: MAX_DEADLINE_MILLIS,
  maxRequestLineBytes: MAX_REQUEST_LINE_BYTES,
  maxHeaderFields: MAX_HEADER_FIELDS,
  maxAggregateHeaderBytes: MAX_AGGREGATE_HEADER_BYTES,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false
})

export class ForwardHttpsEdgeVnextError extends Error {
  constructor (message, code = 'BLIND_FORWARD_HTTPS_EDGE_VNEXT', status = null) {
    super(message)
    this.name = 'ForwardHttpsEdgeVnextError'
    this.code = code
    if (status != null) this.status = status
  }
}

function fail (message, code = 'BLIND_FORWARD_HTTPS_EDGE_VNEXT', status = null) {
  throw new ForwardHttpsEdgeVnextError(message, code, status)
}

function transport (status, message) {
  fail(message, 'BLIND_FORWARD_HTTPS_EDGE_VNEXT_TRANSPORT', status)
}

function exactBytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.from(value)
  if (value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero) {
    let found = false
    for (const byte of value) if (byte !== 0) { found = true; break }
    if (!found) fail(`${field} must be nonzero`)
  }
  return value
}

function randomNonzero (length, field) {
  const output = b4a.alloc(length)
  for (let attempt = 0; attempt < 8; attempt++) {
    sodium.randombytes_buf(output)
    if (output.some(byte => byte !== 0)) return output
  }
  fail(`${field} remained zero`, 'BLIND_FORWARD_HTTPS_EDGE_VNEXT_RNG')
}

function defaultMonotonicMillis () {
  return Number(process.hrtime.bigint() / 1_000_000n)
}

// Exact credential-free header policy shared by every route: one canonical
// content-length, the blind media type, and no chunking, compression,
// credentials, referrer, range or conditional negotiation of any kind.
export function assertForwardHttpsHeadersVnext (headers, exactLength) {
  if (!headers || typeof headers !== 'object') fail('request headers are required')
  for (const field of ['transfer-encoding', 'content-encoding', 'authorization', 'cookie', 'referer', 'range']) {
    if (headers[field] != null) transport(400, `FORWARD/UNARY request header ${field} is forbidden`)
  }
  if (headers.expect != null || headers.trailer != null) {
    transport(400, 'chunking or trailer negotiation is forbidden')
  }
  const declared = headers['content-length']
  if (declared == null || !/^(0|[1-9][0-9]*)$/.test(declared)) {
    transport(400, 'an exact canonical content-length is required')
  }
  if (Number(declared) !== exactLength) transport(400, 'request body is outside its exact byte class')
  return true
}

// Derive the source-side TLS exporter binding from the live client TLS socket.
// The raw exporter leaves this function only to be zeroed; only the binding
// hash crosses the IPC boundary.
export function deriveForwardHttpsOriginExporterBindingVnext (socket, request, requestBytes) {
  if (!socket || socket.encrypted !== true || typeof socket.exportKeyingMaterial !== 'function') {
    fail('FORWARD requires a live Edge-owned TLS exporter', 'BLIND_FORWARD_TLS_REQUIRED', 400)
  }
  const commitment = forwardHttpsOriginRequestCommitmentV1(requestBytes)
  const context = forwardHttpsTlsExporterContextV1(request.stableSessionId, request.sequence, commitment)
  let exporter
  try {
    exporter = b4a.from(socket.exportKeyingMaterial(32, FORWARD_HTTPS_TLS_EXPORTER_LABEL_V1, context))
    return {
      tlsExporterBindingHash: forwardHttpsTlsExporterBindingHashV1(exporter, context),
      originRequestCommitment: commitment
    }
  } catch (error) {
    if (error && error.status === 400) throw error
    fail('FORWARD TLS exporter derivation failed', 'BLIND_FORWARD_TLS_REQUIRED', 400)
  } finally {
    if (exporter) exporter.fill(0)
  }
}

// Derive the target-side TLS exporter binding from the live source-daemon TLS
// session. The target edge is a bounded byte relay: no caller URL, host, IP,
// address or credentials are accepted or observed beyond the exact body.
export function deriveForwardHttpsTargetExporterBindingVnext (socket, request, requestBytes) {
  if (!socket || socket.encrypted !== true || typeof socket.exportKeyingMaterial !== 'function') {
    fail('FORWARD requires a live Edge-owned TLS exporter', 'BLIND_FORWARD_TLS_REQUIRED', 400)
  }
  const commitment = forwardHttpsForwardedRequestCommitmentV1(requestBytes)
  const context = forwardHttpsTargetTlsExporterContextV4(request.stableSessionId, request.sequence, commitment)
  let exporter
  try {
    exporter = b4a.from(socket.exportKeyingMaterial(32, FORWARD_HTTPS_TARGET_TLS_EXPORTER_LABEL_V4, context))
    return {
      targetTlsExporterBindingHash: forwardHttpsTargetTlsExporterBindingHashV4(exporter, context),
      forwardedRequestCommitment: commitment
    }
  } catch (error) {
    if (error && error.status === 400) throw error
    fail('FORWARD TLS exporter derivation failed', 'BLIND_FORWARD_TLS_REQUIRED', 400)
  } finally {
    if (exporter) exporter.fill(0)
  }
}

// One bounded exact transcript exchange over the private Unix socket: write
// the transcript, half-close, and read exactly one result transcript. The
// daemon's peercred identity is verified on the live connected socket before
// any byte is written.
export function exchangeForwardHttpsTranscriptVnext (socketPath, transcriptBytes, options = {}) {
  transcriptBytes = exactBytes(transcriptBytes, transcriptBytes.byteLength, 'IPC transcript')
  const timeoutMs = options.timeoutMs == null ? 15_000 : options.timeoutMs
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 35_000) fail('IPC timeout is outside its bound')
  if (typeof socketPath !== 'string' || !socketPath.startsWith('/') || socketPath.includes('\0')) {
    fail('forward IPC socket path is invalid')
  }
  return new Promise((resolve, reject) => {
    const socketFactory = options.socketFactory || (socketOptions => net.createConnection(socketOptions))
    const socket = socketFactory({ path: socketPath, allowHalfOpen: true })
    const chunks = []
    let total = 0
    let settled = false
    const timer = setTimeout(() => finish(Object.assign(new Error('forward IPC deadline elapsed'), { code: 'BLIND_FORWARD_IPC_TIMEOUT' })), timeoutMs)
    if (timer.unref) timer.unref()
    const onAbort = () => finish(options.signal.reason || Object.assign(new Error('forward IPC aborted'), { code: 'ABORT_ERR' }))
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (options.signal) options.signal.removeEventListener('abort', onAbort)
      socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    socket.once('connect', async () => {
      try {
        if (typeof options.verifyConnectedSocket === 'function') await options.verifyConnectedSocket(socket)
        socket.end(transcriptBytes)
      } catch (error) {
        finish(error)
      }
    })
    socket.on('data', chunk => {
      if (total + chunk.byteLength > RESULT_TRANSCRIPT_BYTES) {
        finish(Object.assign(new Error('forward IPC result exceeded its exact bound'), { code: 'BLIND_FORWARD_IPC_LENGTH' }))
        return
      }
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
    })
    socket.once('end', () => {
      if (total !== RESULT_TRANSCRIPT_BYTES) {
        finish(Object.assign(new Error('forward IPC result was not one exact turn'), { code: 'BLIND_FORWARD_IPC_LENGTH' }))
        return
      }
      finish(null, b4a.concat(chunks, total))
    })
    socket.once('error', finish)
    if (options.signal) {
      if (options.signal.aborted) return onAbort()
      options.signal.addEventListener('abort', onAbort, { once: true })
    }
  })
}

export class ForwardHttpsEdgeVnext {
  constructor (options = {}) {
    this.host = options.host || '127.0.0.1'
    this.port = options.port == null ? 0 : options.port
    this.endpointId = options.endpointId == null ? 1 : options.endpointId
    this.role = options.role || FORWARD_HTTPS_EDGE_ROLE_VNEXT.SOURCE
    this.unarySocketPath = options.unarySocketPath || null
    this.forwardSocketPath = options.forwardSocketPath || null
    this.tls = options.tls || null
    this.allowInsecureLoopback = options.allowInsecureLoopback === true
    this.launchTopologyHash = options.launchTopologyHash
      ? exactBytes(options.launchTopologyHash, 32, 'launchTopologyHash', true)
      : null
    this.wireV3AbiHash = options.wireV3AbiHash
      ? exactBytes(options.wireV3AbiHash, 32, 'wireV3AbiHash', true)
      : null
    this.edgeProcessNonce = options.edgeProcessNonce
      ? exactBytes(options.edgeProcessNonce, 32, 'edgeProcessNonce', true)
      : randomNonzero(32, 'edgeProcessNonce')
    this.expectedDaemonUid = options.expectedDaemonUid
    this.expectedDaemonGid = options.expectedDaemonGid
    this.monotonicMillis = options.monotonicMillis || defaultMonotonicMillis
    this.onError = options.onError || (() => {})
    this.onUnaryExchange = options.onUnaryExchange || null
    this.onForwardExchange = options.onForwardExchange || null
    this.socketFactory = options.socketFactory || null
    this.inFlight = 0
    this.maxInFlight = Number.isSafeInteger(options.maxInFlight) ? options.maxInFlight : 1024
    this.server = null
    this.sockets = new Set()
    if (!Number.isInteger(this.endpointId) || this.endpointId < 1 || this.endpointId > 255) {
      throw new TypeError('endpointId is outside 1..255')
    }
    if (this.role !== FORWARD_HTTPS_EDGE_ROLE_VNEXT.SOURCE && this.role !== FORWARD_HTTPS_EDGE_ROLE_VNEXT.TARGET) {
      throw new TypeError('role must be SOURCE or TARGET')
    }
    if (this.tls == null && !this.allowInsecureLoopback) {
      fail('public edge requires operator TLS key material', 'BLIND_TLS_REQUIRED')
    }
    if (!Number.isInteger(this.expectedDaemonUid) || !Number.isInteger(this.expectedDaemonGid)) {
      throw new TypeError('expected daemon UID/GID are required for the peercred boundary')
    }
  }

  address () {
    return this.server && this.server.address()
  }

  _verifyDaemonPeer (socket) {
    const credentials = socketPeerCredentials(socket)
    if (credentials.uid !== this.expectedDaemonUid || credentials.gid !== this.expectedDaemonGid) {
      fail('daemon peer credentials do not match the expected launch identity', 'BLIND_FORWARD_PEERCRED')
    }
    return credentials
  }

  async start () {
    if (this.server) return this
    const listener = (request, response) => {
      this._handle(request, response).catch(error => {
        // A dead socket must never turn the floating handler promise into an
        // unhandled rejection; the exact status was already best-effort.
        this.onError(error)
        try {
          response.destroy()
        } catch {}
      })
    }
    const server = this.tls
      ? https.createServer({ ...this.tls, handshakeTimeout: 5_000 }, listener)
      : http.createServer(listener)
    server.maxRequestsPerSocket = 1
    server.keepAliveTimeout = 1
    server.maxHeadersCount = 0
    server.requestTimeout = 0
    server.on('connection', socket => {
      socket.on('error', () => {})
      this.sockets.add(socket)
      socket.once('close', () => this.sockets.delete(socket))
    })
    server.on('secureConnection', socket => {
      socket.on('error', () => {})
      this.sockets.add(socket)
      socket.once('close', () => this.sockets.delete(socket))
    })
    server.on('clientError', (error, socket) => {
      this.onError(error)
      socket.destroy()
    })
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(this.port, this.host, resolve)
    })
    this.server = server
    return this
  }

  async close () {
    const server = this.server
    if (!server) return
    for (const socket of this.sockets) socket.destroy()
    await new Promise(resolve => server.close(resolve))
    this.server = null
  }

  _transportFailure (response, status, request) {
    // Early rejections must still flush before the connection closes: drain
    // the bounded request first so the client always observes the exact
    // status, then close. Chunked ingress is discarded, never decoded.
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      try {
        response.writeHead(status, {
          'content-type': 'text/plain; charset=utf-8',
          'content-length': 0,
          'cache-control': 'no-store',
          connection: 'close'
        })
        response.end()
      } catch {}
    }
    if (request && !request.readableEnded && typeof request.resume === 'function') {
      request.once('end', finish)
      request.once('error', finish)
      const timer = setTimeout(finish, 2_000)
      if (timer.unref) timer.unref()
      request.resume()
      return
    }
    finish()
  }

  _respond (response, bytes) {
    response.writeHead(200, {
      'content-type': PROTOCOL.mediaType,
      'content-length': bytes.byteLength,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      connection: 'close'
    })
    response.end(bytes)
  }

  async _readBody (request, exactLength) {
    const chunks = []
    let total = 0
    for await (const chunk of request) {
      total += chunk.byteLength
      if (total > exactLength) transport(400, 'request body exceeds its exact byte class')
      chunks.push(b4a.from(chunk))
    }
    if (total !== exactLength) transport(400, 'request body is shorter than its exact byte class')
    return b4a.concat(chunks, total)
  }

  async _handle (request, response) {
    try {
      if (this.inFlight >= this.maxInFlight) return this._transportFailure(response, 429, request)
      this.inFlight++
      try {
        const family = ROUTE_TO_FAMILY[request.url]
        if (family == null) return this._transportFailure(response, 404, request)
        if (request.method !== 'POST') return this._transportFailure(response, 405, request)
        const contentType = request.headers['content-type']
        if (contentType !== PROTOCOL.mediaType) return this._transportFailure(response, 400, request)
        if (request.rawHeaders.length / 2 > MAX_HEADER_FIELDS) return this._transportFailure(response, 400, request)
        let aggregate = 0
        for (let index = 0; index < request.rawHeaders.length; index += 2) {
          aggregate += request.rawHeaders[index].length + request.rawHeaders[index + 1].length + 4
        }
        if (aggregate > MAX_AGGREGATE_HEADER_BYTES) return this._transportFailure(response, 400, request)
        if (family === FAMILY.FORWARD) {
          const body = await this._readTurn(request)
          return await this._forward(request, response, body)
        }
        const outerClass = this._outerClassFor(request)
        const body = await this._readEnvelope(request, outerClass)
        return await this._unary(request, response, family, outerClass, body)
      } finally {
        this.inFlight--
      }
    } catch (error) {
      if (error && Number.isInteger(error.status)) return this._transportFailure(response, error.status, request)
      this.onError(error)
      if (!response.headersSent) return this._transportFailure(response, 503, request)
      response.destroy()
    }
  }

  _outerClassFor (request) {
    const declared = request.headers['content-length']
    if (declared == null || !/^(0|[1-9][0-9]*)$/.test(declared)) transport(400, 'an exact canonical content-length is required')
    const outerClass = Object.entries(OUTER_CLASS).find(([, bytes]) => bytes === Number(declared))
    if (!outerClass) transport(400, 'request body is not an exact outer class')
    return Number(outerClass[0])
  }

  async _readTurn (request) {
    assertForwardHttpsHeadersVnext(request.headers, REQUEST_BYTES)
    return this._readBody(request, REQUEST_BYTES)
  }

  async _readEnvelope (request, outerClass) {
    assertForwardHttpsHeadersVnext(request.headers, OUTER_CLASS[outerClass])
    const body = await this._readBody(request, OUTER_CLASS[outerClass])
    let envelope
    try {
      envelope = decodeOuterEnvelope(body, { copyInner: true, copyBody: false })
    } catch {
      transport(400, 'malformed blind envelope')
    }
    return { body, frame: envelope.frame, outerClass: envelope.outerClass }
  }

  async _unary (request, response, family, outerClass, read) {
    const frame = read.frame
    // Exact opaque operation/transport qualification before any IPC contact:
    // the envelope family must equal the route family, the operation must be
    // advertised by the active release profile, and the operation must
    // support the direct HTTP transport. Reserved operations fail closed with
    // a bare transport 400 (the corrected fixture behavior).
    if (frame.familyId !== family) transport(400, 'envelope family does not match the route family')
    try {
      assertAdvertisedOperation(frame.familyId, frame.operationId)
    } catch {
      transport(400, 'operation is outside the advertised release profile')
    }
    const profile = operationProfile(frame.familyId, frame.operationId)
    if (!profile || (profile.transportSupportBits & TRANSPORT_SUPPORT.DIRECT_HTTP) === 0) {
      transport(400, 'operation is not qualified for the direct HTTP transport')
    }
    if (!this.unarySocketPath) transport(503, 'unary IPC is unavailable')
    const accepted = BigInt(this.monotonicMillis())
    const deadline = accepted + BigInt(family === FAMILY.INBOX ? 35_000 : 15_000)
    const requestFrame = encodeLocalRequest({
      family,
      transportId: TRANSPORT_ID.HTTPS_DIRECT,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
      endpointId: this.endpointId,
      outerClass,
      acceptedMonotonicMillis: accepted,
      absoluteDeadlineMonotonicMillis: deadline,
      body: read.body
    })
    if (this.onUnaryExchange) this.onUnaryExchange({ phase: 'request', bytes: requestFrame, body: read.body })
    const responseBytes = await this._exchangeUnary(requestFrame, family)
    if (this.onUnaryExchange) this.onUnaryExchange({ phase: 'response', bytes: responseBytes })
    this._respond(response, responseBytes)
  }

  async _exchangeUnary (requestFrame, family) {
    const timeoutMs = family === FAMILY.INBOX ? 35_000 : 15_000
    return new Promise((resolve, reject) => {
      const socketFactory = this.socketFactory || (socketOptions => net.createConnection(socketOptions))
      const socket = socketFactory({ path: this.unarySocketPath, allowHalfOpen: true })
      const chunks = []
      let total = 0
      let settled = false
      const timer = setTimeout(() => finish(Object.assign(new Error('unary IPC deadline elapsed'), { code: 'BLIND_UNARY_IPC_TIMEOUT' })), timeoutMs)
      if (timer.unref) timer.unref()
      const finish = (error, value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.destroy()
        if (error) reject(error)
        else resolve(value)
      }
      socket.once('connect', () => {
        try {
          this._verifyDaemonPeer(socket)
          socket.end(requestFrame)
        } catch (error) {
          finish(error)
        }
      })
      socket.on('data', chunk => {
        chunks.push(b4a.from(chunk))
        total += chunk.byteLength
      })
      socket.once('end', () => {
        try {
          const decoded = decodeLocalResponse(b4a.concat(chunks, total))
          if (decoded.responseKind === LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR) {
            const error = new Error('daemon broker rejected the exchange')
            error.code = 'LOCAL_BROKER_ERROR'
            error.localBrokerError = decoded.localBrokerError
            finish(error)
            return
          }
          finish(null, b4a.from(decoded.externalCanonicalBytes))
        } catch (error) {
          finish(error)
        }
      })
      socket.once('error', finish)
    })
  }

  async _forward (request, response, body) {
    let turn
    try {
      turn = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, body, { copyBytes: true })
    } catch {
      transport(400, 'FORWARD request is not the exact canonical turn body')
    }
    const expectedRole = this.role === FORWARD_HTTPS_EDGE_ROLE_VNEXT.SOURCE
      ? FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE
      : FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED
    if (turn.requestRole !== expectedRole) transport(400, 'FORWARD request role is not accepted by this edge')
    if (!this.forwardSocketPath) transport(503, 'forward IPC is unavailable')
    const accepted = BigInt(this.monotonicMillis())
    const deadline = accepted + 10_000n
    const localChannelNonce = randomNonzero(32, 'localChannelNonce')
    let transcript
    let authority
    if (this.role === FORWARD_HTTPS_EDGE_ROLE_VNEXT.SOURCE) {
      const derived = deriveForwardHttpsOriginExporterBindingVnext(request.socket, turn, body)
      authority = createLocalForwardHttpsOriginAuthorityV4({
        version: 4,
        authorityKind: 1,
        transportId: 1,
        endpointId: this.endpointId,
        flags: 0,
        wireV3AbiHash: this.wireV3AbiHash,
        signedLaunchTopologyHash: this.launchTopologyHash,
        edgeProcessNonce: this.edgeProcessNonce,
        localChannelNonce,
        tlsExporterBindingHash: derived.tlsExporterBindingHash,
        originRequestCommitment: derived.originRequestCommitment,
        stableSessionId: turn.stableSessionId,
        sequence: turn.sequence,
        acceptedMonotonicMillis: accepted,
        absoluteDeadlineMonotonicMillis: deadline
      })
      transcript = encodeLocalForwardHttpsSourceOriginTranscriptV4(authority, {
        version: 4,
        direction: LOCAL_FORWARD_HTTPS_DIRECTION_V4.ORIGIN_REQUEST,
        wireRole: FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE,
        flags: 0,
        wireV3AbiHash: this.wireV3AbiHash,
        localExchangeId: authority.localExchangeId,
        originRequestCommitment: derived.originRequestCommitment,
        stableSessionId: turn.stableSessionId,
        sequence: turn.sequence,
        body
      })
    } else {
      const derived = deriveForwardHttpsTargetExporterBindingVnext(request.socket, turn, body)
      authority = createLocalForwardHttpsTargetIngressV4({
        endpointId: this.endpointId,
        wireV3AbiHash: this.wireV3AbiHash,
        signedLaunchTopologyHash: this.launchTopologyHash,
        edgeProcessNonce: this.edgeProcessNonce,
        localChannelNonce,
        targetTlsExporterBindingHash: derived.targetTlsExporterBindingHash,
        acceptedMonotonicMillis: accepted,
        absoluteDeadlineMonotonicMillis: deadline,
        body
      })
      transcript = encodeLocalForwardHttpsTargetIngressV4(authority)
    }
    if (this.onForwardExchange) this.onForwardExchange({ phase: 'request', bytes: transcript, body })
    const resultTranscript = await exchangeForwardHttpsTranscriptVnext(this.forwardSocketPath, transcript, {
      verifyConnectedSocket: socket => this._verifyDaemonPeer(socket),
      socketFactory: this.socketFactory || undefined
    })
    if (this.onForwardExchange) this.onForwardExchange({ phase: 'response', bytes: resultTranscript })
    const resultTurn = decodeLocalForwardHttpsTurnV4(resultTranscript)
    assertLocalForwardHttpsResultTranscriptV4(resultTranscript, authority)
    this._respond(response, b4a.from(resultTurn.body))
  }
}

export const FORWARD_HTTPS_EXPORTER_LABEL_VNEXT = FORWARD_HTTPS_TLS_EXPORTER_LABEL_V1
