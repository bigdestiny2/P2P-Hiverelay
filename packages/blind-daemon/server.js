import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import { socketPeerCredentials } from '@hiverelay/blind-peercred'
import {
  BlindProtocolError,
  DISPATCH_LIMITS,
  ERROR_CODE,
  ERROR_PROFILE_ID,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  assertReleaseReady,
  blindErrorV1,
  decodeDispatchFrame,
  decodeOuterEnvelope,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  errorProfileEntry,
  operationProfile
} from '@hiverelay/blind-protocol'
import {
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LOCAL_STREAM_MODE,
  LOCAL_STREAM_OPEN_KIND,
  LOCAL_BROKER_ERROR,
  LOCAL_RESPONSE_KIND,
  LOCAL_DISPATCH_ADJACENT_HEADER_BYTES,
  LocalStreamSequenceGuard,
  MAX_LOCAL_BODY_BYTES,
  PRIVATE_IPC_TIMING_MILLIS,
  assertPrivateIpcReady,
  decodeLocalStreamFrame,
  decodeLocalStreamOpen,
  decodeLocalRequest,
  encodeLocalReadyAckBody,
  encodeLocalResponse,
  fragmentLocalContent,
  localAuthenticatedChannelAuthority,
  localRequestFrameLength,
  localStreamFrameLength,
  localStreamOpenFrameLength,
  verifyLocalAuthenticatedChannelContext
} from '@hiverelay/blind-ipc'
import {
  STAGED_CELL_PUT_DEFAULT_QUEUE_BYTES,
  STAGED_CELL_PUT_MAX_PREFIX_BYTES,
  StagedCellPutDispatchIngestor
} from './staged-put.js'

const DEFAULT_SOCKET_MODE = 0o660
const DEFAULT_REQUEST_TIMEOUT_MS = 35_000
const DEFAULT_MAX_CONNECTIONS = 1024
const DEFAULT_CLOSE_TIMEOUT_MS = 5_000
const DEFAULT_MAX_BUFFERED_BYTES = 64 * 1024 * 1024
const DEFAULT_MAX_PENDING_READINESS_CHECKS = 64
const REQUIRED_DESCRIBE_OPERATION_BITS = 0x00000007
const KNOWN_OPERATION_BITS = 0x003fffff
const KNOWN_ROLE_BITS = 0x007f
const MAX_U64 = (1n << 64n) - 1n
const STAGED_PUT_RESPONSE_BYTES = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES +
  operationProfile(FAMILY.CELL, OPERATION.CELL.PUT).maxResultBodyBytes
const STAGED_PUT_STREAM_RESERVATION_BYTES = (3 * STAGED_CELL_PUT_MAX_PREFIX_BYTES) +
  STAGED_CELL_PUT_DEFAULT_QUEUE_BYTES + STAGED_PUT_RESPONSE_BYTES

function assertExecutableReleaseReady () {
  assertReleaseReady()
  assertPrivateIpcReady()
}

function monotonicMillis () {
  return process.hrtime.bigint() / 1_000_000n
}

function localBrokerResponse (localBrokerError) {
  return { responseKind: LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR, localBrokerError }
}

function validSocketPath (value, field) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw new TypeError(`${field} must be an absolute filesystem path without NUL`)
  }
  if (path.normalize(value) !== value) throw new TypeError(`${field} must be a canonical normalized path`)
  if (Buffer.byteLength(value) > 100) throw new TypeError(`${field} is too long for a portable Unix socket`)
  return value
}

function positiveInteger (value, fallback, field, allowZero = false) {
  if (value == null) return fallback
  const lower = allowZero ? 0 : 1
  if (!Number.isSafeInteger(value) || value < lower) throw new TypeError(`${field} must be an integer >= ${lower}`)
  return value
}

function sameBytes (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

function allZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function fixed32 (value, field, optional = false) {
  if (value == null && optional) return null
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be exactly 32 bytes`)
  const bytes = b4a.isBuffer(value)
    ? value
    : b4a.from(value.buffer || value, value.byteOffset || 0, value.byteLength)
  if (bytes.byteLength !== 32) throw new TypeError(`${field} must be exactly 32 bytes`)
  return b4a.from(bytes)
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) throw new TypeError(`${field} is outside u64`)
  return value
}

function endpointSet (options) {
  const input = options.endpointIds == null
    ? (options.endpointId == null ? null : [options.endpointId])
    : options.endpointIds
  if (!Array.isArray(input) || input.length < 1 || input.length > 255) {
    throw new TypeError('endpointIds must be a non-empty array of endpoint IDs')
  }
  const result = new Set()
  for (const value of input) {
    if (!Number.isInteger(value) || value < 1 || value > 0xff) throw new TypeError('endpointIds contains an ID outside 1..255')
    if (result.has(value)) throw new TypeError('endpointIds must not contain duplicates')
    result.add(value)
  }
  return result
}

function currentMonotonic (now) {
  const value = now()
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new TypeError('monotonicMillis must return a u64 bigint')
  }
  return value
}

function abortError () {
  const error = new Error('blind readiness snapshot was aborted')
  error.code = 'ABORT_ERR'
  return error
}

async function abortableCall (operation, signal) {
  if (signal.aborted) throw abortError()
  let onAbort
  const aborted = new Promise((resolve, reject) => {
    onAbort = () => reject(abortError())
    signal.addEventListener('abort', onAbort, { once: true })
  })
  try {
    return await Promise.race([Promise.resolve().then(operation), aborted])
  } finally {
    signal.removeEventListener('abort', onAbort)
  }
}

function safeErrorCode (error) {
  const code = error instanceof BlindProtocolError && ERROR_CODE[error.code]
    ? ERROR_CODE[error.code]
    : ERROR_CODE.INTERNAL
  if (code === ERROR_CODE.RENEW_NOT_DUE && error.retryAfterEpoch == null) return ERROR_CODE.INTERNAL
  return code
}

function correlatedErrorDispatch (request, error) {
  const code = safeErrorCode(error)
  const profile = errorProfileEntry(ERROR_PROFILE_ID.CANONICAL_V1, code)
  const value = {
    version: 1,
    code,
    retryable: profile.retryable,
    retryAfterEpoch: profile.retryAfterMode === 1 ? error.retryAfterEpoch : null
  }
  return encodeDispatchFrame({
    frameKind: FRAME_KIND.ERROR,
    familyId: request.familyId,
    operationId: request.operationId,
    requestId: request.requestId,
    body: encodeCanonical(blindErrorV1, value)
  })
}

function normalizeDispatchResult (request, result) {
  let dispatch
  let outerClass = null
  if (result && typeof result === 'object' && result.dispatch != null) {
    dispatch = result.dispatch
    outerClass = result.outerClass == null ? null : result.outerClass
  } else {
    dispatch = result
  }

  if (dispatch && typeof dispatch.byteLength === 'number') {
    dispatch = b4a.isBuffer(dispatch)
      ? dispatch
      : b4a.from(dispatch.buffer || dispatch, dispatch.byteOffset || 0, dispatch.byteLength)
  } else if (dispatch && typeof dispatch === 'object') {
    dispatch = encodeDispatchFrame({
      ...dispatch,
      frameKind: dispatch.frameKind == null ? FRAME_KIND.RESPONSE : dispatch.frameKind,
      familyId: dispatch.familyId == null ? request.familyId : dispatch.familyId,
      operationId: dispatch.operationId == null ? request.operationId : dispatch.operationId,
      requestId: dispatch.requestId == null ? request.requestId : dispatch.requestId
    })
  } else {
    throw new BlindProtocolError('INTERNAL', 'dispatcher returned no canonical result')
  }

  const decoded = decodeDispatchFrame(dispatch)
  if (decoded.frameKind !== FRAME_KIND.RESPONSE && decoded.frameKind !== FRAME_KIND.ERROR) {
    throw new BlindProtocolError('INTERNAL', 'dispatcher returned a non-result frame')
  }
  if (decoded.familyId !== request.familyId || decoded.operationId !== request.operationId ||
      !sameBytes(decoded.requestId, request.requestId)) {
    throw new BlindProtocolError('INTERNAL', 'dispatcher returned mismatched correlation fields')
  }
  return { dispatch, outerClass }
}

function socketIdentity (stat) {
  return { dev: stat.dev, ino: stat.ino, uid: stat.uid, gid: stat.gid }
}

function sameSocketIdentity (left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino)
}

function probeUnixSocket (socketPath, timeoutMs = 250) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath })
    let settled = false
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      const error = new Error('existing Unix socket did not prove stale')
      error.code = 'EADDRINUSE'
      finish(error)
    }, timeoutMs)
    if (timer.unref) timer.unref()
    socket.once('connect', () => finish(null, true))
    socket.once('error', error => {
      if (error && (error.code === 'ECONNREFUSED' || error.code === 'ENOENT')) finish(null, false)
      else finish(error)
    })
  })
}

async function removeStaleSocket (socketPath) {
  let stat
  try {
    stat = await fs.lstat(socketPath)
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  if (!stat.isSocket()) throw new Error('refusing to replace a non-socket at socketPath')
  if (await probeUnixSocket(socketPath)) {
    const error = new Error('refusing to replace an active blind daemon socket')
    error.code = 'EADDRINUSE'
    throw error
  }
  let current
  try {
    current = await fs.lstat(socketPath)
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  if (!current.isSocket() || !sameSocketIdentity(socketIdentity(stat), socketIdentity(current))) {
    const error = new Error('socketPath changed during stale-socket verification')
    error.code = 'EADDRINUSE'
    throw error
  }
  try {
    await fs.unlink(socketPath)
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error
  }
}

async function prepareSocketParent (socketPath) {
  const directory = path.dirname(socketPath)
  await fs.mkdir(directory, { recursive: true, mode: 0o750 })
  const stat = await fs.lstat(directory)
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`refusing non-directory or symlink socket parent ${directory}`)
  }
  const real = await fs.realpath(directory)
  if (real !== directory) throw new Error(`refusing symlinked socket parent ${directory}`)
}

function closeServer (server) {
  if (!server || !server.listening) return Promise.resolve()
  return new Promise(resolve => server.close(() => resolve()))
}

async function unlinkOwnedSocket (socketPath, identity) {
  if (!identity) return
  try {
    const stat = await fs.lstat(socketPath)
    if (stat.isSocket() && sameSocketIdentity(identity, socketIdentity(stat))) await fs.unlink(socketPath)
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error
  }
}

async function fenceSocketPathForClose (socketPath, identity) {
  // Node/libuv unlinks a Unix-listener pathname during server.close(). Move the
  // current directory entry aside and occupy the path with a directory sentinel
  // so libuv cannot unlink an operator replacement behind our inode check.
  const directory = path.dirname(socketPath)
  const guardDirectory = await fs.mkdtemp(path.join(directory, '.blind-socket-close-'))
  const heldPath = path.join(guardDirectory, 'held-path')
  const sentinelSource = path.join(guardDirectory, 'sentinel-source')
  await fs.mkdir(sentinelSource, { mode: 0o700 })
  let held = false
  let heldOwned = false
  try {
    try {
      await fs.rename(socketPath, heldPath)
      held = true
      const heldStat = await fs.lstat(heldPath)
      heldOwned = heldStat.isSocket() && sameSocketIdentity(identity, socketIdentity(heldStat))
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error
    }
    await fs.rename(sentinelSource, socketPath)
    const sentinelStat = await fs.lstat(socketPath)
    return {
      socketPath,
      guardDirectory,
      heldPath,
      held,
      heldOwned,
      sentinelIdentity: socketIdentity(sentinelStat)
    }
  } catch (error) {
    try {
      if (held && !(await pathExistsForCleanup(socketPath))) await fs.rename(heldPath, socketPath)
    } finally {
      await fs.rm(guardDirectory, { recursive: true, force: true })
    }
    throw error
  }
}

async function pathExistsForCleanup (file) {
  try {
    await fs.lstat(file)
    return true
  } catch (error) {
    if (error && error.code === 'ENOENT') return false
    throw error
  }
}

async function releaseSocketPathFence (fence) {
  const stat = await fs.lstat(fence.socketPath)
  if (!stat.isDirectory() || !sameSocketIdentity(fence.sentinelIdentity, socketIdentity(stat))) {
    throw new Error(`socket close sentinel changed unexpectedly: ${fence.socketPath}`)
  }
  await fs.rmdir(fence.socketPath)
  if (fence.held) {
    if (fence.heldOwned) await fs.unlink(fence.heldPath)
    else await fs.rename(fence.heldPath, fence.socketPath)
  }
  await fs.rmdir(fence.guardDirectory)
}

async function closeOwnedSocketServer (server, socketPath, identity) {
  if (!server || !server.listening) {
    await unlinkOwnedSocket(socketPath, identity)
    return
  }
  const fence = await fenceSocketPathForClose(socketPath, identity)
  await closeServer(server)
  await releaseSocketPathFence(fence)
}

async function cleanupBoundSocket (bound) {
  if (!bound) return
  await closeOwnedSocketServer(bound.server, bound.socketPath, bound.identity)
}

async function bindSocketServer ({ socketPath, socketMode, socketGroupGid, maxConnections, accept }) {
  const server = net.createServer({ allowHalfOpen: true }, socket => accept(socket))
  server.maxConnections = maxConnections
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
    server.listen(socketPath)
  })
  let identity = null
  try {
    const before = await fs.lstat(socketPath)
    if (!before.isSocket() || before.isSymbolicLink()) throw new Error(`bound path is not a Unix socket: ${socketPath}`)
    identity = socketIdentity(before)
    await fs.chown(socketPath, -1, socketGroupGid)
    await fs.chmod(socketPath, socketMode)
    const after = await fs.lstat(socketPath)
    if (!after.isSocket() || !sameSocketIdentity(identity, socketIdentity(after)) ||
        after.gid !== socketGroupGid || (after.mode & 0o777) !== socketMode) {
      throw new Error(`Unix socket identity or mode changed during bind: ${socketPath}`)
    }
    identity = socketIdentity(after)
    return { server, socketPath, identity }
  } catch (error) {
    await cleanupBoundSocket({ server, socketPath, identity })
    throw error
  }
}

async function * localStreamRecords (socket) {
  let buffer = b4a.alloc(0)
  let open = true
  const maximum = 2 * (21 + 65_535)
  for await (const chunk of socket.iterator({ destroyOnReturn: false })) {
    if (buffer.byteLength + chunk.byteLength > maximum) {
      const error = new Error('private stream record buffer exceeds two bounded records')
      error.code = 'BAD_LOCAL_STREAM'
      throw error
    }
    buffer = buffer.byteLength === 0 ? b4a.from(chunk) : b4a.concat([buffer, chunk])
    for (;;) {
      const expected = open ? localStreamOpenFrameLength(buffer) : localStreamFrameLength(buffer)
      if (expected == null || buffer.byteLength < expected) break
      const record = b4a.from(buffer.subarray(0, expected))
      buffer = b4a.from(buffer.subarray(expected))
      open = false
      yield record
    }
  }
  if (buffer.byteLength !== 0) {
    const error = new Error('private stream ended with a truncated record')
    error.code = 'BAD_LOCAL_STREAM'
    throw error
  }
}

async function writeSocketFrames (socket, frames, timeoutMs) {
  for (const frame of frames) {
    if (socket.destroyed) throw new Error('private stream closed before response write')
    await new Promise((resolve, reject) => {
      let settled = false
      const finish = error => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.off('error', finish)
        if (error) reject(error)
        else resolve()
      }
      const timer = setTimeout(() => finish(Object.assign(new Error('private stream response write timed out'), {
        code: 'IPC_WRITE_TIMEOUT'
      })), timeoutMs)
      if (timer.unref) timer.unref()
      socket.once('error', finish)
      socket.write(frame, finish)
    })
  }
}

export class BlindDaemon {
  constructor (options = {}) {
    this.unarySocketPath = validSocketPath(options.unarySocketPath, 'unarySocketPath')
    this.streamSocketPath = validSocketPath(options.streamSocketPath, 'streamSocketPath')
    if (this.unarySocketPath === this.streamSocketPath) {
      throw new TypeError('unarySocketPath and streamSocketPath must be unequal')
    }
    this.socketMode = options.socketMode == null ? DEFAULT_SOCKET_MODE : options.socketMode
    if (!Number.isInteger(this.socketMode) || this.socketMode < 0 || this.socketMode > 0o777) {
      throw new TypeError('socketMode must be a Unix permission mode')
    }
    this.requestTimeoutMs = positiveInteger(options.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS, 'requestTimeoutMs')
    this.maxConnections = positiveInteger(options.maxConnections, DEFAULT_MAX_CONNECTIONS, 'maxConnections')
    this.closeTimeoutMs = positiveInteger(options.closeTimeoutMs, DEFAULT_CLOSE_TIMEOUT_MS, 'closeTimeoutMs')
    this.maxBufferedBytes = positiveInteger(options.maxBufferedBytes, DEFAULT_MAX_BUFFERED_BYTES, 'maxBufferedBytes')
    this.maxPendingReadinessChecks = positiveInteger(options.maxPendingReadinessChecks,
      Math.min(DEFAULT_MAX_PENDING_READINESS_CHECKS, this.maxConnections), 'maxPendingReadinessChecks')
    if (this.maxPendingReadinessChecks > this.maxConnections) {
      throw new TypeError('maxPendingReadinessChecks cannot exceed maxConnections')
    }
    this.expectedPeerUid = positiveInteger(options.expectedPeerUid, null, 'expectedPeerUid', true)
    this.expectedPeerGid = positiveInteger(options.expectedPeerGid, null, 'expectedPeerGid', true)
    this.socketGroupGid = positiveInteger(options.socketGroupGid, null, 'socketGroupGid', true)
    if (this.expectedPeerUid == null || this.expectedPeerGid == null || this.socketGroupGid == null) {
      throw new TypeError('expected peer UID/GID and socketGroupGid are required from the signed launch topology')
    }
    this.dispatch = typeof options.dispatch === 'function' ? options.dispatch : null
    this.dispatchStagedPut = typeof options.dispatchStagedPut === 'function' ? options.dispatchStagedPut : null
    this.streamTransportProfileHash = fixed32(options.streamTransportProfileHash,
      'streamTransportProfileHash', true)
    this.streamTransportProfileHashForEndpoint = typeof options.streamTransportProfileHashForEndpoint === 'function'
      ? options.streamTransportProfileHashForEndpoint
      : null
    if (this.streamTransportProfileHash && this.streamTransportProfileHashForEndpoint) {
      throw new TypeError('configure one static or endpoint-resolved stream transport profile hash, not both')
    }
    if (this.streamTransportProfileHash && allZero(this.streamTransportProfileHash)) {
      throw new TypeError('streamTransportProfileHash must be nonzero')
    }
    const streamProfileConfigured = this.streamTransportProfileHash != null ||
      this.streamTransportProfileHashForEndpoint != null
    if ((this.dispatchStagedPut != null) !== streamProfileConfigured) {
      throw new TypeError('dispatchStagedPut and a stream transport profile authority must be configured together')
    }
    this.readinessSnapshot = typeof options.readinessSnapshot === 'function' ? options.readinessSnapshot : null
    this.launchTopologyHash = fixed32(options.launchTopologyHash, 'launchTopologyHash', true)
    this.endpointIds = options.endpointIds == null && options.endpointId == null ? null : endpointSet(options)
    this.releaseGate = typeof options.releaseGate === 'function' ? options.releaseGate : assertExecutableReleaseReady
    this.onError = typeof options.onError === 'function' ? options.onError : () => {}
    this.now = typeof options.monotonicMillis === 'function' ? options.monotonicMillis : monotonicMillis
    currentMonotonic(this.now)
    this.unaryServer = null
    this.streamServer = null
    this.sockets = new Set()
    this.abortControllers = new Set()
    this.tasks = new Set()
    this.bufferedBytes = 0
    this.pendingReadinessChecks = []
    this.lastReadyDescriptor = null
    this.started = false
    this.closing = false
    this.boundSocketIdentities = new Map()
    this.closePromise = null
  }

  async start () {
    if (this.started) return this
    if (this.closing) throw new Error('blind daemon is closing')
    await this.releaseGate()
    if (!this.dispatch) {
      const error = new Error('blind daemon has no complete dispatcher/storage engine')
      error.code = 'BLIND_DISPATCHER_MISSING'
      throw error
    }
    if (!this.readinessSnapshot) {
      const error = new Error('blind daemon has no self-verified readiness snapshot provider')
      error.code = 'BLIND_READINESS_SNAPSHOT_MISSING'
      throw error
    }
    if (!this.launchTopologyHash || !this.endpointIds) {
      const error = new Error('blind daemon has no signed topology hash or endpoint set')
      error.code = 'BLIND_TOPOLOGY_BINDING_MISSING'
      throw error
    }

    await Promise.all([
      prepareSocketParent(this.unarySocketPath),
      prepareSocketParent(this.streamSocketPath)
    ])
    await removeStaleSocket(this.unarySocketPath)
    await removeStaleSocket(this.streamSocketPath)

    let unary = null
    let stream = null
    try {
      unary = await bindSocketServer({
        socketPath: this.unarySocketPath,
        socketMode: this.socketMode,
        socketGroupGid: this.socketGroupGid,
        maxConnections: this.maxConnections,
        accept: socket => this._acceptUnary(socket)
      })
      stream = await bindSocketServer({
        socketPath: this.streamSocketPath,
        socketMode: this.socketMode,
        socketGroupGid: this.socketGroupGid,
        maxConnections: this.maxConnections,
        accept: socket => this._acceptStream(socket)
      })
      unary.server.on('error', error => this.onError(error))
      stream.server.on('error', error => this.onError(error))
      this.unaryServer = unary.server
      this.streamServer = stream.server
      this.boundSocketIdentities.set(this.unarySocketPath, unary.identity)
      this.boundSocketIdentities.set(this.streamSocketPath, stream.identity)
      this.started = true
      return this
    } catch (error) {
      await cleanupBoundSocket(stream)
      await cleanupBoundSocket(unary)
      throw error
    }
  }

  _acceptUnary (socket) {
    if (!this.started || this.closing || this.sockets.size >= this.maxConnections) {
      socket.destroy()
      return
    }
    let credentials
    try {
      credentials = socketPeerCredentials(socket)
    } catch (error) {
      this.onError(error)
      socket.destroy()
      return
    }
    if (credentials.uid !== this.expectedPeerUid || credentials.gid !== this.expectedPeerGid) {
      socket.end(encodeLocalResponse({
        responseKind: LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR,
        localBrokerError: LOCAL_BROKER_ERROR.UNAUTHORIZED_EDGE_PEER
      }), () => socket.destroy())
      return
    }
    this.sockets.add(socket)
    const abortController = new AbortController()
    this.abortControllers.add(abortController)
    const chunks = []
    let total = 0
    let reservedBytes = 0
    let expectedLength = null
    let handling = false
    let task = null
    let taskSettled = false

    const releaseReservation = () => {
      this.bufferedBytes = Math.max(0, this.bufferedBytes - reservedBytes)
      reservedBytes = 0
    }
    const finish = () => {
      abortController.abort()
      this.sockets.delete(socket)
      if (!task || taskSettled) {
        releaseReservation()
        this.abortControllers.delete(abortController)
      }
    }
    socket.once('close', finish)
    socket.once('error', error => this.onError(error))
    socket.setTimeout(Math.min(this.requestTimeoutMs, PRIVATE_IPC_TIMING_MILLIS.IPC_CONNECT_AND_WRITE), () => socket.destroy())
    socket.on('data', chunk => {
      if (handling) {
        socket.destroy()
        return
      }
      if (total + chunk.byteLength > LOCAL_DISPATCH_ADJACENT_HEADER_BYTES + MAX_LOCAL_BODY_BYTES) {
        socket.destroy()
        return
      }
      const charge = chunk.byteLength * 2
      if (this.bufferedBytes + charge > this.maxBufferedBytes) {
        socket.destroy()
        return
      }
      this.bufferedBytes += charge
      reservedBytes += charge
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
      try {
        if (expectedLength == null && total >= 4) expectedLength = localRequestFrameLength(b4a.concat(chunks, total))
      } catch (error) {
        this.onError(error)
        socket.destroy()
        return
      }
      if (expectedLength == null || total < expectedLength) return
      if (total !== expectedLength) {
        socket.destroy()
        return
      }
      handling = true
      socket.pause()
      socket.setTimeout(0)
      task = this._handle(b4a.concat(chunks, total), abortController.signal, credentials)
      this.tasks.add(task)
      task.then(response => {
        if (socket.destroyed) return
        const responseTimer = setTimeout(() => socket.destroy(), PRIVATE_IPC_TIMING_MILLIS.DAEMON_RESPONSE_WRITE)
        if (responseTimer.unref) responseTimer.unref()
        socket.end(encodeLocalResponse(response), () => {
          clearTimeout(responseTimer)
          releaseReservation()
        })
      }, error => {
        this.onError(error)
        socket.destroy()
      }).finally(() => {
        taskSettled = true
        this.tasks.delete(task)
        this.abortControllers.delete(abortController)
        if (socket.destroyed) releaseReservation()
      })
    })
  }

  _acceptStream (socket) {
    if (!this.started || this.closing || this.sockets.size >= this.maxConnections) {
      socket.destroy()
      return
    }
    let credentials
    try {
      credentials = socketPeerCredentials(socket)
    } catch (error) {
      this.onError(error)
      socket.destroy()
      return
    }
    if (credentials.uid !== this.expectedPeerUid || credentials.gid !== this.expectedPeerGid) {
      socket.destroy()
      return
    }
    this.sockets.add(socket)
    const abortController = new AbortController()
    this.abortControllers.add(abortController)
    socket.once('close', () => {
      abortController.abort()
      this.sockets.delete(socket)
    })
    socket.once('error', error => this.onError(error))
    socket.setTimeout(PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT, () => socket.destroy())
    const task = this._handleStream(socket, credentials, abortController.signal)
    this.tasks.add(task)
    task.catch(error => {
      if (!abortController.signal.aborted) this.onError(error)
      if (!socket.destroyed) socket.destroy()
    }).finally(() => {
      this.tasks.delete(task)
      this.abortControllers.delete(abortController)
    })
  }

  async _handleStream (socket, credentials, signal) {
    const startedMonotonicMillis = currentMonotonic(this.now)
    const records = localStreamRecords(socket)
    const first = await records.next()
    if (first.done) {
      const completedMonotonicMillis = currentMonotonic(this.now)
      const elapsed = completedMonotonicMillis - startedMonotonicMillis
      if (!this.closing && this.started && elapsed >= 0n &&
          elapsed <= BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT)) {
        this._recordReadinessCheck(credentials, completedMonotonicMillis)
      }
      socket.end()
      return
    }
    socket.setTimeout(0)
    if (!this.dispatchStagedPut || (!this.streamTransportProfileHash && !this.streamTransportProfileHashForEndpoint)) {
      throw Object.assign(new Error('staged private stream runtime is not configured'), { code: 'BLIND_STREAM_UNAVAILABLE' })
    }
    const open = decodeLocalStreamOpen(first.value, { copyContext: true })
    const now = currentMonotonic(this.now)
    if (open.openKind !== LOCAL_STREAM_OPEN_KIND.PUBLIC_CONTENT_CHANNEL ||
        open.streamMode !== LOCAL_STREAM_MODE.DISPATCH_CONTENT ||
        open.adjacentRelayKey != null || !this.endpointIds.has(open.endpointId) ||
        open.acceptedMonotonicMillis > now || open.openDeadlineMonotonicMillis <= now) {
      throw Object.assign(new Error('private stream open does not match the staged public PUT path'), {
        code: 'BAD_LOCAL_STREAM'
      })
    }
    const expectedTransportProfileHash = this.streamTransportProfileHash || fixed32(
      await this.streamTransportProfileHashForEndpoint({
        endpointId: open.endpointId,
        transportId: open.transportId,
        transportSupportBit: open.transportSupportBit,
        signal
      }), 'resolved stream transportProfileHash')
    if (allZero(expectedTransportProfileHash)) throw new Error('resolved stream transportProfileHash must be nonzero')
    const channelHandle = verifyLocalAuthenticatedChannelContext(open.contextBytes, open, {
      launchTopologyHash: this.launchTopologyHash,
      transportProfileHash: expectedTransportProfileHash
    })
    const channel = localAuthenticatedChannelAuthority(channelHandle)
    if (channel.endpointId !== open.endpointId || channel.transportId !== open.transportId ||
        channel.transportSupportBit !== open.transportSupportBit) {
      throw Object.assign(new Error('private stream channel authority does not match its open'), {
        code: 'BAD_LOCAL_STREAM'
      })
    }

    if (this.bufferedBytes + STAGED_PUT_STREAM_RESERVATION_BYTES > this.maxBufferedBytes) {
      throw Object.assign(new Error('staged PUT private-stream memory budget is exhausted'), {
        code: 'BLIND_STREAM_BUSY'
      })
    }
    this.bufferedBytes += STAGED_PUT_STREAM_RESERVATION_BYTES
    try {
      await this._runStagedPutStream(socket, records, open, signal, now)
    } finally {
      this.bufferedBytes = Math.max(0, this.bufferedBytes - STAGED_PUT_STREAM_RESERVATION_BYTES)
    }
  }

  async _runStagedPutStream (socket, records, open, signal, now) {
    const remainingMillis = Math.max(1, Number(open.openDeadlineMonotonicMillis - now))
    const deadlineSignal = AbortSignal.timeout(remainingMillis)
    const operationSignal = AbortSignal.any([signal, deadlineSignal])
    const absoluteTimer = setTimeout(() => socket.destroy(), remainingMillis)
    if (absoluteTimer.unref) absoluteTimer.unref()
    socket.once('close', () => clearTimeout(absoluteTimer))
    socket.setTimeout(PRIVATE_IPC_TIMING_MILLIS.BODY_PROGRESS_IDLE, () => socket.destroy())
    const guard = new LocalStreamSequenceGuard(open)
    const ingestor = new StagedCellPutDispatchIngestor()
    const dispatched = ingestor.ready.then(staged => this.dispatchStagedPut(staged, {
      transportId: open.transportId,
      transportSupportBit: open.transportSupportBit,
      endpointId: open.endpointId,
      outerClass: null,
      adjacentRelayKey: null,
      acceptedMonotonicMillis: open.acceptedMonotonicMillis,
      absoluteDeadlineMonotonicMillis: open.openDeadlineMonotonicMillis,
      signal: operationSignal
    }))
    // A parser failure can reject readiness before the dispatch task is awaited.
    dispatched.catch(() => {})
    let ingressError = null
    let sawFin = false
    let sawAbort = false
    try {
      for await (const record of records) {
        const frame = decodeLocalStreamFrame(record, { copyBody: true })
        if (sawAbort) {
          throw Object.assign(new Error('staged PUT received a record after terminal ABORT'), {
            code: 'BAD_LOCAL_STREAM'
          })
        }
        guard.accept(frame)
        if (frame.direction !== LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON) {
          throw Object.assign(new Error('staged PUT accepts only Edge-to-daemon frames'), {
            code: 'BAD_LOCAL_STREAM'
          })
        }
        if (frame.frameKind === LOCAL_STREAM_FRAME_KIND.ABORT) {
          sawAbort = true
          continue
        }
        if (frame.frameKind !== LOCAL_STREAM_FRAME_KIND.CONTENT) {
          throw Object.assign(new Error('staged PUT accepts only Edge-to-daemon CONTENT frames'), {
            code: 'BAD_LOCAL_STREAM'
          })
        }
        await ingestor.push(frame.bytes)
        if ((frame.flags & LOCAL_STREAM_FLAG.FIN) !== 0) {
          sawFin = true
        }
      }
      // A terminal frame is not sufficient by itself: the peer must half-close
      // its request direction. Waiting for exact EOF makes both coalesced and
      // later post-FIN bytes observable before the staged ingest can finish.
      if (!socket.readableEnded || signal.aborted || deadlineSignal.aborted) {
        throw Object.assign(new Error('staged PUT request direction did not end cleanly at its terminal boundary'), {
          code: 'BAD_LOCAL_STREAM'
        })
      }
      if (sawAbort) {
        const error = new Error('staged PUT was aborted by its authenticated edge')
        error.code = 'ABORT_ERR'
        throw error
      }
      if (!sawFin) {
        throw Object.assign(new Error('staged PUT request direction ended before terminal FIN'), {
          code: 'BAD_LOCAL_STREAM'
        })
      }
      socket.setTimeout(0)
      ingestor.finish()
    } catch (error) {
      ingressError = error
      try { ingestor.abort(error) } catch {}
    }

    let result
    try {
      result = await dispatched
    } catch (error) {
      throw ingressError || error
    }
    if (ingressError) throw ingressError
    if (!result || !result.dispatch || typeof result.dispatch.byteLength !== 'number') {
      throw Object.assign(new Error('staged PUT dispatcher returned no canonical response'), { code: 'BAD_LOCAL_STREAM' })
    }
    const responseFrames = fragmentLocalContent(result.dispatch, {
      direction: LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE,
      wireClass: open.channelClass,
      sequence: 0n,
      fin: true
    })
    await writeSocketFrames(socket, responseFrames, PRIVATE_IPC_TIMING_MILLIS.DAEMON_RESPONSE_WRITE)
    socket.end()
  }

  _recordReadinessCheck (credentials, completedMonotonicMillis) {
    const minimum = completedMonotonicMillis >= BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT)
      ? completedMonotonicMillis - BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT)
      : 0n
    this.pendingReadinessChecks = this.pendingReadinessChecks.filter(check =>
      check.completedMonotonicMillis >= minimum && check.completedMonotonicMillis <= completedMonotonicMillis)
    if (this.pendingReadinessChecks.length >= this.maxPendingReadinessChecks) this.pendingReadinessChecks.shift()
    this.pendingReadinessChecks.push({
      uid: credentials.uid,
      gid: credentials.gid,
      completedMonotonicMillis
    })
  }

  _consumeReadinessCheck (credentials, acceptedMonotonicMillis, now) {
    const maximumAge = BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT)
    let selected = -1
    const retained = []
    for (const check of this.pendingReadinessChecks) {
      if (check.completedMonotonicMillis > now) continue
      if (check.completedMonotonicMillis <= acceptedMonotonicMillis &&
          acceptedMonotonicMillis - check.completedMonotonicMillis > maximumAge) continue
      if (selected === -1 && check.uid === credentials.uid && check.gid === credentials.gid &&
          check.completedMonotonicMillis <= acceptedMonotonicMillis) {
        selected = retained.length
      }
      retained.push(check)
    }
    if (selected === -1) {
      this.pendingReadinessChecks = retained
      return false
    }
    retained.splice(selected, 1)
    this.pendingReadinessChecks = retained
    return true
  }

  async _boundSocketsStillMatch () {
    for (const socketPath of [this.unarySocketPath, this.streamSocketPath]) {
      const expected = this.boundSocketIdentities.get(socketPath)
      if (!expected) return false
      let stat
      try {
        stat = await fs.lstat(socketPath)
      } catch {
        return false
      }
      if (!stat.isSocket() || stat.isSymbolicLink() || !sameSocketIdentity(expected, socketIdentity(stat)) ||
          stat.uid !== expected.uid || stat.gid !== expected.gid || (stat.mode & 0o777) !== this.socketMode) return false
    }
    return true
  }

  _validateReadinessSnapshot (snapshot) {
    if (!snapshot || typeof snapshot !== 'object' || snapshot.selfVerified !== true) return null
    let descriptorSequence
    let descriptorHash
    try {
      descriptorSequence = u64(snapshot.descriptorSequence, 'descriptorSequence')
      descriptorHash = fixed32(snapshot.descriptorHash, 'descriptorHash')
    } catch {
      return null
    }
    if (!Number.isInteger(snapshot.readyRoleBits) || snapshot.readyRoleBits < 0 ||
        snapshot.readyRoleBits > KNOWN_ROLE_BITS) return null
    if (!Number.isInteger(snapshot.readyOperationBits) || snapshot.readyOperationBits < 0 ||
        snapshot.readyOperationBits > 0xffffffff || (snapshot.readyOperationBits & ~KNOWN_OPERATION_BITS) !== 0) return null
    return {
      descriptorSequence,
      descriptorHash,
      readyRoleBits: snapshot.readyRoleBits,
      readyOperationBits: snapshot.readyOperationBits
    }
  }

  _descriptorTupleAdvances (snapshot) {
    const previous = this.lastReadyDescriptor
    if (!previous) return true
    if (snapshot.descriptorSequence < previous.descriptorSequence) return false
    if (snapshot.descriptorSequence === previous.descriptorSequence &&
        !sameBytes(snapshot.descriptorHash, previous.descriptorHash)) return false
    return true
  }

  async _handleReadyProbe (local, operationSignal, credentials) {
    const now = currentMonotonic(this.now)
    if (!sameBytes(local.readyProbe.launchTopologyHash, this.launchTopologyHash) ||
        !this.endpointIds.has(local.endpointId)) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
    }
    if (!this._consumeReadinessCheck(credentials, local.acceptedMonotonicMillis, now)) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
    }
    if (local.acceptedMonotonicMillis > MAX_U64 - BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_ACK_MAX_LIFETIME)) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
    }

    let rawSnapshot
    try {
      rawSnapshot = await abortableCall(() => this.readinessSnapshot({
        edgeInstanceNonce: b4a.from(local.readyProbe.edgeInstanceNonce),
        endpointId: local.endpointId,
        launchTopologyHash: b4a.from(this.launchTopologyHash),
        acceptedMonotonicMillis: local.acceptedMonotonicMillis,
        absoluteDeadlineMonotonicMillis: local.absoluteDeadlineMonotonicMillis,
        signal: operationSignal
      }), operationSignal)
    } catch (error) {
      this.onError(error)
      return localBrokerResponse(LOCAL_BROKER_ERROR.INTERNAL_IPC_FAILURE)
    }
    const snapshot = this._validateReadinessSnapshot(rawSnapshot)
    if (!snapshot) return localBrokerResponse(LOCAL_BROKER_ERROR.INTERNAL_IPC_FAILURE)
    if ((snapshot.readyOperationBits & REQUIRED_DESCRIBE_OPERATION_BITS) !== REQUIRED_DESCRIBE_OPERATION_BITS) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.DAEMON_DRAINING)
    }
    if (!this._descriptorTupleAdvances(snapshot)) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
    }
    const completed = currentMonotonic(this.now)
    const expiresMonotonicMillis = local.acceptedMonotonicMillis +
      BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_ACK_MAX_LIFETIME)
    if (operationSignal.aborted || completed >= local.absoluteDeadlineMonotonicMillis ||
        expiresMonotonicMillis <= completed || !(await this._boundSocketsStillMatch())) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
    }
    if (!this._descriptorTupleAdvances(snapshot)) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
    }
    this.lastReadyDescriptor = {
      descriptorSequence: snapshot.descriptorSequence,
      descriptorHash: b4a.from(snapshot.descriptorHash)
    }
    return {
      responseKind: LOCAL_RESPONSE_KIND.LOCAL_READY_ACK,
      localBrokerError: 0,
      body: encodeLocalReadyAckBody({
        edgeInstanceNonce: local.readyProbe.edgeInstanceNonce,
        launchTopologyHash: this.launchTopologyHash,
        endpointId: local.endpointId,
        descriptorSequence: snapshot.descriptorSequence,
        descriptorHash: snapshot.descriptorHash,
        readyRoleBits: snapshot.readyRoleBits,
        readyOperationBits: snapshot.readyOperationBits,
        expiresMonotonicMillis
      })
    }
  }

  async _handle (bytes, signal, credentials) {
    const local = decodeLocalRequest(bytes)
    const now = currentMonotonic(this.now)
    const horizon = BigInt(local.readyProbe
      ? PRIVATE_IPC_TIMING_MILLIS.READY_PROBE_ABSOLUTE
      : local.family === FAMILY.INBOX
        ? PRIVATE_IPC_TIMING_MILLIS.INBOX_UNARY_ABSOLUTE
        : PRIVATE_IPC_TIMING_MILLIS.ORDINARY_UNARY_ABSOLUTE)
    if (local.acceptedMonotonicMillis > now || local.absoluteDeadlineMonotonicMillis <= now ||
        local.absoluteDeadlineMonotonicMillis - local.acceptedMonotonicMillis > horizon) {
      return localBrokerResponse(LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
    }
    const remainingMillis = local.absoluteDeadlineMonotonicMillis - now
    const deadlineSignal = AbortSignal.timeout(Math.max(1, Number(remainingMillis)))
    const operationSignal = AbortSignal.any([signal, deadlineSignal])
    if (local.readyProbe) return this._handleReadyProbe(local, operationSignal, credentials)
    const envelope = decodeOuterEnvelope(local.externalCanonicalBytes, { copyInner: true, copyBody: true })
    const request = envelope.frame
    if (request.frameKind !== FRAME_KIND.REQUEST) {
      throw new BlindProtocolError('BAD_ENCODING', 'direct IPC request must carry a request frame')
    }
    if (request.familyId !== local.family) {
      return this._wrapForRequest(local, correlatedErrorDispatch(request,
        new BlindProtocolError('BAD_ENCODING', 'route family does not match dispatch family')))
    }
    const profile = operationProfile(request.familyId, request.operationId)
    if (!profile || (profile.transportSupportBits & local.transportSupportBit) === 0) {
      return this._wrapForRequest(local, correlatedErrorDispatch(request,
        new BlindProtocolError('TRANSPORT_UNSUPPORTED', 'operation is unavailable on the bound transport')))
    }

    try {
      const result = await this.dispatch(request, {
        family: local.family,
        transportId: local.transportId,
        transportSupportBit: local.transportSupportBit,
        endpointId: local.endpointId,
        outerClass: local.outerClass,
        adjacentRelayKey: local.adjacentRelayKey,
        acceptedMonotonicMillis: local.acceptedMonotonicMillis,
        absoluteDeadlineMonotonicMillis: local.absoluteDeadlineMonotonicMillis,
        signal: operationSignal
      })
      if (operationSignal.aborted || currentMonotonic(this.now) >= local.absoluteDeadlineMonotonicMillis) {
        throw new BlindProtocolError('INTERNAL', 'absolute request deadline elapsed before result release')
      }
      const normalized = normalizeDispatchResult(request, result)
      return this._wrapForRequest(local, normalized.dispatch, normalized.outerClass)
    } catch (error) {
      return this._wrapForRequest(local, correlatedErrorDispatch(request, error))
    }
  }

  _wrapForRequest (local, dispatch, requestedOuterClass = null) {
    if (requestedOuterClass != null && requestedOuterClass !== local.outerClass) {
      throw new BlindProtocolError('INTERNAL', 'dispatcher attempted to change the selected response class')
    }
    return encodeOuterEnvelope({ innerDispatch: dispatch, outerClass: local.outerClass })
  }

  address () {
    if (!this.unaryServer || !this.streamServer) return null
    return {
      unary: this.unaryServer.address(),
      stream: this.streamServer.address()
    }
  }

  close () {
    if (this.closePromise) return this.closePromise
    this.closePromise = this._close()
    return this.closePromise
  }

  async _close () {
    this.closing = true
    this.started = false
    const serversClosed = Promise.all([
      closeOwnedSocketServer(this.unaryServer, this.unarySocketPath,
        this.boundSocketIdentities.get(this.unarySocketPath)),
      closeOwnedSocketServer(this.streamServer, this.streamSocketPath,
        this.boundSocketIdentities.get(this.streamSocketPath))
    ])
    for (const abortController of this.abortControllers) abortController.abort()
    for (const socket of this.sockets) socket.destroy()
    if (this.tasks.size > 0) {
      let timer
      const timedOut = new Promise((resolve, reject) => {
        timer = setTimeout(() => {
          const error = new Error('blind daemon close timed out with dispatch work still active')
          error.code = 'BLIND_CLOSE_TIMEOUT'
          reject(error)
        }, this.closeTimeoutMs)
        if (timer.unref) timer.unref()
      })
      try {
        await Promise.race([Promise.allSettled([...this.tasks]), timedOut])
      } finally {
        clearTimeout(timer)
      }
    }
    await serversClosed
    this.unaryServer = null
    this.streamServer = null
    this.boundSocketIdentities.clear()
    this.pendingReadinessChecks = []
    this.lastReadyDescriptor = null
  }
}

export function createBlindDaemon (options) {
  return new BlindDaemon(options)
}
