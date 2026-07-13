import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import { socketPeerCredentials } from '@hiverelay/blind-peercred'
import {
  BlindProtocolError,
  ERROR_CODE,
  ERROR_PROFILE_ID,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  allocationCommitment,
  assertReleaseReady,
  blindErrorV1,
  cellPutRequestCommitment,
  decodeDispatchFrame,
  decodeOuterEnvelope,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  errorProfileEntry,
  operationProfile
} from '@hiverelay/blind-protocol'
import {
  LOCAL_BROKER_ERROR,
  LOCAL_RESPONSE_KIND,
  LOCAL_DISPATCH_ADJACENT_HEADER_BYTES,
  MAX_LOCAL_BODY_BYTES,
  PRIVATE_IPC_LIMITS,
  PRIVATE_IPC_TIMING_MILLIS,
  assertPrivateIpcReady,
  decodeLocalRequest,
  encodeLocalReadyAckBody,
  encodeLocalResponse,
  localRequestFrameLength,
  localStreamOpenFrameLength
} from '@hiverelay/blind-ipc'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_STAGED_FLAG_V2,
  LOCAL_STAGED_FRAME_KIND_V2,
  PRIVATE_IPC_V2_LIMITS,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  assertPrecommitCellPutResultFitV2,
  decodeLocalReadyProbeV2,
  decodeLocalStagedCellPutFrameV2,
  decodeLocalStagedCellPutOpenV2,
  encodeLocalReadyAckV2,
  readLocalReadyProbeLengthV2,
  readLocalStagedCellPutFrameLengthV2,
  readLocalStagedCellPutOpenLengthV2,
  replayTupleHashV2,
  validateLocalStagedCellPutOpenBindingV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import {
  STAGED_CELL_PUT_DEFAULT_QUEUE_BYTES,
  STAGED_CELL_PUT_MAX_PREFIX_BYTES
} from './staged-put.js'
import {
  STAGED_CELL_PUT_FRAME_DECODER_MAX_BUFFERED_BYTES_V2,
  STAGED_CELL_PUT_FRAME_READER_MAX_BUFFERED_BYTES_V2,
  STAGED_CELL_PUT_RESULT_ENCODER_MAX_BUFFERED_BYTES_V2,
  StagedCellPutOuterEnvelopeIngestorV2,
  StagedCellPutResultEncoderV2,
  writeSocketFramesWithinDeadlineV2
} from './private-ipc-v2-runtime.js'
import {
  createDaemonPrivatePostEofAuthorityIssuer,
  isDaemonPrivatePostEofAuthorityIssuer
} from './post-eof-authority.js'

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
export const STAGED_PUT_MEMORY_LEDGER_V2 = Object.freeze({
  socketReadBytes: 2 * PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES,
  frameReaderBytes: STAGED_CELL_PUT_FRAME_READER_MAX_BUFFERED_BYTES_V2,
  frameDecoderPeakBytes: STAGED_CELL_PUT_FRAME_DECODER_MAX_BUFFERED_BYTES_V2,
  stagedIngressBytes: (5 * STAGED_CELL_PUT_MAX_PREFIX_BYTES) +
    STAGED_CELL_PUT_DEFAULT_QUEUE_BYTES,
  resultEncoderPeakBytes: STAGED_CELL_PUT_RESULT_ENCODER_MAX_BUFFERED_BYTES_V2
})
export const STAGED_PUT_SOCKET_RESERVATION_BYTES_V2 =
  STAGED_PUT_MEMORY_LEDGER_V2.socketReadBytes
export const STAGED_PUT_STREAM_RESERVATION_BYTES_V2 =
  STAGED_PUT_MEMORY_LEDGER_V2.socketReadBytes +
  STAGED_PUT_MEMORY_LEDGER_V2.frameDecoderPeakBytes +
  STAGED_PUT_MEMORY_LEDGER_V2.stagedIngressBytes +
  STAGED_PUT_MEMORY_LEDGER_V2.resultEncoderPeakBytes
const STAGED_PUT_POST_READY_RESERVATION_BYTES_V2 =
  STAGED_PUT_STREAM_RESERVATION_BYTES_V2 - STAGED_PUT_SOCKET_RESERVATION_BYTES_V2
const OBSERVED_PEERCRED_SOCKETS = new WeakMap()
const V2_DAEMON_AUTHORITIES = new WeakMap()

export const V2_WRITE_DISABLED_REASON = Object.freeze({
  STAGED_DISPATCHER_MISSING: 'STAGED_DISPATCHER_MISSING',
  STAGED_PUT_RELAY_KEY_MISSING: 'STAGED_PUT_RELAY_KEY_MISSING',
  TRANSPORT_PROFILE_MISSING: 'TRANSPORT_PROFILE_MISSING',
  WRITE_READINESS_PROJECTION_MISSING: 'WRITE_READINESS_PROJECTION_MISSING',
  DURABLE_REPLAY_AUTHORITY_MISSING: 'DURABLE_REPLAY_AUTHORITY_MISSING'
})

function assertExecutableReleaseReady () {
  assertReleaseReady()
  assertPrivateIpcReady()
}

function monotonicMillis () {
  return process.hrtime.bigint() / 1_000_000n
}

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
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

function absoluteOperationSignal (parent, absoluteDeadlineMonotonicMillis, nowMonotonicMillis) {
  if (absoluteDeadlineMonotonicMillis <= nowMonotonicMillis) throw abortError()
  const remaining = absoluteDeadlineMonotonicMillis - nowMonotonicMillis
  const deadline = AbortSignal.timeout(Math.max(1, Number(remaining)))
  return parent ? AbortSignal.any([parent, deadline]) : deadline
}

function destroySocketOnAbort (socket, signal) {
  const abort = () => {
    if (!socket.destroyed) socket.destroy()
  }
  signal.addEventListener('abort', abort, { once: true })
  if (signal.aborted) queueMicrotask(abort)
  return () => signal.removeEventListener('abort', abort)
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

async function bindSocketServer ({ socketPath, socketMode, socketGroupGid, maxConnections, highWaterMark, accept }) {
  const server = net.createServer({
    allowHalfOpen: true,
    ...(highWaterMark == null ? {} : { highWaterMark })
  }, socket => accept(socket))
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

function waitForSocketReadable (socket) {
  return new Promise((resolve, reject) => {
    let settled = false
    const cleanup = () => {
      socket.off('readable', onReadable)
      socket.off('end', onReadable)
      socket.off('close', onReadable)
      socket.off('error', onError)
    }
    const finish = error => {
      if (settled) return
      settled = true
      cleanup()
      if (error) reject(error)
      else resolve()
    }
    const onReadable = () => finish()
    const onError = error => finish(error)
    socket.once('readable', onReadable)
    socket.once('end', onReadable)
    socket.once('close', onReadable)
    socket.once('error', onError)
    if (socket.readableLength > 0 || socket.readableEnded || socket.destroyed) queueMicrotask(onReadable)
  })
}

async function readExactSocketBytesInto (socket, output, offset = 0, options = {}) {
  const start = offset
  while (offset < output.byteLength) {
    const remaining = output.byteLength - offset
    const requested = socket.readableLength > 0
      ? Math.min(remaining, socket.readableLength)
      : remaining
    const chunk = socket.read(requested)
    if (chunk && chunk.byteLength > 0) {
      if (chunk.byteLength > remaining) {
        throw Object.assign(new Error('private stream exact read exceeded its bounded target'), {
          code: 'BAD_LOCAL_STREAM'
        })
      }
      b4a.copy(chunk, output, offset)
      offset += chunk.byteLength
      continue
    }
    if (socket.readableEnded || socket.destroyed) break
    await waitForSocketReadable(socket)
  }
  if (offset === start && options.allowEmptyEof === true && socket.readableEnded) return false
  if (offset !== output.byteLength) {
    throw Object.assign(new Error('private stream ended before one exact bounded open record'), {
      code: 'BAD_LOCAL_STREAM'
    })
  }
  return true
}

async function readExactSocketBytes (socket, length, options = {}) {
  const output = b4a.alloc(length)
  if (!(await readExactSocketBytesInto(socket, output, 0, options))) return null
  return output
}

async function readFirstLocalStreamOpen (socket) {
  const prefix = await readExactSocketBytes(socket, 5, { allowEmptyEof: true })
  if (prefix == null) return null
  const version = prefix[4]
  const declaredLength = b4a.readUInt32BE(prefix, 0) + 4
  if (version === 2) {
    if (declaredLength !== PRIVATE_IPC_V2_LIMITS.STAGED_OPEN_BYTES) {
      throw Object.assign(new Error('private IPC V2 staged open has a non-exact declared length'), {
        code: 'BAD_LOCAL_STREAM'
      })
    }
  } else if (version === 1) {
    const maximum = PRIVATE_IPC_LIMITS.STREAM_OPEN_ADJACENT_HEADER_BYTES +
      PRIVATE_IPC_LIMITS.MAX_STREAM_CONTEXT_BYTES
    if (declaredLength < PRIVATE_IPC_LIMITS.STREAM_OPEN_BASE_HEADER_BYTES || declaredLength > maximum) {
      throw Object.assign(new Error('private IPC V1 stream open has an out-of-bounds declared length'), {
        code: 'BAD_LOCAL_STREAM'
      })
    }
  } else {
    throw Object.assign(new Error('private stream record has no registered version'), {
      code: 'BAD_LOCAL_STREAM'
    })
  }
  const suffix = await readExactSocketBytes(socket, declaredLength - prefix.byteLength)
  const bytes = b4a.concat([prefix, suffix], declaredLength)
  const validatedLength = version === 2
    ? readLocalStagedCellPutOpenLengthV2(bytes)
    : localStreamOpenFrameLength(bytes)
  if (validatedLength !== declaredLength) {
    throw Object.assign(new Error('private stream open did not validate as one exact record'), {
      code: 'BAD_LOCAL_STREAM'
    })
  }
  return Object.freeze({ version, bytes })
}

async function * localStagedFrameRecordsV2 (socket) {
  for (;;) {
    const prefix = await readExactSocketBytes(socket, 4, { allowEmptyEof: true })
    if (prefix == null) return
    const length = b4a.readUInt32BE(prefix, 0) + 4
    if (length < PRIVATE_IPC_V2_LIMITS.STAGED_FRAME_HEADER_BYTES ||
        length > PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES) {
      const error = new Error('private stream frame declaration is outside its exact bound')
      error.code = 'BAD_LOCAL_STREAM'
      throw error
    }
    const record = b4a.alloc(length)
    b4a.copy(prefix, record, 0)
    await readExactSocketBytesInto(socket, record, prefix.byteLength)
    if (readLocalStagedCellPutFrameLengthV2(record) !== length) {
      const error = new Error('private stream frame did not validate as one exact record')
      error.code = 'BAD_LOCAL_STREAM'
      throw error
    }
    yield record
  }
}

function observedPeerCredentials (socket) {
  const credentials = socket && OBSERVED_PEERCRED_SOCKETS.get(socket)
  if (!credentials) {
    const error = new Error('private IPC socket has no daemon-observed peer credential authority')
    error.code = 'BLIND_PEERCRED_UNAVAILABLE'
    throw error
  }
  return credentials
}

function projectionBits (value, field, maximum = 0xffffffff) {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new TypeError(`${field} must be an unsigned integer within its generated mask`)
  }
  return value
}

export class BlindDaemon {
  #v2ReplayReservationCount
  #v2IngressConstructionCount
  #v2WriteDescriptorFloor

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
    this.readinessSnapshot = typeof options.readinessSnapshot === 'function' ? options.readinessSnapshot : null
    this.writeReadinessProjection = typeof options.writeReadinessProjection === 'function'
      ? options.writeReadinessProjection
      : null
    this.durableReplayAuthority = options.durableReplayAuthority == null
      ? null
      : options.durableReplayAuthority
    if (this.durableReplayAuthority != null &&
        (typeof this.durableReplayAuthority !== 'object' ||
         typeof this.durableReplayAuthority.reserve !== 'function')) {
      throw new TypeError('durableReplayAuthority.reserve is required')
    }
    this.postEofAuthorityIssuer = options.postEofAuthorityIssuer == null
      ? createDaemonPrivatePostEofAuthorityIssuer()
      : options.postEofAuthorityIssuer
    if (!isDaemonPrivatePostEofAuthorityIssuer(this.postEofAuthorityIssuer)) {
      throw new TypeError('postEofAuthorityIssuer must be a daemon-private branded issuer')
    }
    this.stagedPutRelayPublicKey = options.stagedPutRelayPublicKey == null
      ? null
      : fixed32(options.stagedPutRelayPublicKey, 'stagedPutRelayPublicKey')
    this.launchTopologyHash = fixed32(options.launchTopologyHash, 'launchTopologyHash', true)
    this.endpointIds = options.endpointIds == null && options.endpointId == null ? null : endpointSet(options)
    this.releaseGate = typeof options.releaseGate === 'function' ? options.releaseGate : assertExecutableReleaseReady
    this.onError = typeof options.onError === 'function' ? options.onError : () => {}
    this.now = typeof options.monotonicMillis === 'function' ? options.monotonicMillis : monotonicMillis
    currentMonotonic(this.now)
    this.#v2ReplayReservationCount = 0
    this.#v2IngressConstructionCount = 0
    this.#v2WriteDescriptorFloor = null
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
        highWaterMark: PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES,
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
    OBSERVED_PEERCRED_SOCKETS.set(socket, credentials)
    this.sockets.add(socket)
    const abortController = new AbortController()
    this.abortControllers.add(abortController)
    const chunks = []
    let total = 0
    let reservedBytes = 0
    let expectedLength = null
    let requestVersion = null
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
        if (expectedLength == null && total >= 5) {
          const pending = b4a.concat(chunks, total)
          requestVersion = pending[4]
          if (requestVersion === 2) expectedLength = readLocalReadyProbeLengthV2(pending)
          else if (requestVersion === 1) expectedLength = localRequestFrameLength(pending)
          else {
            throw Object.assign(new Error('private unary request has no registered version'), {
              code: 'BAD_LOCAL_REQUEST'
            })
          }
        }
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
      task = requestVersion === 2
        ? this._handleV2ReadyProbe(b4a.concat(chunks, total), socket, abortController.signal)
        : this._handle(b4a.concat(chunks, total), abortController.signal, credentials)
      this.tasks.add(task)
      task.then(response => {
        if (socket.destroyed) return
        let responseTimeoutMillis = PRIVATE_IPC_TIMING_MILLIS.DAEMON_RESPONSE_WRITE
        let wireResponse
        if (requestVersion === 2) {
          const now = currentMonotonic(this.now)
          if (!response || !response.bytes || now >= response.absoluteDeadlineMonotonicMillis) {
            socket.destroy()
            return
          }
          responseTimeoutMillis = Math.min(responseTimeoutMillis,
            Number(response.absoluteDeadlineMonotonicMillis - now))
          wireResponse = response.bytes
        } else {
          wireResponse = encodeLocalResponse(response)
        }
        const responseTimer = setTimeout(() => socket.destroy(), responseTimeoutMillis)
        if (responseTimer.unref) responseTimer.unref()
        socket.end(wireResponse, () => {
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
    if (this.bufferedBytes + STAGED_PUT_SOCKET_RESERVATION_BYTES_V2 > this.maxBufferedBytes) {
      socket.destroy()
      return
    }
    this.bufferedBytes += STAGED_PUT_SOCKET_RESERVATION_BYTES_V2
    let socketReservationReleased = false
    const releaseSocketReservation = () => {
      if (socketReservationReleased) return
      socketReservationReleased = true
      this.bufferedBytes = Math.max(0,
        this.bufferedBytes - STAGED_PUT_SOCKET_RESERVATION_BYTES_V2)
    }
    OBSERVED_PEERCRED_SOCKETS.set(socket, credentials)
    this.sockets.add(socket)
    const abortController = new AbortController()
    this.abortControllers.add(abortController)
    const handshakeTimer = setTimeout(() => socket.destroy(),
      PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT)
    if (handshakeTimer.unref) handshakeTimer.unref()
    socket.once('close', () => {
      clearTimeout(handshakeTimer)
      abortController.abort()
      this.sockets.delete(socket)
      releaseSocketReservation()
    })
    socket.once('error', error => this.onError(error))
    socket.setTimeout(PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT, () => socket.destroy())
    const task = this._handleStream(socket, abortController.signal, handshakeTimer)
    this.tasks.add(task)
    task.catch(error => {
      if (!abortController.signal.aborted) this.onError(error)
      if (!socket.destroyed) socket.destroy()
    }).finally(() => {
      this.tasks.delete(task)
      this.abortControllers.delete(abortController)
    })
  }

  async _handleStream (socket, signal, handshakeTimer = null) {
    const credentials = observedPeerCredentials(socket)
    const startedMonotonicMillis = currentMonotonic(this.now)
    const first = await readFirstLocalStreamOpen(socket)
    if (handshakeTimer) clearTimeout(handshakeTimer)
    if (first == null) {
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
    if (first.version !== 2) {
      // V1 remains authoritative for the existing zero-byte readiness path only.
      // A data-bearing V1 stream can never fall back into a write runtime.
      throw Object.assign(new Error('private IPC V1 staged writes are retired; V2 is required'), {
        code: 'PRIVATE_IPC_V2_NO_FALLBACK'
      })
    }
    await this._handleStagedPutV2(socket, first.bytes, signal)
  }

  async _resolveV2TransportProfileHash (endpointId, signal) {
    if (!this.streamTransportProfileHash && !this.streamTransportProfileHashForEndpoint) {
      throw Object.assign(new Error('V2 staged write transport profile is not configured'), {
        code: 'BLIND_STREAM_UNAVAILABLE'
      })
    }
    const resolved = this.streamTransportProfileHash || fixed32(
      await abortableCall(() => this.streamTransportProfileHashForEndpoint({
        endpointId,
        transportId: TRANSPORT_ID.HTTPS_DIRECT,
        transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
        signal
      }), signal), 'resolved stream transportProfileHash')
    if (allZero(resolved)) throw new Error('resolved stream transportProfileHash must be nonzero')
    return b4a.from(resolved)
  }

  async _liveWriteReadinessV2 (input, signal) {
    const disabledReason = this.v2WriteDisabledReason
    if (disabledReason) {
      throw Object.assign(new Error(`V2 writes are disabled: ${disabledReason}`), {
        code: 'BLIND_STREAM_UNAVAILABLE',
        disabledReason
      })
    }
    const raw = await abortableCall(() => this.writeReadinessProjection(Object.freeze({
      phase: input.phase,
      endpointId: input.endpointId,
      edgeProcessNonce: b4a.from(input.edgeProcessNonce),
      launchTopologyHash: b4a.from(this.launchTopologyHash),
      transportProfileHash: b4a.from(input.transportProfileHash),
      acceptedMonotonicMillis: input.acceptedMonotonicMillis,
      absoluteDeadlineMonotonicMillis: input.absoluteDeadlineMonotonicMillis,
      signal
    })), signal)
    const now = currentMonotonic(this.now)
    if (!raw || typeof raw !== 'object' || raw.selfVerified !== true ||
        raw.cellRuntimeReady !== true || raw.storageReady !== true || raw.admissionReady !== true) {
      throw Object.assign(new Error('V2 write-readiness projection is not a complete live assembly proof'), {
        code: 'BLIND_STREAM_UNAVAILABLE'
      })
    }
    const endpointId = projectionBits(raw.endpointId, 'write readiness endpointId', 0xff)
    const launchTopologyHash = fixed32(raw.launchTopologyHash, 'write readiness launchTopologyHash')
    const transportProfileHash = fixed32(raw.transportProfileHash, 'write readiness transportProfileHash')
    const descriptorSequence = u64(raw.descriptorSequence, 'write readiness descriptorSequence')
    const descriptorHash = fixed32(raw.descriptorHash, 'write readiness descriptorHash')
    const descriptorRoleBits = projectionBits(raw.descriptorRoleBits, 'write readiness descriptorRoleBits', 0xffff)
    const descriptorEnabledOperationBits = projectionBits(raw.descriptorEnabledOperationBits,
      'write readiness descriptorEnabledOperationBits')
    const readyRoleBits = projectionBits(raw.readyRoleBits, 'write readiness readyRoleBits', 0xffff)
    const readyOperationBits = projectionBits(raw.readyOperationBits, 'write readiness readyOperationBits')
    const readyWriteOperationBits = projectionBits(raw.readyWriteOperationBits,
      'write readiness readyWriteOperationBits')
    const readyIpcFeatureBits = projectionBits(raw.readyIpcFeatureBits, 'write readiness readyIpcFeatureBits')
    const expiresMonotonicMillis = u64(raw.expiresMonotonicMillis,
      'write readiness expiresMonotonicMillis')
    const descriptorExpiresMonotonicMillis = u64(raw.descriptorExpiresMonotonicMillis,
      'write readiness descriptorExpiresMonotonicMillis')
    if (descriptorSequence === 0n || allZero(descriptorHash) || endpointId !== input.endpointId ||
        !this.endpointIds.has(endpointId) || !sameBytes(launchTopologyHash, this.launchTopologyHash) ||
        !sameBytes(transportProfileHash, input.transportProfileHash) ||
        input.acceptedMonotonicMillis > now || now >= input.absoluteDeadlineMonotonicMillis ||
        expiresMonotonicMillis <= now || expiresMonotonicMillis > input.absoluteDeadlineMonotonicMillis ||
        descriptorExpiresMonotonicMillis <= now || expiresMonotonicMillis > descriptorExpiresMonotonicMillis ||
        (readyRoleBits & ~descriptorRoleBits) !== 0 ||
        (readyOperationBits & ~descriptorEnabledOperationBits) !== 0 ||
        (readyWriteOperationBits & ~descriptorEnabledOperationBits) !== 0 ||
        (readyRoleBits & CELL_PUT_ENDPOINT_ROLE_BIT_V2) === 0 ||
        readyWriteOperationBits !== CELL_PUT_OPERATION_BIT_V2 ||
        (readyWriteOperationBits & readyOperationBits) !== readyWriteOperationBits ||
        readyIpcFeatureBits !== REQUIRED_LOCAL_IPC_FEATURE_BITS_V2) {
      throw Object.assign(new Error('V2 write-readiness projection does not match live descriptor/profile/topology'), {
        code: 'BLIND_STREAM_UNAVAILABLE'
      })
    }
    const projection = Object.freeze({
      endpointId,
      descriptorSequence,
      descriptorHash: b4a.from(descriptorHash),
      descriptorRoleBits,
      descriptorEnabledOperationBits,
      readyRoleBits,
      readyOperationBits,
      readyWriteOperationBits,
      readyIpcFeatureBits,
      expiresMonotonicMillis,
      descriptorExpiresMonotonicMillis,
      launchTopologyHash: b4a.from(launchTopologyHash),
      transportProfileHash: b4a.from(transportProfileHash)
    })
    this._acceptV2WriteDescriptorFloor(projection)
    return projection
  }

  _acceptV2WriteDescriptorFloor (projection) {
    const floor = this.#v2WriteDescriptorFloor
    if (floor && (projection.descriptorSequence < floor.descriptorSequence ||
        (projection.descriptorSequence === floor.descriptorSequence &&
         !sameBytes(projection.descriptorHash, floor.descriptorHash)))) {
      throw Object.assign(new Error('V2 write readiness descriptor rolled back or forked at its retained floor'), {
        code: 'BLIND_STREAM_UNAVAILABLE'
      })
    }
    if (!floor || projection.descriptorSequence > floor.descriptorSequence) {
      this.#v2WriteDescriptorFloor = Object.freeze({
        descriptorSequence: projection.descriptorSequence,
        descriptorHash: b4a.from(projection.descriptorHash)
      })
    }
  }

  async _handleV2ReadyProbe (bytes, socket, signal) {
    // This lookup can only succeed after native socketPeerCredentials and the
    // configured UID/GID policy passed in _acceptUnary.
    observedPeerCredentials(socket)
    const probe = decodeLocalReadyProbeV2(bytes)
    const now = currentMonotonic(this.now)
    if (!this.endpointIds.has(probe.endpointId) || !sameBytes(probe.launchTopologyHash, this.launchTopologyHash) ||
        probe.acceptedMonotonicMillis > now || now >= probe.absoluteDeadlineMonotonicMillis) {
      throw Object.assign(new Error('V2 ready probe does not match live topology, endpoint, or deadline'), {
        code: 'BLIND_STREAM_UNAVAILABLE'
      })
    }
    const operationSignal = absoluteOperationSignal(signal,
      probe.absoluteDeadlineMonotonicMillis, now)
    const stopDestroyOnAbort = destroySocketOnAbort(socket, operationSignal)
    try {
      const transportProfileHash = await this._resolveV2TransportProfileHash(probe.endpointId, operationSignal)
      const projection = await this._liveWriteReadinessV2({
        phase: 'ready-probe',
        endpointId: probe.endpointId,
        edgeProcessNonce: probe.edgeProcessNonce,
        transportProfileHash,
        acceptedMonotonicMillis: probe.acceptedMonotonicMillis,
        absoluteDeadlineMonotonicMillis: probe.absoluteDeadlineMonotonicMillis
      }, operationSignal)
      if (operationSignal.aborted || currentMonotonic(this.now) >= projection.expiresMonotonicMillis) {
        throw Object.assign(new Error('V2 write readiness expired before ACK release'), {
          code: 'BLIND_STREAM_UNAVAILABLE'
        })
      }
      const ackDeadlineMonotonicMillis = [
        probe.absoluteDeadlineMonotonicMillis,
        projection.expiresMonotonicMillis,
        projection.descriptorExpiresMonotonicMillis
      ].reduce((minimum, value) => value < minimum ? value : minimum)
      return Object.freeze({
        bytes: encodeLocalReadyAckV2({
          endpointId: probe.endpointId,
          edgeProcessNonce: probe.edgeProcessNonce,
          launchTopologyHash: this.launchTopologyHash,
          descriptorSequence: projection.descriptorSequence,
          descriptorHash: projection.descriptorHash,
          readyRoleBits: projection.readyRoleBits,
          readyOperationBits: projection.readyOperationBits,
          readyWriteOperationBits: projection.readyWriteOperationBits,
          readyIpcFeatureBits: projection.readyIpcFeatureBits,
          expiresMonotonicMillis: projection.expiresMonotonicMillis
        }),
        absoluteDeadlineMonotonicMillis: ackDeadlineMonotonicMillis
      })
    } finally {
      stopDestroyOnAbort()
    }
  }

  async _handleStagedPutV2 (socket, openBytes, signal) {
    const credentials = observedPeerCredentials(socket)
    if (!this.dispatchStagedPut) {
      throw Object.assign(new Error('V2 staged write dispatcher is not configured'), {
        code: 'BLIND_STREAM_UNAVAILABLE'
      })
    }
    const open = decodeLocalStagedCellPutOpenV2(openBytes)
    const now = currentMonotonic(this.now)
    if (!this.endpointIds.has(open.endpointId) || open.acceptedMonotonicMillis > now ||
        now >= open.openDeadlineMonotonicMillis) {
      throw Object.assign(new Error('V2 staged open does not match a live configured endpoint'), {
        code: 'BAD_LOCAL_STREAM'
      })
    }
    const openSignal = absoluteOperationSignal(signal, open.openDeadlineMonotonicMillis, now)
    const stopOpenDestroyOnAbort = destroySocketOnAbort(socket, openSignal)
    try {
      assertPrecommitCellPutResultFitV2(open.outerClass)
      const transportProfileHash = await this._resolveV2TransportProfileHash(open.endpointId, openSignal)
      const replayTupleHash = replayTupleHashV2(open.context)
      // Deliberate anti-poisoning deviation pending spec reconciliation: validate
      // binding/readiness and reserve memory before consuming the exact tuple.
      const validation = validateLocalStagedCellPutOpenBindingV2(open, {
        launchTopologyHash: this.launchTopologyHash,
        transportProfileHash
      })
      if (validation.authorityGranted !== false || validation.peerCredentialsObserved !== false ||
          validation.endpointId !== open.endpointId || validation.outerClass !== open.outerClass ||
          !sameBytes(validation.replayTupleHash, replayTupleHash)) {
        throw Object.assign(new Error('V2 contract binding validator returned an authoritative or inconsistent value'), {
          code: 'BAD_LOCAL_STREAM'
        })
      }
      const projection = await this._liveWriteReadinessV2({
        phase: 'staged-open',
        endpointId: open.endpointId,
        edgeProcessNonce: open.context.edgeProcessNonce,
        transportProfileHash,
        acceptedMonotonicMillis: open.acceptedMonotonicMillis,
        absoluteDeadlineMonotonicMillis: open.openDeadlineMonotonicMillis
      }, openSignal)
      if (this.bufferedBytes + STAGED_PUT_POST_READY_RESERVATION_BYTES_V2 > this.maxBufferedBytes) {
        throw Object.assign(new Error('V2 staged PUT private-stream memory budget is exhausted'), {
          code: 'BLIND_STREAM_BUSY'
        })
      }
      this.bufferedBytes += STAGED_PUT_POST_READY_RESERVATION_BYTES_V2
      try {
        const effectiveDeadlineMonotonicMillis = [
          open.openDeadlineMonotonicMillis,
          projection.expiresMonotonicMillis,
          projection.descriptorExpiresMonotonicMillis
        ].reduce((minimum, value) => value < minimum ? value : minimum)
        const replayNow = currentMonotonic(this.now)
        if (replayNow >= effectiveDeadlineMonotonicMillis) throw abortError()
        const operationSignal = absoluteOperationSignal(openSignal,
          effectiveDeadlineMonotonicMillis, replayNow)
        const reservation = await abortableCall(() => this.durableReplayAuthority.reserve(Object.freeze({
          replayTupleHash: b4a.from(replayTupleHash),
          expiresMonotonicMillis: open.openDeadlineMonotonicMillis,
          nowMonotonicMillis: replayNow,
          signal: operationSignal
        })), operationSignal)
        if (!reservation || typeof reservation !== 'object' || !Object.isFrozen(reservation) ||
            reservation.kind !== 'reserved-new' ||
            reservation.durablyCommitted !== true ||
            reservation.expiresMonotonicMillis !== open.openDeadlineMonotonicMillis ||
            !reservation.replayTupleHash ||
            !sameBytes(reservation.replayTupleHash, replayTupleHash)) {
          throw Object.assign(new Error('durable replay authority returned no exact committed reservation'), {
            code: 'BLIND_STREAM_UNAVAILABLE'
          })
        }
        this.#v2ReplayReservationCount++
        const authority = Object.freeze({})
        V2_DAEMON_AUTHORITIES.set(authority, Object.freeze({
          credentials,
          open,
          projection,
          transportProfileHash: b4a.from(transportProfileHash),
          replayTupleHash: b4a.from(replayTupleHash),
          effectiveDeadlineMonotonicMillis,
          operationSignal
        }))
        await this._runStagedPutV2(socket, authority)
      } finally {
        this.bufferedBytes = Math.max(0,
          this.bufferedBytes - STAGED_PUT_POST_READY_RESERVATION_BYTES_V2)
      }
    } finally {
      stopOpenDestroyOnAbort()
    }
  }

  async _runStagedPutV2 (socket, authority) {
    const authenticated = V2_DAEMON_AUTHORITIES.get(authority)
    if (!authenticated) {
      throw Object.assign(new Error('V2 staged PUT requires daemon-private peercred authority'), {
        code: 'UNAUTHORIZED'
      })
    }
    V2_DAEMON_AUTHORITIES.delete(authority)
    const { open, effectiveDeadlineMonotonicMillis, operationSignal } = authenticated
    const timerStartMonotonicMillis = currentMonotonic(this.now)
    if (timerStartMonotonicMillis >= effectiveDeadlineMonotonicMillis) {
      throw Object.assign(new Error('V2 staged PUT write readiness expired before ingress'), {
        code: 'BLIND_STREAM_UNAVAILABLE'
      })
    }
    const stopDestroyOnAbort = destroySocketOnAbort(socket, operationSignal)
    let abortIngress = null
    try {
      socket.setTimeout(PRIVATE_IPC_TIMING_MILLIS.BODY_PROGRESS_IDLE, () => socket.destroy())
      this.#v2IngressConstructionCount++
      const ingress = new StagedCellPutOuterEnvelopeIngestorV2({ open })
      abortIngress = () => {
        const error = abortError()
        try { ingress.abort(error) } catch {}
      }
      operationSignal.addEventListener('abort', abortIngress, { once: true })
      if (operationSignal.aborted) queueMicrotask(abortIngress)
      const records = localStagedFrameRecordsV2(socket)
      let requestId = null
      let requestCommitment = null
      const postEof = deferred()
      const dispatched = ingress.ready.then(staged => {
        if (this.stagedPutRelayPublicKey == null) {
          throw Object.assign(new Error('V2 staged PUT has no exact relay-key commitment authority'), {
            code: 'BLIND_STREAM_UNAVAILABLE'
          })
        }
        requestId = b4a.from(staged.frame.requestId)
        const committedAllocation = allocationCommitment({
          ...staged.request,
          relayPublicKey: this.stagedPutRelayPublicKey,
          declaredCellBlobHash: staged.request.declaredBlobHash
        })
        requestCommitment = cellPutRequestCommitment({
          allocationCommitment: committedAllocation,
          clientNonce: staged.request.clientNonce
        })
        // The dispatcher may perform side-effect-free admission preflight and
        // bounded ephemeral staging now. Its confirmation and durable mutation
        // remain fenced on this same-stream PostEOF promise.
        return this.dispatchStagedPut(staged, {
          transportId: open.transportId,
          transportSupportBit: open.transportSupportBit,
          endpointId: open.endpointId,
          outerClass: open.outerClass,
          adjacentRelayKey: null,
          acceptedMonotonicMillis: open.acceptedMonotonicMillis,
          absoluteDeadlineMonotonicMillis: effectiveDeadlineMonotonicMillis,
          postEofAuthority: postEof.promise,
          signal: operationSignal
        })
      })
      dispatched.catch(() => {})
      let ingressError = null
      let expectedSequence = 0n
      let sawFin = false
      try {
        for await (const record of records) {
          const frame = decodeLocalStagedCellPutFrameV2(record)
          if (sawFin) {
            throw Object.assign(new Error('V2 staged PUT received a frame after request FIN'), {
              code: 'BAD_LOCAL_STREAM'
            })
          }
          if (frame.direction !== LOCAL_STAGED_DIRECTION_V2.REQUEST || frame.sequence !== expectedSequence++) {
            throw Object.assign(new Error('V2 staged PUT request direction or sequence is invalid'), {
              code: 'BAD_LOCAL_STREAM'
            })
          }
          if (frame.frameKind === LOCAL_STAGED_FRAME_KIND_V2.ABORT) {
            throw Object.assign(new Error('V2 staged PUT was aborted by its authenticated edge'), {
              code: 'ABORT_ERR'
            })
          }
          await ingress.push(frame.bytes)
          if ((frame.flags & LOCAL_STAGED_FLAG_V2.FIN) !== 0) sawFin = true
        }
        // allowHalfOpen keeps the daemon's response direction writable here. A
        // V2 FIN frame alone never completes ingestion: actual request EOF must
        // also have been observed by the socket iterator.
        if (!sawFin || !socket.readableEnded || operationSignal.aborted) {
          throw Object.assign(new Error('V2 staged PUT requires request FIN followed by actual peer EOF'), {
            code: 'BAD_LOCAL_STREAM'
          })
        }
        socket.setTimeout(0)
        ingress.finishRequest()
        if (requestId == null || requestCommitment == null) {
          if (this.stagedPutRelayPublicKey == null) {
            throw Object.assign(new Error('V2 staged PUT has no exact relay-key commitment authority'), {
              code: 'BLIND_STREAM_UNAVAILABLE'
            })
          }
          const staged = await ingress.ready
          requestId = b4a.from(staged.frame.requestId)
          const committedAllocation = allocationCommitment({
            ...staged.request,
            relayPublicKey: this.stagedPutRelayPublicKey,
            declaredCellBlobHash: staged.request.declaredBlobHash
          })
          requestCommitment = cellPutRequestCommitment({
            allocationCommitment: committedAllocation,
            clientNonce: staged.request.clientNonce
          })
        }
        postEof.resolve(this.postEofAuthorityIssuer.mint({
          actualPeerEof: true,
          exactRequestValidated: true,
          endpointId: open.endpointId,
          familyId: FAMILY.CELL,
          operationId: OPERATION.CELL.PUT,
          descriptorSequence: authenticated.projection.descriptorSequence,
          descriptorHash: authenticated.projection.descriptorHash,
          requestId,
          requestCommitment
        }))
      } catch (error) {
        ingressError = error
        postEof.reject(error)
        try { ingress.abort(error) } catch {}
      }

      let result
      try {
        result = await abortableCall(() => dispatched, operationSignal)
      } catch (error) {
        throw ingressError || error
      }
      if (ingressError) throw ingressError
      if (!result || !result.dispatch || typeof result.dispatch.byteLength !== 'number' ||
          result.outerClass !== open.outerClass) {
        throw Object.assign(new Error('V2 staged PUT dispatcher returned no same-class canonical result'), {
          code: 'BAD_LOCAL_STREAM'
        })
      }
      const resultWriteNow = currentMonotonic(this.now)
      if (operationSignal.aborted || resultWriteNow >= effectiveDeadlineMonotonicMillis) {
        throw Object.assign(new Error('V2 write readiness expired before result release'), {
          code: 'BLIND_STREAM_UNAVAILABLE'
        })
      }
      const resultFrames = new StagedCellPutResultEncoderV2({
        dispatch: result.dispatch,
        outerClass: open.outerClass,
        requestId
      })
      const writeTimeoutMillis = Math.min(
        PRIVATE_IPC_TIMING_MILLIS.DAEMON_RESPONSE_WRITE,
        Number(effectiveDeadlineMonotonicMillis - resultWriteNow)
      )
      await writeSocketFramesWithinDeadlineV2(socket, resultFrames, writeTimeoutMillis, { end: true })
    } finally {
      if (abortIngress) operationSignal.removeEventListener('abort', abortIngress)
      stopDestroyOnAbort()
    }
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

  get v2ReplayReservationCount () {
    return this.#v2ReplayReservationCount
  }

  get v2WriteDisabledReason () {
    if (!this.dispatchStagedPut) return V2_WRITE_DISABLED_REASON.STAGED_DISPATCHER_MISSING
    if (!this.stagedPutRelayPublicKey) {
      return V2_WRITE_DISABLED_REASON.STAGED_PUT_RELAY_KEY_MISSING
    }
    if (!this.streamTransportProfileHash && !this.streamTransportProfileHashForEndpoint) {
      return V2_WRITE_DISABLED_REASON.TRANSPORT_PROFILE_MISSING
    }
    if (!this.writeReadinessProjection) {
      return V2_WRITE_DISABLED_REASON.WRITE_READINESS_PROJECTION_MISSING
    }
    if (!this.durableReplayAuthority) {
      return V2_WRITE_DISABLED_REASON.DURABLE_REPLAY_AUTHORITY_MISSING
    }
    return null
  }

  get v2IngressConstructionCount () {
    return this.#v2IngressConstructionCount
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
