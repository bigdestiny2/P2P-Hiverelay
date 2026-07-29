import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import { socketPeerCredentials } from '@hiverelay/blind-peercred'
import {
  LOCAL_RESPONSE_HEADER_BYTES,
  LOCAL_RESPONSE_KIND,
  LOCAL_READY_ACK_BODY_BYTES,
  PRIVATE_IPC_TIMING_MILLIS,
  decodeLocalResponse,
  encodeLocalReadyProbe,
  localResponseFrameLength
} from '@hiverelay/blind-ipc'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  PRIVATE_IPC_V2_LIMITS,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
  decodeLocalReadyAckV2,
  encodeLocalReadyProbeV2,
  readLocalReadyAckLengthV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'

const REQUIRED_DESCRIBE_OPERATION_BITS = 0x00000007
const PORTABLE_UNIX_SOCKET_PATH_BYTES = 100
const READY_RESPONSE_BYTES = LOCAL_RESPONSE_HEADER_BYTES + LOCAL_READY_ACK_BODY_BYTES
const WRITE_READY_RESPONSE_BYTES_V2 = PRIVATE_IPC_V2_LIMITS.READY_ACK_BYTES

export class EdgeReadinessError extends Error {
  constructor (code, message, cause = null) {
    super(message, cause == null ? undefined : { cause })
    this.code = code
  }
}

function fail (code, message, cause) {
  throw new EdgeReadinessError(code, message, cause)
}

function unsignedInteger (value, field, maximum = 0xffffffff) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new TypeError(`${field} must be an unsigned integer <= ${maximum}`)
  }
  return value
}

function socketPath (value, field) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0') || path.normalize(value) !== value) {
    throw new TypeError(`${field} must be a normalized absolute Unix socket path`)
  }
  if (Buffer.byteLength(value) > PORTABLE_UNIX_SOCKET_PATH_BYTES) throw new TypeError(`${field} exceeds the portable Unix socket path bound`)
  return value
}

function exactBytes32 (value, field) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be 32 bytes`)
  const bytes = b4a.isBuffer(value)
    ? b4a.from(value)
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (bytes.byteLength !== 32) throw new TypeError(`${field} must be 32 bytes`)
  return bytes
}

function nonzeroBytes32 (value, field) {
  const bytes = exactBytes32(value, field)
  for (const byte of bytes) {
    if (byte !== 0) return bytes
  }
  throw new TypeError(`${field} must not be all zero`)
}

export function validateReadinessTopology (input, endpointId) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('readinessTopology must be an object')
  const unarySocketPath = socketPath(input.unarySocketPath, 'readinessTopology.unarySocketPath')
  const streamSocketPath = socketPath(input.streamSocketPath, 'readinessTopology.streamSocketPath')
  if (unarySocketPath === streamSocketPath) throw new TypeError('readiness topology unary and stream socket paths must be unequal')
  const socketMode = unsignedInteger(input.socketMode, 'readinessTopology.socketMode', 0o7777)
  if (socketMode !== 0o660) throw new TypeError('readinessTopology.socketMode must be exact POSIX 0660')
  return Object.freeze({
    unarySocketPath,
    streamSocketPath,
    launchTopologyHash: exactBytes32(input.launchTopologyHash, 'readinessTopology.launchTopologyHash'),
    daemonUid: unsignedInteger(input.daemonUid, 'readinessTopology.daemonUid'),
    daemonGid: unsignedInteger(input.daemonGid, 'readinessTopology.daemonGid'),
    socketGroupGid: unsignedInteger(input.socketGroupGid, 'readinessTopology.socketGroupGid'),
    socketMode,
    // A CELL.PUT content stream is accepted only when the edge has the
    // descriptor-bound transport profile used by the daemon to authenticate
    // its private channel. Older/read-only topologies deliberately omit it.
    streamTransportProfileHash: input.streamTransportProfileHash == null
      ? null
      : nonzeroBytes32(input.streamTransportProfileHash, 'readinessTopology.streamTransportProfileHash'),
    endpointId: unsignedInteger(endpointId, 'endpointId', 0xff)
  })
}

function sameSocketIdentity (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

async function verifySocketPath (socketPath, topology) {
  let stat
  let resolved
  try {
    [stat, resolved] = await Promise.all([fs.lstat(socketPath), fs.realpath(socketPath)])
  } catch (error) {
    fail('BLIND_READINESS_PATH', 'readiness socket path is unavailable', error)
  }
  if (resolved !== socketPath || stat.isSymbolicLink() || !stat.isSocket()) {
    fail('BLIND_READINESS_PATH', 'readiness path is not one exact non-symlink Unix socket')
  }
  if (stat.uid !== topology.daemonUid || stat.gid !== topology.socketGroupGid || (stat.mode & 0o7777) !== topology.socketMode) {
    fail('BLIND_READINESS_PATH', 'readiness socket owner, group, or mode does not match signed topology')
  }
  return Object.freeze({ dev: stat.dev, ino: stat.ino })
}

function timeoutAfter (delayMs, onTimeout) {
  const timer = setTimeout(onTimeout, Math.max(1, delayMs))
  if (timer.unref) timer.unref()
  return timer
}

async function openVerifiedSocket (socketPath, topology, now) {
  const startedMonotonicMillis = now()
  const deadlineMonotonicMillis = startedMonotonicMillis + BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PATH_CONNECT)
  let expired = false
  let socket = null
  let timer = null

  const task = (async () => {
    const before = await verifySocketPath(socketPath, topology)
    if (expired || now() > deadlineMonotonicMillis) fail('BLIND_READINESS_TIMEOUT', 'readiness path verification timed out')
    socket = net.createConnection({ path: socketPath })
    await new Promise((resolve, reject) => {
      socket.once('connect', resolve)
      socket.once('error', reject)
    })
    if (expired || now() > deadlineMonotonicMillis) fail('BLIND_READINESS_TIMEOUT', 'readiness path connection timed out')
    let credentials
    try {
      credentials = socketPeerCredentials(socket)
    } catch (error) {
      fail('BLIND_READINESS_PEER', 'daemon peer credentials are unavailable', error)
    }
    if (credentials.uid !== topology.daemonUid || credentials.gid !== topology.daemonGid) {
      fail('BLIND_READINESS_PEER', 'daemon peer credentials do not match signed topology')
    }
    const after = await verifySocketPath(socketPath, topology)
    if (expired || now() > deadlineMonotonicMillis) fail('BLIND_READINESS_TIMEOUT', 'readiness path post-connect verification timed out')
    if (!sameSocketIdentity(before, after)) fail('BLIND_READINESS_PATH', 'readiness socket inode changed during connection')
    return { socket, deadlineMonotonicMillis, identity: after }
  })()

  const timeout = new Promise((resolve, reject) => {
    const remaining = Number(deadlineMonotonicMillis - now())
    timer = timeoutAfter(remaining, () => {
      expired = true
      if (socket) socket.destroy()
      reject(new EdgeReadinessError('BLIND_READINESS_TIMEOUT', 'readiness path connect/credential/inode check timed out'))
    })
  })

  try {
    return await Promise.race([task, timeout])
  } catch (error) {
    if (socket) socket.destroy()
    if (error instanceof EdgeReadinessError) throw error
    fail('BLIND_READINESS_PATH', 'readiness socket connection failed', error)
  } finally {
    if (timer) clearTimeout(timer)
  }
}

async function verifyNoFrameStreamPath (topology, now) {
  const opened = await openVerifiedSocket(topology.streamSocketPath, topology, now)
  const { socket, deadlineMonotonicMillis } = opened
  let receivedBytes = false
  socket.on('data', () => { receivedBytes = true })
  try {
    await new Promise((resolve, reject) => {
      let settled = false
      const finish = error => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.off('error', onError)
        socket.off('close', onClose)
        if (error) reject(error)
        else resolve()
      }
      const onError = error => finish(error)
      const onClose = () => finish(receivedBytes
        ? new EdgeReadinessError('BLIND_READINESS_PATH', 'stream readiness path emitted a frame')
        : null)
      const remaining = Number(deadlineMonotonicMillis - now())
      const timer = timeoutAfter(remaining, () => {
        socket.destroy()
        finish(new EdgeReadinessError('BLIND_READINESS_TIMEOUT', 'no-frame stream readiness close timed out'))
      })
      socket.once('error', onError)
      socket.once('close', onClose)
      socket.end()
    })
  } finally {
    socket.destroy()
  }
  return opened.identity
}

function exchangeReadyProbe (socket, probe, deadlineMonotonicMillis, now) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    let expectedLength = null
    let settled = false

    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('data', onData)
      socket.off('end', onEnd)
      socket.off('error', onError)
      socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const onError = error => finish(new EdgeReadinessError('BLIND_READINESS_PATH', 'readiness unary socket failed', error))
    const onEnd = () => finish(new EdgeReadinessError('BLIND_READINESS_ACK', 'readiness unary response ended before one complete ACK'))
    const onData = chunk => {
      if (now() > deadlineMonotonicMillis) return finish(new EdgeReadinessError('BLIND_READINESS_TIMEOUT', 'readiness probe timed out'))
      if (total + chunk.byteLength > READY_RESPONSE_BYTES) return finish(new EdgeReadinessError('BLIND_READINESS_ACK', 'readiness response exceeds the exact ACK bound'))
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
      try {
        if (expectedLength == null && total >= 4) expectedLength = localResponseFrameLength(b4a.concat(chunks, total))
      } catch (error) {
        return finish(new EdgeReadinessError('BLIND_READINESS_ACK', 'readiness response framing is invalid', error))
      }
      if (expectedLength == null || total < expectedLength) return
      if (total !== expectedLength) return finish(new EdgeReadinessError('BLIND_READINESS_ACK', 'readiness response has trailing bytes'))
      try {
        const decoded = decodeLocalResponse(b4a.concat(chunks, total), { copyBody: true })
        if (decoded.responseKind !== LOCAL_RESPONSE_KIND.LOCAL_READY_ACK || !decoded.readyAck) {
          return finish(new EdgeReadinessError('BLIND_READINESS_ACK', 'daemon did not return one local readiness ACK'))
        }
        finish(null, decoded.readyAck)
      } catch (error) {
        finish(new EdgeReadinessError('BLIND_READINESS_ACK', 'readiness ACK decoding failed', error))
      }
    }
    const remaining = Number(deadlineMonotonicMillis - now())
    const timer = timeoutAfter(remaining, () => finish(new EdgeReadinessError('BLIND_READINESS_TIMEOUT', 'readiness probe timed out')))
    socket.on('data', onData)
    socket.once('end', onEnd)
    socket.once('error', onError)
    try {
      socket.write(probe, error => {
        if (error) return finish(new EdgeReadinessError('BLIND_READINESS_PATH', 'readiness probe write failed', error))
        if (now() > deadlineMonotonicMillis) finish(new EdgeReadinessError('BLIND_READINESS_TIMEOUT', 'readiness probe write timed out'))
      })
    } catch (error) {
      finish(new EdgeReadinessError('BLIND_READINESS_PATH', 'readiness probe write failed', error))
    }
  })
}

function exchangeWriteReadyProbeV2 (socket, probe, deadlineMonotonicMillis, now) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    let expectedLength = null
    let settled = false

    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('data', onData)
      socket.off('end', onEnd)
      socket.off('error', onError)
      socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const onError = error => finish(new EdgeReadinessError('BLIND_WRITE_READINESS_PATH',
      'V2 write-readiness unary socket failed', error))
    const onEnd = () => finish(new EdgeReadinessError('BLIND_WRITE_READINESS_ACK',
      'V2 write-readiness response ended before one complete ACK'))
    const onData = chunk => {
      if (now() >= deadlineMonotonicMillis) {
        return finish(new EdgeReadinessError('BLIND_WRITE_READINESS_TIMEOUT', 'V2 write-readiness probe timed out'))
      }
      if (total + chunk.byteLength > WRITE_READY_RESPONSE_BYTES_V2) {
        return finish(new EdgeReadinessError('BLIND_WRITE_READINESS_ACK',
          'V2 write-readiness response exceeds the exact ACK bound'))
      }
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
      try {
        if (expectedLength == null) expectedLength = readLocalReadyAckLengthV2(b4a.concat(chunks, total))
      } catch (error) {
        return finish(new EdgeReadinessError('BLIND_WRITE_READINESS_ACK',
          'V2 write-readiness ACK framing is invalid', error))
      }
      if (expectedLength == null || total < expectedLength) return
      if (total !== expectedLength) {
        return finish(new EdgeReadinessError('BLIND_WRITE_READINESS_ACK',
          'V2 write-readiness ACK has trailing bytes'))
      }
      try {
        finish(null, decodeLocalReadyAckV2(b4a.concat(chunks, total)))
      } catch (error) {
        finish(new EdgeReadinessError('BLIND_WRITE_READINESS_ACK',
          'V2 write-readiness ACK decoding failed', error))
      }
    }
    const remaining = Number(deadlineMonotonicMillis - now())
    const timer = timeoutAfter(remaining, () => finish(new EdgeReadinessError(
      'BLIND_WRITE_READINESS_TIMEOUT', 'V2 write-readiness probe timed out'
    )))
    socket.on('data', onData)
    socket.once('end', onEnd)
    socket.once('error', onError)
    try {
      socket.write(probe, error => {
        if (error) {
          return finish(new EdgeReadinessError('BLIND_WRITE_READINESS_PATH',
            'V2 write-readiness probe write failed', error))
        }
        if (now() >= deadlineMonotonicMillis) {
          finish(new EdgeReadinessError('BLIND_WRITE_READINESS_TIMEOUT', 'V2 write-readiness probe write timed out'))
        }
      })
    } catch (error) {
      finish(new EdgeReadinessError('BLIND_WRITE_READINESS_PATH',
        'V2 write-readiness probe write failed', error))
    }
  })
}

function validateAck (ack, expected, previous, probeT0, receivedAt) {
  if (!b4a.equals(ack.edgeInstanceNonce, expected.edgeInstanceNonce) ||
      !b4a.equals(ack.launchTopologyHash, expected.launchTopologyHash) ||
      ack.endpointId !== expected.endpointId) {
    fail('BLIND_READINESS_ACK', 'readiness ACK echo/topology/endpoint mismatch')
  }
  if ((ack.readyOperationBits & REQUIRED_DESCRIBE_OPERATION_BITS) !== REQUIRED_DESCRIBE_OPERATION_BITS) {
    fail('BLIND_READINESS_ACK', 'readiness ACK is missing required DESCRIBE operation bits')
  }
  if (ack.expiresMonotonicMillis <= receivedAt ||
      ack.expiresMonotonicMillis > probeT0 + BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_ACK_MAX_LIFETIME)) {
    fail('BLIND_READINESS_ACK', 'readiness ACK expiry is outside its exact receipt/probe bounds')
  }
  if (previous) {
    if (ack.descriptorSequence < previous.descriptorSequence ||
        (ack.descriptorSequence === previous.descriptorSequence && !b4a.equals(ack.descriptorHash, previous.descriptorHash))) {
      fail('BLIND_READINESS_ROLLBACK', 'readiness descriptor tuple rolled back or forked')
    }
    if (ack.expiresMonotonicMillis <= previous.expiresMonotonicMillis) {
      fail('BLIND_READINESS_ROLLBACK', 'readiness refresh did not advance its expiry')
    }
  }
  return Object.freeze({
    descriptorSequence: ack.descriptorSequence,
    descriptorHash: b4a.from(ack.descriptorHash),
    readyRoleBits: ack.readyRoleBits,
    readyOperationBits: ack.readyOperationBits,
    expiresMonotonicMillis: ack.expiresMonotonicMillis
  })
}

function validateWriteAckV2 (ack, expected, previous, probeT0, probeDeadline, receivedAt) {
  if (!b4a.equals(ack.edgeProcessNonce, expected.edgeProcessNonce) ||
      !b4a.equals(ack.launchTopologyHash, expected.launchTopologyHash) ||
      ack.endpointId !== expected.endpointId) {
    fail('BLIND_WRITE_READINESS_ACK', 'V2 write-readiness ACK echo/topology/endpoint mismatch')
  }
  if (ack.descriptorSequence === 0n ||
      (ack.readyRoleBits & CELL_PUT_ENDPOINT_ROLE_BIT_V2) === 0 ||
      ack.readyWriteOperationBits !== CELL_PUT_OPERATION_BIT_V2 ||
      (ack.readyWriteOperationBits & ack.readyOperationBits) !== ack.readyWriteOperationBits ||
      ack.readyIpcFeatureBits !== REQUIRED_LOCAL_IPC_FEATURE_BITS_V2) {
    fail('BLIND_WRITE_READINESS_ACK', 'V2 write-readiness ACK omits required write authority')
  }
  if (ack.expiresMonotonicMillis <= receivedAt || ack.expiresMonotonicMillis > probeDeadline ||
      receivedAt < probeT0) {
    fail('BLIND_WRITE_READINESS_ACK', 'V2 write-readiness ACK expiry is outside exact probe bounds')
  }
  if (previous && (ack.descriptorSequence < previous.descriptorSequence ||
      (ack.descriptorSequence === previous.descriptorSequence && !b4a.equals(ack.descriptorHash, previous.descriptorHash)))) {
    fail('BLIND_WRITE_READINESS_ROLLBACK', 'V2 write-readiness descriptor tuple rolled back or forked')
  }
  return Object.freeze({
    version: 2,
    descriptorSequence: ack.descriptorSequence,
    descriptorHash: b4a.from(ack.descriptorHash),
    readyRoleBits: ack.readyRoleBits,
    readyOperationBits: ack.readyOperationBits,
    readyWriteOperationBits: ack.readyWriteOperationBits,
    readyIpcFeatureBits: ack.readyIpcFeatureBits,
    expiresMonotonicMillis: ack.expiresMonotonicMillis
  })
}

export async function performReadinessHandshake (topology, options = {}) {
  const now = typeof options.now === 'function' ? options.now : () => process.hrtime.bigint() / 1_000_000n
  const streamIdentity = await verifyNoFrameStreamPath(topology, now)
  const opened = await openVerifiedSocket(topology.unarySocketPath, topology, now)
  if (sameSocketIdentity(streamIdentity, opened.identity)) {
    opened.socket.destroy()
    fail('BLIND_READINESS_PATH', 'readiness unary and stream paths resolve to one socket inode')
  }
  const edgeInstanceNonce = crypto.randomBytes(32)
  const probeT0 = now()
  const probeDeadline = probeT0 + BigInt(PRIVATE_IPC_TIMING_MILLIS.READY_PROBE_ABSOLUTE)
  const probe = encodeLocalReadyProbe({
    endpointId: topology.endpointId,
    acceptedMonotonicMillis: probeT0,
    edgeInstanceNonce,
    launchTopologyHash: topology.launchTopologyHash
  })
  let ack
  try {
    ack = await exchangeReadyProbe(opened.socket, probe, probeDeadline, now)
  } finally {
    opened.socket.destroy()
  }
  return validateAck(ack, {
    edgeInstanceNonce,
    launchTopologyHash: topology.launchTopologyHash,
    endpointId: topology.endpointId
  }, options.previous || null, probeT0, now())
}

// V2 readiness is write-specific. The edge retains the V1 read handshake for
// read service, but a staged CELL.PUT obtains this independent ACK immediately
// before opening its V2 stream. There is deliberately no V1 downgrade path.
export async function performWriteReadinessHandshakeV2 (topology, options = {}) {
  if (!topology || !topology.streamTransportProfileHash) {
    fail('BLIND_WRITE_READINESS_TOPOLOGY', 'V2 write readiness requires a signed stream transport profile')
  }
  const now = typeof options.now === 'function' ? options.now : () => process.hrtime.bigint() / 1_000_000n
  const edgeProcessNonce = nonzeroBytes32(options.edgeProcessNonce, 'edgeProcessNonce')
  const streamIdentity = await verifyNoFrameStreamPath(topology, now)
  const opened = await openVerifiedSocket(topology.unarySocketPath, topology, now)
  if (sameSocketIdentity(streamIdentity, opened.identity)) {
    opened.socket.destroy()
    fail('BLIND_WRITE_READINESS_PATH', 'write-readiness unary and stream paths resolve to one socket inode')
  }
  const probeT0 = now()
  const probeDeadline = probeT0 + BigInt(PRIVATE_IPC_V2_LIMITS.READY_DEADLINE_MILLIS)
  const probe = encodeLocalReadyProbeV2({
    endpointId: topology.endpointId,
    edgeProcessNonce,
    launchTopologyHash: topology.launchTopologyHash,
    edgeFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
    requestedWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
    acceptedMonotonicMillis: probeT0,
    absoluteDeadlineMonotonicMillis: probeDeadline
  })
  let ack
  try {
    ack = await exchangeWriteReadyProbeV2(opened.socket, probe, probeDeadline, now)
  } finally {
    opened.socket.destroy()
  }
  const acknowledgement = validateWriteAckV2(ack, {
    edgeProcessNonce,
    launchTopologyHash: topology.launchTopologyHash,
    endpointId: topology.endpointId
  }, options.previous || null, probeT0, probeDeadline, now())
  // The edge must retain the exact stream-socket inode it qualified. The
  // subsequent staged connection revalidates it after connect, before sending
  // a single V2 byte; this closes the readiness-to-dial path substitution gap.
  return Object.freeze({
    ...acknowledgement,
    streamSocketIdentity: Object.freeze({
      dev: streamIdentity.dev,
      ino: streamIdentity.ino
    })
  })
}

// This is intentionally separate from the readiness exchange. The stream
// listener is a new Unix connection, so it must prove it still resolves to the
// exact inode qualified immediately before the V2 readiness ACK and that the
// connected daemon has the configured native peer credentials. The caller must
// invoke this after connect and before it writes the staged open.
export async function verifyWriteStreamDialV2 (topology, expectedStreamSocketIdentity, socket) {
  if (!topology || !expectedStreamSocketIdentity || !socket) {
    fail('BLIND_WRITE_READINESS_PATH', 'V2 stream dial revalidation requires topology, qualified inode, and connected socket')
  }
  let credentials
  try {
    credentials = socketPeerCredentials(socket)
  } catch (error) {
    fail('BLIND_WRITE_READINESS_PEER', 'V2 stream dial peer credentials are unavailable', error)
  }
  if (credentials.uid !== topology.daemonUid || credentials.gid !== topology.daemonGid) {
    fail('BLIND_WRITE_READINESS_PEER', 'V2 stream dial peer credentials do not match signed topology')
  }
  let current
  try {
    current = await verifySocketPath(topology.streamSocketPath, topology)
  } catch (error) {
    fail('BLIND_WRITE_READINESS_PATH', 'V2 stream dial path no longer matches signed topology', error)
  }
  if (!sameSocketIdentity(expectedStreamSocketIdentity, current)) {
    fail('BLIND_WRITE_READINESS_PATH', 'V2 stream dial socket inode changed after readiness qualification')
  }
  return Object.freeze({ dev: current.dev, ino: current.ino })
}

export { REQUIRED_DESCRIBE_OPERATION_BITS }
