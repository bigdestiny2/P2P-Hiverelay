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

const REQUIRED_DESCRIBE_OPERATION_BITS = 0x00000007
const PORTABLE_UNIX_SOCKET_PATH_BYTES = 100
const READY_RESPONSE_BYTES = LOCAL_RESPONSE_HEADER_BYTES + LOCAL_READY_ACK_BODY_BYTES

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

export { REQUIRED_DESCRIBE_OPERATION_BITS }
