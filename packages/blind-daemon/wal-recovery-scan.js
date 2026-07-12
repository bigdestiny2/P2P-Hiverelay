import fs from 'node:fs/promises'
import { constants as FS_CONSTANTS } from 'node:fs'
import path from 'node:path'
import b4a from 'b4a'
import { verifyBlindStoreSessionTransactionLease } from './store-session.js'
import {
  BLIND_WAL_LAYOUT,
  BlindStoreBoundsError,
  BlindWalIntegrityError,
  decodeBlindWalFrameV2,
  inspectBlindWalFrameV2Header
} from './transaction-store.js'

const ZERO32 = b4a.alloc(32)
const MAX_U64 = (1n << 64n) - 1n
const HARD_MAX_WAL_BYTES = 1024 * 1024 * 1024 * 1024
const HARD_MAX_WAL_FRAMES = 16 * 1024 * 1024
const MIN_WAL_PAYLOAD_BYTES = 1024
const MAX_WAL_PAYLOAD_BYTES = 16 * 1024 * 1024
const ACTIVE_RESULTS = new WeakSet()
const RESULT_STATE = new WeakMap()

export class BlindWalRecoveryResultError extends Error {
  constructor (message, code = 'BLIND_WAL_RECOVERY_RESULT_INVALID') {
    super(message)
    this.name = 'BlindWalRecoveryResultError'
    this.code = code
  }
}

function canonicalRoot (root) {
  if (typeof root !== 'string' || root.includes('\0') || !path.isAbsolute(root) || path.normalize(root) !== root) {
    throw new TypeError('WAL recovery root must be a canonical absolute path')
  }
  return root
}

function asBytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (value.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  if (nonzero && b4a.equals(value, ZERO32)) throw new TypeError(`${field} must be nonzero`)
  return b4a.from(value)
}

function asU64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) {
    throw new TypeError(`${field} is outside its u64 bound`)
  }
  return value
}

function boundedInteger (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function assertPrivateDirectory (stat, field) {
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new BlindWalIntegrityError(`${field} is not a private directory`)
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindWalIntegrityError(`${field} is not owned by the daemon uid`)
  }
  if ((stat.mode & 0o700) !== 0o700 || (stat.mode & 0o077) !== 0) {
    throw new BlindWalIntegrityError(`${field} must have private owner-only mode`)
  }
}

function assertPrivateFile (stat, field) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new BlindWalIntegrityError(`${field} is not a single-link regular file`)
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new BlindWalIntegrityError(`${field} is not owned by the daemon uid`)
  }
  if ((stat.mode & 0o600) !== 0o600 || (stat.mode & 0o077) !== 0) {
    throw new BlindWalIntegrityError(`${field} must have private owner-only mode`)
  }
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function sameFileState (left, right) {
  return sameInode(left, right) && left.size === right.size && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
}

function immutableFileState (stat) {
  return Object.freeze({
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mode: stat.mode,
    uid: stat.uid,
    gid: stat.gid,
    nlink: stat.nlink,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs
  })
}

async function readExact (handle, output, position) {
  let offset = 0
  while (offset < output.byteLength) {
    const { bytesRead } = await handle.read(output, offset, output.byteLength - offset, position + offset)
    if (bytesRead === 0) break
    offset += bytesRead
  }
  return offset
}

function assertHeaderBindings (header, expected) {
  if (header.sequence !== expected.sequence) throw new BlindWalIntegrityError('WAL sequence gap or fork')
  if (!b4a.equals(header.previousWalHash, expected.previousWalHash)) {
    throw new BlindWalIntegrityError('WAL predecessor hash fork')
  }
  if (!b4a.equals(header.durabilityContinuityHash, expected.durabilityContinuityHash)) {
    throw new BlindWalIntegrityError('WAL durability continuity binding mismatch')
  }
  if (header.mapGeneration !== expected.mapGeneration ||
      !b4a.equals(header.ownerFenceTokenHash, expected.writerFenceTokenHash)) {
    throw new BlindWalIntegrityError('WAL bucket-map generation or writer fence does not match recovery authority')
  }
}

function callbackFrame (frame, walOffset) {
  return Object.freeze({
    type: frame.type,
    sequence: frame.sequence,
    transactionId: b4a.from(frame.transactionId),
    virtualBucket: frame.virtualBucket,
    mapGeneration: frame.mapGeneration,
    ownerFenceTokenHash: b4a.from(frame.ownerFenceTokenHash),
    previousWalHash: b4a.from(frame.previousWalHash),
    durabilityContinuityHash: b4a.from(frame.durabilityContinuityHash),
    payload: b4a.from(frame.payload),
    payloadHash: b4a.from(frame.payloadHash),
    walHash: b4a.from(frame.walHash),
    frameBytes: frame.frameBytes,
    walOffset,
    walEndOffset: walOffset + frame.frameBytes
  })
}

function mintResult (state) {
  const result = {}
  Object.defineProperties(result, {
    root: { enumerable: true, value: state.root },
    walPath: { enumerable: true, value: state.walPath },
    checkpointSequence: { enumerable: true, value: state.checkpointSequence },
    checkpointHash: { enumerable: true, get: () => b4a.from(state.checkpointHash) },
    checkpointEndOffset: { enumerable: true, value: state.checkpointEndOffset },
    headSequence: { enumerable: true, value: state.headSequence },
    headHash: { enumerable: true, get: () => b4a.from(state.headHash) },
    headEndOffset: { enumerable: true, value: state.headEndOffset },
    observedWalBytes: { enumerable: true, value: state.observedWalBytes },
    completeFrameCount: { enumerable: true, value: state.completeFrameCount },
    replayedFrameCount: { enumerable: true, value: state.replayedFrameCount },
    tornTailOffset: { enumerable: true, value: state.tornTailOffset },
    tornTailBytes: { enumerable: true, value: state.tornTailBytes }
  })
  Object.freeze(result)
  ACTIVE_RESULTS.add(result)
  RESULT_STATE.set(result, state)
  return result
}

function resultMatchesState (result, state) {
  return result.root === state.root && result.walPath === state.walPath &&
    result.checkpointSequence === state.checkpointSequence &&
    b4a.equals(result.checkpointHash, state.checkpointHash) &&
    result.checkpointEndOffset === state.checkpointEndOffset &&
    result.headSequence === state.headSequence && b4a.equals(result.headHash, state.headHash) &&
    result.headEndOffset === state.headEndOffset && result.observedWalBytes === state.observedWalBytes &&
    result.completeFrameCount === state.completeFrameCount &&
    result.replayedFrameCount === state.replayedFrameCount &&
    result.tornTailOffset === state.tornTailOffset && result.tornTailBytes === state.tornTailBytes
}

export async function verifyBlindWalRecoveryScanResult (result, expectedRoot, lease) {
  const root = canonicalRoot(expectedRoot)
  if (!result || typeof result !== 'object' || !ACTIVE_RESULTS.has(result)) {
    throw new BlindWalRecoveryResultError('WAL recovery result is forged or unsupported')
  }
  const state = RESULT_STATE.get(result)
  if (!state || state.root !== root || state.lease !== lease || !resultMatchesState(result, state)) {
    throw new BlindWalRecoveryResultError('WAL recovery result binding is invalid')
  }
  await verifyBlindStoreSessionTransactionLease(lease, root)
  const linked = await fs.lstat(state.walPath)
  assertPrivateFile(linked, 'WAL recovery result file')
  if (!sameFileState(linked, state.walFileState)) {
    throw new BlindWalRecoveryResultError('WAL changed after its recovery result was minted')
  }
  return true
}

export async function scanBlindWalV2ForAnchoredRecovery (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('WAL recovery options must be an object')
  }
  const root = canonicalRoot(options.root)
  const lease = options.lease
  const checkpoint = options.checkpoint
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) {
    throw new TypeError('checkpoint must be an object')
  }
  const checkpointSequence = asU64(checkpoint.sequence, 'checkpoint.sequence', true)
  const checkpointHash = asBytes(checkpoint.hash, 32, 'checkpoint.hash', true)
  const mapGeneration = asU64(options.mapGeneration, 'mapGeneration', true)
  const writerFenceTokenHash = asBytes(options.writerFenceTokenHash, 32, 'writerFenceTokenHash', true)
  const durabilityContinuityHash = asBytes(options.durabilityContinuityHash, 32, 'durabilityContinuityHash', true)
  const maximumWalBytes = boundedInteger(options.maximumWalBytes, BLIND_WAL_LAYOUT.minimumFrameBytes,
    HARD_MAX_WAL_BYTES, 'maximumWalBytes')
  const maximumWalFrames = boundedInteger(options.maximumWalFrames, 1,
    HARD_MAX_WAL_FRAMES, 'maximumWalFrames')
  const maximumWalPayloadBytes = boundedInteger(options.maximumWalPayloadBytes,
    MIN_WAL_PAYLOAD_BYTES, MAX_WAL_PAYLOAD_BYTES, 'maximumWalPayloadBytes')
  if (checkpointSequence > BigInt(maximumWalFrames)) {
    throw new BlindStoreBoundsError('checkpoint sequence exceeds maximumWalFrames')
  }
  if (typeof options.applyShadowFrame !== 'function') {
    throw new TypeError('applyShadowFrame must be an awaited shadow-state callback')
  }

  await verifyBlindStoreSessionTransactionLease(lease, root)
  if (!FS_CONSTANTS.O_NOFOLLOW) throw new BlindWalIntegrityError('O_NOFOLLOW is required for WAL recovery scan')
  const controlDirectory = path.join(root, 'control')
  const walPath = path.join(controlDirectory, BLIND_WAL_LAYOUT.fileName)
  const controlStat = await fs.lstat(controlDirectory)
  assertPrivateDirectory(controlStat, 'WAL recovery control directory')
  if (await fs.realpath(controlDirectory) !== controlDirectory) {
    throw new BlindWalIntegrityError('WAL recovery control directory is not its canonical realpath')
  }

  let handle
  try {
    const linkedBefore = await fs.lstat(walPath)
    assertPrivateFile(linkedBefore, 'WAL recovery file')
    handle = await fs.open(walPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    const openedBefore = await handle.stat()
    assertPrivateFile(openedBefore, 'opened WAL recovery file')
    if (!sameInode(linkedBefore, openedBefore)) {
      throw new BlindWalIntegrityError('WAL path and opened recovery inode disagree')
    }
    if (!Number.isSafeInteger(openedBefore.size) || openedBefore.size < 0 || openedBefore.size > maximumWalBytes) {
      throw new BlindStoreBoundsError('WAL byte length exceeds maximumWalBytes')
    }
    await verifyBlindStoreSessionTransactionLease(lease, root)

    let offset = 0
    let expectedSequence = 1n
    let expectedPreviousWalHash = b4a.from(ZERO32)
    let completeFrameCount = 0
    let replayedFrameCount = 0
    let checkpointEndOffset = null
    let checkpointFound = false
    let headSequence = 0n
    let headHash = b4a.from(ZERO32)
    let headEndOffset = 0
    let tornTailOffset = null

    while (offset < openedBefore.size) {
      const remaining = openedBefore.size - offset
      if (remaining < BLIND_WAL_LAYOUT.headerBytes) {
        const tail = b4a.alloc(remaining)
        if (await readExact(handle, tail, offset) !== remaining) {
          throw new BlindWalIntegrityError('WAL final partial header changed while it was read')
        }
        tornTailOffset = offset
        break
      }

      const headerBytes = b4a.alloc(BLIND_WAL_LAYOUT.headerBytes)
      if (await readExact(handle, headerBytes, offset) !== headerBytes.byteLength) {
        throw new BlindWalIntegrityError('WAL header changed while it was read')
      }
      const header = inspectBlindWalFrameV2Header(headerBytes, maximumWalPayloadBytes)
      assertHeaderBindings(header, {
        sequence: expectedSequence,
        previousWalHash: expectedPreviousWalHash,
        durabilityContinuityHash,
        mapGeneration,
        writerFenceTokenHash
      })
      if (remaining < header.totalLength) {
        const tail = b4a.alloc(remaining)
        b4a.copy(headerBytes, tail, 0)
        if (await readExact(handle, tail.subarray(headerBytes.byteLength), offset + headerBytes.byteLength) !==
            remaining - headerBytes.byteLength) {
          throw new BlindWalIntegrityError('WAL final partial frame changed while it was read')
        }
        tornTailOffset = offset
        break
      }
      if (completeFrameCount >= maximumWalFrames) {
        throw new BlindStoreBoundsError('WAL complete frame count exceeds maximumWalFrames')
      }

      const frameBytes = b4a.alloc(header.totalLength)
      b4a.copy(headerBytes, frameBytes, 0)
      if (await readExact(handle, frameBytes.subarray(headerBytes.byteLength), offset + headerBytes.byteLength) !==
          header.totalLength - headerBytes.byteLength) {
        throw new BlindWalIntegrityError('WAL complete frame changed while it was read')
      }
      const frame = decodeBlindWalFrameV2(
        frameBytes,
        expectedSequence,
        expectedPreviousWalHash,
        durabilityContinuityHash,
        maximumWalPayloadBytes
      )
      if (frame.mapGeneration !== mapGeneration || !b4a.equals(frame.ownerFenceTokenHash, writerFenceTokenHash)) {
        throw new BlindWalIntegrityError('WAL bucket-map generation or writer fence does not match recovery authority')
      }

      completeFrameCount++
      const nextOffset = offset + frame.frameBytes
      headSequence = frame.sequence
      headHash = b4a.from(frame.walHash)
      headEndOffset = nextOffset
      expectedSequence = frame.sequence + 1n
      expectedPreviousWalHash = b4a.from(frame.walHash)

      if (frame.sequence === checkpointSequence) {
        if (!b4a.equals(frame.walHash, checkpointHash)) {
          throw new BlindWalIntegrityError('WAL checkpoint hash does not match its exact sequence')
        }
        checkpointFound = true
        checkpointEndOffset = nextOffset
      } else if (frame.sequence > checkpointSequence) {
        if (!checkpointFound) throw new BlindWalIntegrityError('WAL crossed an unverified checkpoint anchor')
        await options.applyShadowFrame(callbackFrame(frame, offset))
        replayedFrameCount++
        await verifyBlindStoreSessionTransactionLease(lease, root)
      }
      offset = nextOffset
    }

    if (!checkpointFound) {
      throw new BlindWalIntegrityError('WAL did not contain the exact complete checkpoint anchor')
    }

    const [openedAfter, linkedAfter] = await Promise.all([handle.stat(), fs.lstat(walPath)])
    assertPrivateFile(openedAfter, 'opened WAL recovery file')
    assertPrivateFile(linkedAfter, 'WAL recovery file')
    if (!sameFileState(openedBefore, openedAfter) || !sameFileState(openedBefore, linkedAfter)) {
      throw new BlindWalIntegrityError('WAL file changed while anchored recovery was scanned')
    }
    await verifyBlindStoreSessionTransactionLease(lease, root)

    return mintResult(Object.freeze({
      root,
      walPath,
      lease,
      checkpointSequence,
      checkpointHash,
      checkpointEndOffset,
      headSequence,
      headHash,
      headEndOffset,
      observedWalBytes: openedBefore.size,
      completeFrameCount,
      replayedFrameCount,
      tornTailOffset,
      tornTailBytes: tornTailOffset == null ? 0 : openedBefore.size - tornTailOffset,
      walFileState: immutableFileState(openedBefore)
    }))
  } finally {
    if (handle) await handle.close()
  }
}

export const BLIND_WAL_RECOVERY_SCAN_LIMITS = Object.freeze({
  hardMaximumWalBytes: HARD_MAX_WAL_BYTES,
  hardMaximumWalFrames: HARD_MAX_WAL_FRAMES,
  minimumWalPayloadBytes: MIN_WAL_PAYLOAD_BYTES,
  maximumWalPayloadBytes: MAX_WAL_PAYLOAD_BYTES,
  mutationFree: true,
  truncatesTornTail: false
})
