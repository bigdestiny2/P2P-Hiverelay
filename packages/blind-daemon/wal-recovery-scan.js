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
const WAL_SEALED_SEGMENT_NAME = new RegExp(BLIND_WAL_LAYOUT.sealedSegmentFileName)
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
    sealedSegmentCount: { enumerable: true, value: state.sealedSegmentCount },
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
    result.sealedSegmentCount === state.sealedSegmentCount &&
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
  if (state.walFileState === null) {
    // The live segment was absent at scan time (a crash sealed the previous
    // segment before its replacement was created); it must still be absent —
    // the writer recreates it only after this result is verified.
    let missing = false
    try {
      await fs.lstat(state.walPath)
    } catch (error) {
      if (error && error.code === 'ENOENT') missing = true
      else throw error
    }
    if (!missing) {
      throw new BlindWalRecoveryResultError('WAL live segment appeared after its recovery result was minted')
    }
  } else {
    const linked = await fs.lstat(state.walPath)
    assertPrivateFile(linked, 'WAL recovery result file')
    if (!sameFileState(linked, state.walFileState)) {
      throw new BlindWalRecoveryResultError('WAL changed after its recovery result was minted')
    }
  }
  for (const segment of state.segmentFileStates) {
    const linked = await fs.lstat(segment.path)
    assertPrivateFile(linked, 'WAL recovery result segment file')
    if (!sameFileState(linked, segment.fileState)) {
      throw new BlindWalRecoveryResultError('a sealed WAL segment changed after its recovery result was minted')
    }
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

  // Segmented WAL enumeration (Phase 3): sealed segments in sequence order,
  // then the live segment. A malformed segment entry or a coverage gap is an
  // interior break and fails closed. The retained prefix may start after
  // sequence 1 only when the checkpoint anchor pins the boundary: the first
  // retained frame is either exactly anchor+1 (its predecessor field must
  // equal the anchor hash) or the anchor frame itself must still be retained
  // and hash to the anchor value. Torn tails are tolerated only in the live
  // segment and are never truncated here (mutation-free scan).
  const segments = []
  const controlEntries = await fs.opendir(controlDirectory)
  for await (const entry of controlEntries) {
    if (!entry.name.startsWith('wal-')) continue
    const match = WAL_SEALED_SEGMENT_NAME.exec(entry.name)
    if (!match || !entry.isFile()) {
      throw new BlindWalIntegrityError(`unexpected WAL segment entry ${entry.name}`)
    }
    const firstSequence = BigInt(`0x${match[1]}`)
    const lastSequence = BigInt(`0x${match[2]}`)
    if (firstSequence === 0n || lastSequence < firstSequence) {
      throw new BlindWalIntegrityError(`WAL segment entry ${entry.name} carries an invalid sequence range`)
    }
    segments.push({ name: entry.name, firstSequence, lastSequence })
  }
  segments.sort((left, right) => (left.firstSequence < right.firstSequence ? -1 : 1))
  for (let index = 1; index < segments.length; index++) {
    if (segments[index].firstSequence !== segments[index - 1].lastSequence + 1n) {
      throw new BlindWalIntegrityError('WAL segment chain has an interior gap')
    }
  }

  const handles = []
  try {
    const files = []
    let observedWalBytes = 0
    for (const segment of segments) {
      const segmentPath = path.join(controlDirectory, segment.name)
      const linkedBefore = await fs.lstat(segmentPath)
      assertPrivateFile(linkedBefore, 'WAL recovery segment file')
      const handle = await fs.open(segmentPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
      handles.push(handle)
      const openedBefore = await handle.stat()
      assertPrivateFile(openedBefore, 'opened WAL recovery segment file')
      if (!sameInode(linkedBefore, openedBefore)) {
        throw new BlindWalIntegrityError('WAL segment path and opened recovery inode disagree')
      }
      files.push({
        name: segment.name,
        path: segmentPath,
        handle,
        sealed: true,
        firstSequence: segment.firstSequence,
        lastSequence: segment.lastSequence,
        before: openedBefore
      })
      observedWalBytes += openedBefore.size
    }
    let liveState = null
    {
      let linkedBefore = null
      try {
        linkedBefore = await fs.lstat(walPath)
      } catch (error) {
        if (!error || error.code !== 'ENOENT' || segments.length === 0) throw error
        // A crash between seal and live-segment creation leaves no live
        // segment; the scan treats it as empty and the writer recreates it
        // only after this result verifies.
      }
      if (linkedBefore !== null) {
        assertPrivateFile(linkedBefore, 'WAL recovery file')
        const handle = await fs.open(walPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
        handles.push(handle)
        const openedBefore = await handle.stat()
        assertPrivateFile(openedBefore, 'opened WAL recovery file')
        if (!sameInode(linkedBefore, openedBefore)) {
          throw new BlindWalIntegrityError('WAL path and opened recovery inode disagree')
        }
        files.push({
          name: BLIND_WAL_LAYOUT.fileName,
          path: walPath,
          handle,
          sealed: false,
          firstSequence: null,
          lastSequence: null,
          before: openedBefore
        })
        liveState = openedBefore
        observedWalBytes += openedBefore.size
      }
    }
    if (!Number.isSafeInteger(observedWalBytes) || observedWalBytes < 0 || observedWalBytes > maximumWalBytes) {
      throw new BlindStoreBoundsError('WAL byte length exceeds maximumWalBytes')
    }
    await verifyBlindStoreSessionTransactionLease(lease, root)

    // When no sealed segment survives, the live segment's own first frame
    // header declares the first retained sequence (a store pruned down to
    // its live segment starts above 1); the scan verifies the chain from
    // that frame on, so the peek fixes only the boundary the checkpoint
    // anchor pins.
    let firstRetainedSequence = 1n
    if (segments.length > 0) {
      firstRetainedSequence = segments[0].firstSequence
    } else if (liveState !== null && liveState.size >= BLIND_WAL_LAYOUT.headerBytes) {
      const firstHeader = b4a.alloc(BLIND_WAL_LAYOUT.headerBytes)
      const liveFile = files[files.length - 1]
      if (await readExact(liveFile.handle, firstHeader, 0) !== firstHeader.byteLength) {
        throw new BlindWalIntegrityError('WAL first header changed while it was read')
      }
      firstRetainedSequence = inspectBlindWalFrameV2Header(firstHeader, maximumWalPayloadBytes).sequence
    }
    if (firstRetainedSequence > checkpointSequence + 1n) {
      throw new BlindWalIntegrityError('WAL begins after the checkpoint anchor')
    }

    let expectedSequence = firstRetainedSequence
    let expectedPreviousWalHash = firstRetainedSequence === 1n ? b4a.from(ZERO32) : null
    let completeFrameCount = 0
    let replayedFrameCount = 0
    let checkpointEndOffset = null
    let checkpointFound = false
    let headSequence = 0n
    let headHash = b4a.from(ZERO32)
    let headEndOffset = 0
    let tornTailOffset = null
    if (firstRetainedSequence === checkpointSequence + 1n) {
      expectedPreviousWalHash = b4a.from(checkpointHash)
      checkpointFound = true
      checkpointEndOffset = 0
    }

    for (const file of files) {
      if (file.sealed && file.firstSequence !== expectedSequence) {
        throw new BlindWalIntegrityError('WAL segment chain has an interior gap')
      }
      let offset = 0
      while (offset < file.before.size) {
        const remaining = file.before.size - offset
        if (remaining < BLIND_WAL_LAYOUT.headerBytes) {
          if (file.sealed) throw new BlindWalIntegrityError(`sealed WAL segment ${file.name} ends inside a frame header`)
          const tail = b4a.alloc(remaining)
          if (await readExact(file.handle, tail, offset) !== remaining) {
            throw new BlindWalIntegrityError('WAL final partial header changed while it was read')
          }
          tornTailOffset = offset
          break
        }

        const headerBytes = b4a.alloc(BLIND_WAL_LAYOUT.headerBytes)
        if (await readExact(file.handle, headerBytes, offset) !== headerBytes.byteLength) {
          if (file.sealed) throw new BlindWalIntegrityError(`sealed WAL segment ${file.name} frame header changed while it was read`)
          throw new BlindWalIntegrityError('WAL header changed while it was read')
        }
        const header = inspectBlindWalFrameV2Header(headerBytes, maximumWalPayloadBytes)
        assertHeaderBindings(header, {
          sequence: expectedSequence,
          previousWalHash: expectedPreviousWalHash === null ? header.previousWalHash : expectedPreviousWalHash,
          durabilityContinuityHash,
          mapGeneration,
          writerFenceTokenHash
        })
        if (remaining < header.totalLength) {
          if (file.sealed) throw new BlindWalIntegrityError(`sealed WAL segment ${file.name} ends inside a frame`)
          const tail = b4a.alloc(remaining)
          b4a.copy(headerBytes, tail, 0)
          if (await readExact(file.handle, tail.subarray(headerBytes.byteLength), offset + headerBytes.byteLength) !==
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
        if (await readExact(file.handle, frameBytes.subarray(headerBytes.byteLength), offset + headerBytes.byteLength) !==
            header.totalLength - headerBytes.byteLength) {
          if (file.sealed) throw new BlindWalIntegrityError(`sealed WAL segment ${file.name} frame changed while it was read`)
          throw new BlindWalIntegrityError('WAL complete frame changed while it was read')
        }
        const frame = decodeBlindWalFrameV2(
          frameBytes,
          expectedSequence,
          expectedPreviousWalHash === null ? header.previousWalHash : expectedPreviousWalHash,
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

        if (!checkpointFound && frame.sequence === checkpointSequence) {
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
      if (file.sealed && expectedSequence !== file.lastSequence + 1n) {
        throw new BlindWalIntegrityError(`sealed WAL segment ${file.name} does not contain its sealed sequence range`)
      }
    }

    if (!checkpointFound) {
      throw new BlindWalIntegrityError('WAL did not contain the exact complete checkpoint anchor')
    }

    const segmentFileStates = []
    for (const file of files) {
      const [openedAfter, linkedAfter] = await Promise.all([file.handle.stat(), fs.lstat(file.path)])
      assertPrivateFile(openedAfter, 'opened WAL recovery file')
      assertPrivateFile(linkedAfter, 'WAL recovery file')
      if (!sameFileState(file.before, openedAfter) || !sameFileState(file.before, linkedAfter)) {
        throw new BlindWalIntegrityError('WAL file changed while anchored recovery was scanned')
      }
      if (file.sealed) {
        segmentFileStates.push(Object.freeze({ path: file.path, fileState: immutableFileState(file.before) }))
      }
    }
    await verifyBlindStoreSessionTransactionLease(lease, root)

    const liveFile = files.length > 0 && !files[files.length - 1].sealed ? files[files.length - 1] : null
    return mintResult(Object.freeze({
      root,
      walPath,
      lease,
      sealedSegmentCount: segments.length,
      checkpointSequence,
      checkpointHash,
      checkpointEndOffset,
      headSequence,
      headHash,
      headEndOffset,
      observedWalBytes,
      completeFrameCount,
      replayedFrameCount,
      tornTailOffset,
      tornTailBytes: tornTailOffset == null || liveFile === null ? 0 : liveFile.before.size - tornTailOffset,
      walFileState: liveFile === null ? null : immutableFileState(liveState),
      segmentFileStates: Object.freeze(segmentFileStates)
    }))
  } finally {
    for (const handle of handles) await handle.close().catch(() => {})
  }
}

export const BLIND_WAL_RECOVERY_SCAN_LIMITS = Object.freeze({
  hardMaximumWalBytes: HARD_MAX_WAL_BYTES,
  hardMaximumWalFrames: HARD_MAX_WAL_FRAMES,
  minimumWalPayloadBytes: MIN_WAL_PAYLOAD_BYTES,
  maximumWalPayloadBytes: MAX_WAL_PAYLOAD_BYTES,
  segmented: true,
  mutationFree: true,
  truncatesTornTail: false
})
