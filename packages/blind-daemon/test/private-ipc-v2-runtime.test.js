import fs from 'node:fs'
import test from 'brittle'
import b4a from 'b4a'
import { decodeOuterEnvelope } from '@hiverelay/blind-protocol'
import {
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_STAGED_FLAG_V2,
  LOCAL_STAGED_FRAME_KIND_V2,
  OUTER_CLASS,
  PRIVATE_IPC_V2_LIMITS,
  decodeLocalStagedCellPutFrameV2,
  decodeLocalStagedCellPutOpenV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { stagedCellPutAuthority } from '../staged-put.js'
import {
  BoundedReplayGuardV2,
  STAGED_CELL_PUT_RESULT_ENCODER_MAX_BUFFERED_BYTES_V2,
  StagedCellPutOuterEnvelopeIngestorV2,
  StagedCellPutResultEncoderV2,
  writeSocketFramesWithinDeadlineV2
} from '../private-ipc-v2-runtime.js'

const openBytes = fs.readFileSync(new URL(
  '../../blind-ipc/vectors/v2/accepted/staged-cell-put-open-class-3.bin', import.meta.url))
const outerBytes = fs.readFileSync(new URL(
  '../../blind-ipc/vectors/v2/accepted/public-request-outer-envelope-class-3.bin', import.meta.url))
const resultOuterBytes = fs.readFileSync(new URL(
  '../../blind-ipc/vectors/v2/accepted/public-result-outer-envelope-class-3.bin', import.meta.url))
const open = decodeLocalStagedCellPutOpenV2(openBytes)

test('V2 replay guard expires only by clock and never evicts a live reservation', t => {
  const guard = new BoundedReplayGuardV2({ capacity: 2, maximumTtlMillis: 100n })
  guard.reserve(b4a.from([1]), 50n, 1n)
  guard.reserve(b4a.from([2]), 60n, 1n)
  t.is(guard.size, 2)
  t.exception(() => guard.reserve(b4a.from([3]), 70n, 1n), /live capacity/)
  t.ok(guard.has(b4a.from([1]), 49n))
  t.ok(guard.has(b4a.from([2]), 49n))
  t.exception(() => guard.reserve(b4a.from([1]), 70n, 49n), /already reserved/)

  guard.reserve(b4a.from([3]), 100n, 50n)
  t.is(guard.size, 2)
  t.absent(guard.has(b4a.from([1]), 50n))
  t.ok(guard.has(b4a.from([2]), 50n))
  t.ok(guard.has(b4a.from([3]), 50n))
  t.exception(() => guard.reserve(b4a.from([4]), 50n, 50n), /not live and bounded/)
  t.exception(() => guard.reserve(b4a.from([4]), 151n, 50n), /not live and bounded/)
})

test('V2 outer ingestion crosses every byte boundary without buffering public padding', async t => {
  const ingress = new StagedCellPutOuterEnvelopeIngestorV2({ open, maxQueuedBodyBytes: 4096 })
  let staged = null
  let sourceDone = false
  let sourceBytes = 0
  const consumer = ingress.ready.then(value => {
    staged = value
    const authority = stagedCellPutAuthority(value)
    return (async () => {
      for await (const chunk of authority.source) sourceBytes += chunk.byteLength
      sourceDone = true
    })()
  })

  // One-byte pushes exercise every possible inter-byte split in the outer
  // header, dispatch prefix/metadata/body boundary, and random padding.
  for (const byte of outerBytes) await ingress.push(b4a.from([byte]))
  await ingress.ready
  await new Promise(resolve => setImmediate(resolve))
  t.is(sourceDone, false, 'exact bytes without request completion cannot end the body source')
  t.is(ingress.receivedBytes, outerBytes.byteLength)
  t.is(ingress.innerBytes, b4a.readUInt32BE(outerBytes, 2))
  t.is(ingress.paddingBytes, outerBytes.byteLength - 6 - ingress.innerBytes)
  t.ok(ingress.maximumBufferedBytes < outerBytes.byteLength)

  ingress.finishRequest()
  await consumer
  t.ok(staged)
  t.ok(sourceDone)
  t.is(sourceBytes, stagedCellPutAuthority(staged).sourceByteLength)
})

test('V2 outer ingestion rejects truncation, overflow, class substitution and post-completion bytes', async t => {
  const truncated = new StagedCellPutOuterEnvelopeIngestorV2({ open })
  await truncated.push(outerBytes.subarray(0, outerBytes.byteLength - 1))
  t.exception(() => truncated.finishRequest(), /exact full outer envelope/)

  const overflow = new StagedCellPutOuterEnvelopeIngestorV2({ open })
  await t.exception(overflow.push(b4a.concat([outerBytes, b4a.from([1])])), /exceeds its exact outer class/)

  const changedClass = b4a.from(outerBytes)
  changedClass[1] = 2
  const substituted = new StagedCellPutOuterEnvelopeIngestorV2({ open })
  await t.exception(substituted.push(changedClass), /class differs/)

  const complete = new StagedCellPutOuterEnvelopeIngestorV2({ open })
  await complete.push(outerBytes)
  complete.finishRequest()
  await t.exception(complete.push(b4a.from([1])), /after terminal completion/)
})

test('V2 class-6 result encoding is canonical, same-class and bounded to one-frame-scale memory', t => {
  const request = decodeOuterEnvelope(outerBytes, { copyInner: true, copyBody: true })
  const result = decodeOuterEnvelope(resultOuterBytes, { copyInner: true, copyBody: true })
  const mutableDispatch = b4a.from(result.innerDispatch)
  const expectedDispatch = b4a.from(mutableDispatch)
  const encoder = new StagedCellPutResultEncoderV2({
    dispatch: mutableDispatch,
    outerClass: 6,
    requestId: request.frame.requestId,
    randomFill: buffer => buffer.fill(0x5a)
  })
  mutableDispatch.fill(0)

  const expectedPrefix = b4a.alloc(6 + expectedDispatch.byteLength)
  expectedPrefix[0] = 1
  expectedPrefix[1] = 6
  b4a.writeUInt32BE(expectedPrefix, expectedDispatch.byteLength, 2)
  b4a.copy(expectedDispatch, expectedPrefix, 6)
  const observedPrefix = b4a.alloc(expectedPrefix.byteLength)
  let observedPrefixBytes = 0
  let totalOuterBytes = 0
  let expectedSequence = 0n
  let frameCount = 0
  let finCount = 0
  let maximumWireBytes = 0
  let paddingIsDeterministic = true

  for (const wire of encoder) {
    maximumWireBytes = Math.max(maximumWireBytes, wire.byteLength)
    const frame = decodeLocalStagedCellPutFrameV2(wire)
    if (frame.direction !== LOCAL_STAGED_DIRECTION_V2.RESULT ||
        frame.frameKind !== LOCAL_STAGED_FRAME_KIND_V2.CONTENT ||
        frame.sequence !== expectedSequence++) {
      throw new Error('class-6 encoder emitted a non-canonical frame')
    }
    if ((frame.flags & LOCAL_STAGED_FLAG_V2.FIN) !== 0) finCount++
    const prefixTake = Math.min(frame.bytes.byteLength, observedPrefix.byteLength - observedPrefixBytes)
    if (prefixTake > 0) {
      b4a.copy(frame.bytes, observedPrefix, observedPrefixBytes, 0, prefixTake)
      observedPrefixBytes += prefixTake
    }
    for (let index = prefixTake; index < frame.bytes.byteLength; index++) {
      if (frame.bytes[index] !== 0x5a) paddingIsDeterministic = false
    }
    totalOuterBytes += frame.bytes.byteLength
    frameCount++
  }

  t.alike(observedPrefix, expectedPrefix)
  t.ok(paddingIsDeterministic)
  t.is(totalOuterBytes, OUTER_CLASS[6])
  t.is(encoder.emittedOuterBytes, OUTER_CLASS[6])
  t.is(frameCount, Math.ceil(OUTER_CLASS[6] / PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_CONTENT_BYTES))
  t.is(finCount, 1)
  t.ok(maximumWireBytes <= PRIVATE_IPC_V2_LIMITS.LOCAL_FRAME_BYTES)
  t.ok(encoder.maximumBufferedBytes <= STAGED_CELL_PUT_RESULT_ENCODER_MAX_BUFFERED_BYTES_V2)
  t.ok(encoder.maximumBufferedBytes < OUTER_CLASS[6] / 32)
})

test('V2 result writer applies one absolute deadline to multi-frame writes and iterator pulls', async t => {
  const keepalive = setInterval(() => {}, 10)
  t.teardown(() => clearInterval(keepalive))
  const request = decodeOuterEnvelope(outerBytes, { copyBody: true })
  const result = decodeOuterEnvelope(resultOuterBytes, { copyInner: true })
  const encoder = new StagedCellPutResultEncoderV2({
    dispatch: result.innerDispatch,
    outerClass: 6,
    requestId: request.frame.requestId,
    randomFill: buffer => buffer.fill(0x5a)
  })
  const stalled = {
    destroyed: false,
    writes: 0,
    destroy () { this.destroyed = true },
    write (frame, callback) {
      this.writes++
      if (this.writes <= 2) setTimeout(callback, 50)
    }
  }
  const writeStarted = Date.now()
  let writeError = null
  try {
    await writeSocketFramesWithinDeadlineV2(stalled, encoder, 200)
  } catch (error) {
    writeError = error
  }
  const writeElapsed = Date.now() - writeStarted
  t.is(writeError && writeError.code, 'IPC_WRITE_TIMEOUT')
  t.is(stalled.writes, 3)
  t.ok(writeElapsed >= 160 && writeElapsed < 270, 'earlier frames cannot reset the absolute deadline')
  t.ok(stalled.destroyed)
  t.is(encoder.dispatch, null, 'timeout closes the result iterator and releases its dispatch snapshot')

  let returned = false
  const neverPulls = {
    [Symbol.asyncIterator] () { return this },
    next () { return new Promise(() => {}) },
    return () { returned = true; return Promise.resolve({ done: true }) }
  }
  const pullSocket = {
    destroyed: false,
    destroy () { this.destroyed = true },
    write () { throw new Error('a stalled iterator must not reach socket.write') }
  }
  let pullError = null
  try {
    await writeSocketFramesWithinDeadlineV2(pullSocket, neverPulls, 30)
  } catch (error) {
    pullError = error
  }
  t.is(pullError && pullError.code, 'IPC_WRITE_TIMEOUT')
  t.ok(pullSocket.destroyed)
  t.ok(returned)

  const halfCloseSocket = {
    destroyed: false,
    writes: 0,
    ends: 0,
    destroy () { this.destroyed = true },
    write (_frame, callback) { this.writes++; callback() },
    end () { this.ends++ }
  }
  let halfCloseError = null
  try {
    await writeSocketFramesWithinDeadlineV2(halfCloseSocket, [b4a.from([1])], 30, { end: true })
  } catch (error) {
    halfCloseError = error
  }
  t.is(halfCloseError && halfCloseError.code, 'IPC_WRITE_TIMEOUT')
  t.is(halfCloseSocket.writes, 1)
  t.is(halfCloseSocket.ends, 1)
  t.ok(halfCloseSocket.destroyed, 'the frame-write deadline also bounds final response half-close')
})
