import fs from 'node:fs'
import test from 'brittle'
import b4a from 'b4a'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  decodeCanonical,
  encodeDispatchFrame,
  putCellV1
} from '@hiverelay/blind-protocol'
import {
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LOCAL_STREAM_MODE,
  LocalStreamSequenceGuard,
  decodeLocalStreamFrame,
  encodeLocalStreamFrame,
  fragmentLocalContent
} from '@hiverelay/blind-ipc'
import {
  STAGED_CELL_PUT_MAX_PREFIX_BYTES,
  StagedCellPutDispatchIngestor
} from '../staged-put.js'

const putBody = fs.readFileSync(new URL(
  '../../blind-protocol/vectors/draft/cell/put-class-1.bin', import.meta.url))

function dispatch (body = putBody) {
  return encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId: b4a.alloc(16, 0x71),
    body
  })
}

function decodedContent (bytes, sequence, fin) {
  return decodeLocalStreamFrame(encodeLocalStreamFrame({
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
    sequence,
    wireClass: 1,
    flags: fin ? LOCAL_STREAM_FLAG.FIN : 0,
    body: bytes
  }), { copyBody: true })
}

test('staged CELL.PUT parses bounded metadata then streams opaque body from real CONTENT frames', async t => {
  const canonical = dispatch()
  const expected = decodeCanonical(putCellV1, putBody, { copyBytes: true })
  const metadataBytes = canonical.byteLength - expected.cellBlob.byteLength
  t.ok(metadataBytes <= STAGED_CELL_PUT_MAX_PREFIX_BYTES)

  const ingestor = new StagedCellPutDispatchIngestor({ maxQueuedBodyBytes: 4096 })
  const guard = new LocalStreamSequenceGuard({
    streamMode: LOCAL_STREAM_MODE.DISPATCH_CONTENT,
    channelClass: 1
  })
  const prefixFrame = decodedContent(canonical.subarray(0, metadataBytes), 0n, false)
  guard.accept(prefixFrame)
  await ingestor.push(prefixFrame.bytes)
  const staged = await ingestor.ready
  t.is(staged.sourceByteLength, expected.cellBlob.byteLength)
  t.is(staged.frame.bodyLength, putBody.byteLength)
  t.is(staged.request.cellBlob, undefined)
  t.alike(staged.request.admission.token, expected.admission.token)
  t.ok(staged.maximumBufferedBytes <= STAGED_CELL_PUT_MAX_PREFIX_BYTES + 65_535)
  t.is(ingestor.bodyPullCount, 0)

  const consume = (async () => {
    const chunks = []
    let total = 0
    for await (const chunk of staged.source) {
      chunks.push(chunk)
      total += chunk.byteLength
    }
    return b4a.concat(chunks, total)
  })()
  const bodyFrames = fragmentLocalContent(canonical.subarray(metadataBytes), {
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    wireClass: 1,
    sequence: 1n,
    fin: true
  })
  for (const encoded of bodyFrames) {
    const frame = decodeLocalStreamFrame(encoded, { copyBody: true })
    guard.accept(frame)
    await ingestor.push(frame.bytes)
    t.ok(ingestor.bufferedBytes <= STAGED_CELL_PUT_MAX_PREFIX_BYTES + 4096)
    if ((frame.flags & LOCAL_STREAM_FLAG.FIN) !== 0) ingestor.finish()
  }
  t.alike(await consume, expected.cellBlob)
  t.ok(ingestor.bodyPullCount > 0)
})

test('staged CELL.PUT queue applies backpressure and refuses truncation/trailing bytes', async t => {
  const canonical = dispatch()
  const expected = decodeCanonical(putCellV1, putBody, { copyBytes: true })
  const metadataBytes = canonical.byteLength - expected.cellBlob.byteLength
  const ingestor = new StagedCellPutDispatchIngestor({ maxQueuedBodyBytes: 1024 })
  await ingestor.push(canonical.subarray(0, metadataBytes))
  const staged = await ingestor.ready
  let producerSettled = false
  const producer = ingestor.push(canonical.subarray(metadataBytes, metadataBytes + 2048))
    .then(() => { producerSettled = true })
  await new Promise(resolve => setImmediate(resolve))
  t.is(producerSettled, false)
  const iterator = staged.source[Symbol.asyncIterator]()
  t.is((await iterator.next()).value.byteLength, 1024)
  await new Promise(resolve => setImmediate(resolve))
  t.is((await iterator.next()).value.byteLength, 1024)
  await producer
  t.is(producerSettled, true)
  let remaining = 0
  const remainderProducer = ingestor.push(canonical.subarray(metadataBytes + 2048))
    .then(() => ingestor.finish())
  for (;;) {
    const item = await iterator.next()
    if (item.done) break
    remaining += item.value.byteLength
  }
  await remainderProducer
  t.is(remaining, expected.cellBlob.byteLength - 2048)

  const truncated = new StagedCellPutDispatchIngestor()
  await truncated.push(canonical.subarray(0, canonical.byteLength - 1))
  await truncated.ready
  t.exception(() => truncated.finish(), /ended before one exact dispatch/)

  const trailing = new StagedCellPutDispatchIngestor()
  let trailingError = null
  try { await trailing.push(b4a.concat([canonical, b4a.from([0])])) } catch (error) { trailingError = error }
  t.is(trailingError.code, 'BAD_ENCODING')
})

test('staged CELL.PUT cheap prefix authority rejects before admission-token bytes', async t => {
  const canonical = dispatch()
  // Dispatch header (45) + fixed PUT fields (263) + fixed Admission fields
  // (36) + the one-byte canonical token-length marker. No token byte follows.
  const beforeTokenBytes = 45 + 263 + 36 + 1
  const badSlot = b4a.from(canonical.subarray(0, beforeTokenBytes))
  badSlot[46] ^= 1
  const badSlotIngestor = new StagedCellPutDispatchIngestor()
  let badSlotError = null
  try { await badSlotIngestor.push(badSlot) } catch (error) { badSlotError = error }
  t.is(badSlotError.code, 'BAD_ENCODING')
  t.ok(/self-certifying/.test(badSlotError.message))

  const badVersion = b4a.from(canonical.subarray(0, beforeTokenBytes))
  badVersion[45] = 2
  const badVersionIngestor = new StagedCellPutDispatchIngestor()
  let badVersionError = null
  try { await badVersionIngestor.push(badVersion) } catch (error) { badVersionError = error }
  t.is(badVersionError.code, 'BAD_VERSION')
})
