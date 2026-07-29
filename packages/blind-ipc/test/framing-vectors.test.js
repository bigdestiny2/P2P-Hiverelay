import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import { decodeVectorManifest } from '@hiverelay/blind-protocol'
import {
  PRIVATE_IPC_VECTOR_OUTCOME,
  PRIVATE_IPC_VECTOR_PARSER,
  LocalStreamSequenceGuard,
  decodeLocalRequest,
  decodeLocalResponse,
  decodeLocalStreamFrame,
  decodeLocalStreamOpen,
  decodePrivateIpcFramingVector,
  encodePrivateIpcFramingVector,
  localRequestFrameLength,
  localResponseFrameLength,
  localStreamFrameLength,
  localStreamOpenFrameLength
} from '../index.js'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function append (left, right) {
  return left.byteLength === 0 ? b4a.from(right) : b4a.concat([left, right])
}

function runSingleItemScenario (scenario, frameLength, decode) {
  let buffer = b4a.alloc(0)
  let itemCount = 0
  let complete = false
  for (const chunk of scenario.chunks) {
    if (complete) throw new Error('single-item private IPC connection received another chunk')
    buffer = append(buffer, chunk)
    const expected = frameLength(buffer)
    if (expected == null || buffer.byteLength < expected) continue
    if (buffer.byteLength !== expected) throw new Error('single-item private IPC connection has trailing bytes')
    decode(buffer)
    itemCount++
    complete = true
    buffer = b4a.alloc(0)
  }
  if (!complete || buffer.byteLength !== 0) throw new Error('single-item private IPC connection ended truncated')
  return itemCount
}

function runStreamFrameScenario (scenario) {
  let buffer = b4a.alloc(0)
  let itemCount = 0
  const guard = new LocalStreamSequenceGuard()
  for (const chunk of scenario.chunks) {
    buffer = append(buffer, chunk)
    for (;;) {
      const expected = localStreamFrameLength(buffer)
      if (expected == null || buffer.byteLength < expected) break
      const frame = decodeLocalStreamFrame(buffer.subarray(0, expected))
      buffer = b4a.from(buffer.subarray(expected))
      guard.accept(frame)
      itemCount++
    }
  }
  if (buffer.byteLength !== 0) throw new Error('private IPC stream ended with a truncated frame')
  return itemCount
}

function runScenario (scenario) {
  if (scenario.parser === PRIVATE_IPC_VECTOR_PARSER.LOCAL_REQUEST) {
    return runSingleItemScenario(scenario, localRequestFrameLength, decodeLocalRequest)
  }
  if (scenario.parser === PRIVATE_IPC_VECTOR_PARSER.LOCAL_RESPONSE) {
    return runSingleItemScenario(scenario, localResponseFrameLength, decodeLocalResponse)
  }
  if (scenario.parser === PRIVATE_IPC_VECTOR_PARSER.LOCAL_STREAM_OPEN) {
    return runSingleItemScenario(scenario, localStreamOpenFrameLength, decodeLocalStreamOpen)
  }
  return runStreamFrameScenario(scenario)
}

test('manifest-bound private IPC framing vectors execute their exact accept/reject outcomes', async t => {
  const manifest = decodeVectorManifest(await fs.readFile(path.join(packageRoot, 'vector-manifest-v1.cenc')))
  const entries = manifest.filter(entry => entry.path.startsWith('framing/'))
  t.is(entries.length, 44)
  let accepted = 0
  let rejected = 0
  for (const entry of entries) {
    const bytes = await fs.readFile(path.join(packageRoot, 'vectors', ...entry.path.split('/')))
    const scenario = decodePrivateIpcFramingVector(bytes)
    let result = null
    let error = null
    try {
      result = runScenario(scenario)
    } catch (cause) {
      error = cause
    }
    if (scenario.outcome === PRIVATE_IPC_VECTOR_OUTCOME.ACCEPT) {
      t.is(error, null, `${entry.path} accepts`)
      t.is(result, scenario.expectedItemCount, `${entry.path} item count`)
      accepted++
    } else {
      t.ok(error, `${entry.path} rejects`)
      rejected++
    }
  }
  t.is(accepted, 11)
  t.is(rejected, 33)
})

test('private IPC framing-vector container is canonical, bounded and snapshots input', t => {
  const encoded = encodePrivateIpcFramingVector({
    parser: PRIVATE_IPC_VECTOR_PARSER.LOCAL_STREAM_FRAMES,
    outcome: PRIVATE_IPC_VECTOR_OUTCOME.ACCEPT,
    expectedItemCount: 1,
    chunks: [b4a.from([1, 2, 3])]
  })
  const source = b4a.from(encoded)
  const decoded = decodePrivateIpcFramingVector(source)
  source.fill(0)
  t.alike([...decoded.chunks[0]], [1, 2, 3])
  t.ok(b4a.equals(encodePrivateIpcFramingVector(decoded), encoded))
  t.exception(() => decodePrivateIpcFramingVector(encoded.subarray(0, encoded.byteLength - 1)))
  t.exception(() => decodePrivateIpcFramingVector(b4a.concat([encoded, b4a.from([0])])), /trailing/)
  t.exception(() => encodePrivateIpcFramingVector({
    parser: PRIVATE_IPC_VECTOR_PARSER.LOCAL_REQUEST,
    outcome: PRIVATE_IPC_VECTOR_OUTCOME.REJECT,
    expectedItemCount: 1,
    chunks: [b4a.from([1])]
  }), /reject vectors require zero/)
})
