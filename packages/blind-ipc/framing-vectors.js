import b4a from 'b4a'

const HEADER_BYTES = 6
const CHUNK_PREFIX_BYTES = 4
const MAX_SCENARIO_CHUNKS = 64
const MAX_SCENARIO_CHUNK_BYTES = 8 * 1024 * 1024 + 64
const MAX_SCENARIO_BYTES = 2 * MAX_SCENARIO_CHUNK_BYTES + 1024

export const PRIVATE_IPC_VECTOR_PARSER = Object.freeze({
  LOCAL_REQUEST: 1,
  LOCAL_RESPONSE: 2,
  LOCAL_STREAM_OPEN: 3,
  LOCAL_STREAM_FRAMES: 4
})

export const PRIVATE_IPC_VECTOR_OUTCOME = Object.freeze({
  ACCEPT: 1,
  REJECT: 2
})

function fail (message) {
  const error = new Error(message)
  error.code = 'BAD_PRIVATE_IPC_FRAMING_VECTOR'
  throw error
}

function snapshotBytes (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function known (values, value, field) {
  if (!Number.isInteger(value) || !Object.values(values).includes(value)) fail(`${field} is not registered`)
  return value
}

function checkedScenario (input) {
  if (!input || typeof input !== 'object') fail('framing vector must be an object')
  const parser = known(PRIVATE_IPC_VECTOR_PARSER, input.parser, 'parser')
  const outcome = known(PRIVATE_IPC_VECTOR_OUTCOME, input.outcome, 'outcome')
  if (!Array.isArray(input.chunks) || input.chunks.length < 1 || input.chunks.length > MAX_SCENARIO_CHUNKS) {
    fail(`chunks must contain 1..${MAX_SCENARIO_CHUNKS} items`)
  }
  const chunks = input.chunks.map((chunk, index) => {
    const bytes = snapshotBytes(chunk, `chunks[${index}]`)
    if (bytes.byteLength < 1 || bytes.byteLength > MAX_SCENARIO_CHUNK_BYTES) {
      fail(`chunks[${index}] is outside its byte bound`)
    }
    return bytes
  })
  const expectedItemCount = input.expectedItemCount
  if (!Number.isInteger(expectedItemCount) || expectedItemCount < 0 || expectedItemCount > 0xff) {
    fail('expectedItemCount is outside u8')
  }
  if ((outcome === PRIVATE_IPC_VECTOR_OUTCOME.ACCEPT) !== (expectedItemCount > 0)) {
    fail('accept vectors require items and reject vectors require zero expected items')
  }
  const byteLength = HEADER_BYTES + chunks.reduce((total, chunk) => total + CHUNK_PREFIX_BYTES + chunk.byteLength, 0)
  if (byteLength > MAX_SCENARIO_BYTES) fail('framing vector exceeds its total byte bound')
  return { parser, outcome, expectedItemCount, chunks, byteLength }
}

export function encodePrivateIpcFramingVector (input) {
  const value = checkedScenario(input)
  const output = b4a.alloc(value.byteLength)
  output[0] = 1
  output[1] = value.parser
  output[2] = value.outcome
  output[3] = value.expectedItemCount
  output[4] = value.chunks.length >>> 8
  output[5] = value.chunks.length & 0xff
  let offset = HEADER_BYTES
  for (const chunk of value.chunks) {
    b4a.writeUInt32BE(output, chunk.byteLength, offset)
    offset += CHUNK_PREFIX_BYTES
    b4a.copy(chunk, output, offset)
    offset += chunk.byteLength
  }
  return output
}

export function decodePrivateIpcFramingVector (input) {
  const bytes = snapshotBytes(input, 'framing vector')
  if (bytes.byteLength < HEADER_BYTES || bytes.byteLength > MAX_SCENARIO_BYTES || bytes[0] !== 1) {
    fail('framing vector has an invalid bounded prefix')
  }
  const parser = known(PRIVATE_IPC_VECTOR_PARSER, bytes[1], 'parser')
  const outcome = known(PRIVATE_IPC_VECTOR_OUTCOME, bytes[2], 'outcome')
  const expectedItemCount = bytes[3]
  const chunkCount = (bytes[4] << 8) | bytes[5]
  if (chunkCount < 1 || chunkCount > MAX_SCENARIO_CHUNKS) fail('framing vector chunk count is outside its bound')
  const chunks = new Array(chunkCount)
  let offset = HEADER_BYTES
  for (let index = 0; index < chunkCount; index++) {
    if (offset + CHUNK_PREFIX_BYTES > bytes.byteLength) fail('framing vector is truncated before a chunk length')
    const length = b4a.readUInt32BE(bytes, offset)
    offset += CHUNK_PREFIX_BYTES
    if (length < 1 || length > MAX_SCENARIO_CHUNK_BYTES || offset + length > bytes.byteLength) {
      fail('framing vector contains a truncated or overlong chunk')
    }
    chunks[index] = b4a.from(bytes.subarray(offset, offset + length))
    offset += length
  }
  if (offset !== bytes.byteLength) fail('framing vector has trailing bytes')
  const value = checkedScenario({ parser, outcome, expectedItemCount, chunks })
  const canonical = encodePrivateIpcFramingVector(value)
  if (!b4a.equals(canonical, bytes)) fail('framing vector is not canonical')
  return Object.freeze({
    parser,
    outcome,
    expectedItemCount,
    chunks: Object.freeze(chunks)
  })
}

export const PRIVATE_IPC_FRAMING_VECTOR_LIMITS = Object.freeze({
  MAX_SCENARIO_CHUNKS,
  MAX_SCENARIO_CHUNK_BYTES,
  MAX_SCENARIO_BYTES
})
