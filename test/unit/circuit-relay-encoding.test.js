import test from 'brittle'
import b4a from 'b4a'
import c from 'compact-encoding'
import {
  CIRCUIT_ID_BYTES,
  MAX_CIRCUIT_DATA_MSG_BYTES,
  MAX_CIRCUIT_STATUS_MESSAGE_BYTES,
  circuitConnectEncoding,
  circuitDataEncoding,
  circuitStatusEncoding,
  circuitReadyEncoding,
  circuitCloseEncoding
} from 'p2p-hiverelay/core/protocol/relay-circuit.js'
import { ERR } from 'p2p-hiverelay/core/protocol/messages.js'

function encodeFrame (encoding, msg) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, msg)
  state.buffer = b4a.alloc(state.end)
  encoding.encode(state, msg)
  return state.buffer
}

function declaredDataFrame (circuitId, len, payload = null) {
  const state = { start: 0, end: 0, buffer: null }
  c.fixed(CIRCUIT_ID_BYTES).preencode(state, circuitId)
  c.uint.preencode(state, len)
  state.end += payload ? payload.length : 0
  state.buffer = b4a.alloc(state.end)
  c.fixed(CIRCUIT_ID_BYTES).encode(state, circuitId)
  c.uint.encode(state, len)
  if (payload) payload.copy(state.buffer, state.start)
  return state.buffer
}

function declaredStatusFrame (code, len, payload = null) {
  const state = { start: 0, end: 0, buffer: null }
  c.uint.preencode(state, code)
  c.uint.preencode(state, len)
  state.end += payload ? payload.length : 0
  state.buffer = b4a.alloc(state.end)
  c.uint.encode(state, code)
  c.uint.encode(state, len)
  if (payload) payload.copy(state.buffer, state.start)
  return state.buffer
}

const circuitId = b4a.alloc(CIRCUIT_ID_BYTES, 0x11)
const targetPubkey = b4a.alloc(32, 0x22)
const sourcePubkey = b4a.alloc(32, 0x33)

test('circuit-relay encodings: round-trip valid frames', (t) => {
  const connectFrame = encodeFrame(circuitConnectEncoding, { targetPubkey, sourcePubkey })
  t.alike(circuitConnectEncoding.decode({ buffer: connectFrame, start: 0, end: connectFrame.length }), { targetPubkey, sourcePubkey })

  const data = b4a.from('hello')
  const dataFrame = encodeFrame(circuitDataEncoding, { circuitId, data })
  t.alike(circuitDataEncoding.decode({ buffer: dataFrame, start: 0, end: dataFrame.length }), { circuitId, data })

  const statusFrame = encodeFrame(circuitStatusEncoding, { code: 0, message: 'ok' })
  t.alike(circuitStatusEncoding.decode({ buffer: statusFrame, start: 0, end: statusFrame.length }), { code: 0, message: 'ok' })

  const readyFrame = encodeFrame(circuitReadyEncoding, { circuitId, remotePubkey: targetPubkey })
  t.alike(circuitReadyEncoding.decode({ buffer: readyFrame, start: 0, end: readyFrame.length }), { circuitId, remotePubkey: targetPubkey })

  const closeFrame = encodeFrame(circuitCloseEncoding, { circuitId, reason: 2 })
  t.alike(circuitCloseEncoding.decode({ buffer: closeFrame, start: 0, end: closeFrame.length }), { circuitId, reason: 2 })
})

test('circuit-relay encodings: reject bad outbound messages before allocation growth', (t) => {
  const badConnect = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    circuitConnectEncoding.preencode(badConnect, { targetPubkey, sourcePubkey: b4a.alloc(31) })
  }, /sourcePubkey/, 'connect preencode rejects invalid source')
  t.is(badConnect.end, 0, 'bad connect does not grow state.end')

  const badData = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    circuitDataEncoding.preencode(badData, { circuitId, data: b4a.alloc(MAX_CIRCUIT_DATA_MSG_BYTES + 1) })
  }, /frame too large/, 'data preencode rejects oversize')
  t.is(badData.end, 0, 'bad data does not grow state.end')

  const badStatus = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    circuitStatusEncoding.preencode(badStatus, { code: -1, message: 'bad' })
  }, /status code/, 'status preencode rejects invalid code')
  t.is(badStatus.end, 0, 'bad status does not grow state.end')

  const badReady = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    circuitReadyEncoding.preencode(badReady, { circuitId, remotePubkey: b4a.alloc(31) })
  }, /remotePubkey/, 'ready preencode rejects invalid remote pubkey')
  t.is(badReady.end, 0, 'bad ready does not grow state.end')

  const badClose = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    circuitCloseEncoding.preencode(badClose, { circuitId, reason: -1 })
  }, /close reason/, 'close preencode rejects invalid reason')
  t.is(badClose.end, 0, 'bad close does not grow state.end')
})

test('circuit-relay encodings: reject oversized declared inbound frames before decode materializes them', (t) => {
  const dataFrame = declaredDataFrame(circuitId, MAX_CIRCUIT_DATA_MSG_BYTES + 1)
  let dataOut = null
  t.execution(() => {
    dataOut = circuitDataEncoding.decode({ buffer: dataFrame, start: 0, end: dataFrame.length })
  }, 'oversized declared data frame does not throw')
  t.alike(dataOut.circuitId, circuitId)
  t.is(dataOut.data, null)
  t.is(dataOut.error, 'frame too large')

  const statusFrame = declaredStatusFrame(0, MAX_CIRCUIT_STATUS_MESSAGE_BYTES + 1)
  let statusOut = null
  t.execution(() => {
    statusOut = circuitStatusEncoding.decode({ buffer: statusFrame, start: 0, end: statusFrame.length })
  }, 'oversized declared status frame does not throw')
  t.is(statusOut.code, ERR.INVALID_REQUEST)
  t.is(statusOut.error, 'status message too large')
})

test('circuit-relay encodings: reject malformed and truncated frames without throwing', (t) => {
  const connectFrame = b4a.alloc(63)
  let connectOut = null
  t.execution(() => {
    connectOut = circuitConnectEncoding.decode({ buffer: connectFrame, start: 0, end: connectFrame.length })
  }, 'truncated connect frame does not throw')
  t.alike(connectOut.targetPubkey, connectFrame.subarray(0, 32))
  t.is(connectOut.sourcePubkey, null)
  t.is(connectOut.error, 'malformed connect')

  const dataFrame = declaredDataFrame(circuitId, 32)
  let dataOut = null
  t.execution(() => {
    dataOut = circuitDataEncoding.decode({ buffer: dataFrame, start: 0, end: dataFrame.length })
  }, 'truncated data frame does not throw')
  t.alike(dataOut.circuitId, circuitId)
  t.is(dataOut.data, null)
  t.is(dataOut.error, 'malformed data')

  const readyFrame = b4a.alloc(CIRCUIT_ID_BYTES + 31)
  let readyOut = null
  t.execution(() => {
    readyOut = circuitReadyEncoding.decode({ buffer: readyFrame, start: 0, end: readyFrame.length })
  }, 'truncated ready frame does not throw')
  t.is(readyOut.remotePubkey, null)
  t.is(readyOut.error, 'malformed ready')
})

test('circuit-relay encodings: reject invalid decode state without throwing', (t) => {
  const frame = encodeFrame(circuitDataEncoding, { circuitId, data: b4a.from('ok') })
  const cases = [
    { name: 'missing state', state: null },
    { name: 'missing buffer', state: { start: 0, end: 0 } },
    { name: 'negative start', state: { buffer: frame, start: -1, end: frame.length } },
    { name: 'end before start', state: { buffer: frame, start: 4, end: 2 } },
    { name: 'end past buffer', state: { buffer: frame, start: 0, end: frame.length + 1 } },
    { name: 'unsafe start', state: { buffer: frame, start: Number.MAX_SAFE_INTEGER + 1, end: frame.length } }
  ]

  for (const { name, state } of cases) {
    let result = null
    t.execution(() => {
      result = circuitDataEncoding.decode(state)
    }, `${name} does not throw`)
    t.is(result.circuitId, null, `${name} circuitId is null`)
    t.is(result.data, null, `${name} data is null`)
    t.is(result.error, 'malformed data', `${name} error`)
  }
})
