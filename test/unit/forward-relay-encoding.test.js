import test from 'brittle'
import b4a from 'b4a'
import c from 'compact-encoding'
import {
  MAX_FORWARD_DATA_MSG_BYTES,
  MAX_FORWARD_STATUS_MESSAGE_BYTES,
  forwardOpenEncoding,
  forwardDataEncoding,
  forwardStatusEncoding,
  forwardCloseEncoding
} from 'p2p-hiverelay/core/protocol/forward-relay.js'

function encodeFrame (encoding, msg) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, msg)
  state.buffer = b4a.alloc(state.end)
  encoding.encode(state, msg)
  return state.buffer
}

function declaredBytesFrame (len, payload = null) {
  const state = { start: 0, end: 0, buffer: null }
  c.uint.preencode(state, len)
  state.end += payload ? payload.length : 0
  state.buffer = b4a.alloc(state.end)
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

test('forward-relay encodings: round-trip valid frames', (t) => {
  const target = b4a.alloc(32, 0x11)
  const data = b4a.from('hello')

  t.alike(forwardOpenEncoding.decode({ buffer: encodeFrame(forwardOpenEncoding, { target }), start: 0, end: 32 }), { target })

  const dataFrame = encodeFrame(forwardDataEncoding, { data })
  const dataOut = forwardDataEncoding.decode({ buffer: dataFrame, start: 0, end: dataFrame.length })
  t.alike(dataOut, { data })

  const statusFrame = encodeFrame(forwardStatusEncoding, { code: 0, message: 'ok' })
  t.alike(forwardStatusEncoding.decode({ buffer: statusFrame, start: 0, end: statusFrame.length }), { code: 0, message: 'ok' })

  const closeFrame = encodeFrame(forwardCloseEncoding, { reason: 2 })
  t.alike(forwardCloseEncoding.decode({ buffer: closeFrame, start: 0, end: closeFrame.length }), { reason: 2 })
})

test('forward-relay encodings: reject oversized outbound frames before allocation growth', (t) => {
  const dataState = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    forwardDataEncoding.preencode(dataState, { data: b4a.alloc(MAX_FORWARD_DATA_MSG_BYTES + 1) })
  }, /frame too large/, 'data preencode rejects oversize')
  t.is(dataState.end, 0, 'data preencode does not grow state.end')

  const statusState = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    forwardStatusEncoding.preencode(statusState, { code: 0, message: 'x'.repeat(MAX_FORWARD_STATUS_MESSAGE_BYTES + 1) })
  }, /status message too large/, 'status preencode rejects oversize')
  t.is(statusState.end, 0, 'status preencode does not grow state.end')

  const badCodeState = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    forwardStatusEncoding.preencode(badCodeState, { code: -1, message: 'bad' })
  }, /status code/, 'status preencode rejects invalid code')
  t.is(badCodeState.end, 0, 'invalid status code does not grow state.end')

  const badCloseState = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    forwardCloseEncoding.preencode(badCloseState, { reason: -1 })
  }, /close reason/, 'close preencode rejects invalid reason')
  t.is(badCloseState.end, 0, 'invalid close reason does not grow state.end')
})

test('forward-relay encodings: reject oversized declared inbound frames before decode materializes them', (t) => {
  const dataFrame = declaredBytesFrame(MAX_FORWARD_DATA_MSG_BYTES + 1)
  let dataOut = null
  t.execution(() => {
    dataOut = forwardDataEncoding.decode({ buffer: dataFrame, start: 0, end: dataFrame.length })
  }, 'oversized declared data frame does not throw')
  t.is(dataOut.data, null)
  t.is(dataOut.error, 'frame too large')

  const statusFrame = declaredStatusFrame(0, MAX_FORWARD_STATUS_MESSAGE_BYTES + 1)
  let statusOut = null
  t.execution(() => {
    statusOut = forwardStatusEncoding.decode({ buffer: statusFrame, start: 0, end: statusFrame.length })
  }, 'oversized declared status frame does not throw')
  t.is(statusOut.code, 4)
  t.is(statusOut.error, 'status message too large')
})

test('forward-relay encodings: reject malformed and truncated frames without throwing', (t) => {
  const malformedOpen = b4a.alloc(31)
  let openOut = null
  t.execution(() => {
    openOut = forwardOpenEncoding.decode({ buffer: malformedOpen, start: 0, end: malformedOpen.length })
  }, 'truncated open frame does not throw')
  t.is(openOut.target, null)
  t.is(openOut.error, 'malformed target')

  const truncatedData = declaredBytesFrame(32)
  let dataOut = null
  t.execution(() => {
    dataOut = forwardDataEncoding.decode({ buffer: truncatedData, start: 0, end: truncatedData.length })
  }, 'truncated data frame does not throw')
  t.is(dataOut.data, null)
  t.is(dataOut.error, 'malformed data')

  const truncatedStatus = declaredStatusFrame(0, 32)
  let statusOut = null
  t.execution(() => {
    statusOut = forwardStatusEncoding.decode({ buffer: truncatedStatus, start: 0, end: truncatedStatus.length })
  }, 'truncated status frame does not throw')
  t.is(statusOut.code, 4)
  t.is(statusOut.error, 'malformed status')
})

test('forward-relay encodings: reject invalid decode state without throwing', (t) => {
  const frame = encodeFrame(forwardDataEncoding, { data: b4a.from('ok') })
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
      result = forwardDataEncoding.decode(state)
    }, `${name} does not throw`)
    t.is(result.data, null, `${name} data is null`)
    t.is(result.error, 'malformed data', `${name} error`)
  }
})
