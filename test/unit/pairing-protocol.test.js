import test from 'brittle'
import b4a from 'b4a'
import c from 'compact-encoding'
import {
  MAX_FRAME_BYTES,
  pairMessageEncoding
} from 'p2p-hiverelay-client/pairing.js'

function encodePairFrame (msg) {
  const state = { start: 0, end: 0, buffer: null }
  pairMessageEncoding.preencode(state, msg)
  state.buffer = b4a.alloc(state.end)
  pairMessageEncoding.encode(state, msg)
  return state.buffer
}

function declaredStringFrame (len, payload = null) {
  const state = { start: 0, end: 0, buffer: null }
  c.uint.preencode(state, len)
  state.end += payload ? payload.length : 0
  state.buffer = b4a.alloc(state.end)
  c.uint.encode(state, len)
  if (payload) payload.copy(state.buffer, state.start)
  return state.buffer
}

test('pairing protocol encoding: round-trips valid JSON frame', (t) => {
  const frame = encodePairFrame({ type: 'challenge', nonce: 'a'.repeat(64) })
  const result = pairMessageEncoding.decode({ buffer: frame, start: 0, end: frame.length })
  t.is(result.type, 'challenge')
  t.is(result.nonce, 'a'.repeat(64))
})

test('pairing protocol encoding: rejects oversized outbound messages before allocation growth', (t) => {
  const msg = { type: 'identity', bundle: { blob: 'x'.repeat(MAX_FRAME_BYTES + 1) } }
  const preState = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    pairMessageEncoding.preencode(preState, msg)
  }, /frame too large/, 'preencode rejects oversize')
  t.is(preState.end, 0, 'preencode does not grow state.end')

  const encodeState = { start: 0, end: 16, buffer: b4a.alloc(16) }
  t.exception(() => {
    pairMessageEncoding.encode(encodeState, msg)
  }, /frame too large/, 'encode rejects oversize')
  t.is(encodeState.start, 0, 'encode does not advance state.start')
})

test('pairing protocol encoding: rejects oversized declared inbound frame before string decode', (t) => {
  const frame = declaredStringFrame(MAX_FRAME_BYTES + 1)
  let result = null
  t.execution(() => {
    result = pairMessageEncoding.decode({ buffer: frame, start: 0, end: frame.length })
  }, 'oversized declared frame does not throw')
  t.is(result.type, -1)
  t.is(result.error, 'frame too large')
})

test('pairing protocol encoding: rejects malformed and truncated frames without throwing', (t) => {
  const malformed = declaredStringFrame(9, b4a.from('{not json'))
  let malformedResult = null
  t.execution(() => {
    malformedResult = pairMessageEncoding.decode({ buffer: malformed, start: 0, end: malformed.length })
  }, 'malformed JSON does not throw')
  t.is(malformedResult.type, -1)
  t.is(malformedResult.error, 'malformed JSON')

  const truncated = declaredStringFrame(32)
  let truncatedResult = null
  t.execution(() => {
    truncatedResult = pairMessageEncoding.decode({ buffer: truncated, start: 0, end: truncated.length })
  }, 'truncated string does not throw')
  t.is(truncatedResult.type, -1)
  t.is(truncatedResult.error, 'malformed JSON')
})

test('pairing protocol encoding: rejects invalid decode state without throwing', (t) => {
  const frame = encodePairFrame({ type: 'ack' })
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
      result = pairMessageEncoding.decode(state)
    }, `${name} does not throw`)
    t.is(result.type, -1, `${name} type is -1`)
    t.is(result.error, 'malformed JSON', `${name} error`)
  }
})
