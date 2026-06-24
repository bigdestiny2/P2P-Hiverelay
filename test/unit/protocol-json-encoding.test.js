import test from 'brittle'
import b4a from 'b4a'
import {
  MAX_SERVICE_MESSAGE_BYTES,
  serviceMessageEncoding
} from 'p2p-hiverelay/core/services/protocol.js'
import {
  MAX_ANCHOR_MESSAGE_BYTES,
  anchorMessageEncoding
} from 'p2p-hiverelay/core/protocol/anchor-channel.js'
import {
  MAX_CUSTODY_MESSAGE_BYTES,
  custodyMessageEncoding
} from 'p2p-hiverelay/core/protocol/custody-channel.js'
import {
  MAX_PUBLISH_MESSAGE_BYTES,
  publishMessageEncoding
} from 'p2p-hiverelay/core/protocol/publish-channel.js'
import {
  MAX_REGISTRY_META_MESSAGE_BYTES,
  registryMetaMessageEncoding
} from 'p2p-hiverelay/core/registry/index.js'

const CHANNELS = [
  {
    name: 'service',
    encoding: serviceMessageEncoding,
    maxBytes: MAX_SERVICE_MESSAGE_BYTES,
    malformedError: 'malformed JSON'
  },
  {
    name: 'anchor',
    encoding: anchorMessageEncoding,
    maxBytes: MAX_ANCHOR_MESSAGE_BYTES,
    malformedError: 'bad json'
  },
  {
    name: 'custody',
    encoding: custodyMessageEncoding,
    maxBytes: MAX_CUSTODY_MESSAGE_BYTES,
    malformedError: 'bad json'
  },
  {
    name: 'publish',
    encoding: publishMessageEncoding,
    maxBytes: MAX_PUBLISH_MESSAGE_BYTES,
    malformedError: 'bad json'
  },
  {
    name: 'registry',
    encoding: registryMetaMessageEncoding,
    maxBytes: MAX_REGISTRY_META_MESSAGE_BYTES,
    malformedError: 'malformed JSON'
  }
]

function encodeWithLengthPrefix (payload) {
  const payloadBuf = typeof payload === 'string' ? b4a.from(payload) : payload
  const buf = b4a.alloc(4 + payloadBuf.length)
  buf.writeUInt32BE(payloadBuf.length, 0)
  payloadBuf.copy(buf, 4)
  return buf
}

function headerOnlyFrame (len) {
  const buf = b4a.alloc(4)
  buf.writeUInt32BE(len, 0)
  return buf
}

test('protocol-json-encoding: all channel encodings round-trip valid JSON', async (t) => {
  for (const { name, encoding } of CHANNELS) {
    const buf = encodeWithLengthPrefix(JSON.stringify({ type: 1, name }))
    const result = encoding.decode({ buffer: buf, start: 0, end: buf.length })
    t.is(result.type, 1, `${name} type survives decode`)
    t.is(result.name, name, `${name} payload survives decode`)
  }
})

test('protocol-json-encoding: all channel encodings reject oversized declared frames', async (t) => {
  for (const { name, encoding, maxBytes } of CHANNELS) {
    const result = encoding.decode({
      buffer: headerOnlyFrame(maxBytes + 1),
      start: 0,
      end: 4
    })
    t.is(result.type, -1, `${name} oversized type is -1`)
    t.is(result.error, 'message too large', `${name} oversized error`)
  }
})

test('protocol-json-encoding: all channel encodings reject oversized outbound messages before allocation growth', async (t) => {
  for (const { name, encoding, maxBytes } of CHANNELS) {
    const msg = { type: 1, payload: 'x'.repeat(maxBytes + 1) }
    const preState = { start: 0, end: 0 }
    t.exception(() => {
      encoding.preencode(preState, msg)
    }, /message too large/, `${name} preencode rejects oversize`)
    t.is(preState.end, 0, `${name} preencode does not grow state.end`)

    const buffer = b4a.alloc(16)
    const encodeState = { buffer, start: 0, end: buffer.length }
    t.exception(() => {
      encoding.encode(encodeState, msg)
    }, /message too large/, `${name} encode rejects oversize`)
    t.is(encodeState.start, 0, `${name} encode does not advance state.start`)
  }
})

test('protocol-json-encoding: all channel encodings reject malformed and truncated frames without throwing', async (t) => {
  for (const { name, encoding, malformedError } of CHANNELS) {
    const malformed = encodeWithLengthPrefix('{not json')
    let malformedResult = null
    t.execution(() => {
      malformedResult = encoding.decode({ buffer: malformed, start: 0, end: malformed.length })
    }, `${name} malformed JSON does not throw`)
    t.is(malformedResult.type, -1, `${name} malformed type is -1`)
    t.is(malformedResult.error, malformedError, `${name} malformed error`)

    const truncated = headerOnlyFrame(32)
    let truncatedResult = null
    t.execution(() => {
      truncatedResult = encoding.decode({ buffer: truncated, start: 0, end: truncated.length })
    }, `${name} truncated frame does not throw`)
    t.is(truncatedResult.type, -1, `${name} truncated type is -1`)
    t.is(truncatedResult.error, malformedError, `${name} truncated error`)

    const shortHeader = b4a.alloc(3)
    let shortResult = null
    t.execution(() => {
      shortResult = encoding.decode({ buffer: shortHeader, start: 0, end: shortHeader.length })
    }, `${name} short header does not throw`)
    t.is(shortResult.type, -1, `${name} short header type is -1`)
    t.is(shortResult.error, malformedError, `${name} short header error`)
  }
})

test('protocol-json-encoding: all channel encodings reject invalid decode state without throwing', async (t) => {
  const valid = encodeWithLengthPrefix('{}')
  const cases = [
    { name: 'missing state', state: null },
    { name: 'missing buffer', state: { start: 0, end: 0 } },
    { name: 'negative start', state: { buffer: valid, start: -1, end: valid.length } },
    { name: 'end before start', state: { buffer: valid, start: 4, end: 2 } },
    { name: 'end past buffer', state: { buffer: valid, start: 0, end: valid.length + 1 } },
    { name: 'unsafe start', state: { buffer: valid, start: Number.MAX_SAFE_INTEGER + 1, end: valid.length } }
  ]

  for (const { name, encoding, malformedError } of CHANNELS) {
    for (const item of cases) {
      let result = null
      t.execution(() => {
        result = encoding.decode(item.state)
      }, `${name} ${item.name} does not throw`)
      t.is(result.type, -1, `${name} ${item.name} type is -1`)
      t.is(result.error, malformedError, `${name} ${item.name} error`)
    }
  }
})
