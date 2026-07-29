import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PROTOCOL,
  TRANSPORT_ID,
  decodeOuterEnvelope,
  encodeDispatchFrame,
  encodeOuterEnvelope
} from '@hiverelay/blind-protocol'
import { BlindDirectHttpClient } from '../index.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'
import { verifiedEndpointFixture } from './endpoint-fixture.js'

const runtime = createNodeCryptoRuntime()
const rawEndpoint = {
  endpointId: 1,
  transportId: TRANSPORT_ID.HTTPS_DIRECT,
  envelopeClassBits: 0x007e,
  canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/describe')
}
const endpoint = verifiedEndpointFixture(rawEndpoint, FAMILY.CELL, OPERATION.CELL.GET)

function responseHeaders (length) {
  return new Headers([
    ['content-type', PROTOCOL.mediaType],
    ['content-length', String(length)]
  ])
}

test('direct client sends one metadata-minimal fixed-route request and verifies correlation', async t => {
  let observed
  const fetch = async (url, init) => {
    observed = { url, init }
    const request = decodeOuterEnvelope(init.body, { copyBody: true })
    const response = encodeOuterEnvelope({
      outerClass: request.outerClass,
      innerDispatch: encodeDispatchFrame({
        frameKind: FRAME_KIND.RESPONSE,
        familyId: request.frame.familyId,
        operationId: request.frame.operationId,
        requestId: request.frame.requestId,
        body: b4a.from([7, 8, 9])
      })
    }, { randomFill: padding => padding.fill(4) })
    return new Response(response, { status: 200, headers: responseHeaders(response.byteLength) })
  }
  const client = new BlindDirectHttpClient({ runtime, fetch })
  const result = await client.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 3,
    body: b4a.from([1, 2, 3])
  })
  t.ok(result.ok)
  t.alike(result.body, b4a.from([7, 8, 9]))
  t.is(observed.url, 'https://relay.example/api/blind/v1/cell')
  t.is(observed.init.credentials, 'omit')
  t.is(observed.init.redirect, 'error')
  t.is(observed.init.referrerPolicy, 'no-referrer')
  t.alike(observed.init.headers, [
    ['content-type', PROTOCOL.mediaType]
  ])
  t.absent(observed.init.headers.find(([name]) => name === 'content-length'))
  t.absent(observed.init.headers.find(([name]) => name === 'authorization'))
  t.absent(observed.init.headers.find(([name]) => name === 'x-peerit-app'))
})

test('direct client rejects route substitution, class drift and correlation drift', async t => {
  const wrongRoute = new BlindDirectHttpClient({
    runtime,
    fetch: async () => { throw new Error('must not dial') }
  })
  await t.exception(wrongRoute.request({
    endpoint: verifiedEndpointFixture({
      ...rawEndpoint,
      canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/inbox')
    }, FAMILY.CELL, OPERATION.CELL.GET),
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1])
  }), /listener-authority anchor/)

  const drift = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const request = decodeOuterEnvelope(init.body, { copyBody: true })
      const response = encodeOuterEnvelope({
        outerClass: request.outerClass + 1,
        innerDispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: request.frame.familyId,
          operationId: request.frame.operationId,
          requestId: b4a.alloc(16, 99),
          body: b4a.from([1])
        })
      })
      return new Response(response, { status: 200, headers: responseHeaders(response.byteLength) })
    }
  })
  await t.exception(drift.request({ endpoint, familyId: FAMILY.CELL, operationId: OPERATION.CELL.GET, expectedResultBodyBytes: 1, body: b4a.from([1]) }))
})

test('direct client rejects non-protocol statuses before decoding their bodies', async t => {
  let bodyRead = false
  const client = new BlindDirectHttpClient({
    runtime,
    fetch: async () => ({
      status: 503,
      headers: new Headers(),
      arrayBuffer: async () => { bodyRead = true; return new ArrayBuffer(0) }
    })
  })
  await t.exception(client.request({ endpoint, familyId: FAMILY.CELL, operationId: OPERATION.CELL.GET, expectedResultBodyBytes: 1, body: b4a.from([1]) }), /non-protocol status/)
  t.is(bodyRead, false)
})

test('direct client never allocates an unbounded fallback response and aborts a stalled stream', async t => {
  let bodyRead = false
  const fallback = new BlindDirectHttpClient({
    runtime,
    fetch: async () => ({
      status: 200,
      headers: new Headers([['content-type', PROTOCOL.mediaType]]),
      body: null,
      arrayBuffer: async () => { bodyRead = true; return new ArrayBuffer(0) }
    })
  })
  await t.exception(fallback.request({ endpoint, familyId: FAMILY.CELL, operationId: OPERATION.CELL.GET, expectedResultBodyBytes: 1, body: b4a.from([1]) }), /exact content-length/)
  t.is(bodyRead, false)

  const declaredFallback = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => ({
      status: 200,
      headers: responseHeaders(init.body.byteLength),
      body: null,
      arrayBuffer: async () => { bodyRead = true; return new ArrayBuffer(64 * 1024 * 1024) }
    })
  })
  await t.exception(declaredFallback.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1])
  }), /bounded streaming response/)
  t.is(bodyRead, false)

  let cancelled = false
  const stalled = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => new Response(new ReadableStream({
      cancel () { cancelled = true }
    }), {
      status: 200,
      headers: responseHeaders(init.body.byteLength)
    })
  })
  await t.exception(stalled.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1]),
    timeoutMillis: 10
  }))
  t.ok(cancelled)
})

test('direct client converts malformed and oversized relay frames into protocol violations', async t => {
  const oversized = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const request = decodeOuterEnvelope(init.body, { copyBody: true })
      const response = encodeOuterEnvelope({
        outerClass: request.outerClass,
        innerDispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: request.frame.familyId,
          operationId: request.frame.operationId,
          requestId: request.frame.requestId,
          body: b4a.alloc(100, 1)
        })
      })
      return new Response(response, { status: 200, headers: responseHeaders(response.byteLength) })
    }
  })
  let oversizedError
  try {
    await oversized.request({
      endpoint,
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.GET,
      expectedResultBodyBytes: 1,
      body: b4a.from([1])
    })
  } catch (error) {
    oversizedError = error
  }
  t.is(oversizedError.code, 'RELAY_PROTOCOL_VIOLATION')

  const malformed = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const bytes = b4a.from(init.body)
      bytes[0] = 99
      return new Response(bytes, { status: 200, headers: responseHeaders(bytes.byteLength) })
    }
  })
  let malformedError
  try {
    await malformed.request({
      endpoint,
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.GET,
      expectedResultBodyBytes: 1,
      body: b4a.from([1])
    })
  } catch (error) {
    malformedError = error
  }
  t.is(malformedError.code, 'RELAY_PROTOCOL_VIOLATION')
  t.is(malformedError.cause.code, 'BAD_VERSION')
})

test('direct client rejects content transforms and never treats localhost as an insecure loopback authority', async t => {
  const transformed = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => new Response(init.body, {
      status: 200,
      headers: new Headers([
        ['content-type', PROTOCOL.mediaType],
        ['content-length', String(init.body.byteLength)],
        ['content-encoding', 'gzip']
      ])
    })
  })
  await t.exception(transformed.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1])
  }), /forbidden/)

  const loopback = new BlindDirectHttpClient({
    runtime,
    allowInsecureLoopback: true,
    fetch: async () => { throw new Error('must not dial') }
  })
  await t.exception(loopback.request({
    endpoint: verifiedEndpointFixture({
      ...rawEndpoint,
      canonicalUrl: b4a.from('http://localhost:8080/api/blind/v1/describe')
    }, FAMILY.CELL, OPERATION.CELL.GET),
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1])
  }), /must use HTTPS/)
})

test('direct client unconditionally rejects raw relay endpoints', async t => {
  const client = new BlindDirectHttpClient({ runtime, fetch: async () => { throw new Error('must not dial') } })
  await t.exception(client.request({
    endpoint: rawEndpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1])
  }), /VerifiedEndpoint/)
})

test('direct client binds a VerifiedEndpoint to its exact qualified operation', async t => {
  let dialled = false
  const client = new BlindDirectHttpClient({
    runtime,
    fetch: async () => { dialled = true; throw new Error('must not dial') }
  })
  await t.exception(client.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    expectedResultBodyBytes: 1,
    body: b4a.from([1])
  }), /exact direct operation/)
  t.is(dialled, false)
})
