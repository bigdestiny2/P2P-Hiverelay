import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PROTOCOL,
  TRANSPORT_ID
} from '../../blind-protocol/registry.js'
import { decodeOuterEnvelope, encodeOuterEnvelope } from '../../blind-protocol/outer-envelope.js'
import { encodeDispatchFrame } from '../../blind-protocol/dispatch.js'
import { createNodeCryptoRuntime } from '../../blind-client/runtime/node.js'
import { verifiedEndpointFixture } from '../../blind-client/test/endpoint-fixture.js'
import {
  BlindDescriptorBootstrapHttpClient,
  BlindDirectHttpClient,
  BlindRelayQualifier
} from '../src/browser-control.js'

const runtime = createNodeCryptoRuntime()
const rawEndpoint = {
  endpointId: 1,
  transportId: TRANSPORT_ID.HTTPS_DIRECT,
  envelopeClassBits: 0x007e,
  canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/describe')
}
const endpoint = verifiedEndpointFixture(rawEndpoint, FAMILY.CELL, OPERATION.CELL.GET)
const pins = Object.freeze({
  supportedProtocolProfiles: [{ profileId: 1, profileHash: b4a.alloc(32, 1) }],
  supportedTransportProfiles: [{ transportProfileId: 1, transportProfileHash: b4a.alloc(32, 2) }]
})

function responseHeaders (length, contentType = PROTOCOL.mediaType) {
  return new Headers([
    ['content-type', contentType],
    ['content-length', String(length)]
  ])
}

function validResponse (init, body = b4a.from([7])) {
  const request = decodeOuterEnvelope(init.body, { copyBody: true })
  const response = encodeOuterEnvelope({
    outerClass: request.outerClass,
    innerDispatch: encodeDispatchFrame({
      frameKind: FRAME_KIND.RESPONSE,
      familyId: request.frame.familyId,
      operationId: request.frame.operationId,
      requestId: request.frame.requestId,
      body
    })
  })
  return { response, request }
}

function request (client, options = {}) {
  return client.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1]),
    ...options
  })
}

test('reachable HTTP wrappers preserve one explicit fetch identity', t => {
  const fetch = async () => { throw new Error('not invoked') }
  const bootstrap = new BlindDescriptorBootstrapHttpClient({ runtime, fetch })
  const direct = new BlindDirectHttpClient({ runtime, fetch })
  const qualifier = new BlindRelayQualifier({
    runtime,
    fetch,
    nowEpoch: () => 1,
    ...pins
  })
  t.is(bootstrap.fetch, fetch)
  t.is(direct.fetch, fetch)
  t.is(qualifier.bootstrapClient.fetch, fetch)
  t.is(qualifier.directClient.fetch, fetch)
})

test('reachable HTTP wrappers bind global fetch and fail closed when absent', async t => {
  const original = globalThis.fetch
  let receiver = null
  try {
    globalThis.fetch = function () {
      receiver = this
      return Promise.resolve({})
    }
    const direct = new BlindDirectHttpClient({ runtime })
    await direct.fetch('https://example.invalid')
    t.is(receiver, globalThis)

    globalThis.fetch = undefined
    t.exception(() => new BlindDirectHttpClient({ runtime }), /fetch implementation/)
    t.exception(() => new BlindDescriptorBootstrapHttpClient({ runtime }), /fetch implementation/)
  } finally {
    globalThis.fetch = original
  }
})

test('bound wrapper sends one fixed-route minimal request and accepts exact response class', async t => {
  let observed
  const client = new BlindDirectHttpClient({
    runtime,
    fetch: async (url, init) => {
      observed = { url, init }
      const { response } = validResponse(init)
      return new Response(response, { status: 200, headers: responseHeaders(response.byteLength) })
    }
  })
  const result = await request(client)
  t.alike(result.body, b4a.from([7]))
  t.is(observed.url, 'https://relay.example/api/blind/v1/cell')
  t.is(observed.init.credentials, 'omit')
  t.is(observed.init.redirect, 'error')
  t.is(observed.init.referrerPolicy, 'no-referrer')
  t.alike(observed.init.headers, [['content-type', PROTOCOL.mediaType]])
})

test('bound wrapper rejects status, media type, exact length and oversized response', async t => {
  const status = new BlindDirectHttpClient({
    runtime,
    fetch: async () => ({ status: 503, headers: new Headers() })
  })
  await t.exception(request(status), /non-protocol status/)

  const media = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const { response } = validResponse(init)
      return new Response(response, {
        status: 200,
        headers: responseHeaders(response.byteLength, 'application/octet-stream')
      })
    }
  })
  await t.exception(request(media), /media type/)

  const length = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const { response } = validResponse(init)
      return new Response(response, {
        status: 200,
        headers: responseHeaders(response.byteLength + 1)
      })
    }
  })
  await t.exception(request(length), /content-length/)

  const oversized = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const { response } = validResponse(init, b4a.alloc(100, 1))
      return new Response(response, { status: 200, headers: responseHeaders(response.byteLength) })
    }
  })
  await t.exception(request(oversized), /result bound|response body length|expected body length|protocol/i)

  const wrongOuterClass = new BlindDirectHttpClient({
    runtime,
    fetch: async (_url, init) => {
      const { response, request } = validResponse(init)
      const wrong = b4a.from(response)
      wrong[1] = request.outerClass + 1
      return new Response(wrong, { status: 200, headers: responseHeaders(wrong.byteLength) })
    }
  })
  await t.exception(request(wrongOuterClass), /response envelope|outer class/)
})

test('bound wrapper aborts a stalled response at its exact deadline', async t => {
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
  await t.exception(request(stalled, { timeoutMillis: 10 }))
  t.ok(cancelled)
})

test('bound wrapper rejects transfer transforms, raw endpoints and operation substitution', async t => {
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
  await t.exception(request(transformed), /forbidden/)

  const noDial = new BlindDirectHttpClient({
    runtime,
    fetch: async () => { throw new Error('must not dial') }
  })
  await t.exception(noDial.request({
    endpoint: rawEndpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    expectedResultBodyBytes: 1,
    body: b4a.from([1])
  }), /VerifiedEndpoint/)
  await t.exception(request(noDial, { operationId: OPERATION.CELL.PUT }), /exact direct operation/)
})
