import test from 'brittle'
import { Readable } from 'stream'
import {
  buildGatewaySeedErrorResponse,
  readGatewaySeedBody,
  validateGatewaySeedKey
} from 'p2p-hiverelay/gateway/server.js'

function reqFor (body, headers = {}) {
  const req = Readable.from(body === null || body === undefined ? [] : [body])
  req.method = 'POST'
  req.headers = {
    'content-type': 'application/json',
    ...(body === null || body === undefined ? {} : { 'content-length': String(Buffer.byteLength(body)) }),
    ...headers
  }
  return req
}

async function rejects (t, promise, pattern, statusCode) {
  let err = null
  try {
    await promise
  } catch (e) {
    err = e
  }
  t.ok(err, 'expected rejection')
  t.ok(pattern.test(err.message), `message matches ${pattern}`)
  if (statusCode !== undefined) t.is(err.statusCode, statusCode)
  return err
}

test('standalone gateway seed body validates 64-hex keys', async (t) => {
  const key = 'A'.repeat(64)
  const body = await readGatewaySeedBody(reqFor(JSON.stringify({ key })))

  t.alike(body, { key: key.toLowerCase() })
  t.is(validateGatewaySeedKey(key), key.toLowerCase())
  t.exception(() => validateGatewaySeedKey('a'.repeat(63)), /64 hex/)
  t.exception(() => validateGatewaySeedKey('z'.repeat(64)), /64 hex/)
})

test('standalone gateway seed body rejects non-json media types before parsing', async (t) => {
  const err = await rejects(t, readGatewaySeedBody(reqFor('key=' + 'a'.repeat(64), {
    'content-type': 'application/x-www-form-urlencoded'
  })), /Content-Type must be application\/json/, 400)
  t.is(err.close, true, 'body-bearing media-type rejection should close')
})

test('standalone gateway seed body rejects oversized and non-object JSON bodies', async (t) => {
  await rejects(t, readGatewaySeedBody(reqFor(JSON.stringify({
    key: 'a'.repeat(64),
    pad: 'x'.repeat(4096)
  }))), /Request body too large/, 413)

  await rejects(t, readGatewaySeedBody(reqFor(JSON.stringify(['a'.repeat(64)]))), /JSON body must be an object/, 400)
  await rejects(t, readGatewaySeedBody(reqFor(JSON.stringify({ key: 'not-a-key' }))), /64 hex/, 400)
})

test('standalone gateway seed errors redact unexpected internals', async (t) => {
  const validation = await rejects(t, readGatewaySeedBody(reqFor('key=' + 'a'.repeat(64), {
    'content-type': 'application/x-www-form-urlencoded'
  })), /Content-Type must be application\/json/, 400)

  const exposed = buildGatewaySeedErrorResponse(validation)
  t.is(exposed.status, 400, 'validation status is preserved')
  t.alike(exposed.payload, { error: 'Content-Type must be application/json' })
  t.is(exposed.close, true, 'body-bearing media-type rejection keeps close signal')

  const internal = new Error('failed opening /private/data with HIVERELAY_API_KEY=secret')
  internal.statusCode = 503
  const redacted = buildGatewaySeedErrorResponse(internal)
  t.is(redacted.status, 500, 'unexpected internal status is collapsed')
  t.alike(redacted.payload, { error: 'Gateway seed failed' }, 'public error is generic')
  t.is(redacted.close, false, 'unexpected internal errors do not force close by default')
})
