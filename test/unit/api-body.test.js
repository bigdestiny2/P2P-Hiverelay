import test from 'brittle'
import { PassThrough } from 'stream'
import { readJsonBody } from 'p2p-hiverelay/core/relay-node/api-body.js'

function bodyStream (body) {
  const stream = new PassThrough()
  stream.end(body)
  return stream
}

test('api body: parses JSON objects and empty bodies', async (t) => {
  t.alike(await readJsonBody(bodyStream('{"ok":true,"count":2}')), { ok: true, count: 2 })
  t.alike(await readJsonBody(bodyStream('')), {})
})

test('api body: rejects malformed JSON with stable error message', async (t) => {
  try {
    await readJsonBody(bodyStream('{"ok":'))
    t.fail('malformed body should reject')
  } catch (err) {
    t.is(err.message, 'Invalid JSON body')
  }
})

test('api body: rejects top-level arrays and primitives with stable error message', async (t) => {
  for (const body of ['[]', 'null', '"string"', '42', 'true']) {
    try {
      await readJsonBody(bodyStream(body))
      t.fail(`${body} should reject`)
    } catch (err) {
      t.is(err.message, 'JSON body must be an object')
    }
  }
})

test('api body: rejects oversized bodies while draining the stream', async (t) => {
  const stream = new PassThrough()
  const originalResume = stream.resume
  let resumed = false
  stream.resume = function resume () {
    resumed = true
    return originalResume.call(this)
  }

  const result = readJsonBody(stream, 4).catch(err => err)
  stream.write(Buffer.from('{"tooLarge":true}'))
  const err = await result
  stream.end()

  t.is(err.message, 'Request body too large')
  t.ok(resumed, 'oversized body is drained instead of destroying the socket')
})

test('api body: forwards stream errors once', async (t) => {
  const stream = new PassThrough()
  const boom = new Error('socket read failed')
  const result = readJsonBody(stream).catch(err => err)
  stream.emit('error', boom)
  stream.end('{"ignored":true}')

  t.is(await result, boom)
})
