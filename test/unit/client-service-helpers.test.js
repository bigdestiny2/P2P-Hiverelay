/**
 * Client service helpers — assert each method builds the correct HTTP
 * request against a mock fetch (URL, method, headers). No live relay.
 */
import test from 'brittle'
import { HiveRelayClient } from '../../packages/client/index.js'

function mockFetch (calls) {
  return async (url, opts = {}) => {
    calls.push({ url: String(url), method: (opts.method || 'GET').toUpperCase(), headers: opts.headers || {}, body: opts.body })
    // Return a shape that satisfies both JSON and binary consumers.
    const jsonBody = JSON.stringify({ ok: true, url: String(url), method: opts.method || 'GET' })
    return {
      ok: true,
      status: 200,
      async text () { return jsonBody },
      async json () { return JSON.parse(jsonBody) },
      async arrayBuffer () { return new TextEncoder().encode('shard-bytes').buffer }
    }
  }
}

test('client helpers: notifySend POSTs to /api/v1/notify/send', async (t) => {
  const calls = []
  const prev = globalThis.fetch
  globalThis.fetch = mockFetch(calls)
  t.teardown(() => { globalThis.fetch = prev })

  const client = new HiveRelayClient({ storage: null })
  const body = { intentId: 'a'.repeat(64), signature: 'sig' }
  const out = await client.notifySend('http://relay.example:9100', body)

  t.is(calls.length, 1)
  t.is(calls[0].method, 'POST')
  t.is(calls[0].url, 'http://relay.example:9100/api/v1/notify/send')
  t.ok(String(calls[0].headers['Content-Type'] || '').includes('json'))
  t.ok(String(calls[0].body).includes('intentId'))
  t.ok(out && out.ok)
})

test('client helpers: notifyWatch POSTs to /api/v1/notify/watch', async (t) => {
  const calls = []
  const prev = globalThis.fetch
  globalThis.fetch = mockFetch(calls)
  t.teardown(() => { globalThis.fetch = prev })

  const client = new HiveRelayClient({ storage: null })
  await client.notifyWatch('https://r.example', { watchId: 'w'.repeat(64) })

  t.is(calls[0].method, 'POST')
  t.is(calls[0].url, 'https://r.example/api/v1/notify/watch')
})

test('client helpers: shardPut POSTs octet-stream to /api/v1/shard with pin header', async (t) => {
  const calls = []
  const prev = globalThis.fetch
  globalThis.fetch = mockFetch(calls)
  t.teardown(() => { globalThis.fetch = prev })

  const client = new HiveRelayClient({ storage: null })
  const pin = { hash: 'ab'.repeat(32), shareIndex: 0, signature: 's' }
  await client.shardPut('http://relay.test', new Uint8Array([1, 2, 3]), pin)

  t.is(calls[0].method, 'POST')
  t.is(calls[0].url, 'http://relay.test/api/v1/shard')
  t.is(calls[0].headers['Content-Type'], 'application/octet-stream')
  t.ok(calls[0].headers['X-Shard-Pin'].includes('shareIndex'))
})

test('client helpers: shardGet GETs /api/v1/shard/<hash>', async (t) => {
  const calls = []
  const prev = globalThis.fetch
  globalThis.fetch = mockFetch(calls)
  t.teardown(() => { globalThis.fetch = prev })

  const client = new HiveRelayClient({ storage: null })
  const hash = 'cd'.repeat(32)
  const bytes = await client.shardGet('http://relay.test/', 'shard:' + hash)

  t.is(calls[0].method, 'GET')
  t.is(calls[0].url, 'http://relay.test/api/v1/shard/' + hash)
  t.ok(bytes instanceof Uint8Array)
})

test('client helpers: witnessAdd POSTs to /api/witness/append', async (t) => {
  const calls = []
  const prev = globalThis.fetch
  globalThis.fetch = mockFetch(calls)
  t.teardown(() => { globalThis.fetch = prev })

  const client = new HiveRelayClient({ storage: null })
  const record = { id: 'x'.repeat(64), target: 'y'.repeat(64) }
  await client.witnessAdd('http://relay.test', record)

  t.is(calls[0].method, 'POST')
  t.is(calls[0].url, 'http://relay.test/api/witness/append')
  t.ok(String(calls[0].body).includes('"record"'))
})

test('client helpers: vrfBeaconLatest GETs /api/v1/vrf/beacon-latest', async (t) => {
  const calls = []
  const prev = globalThis.fetch
  globalThis.fetch = mockFetch(calls)
  t.teardown(() => { globalThis.fetch = prev })

  const client = new HiveRelayClient({ storage: null })
  await client.vrfBeaconLatest('http://relay.test')

  t.is(calls[0].method, 'GET')
  t.is(calls[0].url, 'http://relay.test/api/v1/vrf/beacon-latest')
})
