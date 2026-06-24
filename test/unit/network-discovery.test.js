import test from 'brittle'
import http from 'http'
import { NetworkDiscovery } from 'p2p-hiverelay/core/network-discovery.js'

const MAX_API_OVERVIEW_BYTES = 256 * 1024
const MAX_META_BYTES = 2048
const VALID_HOLESAIL_KEY = 'y'.repeat(52)

function listen (server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
}

function closeServer (server) {
  return new Promise(resolve => server.close(resolve))
}

async function rejects (t, promise, pattern) {
  let err = null
  try {
    await promise
  } catch (e) {
    err = e
  }
  t.ok(err, 'expected rejection')
  t.ok(pattern.test(err.message), `message matches ${pattern}`)
  return err
}

test('network discovery fetches bounded API overview JSON', async (t) => {
  const payload = {
    publicKey: 'a'.repeat(64),
    connections: 2,
    seededApps: 3
  }
  const server = http.createServer((req, res) => {
    t.is(req.url, '/api/overview')
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify(payload))
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  const data = await discovery._fetchApi('127.0.0.1', server.address().port)
  t.alike(data, payload)
})

test('network discovery rejects oversized API overview content-length', async (t) => {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.setHeader('Content-Length', String(MAX_API_OVERVIEW_BYTES + 1))
    res.end('{}')
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  await rejects(t, discovery._fetchApi('127.0.0.1', server.address().port), /Response too large/)
})

test('network discovery rejects oversized streamed API overview bodies', async (t) => {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ pad: 'x'.repeat(MAX_API_OVERVIEW_BYTES) }))
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  await rejects(t, discovery._fetchApi('127.0.0.1', server.address().port), /Response too large/)
})

test('network discovery rejects non-object API overview JSON', async (t) => {
  const server = http.createServer((_req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end('[]')
  })
  await listen(server)
  t.teardown(() => closeServer(server))

  const discovery = new NetworkDiscovery()
  await rejects(t, discovery._fetchApi('127.0.0.1', server.address().port), /Invalid JSON/)
})

test('network discovery accepts bounded z32 holesail metadata frames', (t) => {
  const pubkey = 'a'.repeat(64)
  const discovery = new NetworkDiscovery()
  const relay = { publicKey: pubkey }
  let event = null

  discovery._relays.set(pubkey, relay)
  discovery.on('relay-holesail-key', data => { event = data })

  discovery._handleMetadataFrame(
    pubkey,
    Buffer.from(JSON.stringify({ holesailKey: `hs://0000${VALID_HOLESAIL_KEY}` }))
  )

  t.is(relay.holesailKey, VALID_HOLESAIL_KEY)
  t.alike(event, { publicKey: pubkey, holesailKey: VALID_HOLESAIL_KEY })
})

test('network discovery ignores oversized holesail metadata frames', (t) => {
  const pubkey = 'b'.repeat(64)
  const discovery = new NetworkDiscovery()
  const relay = { publicKey: pubkey }
  let events = 0

  discovery._relays.set(pubkey, relay)
  discovery.on('relay-holesail-key', () => { events++ })

  discovery._handleMetadataFrame(pubkey, Buffer.alloc(MAX_META_BYTES + 1, 123))

  t.absent(relay.holesailKey)
  t.is(events, 0)
})

test('network discovery rejects malformed holesail metadata frames', (t) => {
  const pubkey = 'c'.repeat(64)
  const discovery = new NetworkDiscovery()
  const relay = { publicKey: pubkey }
  let events = 0

  discovery._relays.set(pubkey, relay)
  discovery.on('relay-holesail-key', () => { events++ })

  discovery._handleMetadataFrame(pubkey, Buffer.from('[]'))
  discovery._handleMetadataFrame(pubkey, Buffer.from('{'))
  discovery._handleMetadataFrame(pubkey, Buffer.from(JSON.stringify({ holesailKey: 'not-valid' })))

  t.absent(relay.holesailKey)
  t.is(events, 0)
})

test('network discovery rejects invalid holesail tunnel keys before connecting', async (t) => {
  const discovery = new NetworkDiscovery()

  await rejects(t, discovery._fetchViaHolesail('not-valid'), /Invalid holesail key/)
})
