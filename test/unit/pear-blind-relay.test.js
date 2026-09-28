import test from 'brittle'
import b4a from 'b4a'
import { EventEmitter } from 'events'
import { duplexPair } from 'stream'
import { createRequire } from 'module'
import { readFileSync } from 'fs'
import { createHash } from 'crypto'
import blindRelay from 'blind-relay'
import { PearBlindRelayTransport, PEAR_BLIND_RELAY_DEFAULTS } from '../../packages/core/transports/pear-blind-relay/index.js'

const require = createRequire(import.meta.url)
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
async function until (predicate, label = 'condition') {
  const end = Date.now() + 2000
  while (!predicate()) {
    if (Date.now() > end) throw new Error(`Timed out: ${label}`)
    await delay(5)
  }
}
const token = n => { const b = b4a.alloc(32); b.writeUInt32LE(n); return b }

class RawStream extends EventEmitter {
  constructor (id, opts) { super(); this.id = id; this.opts = opts; this.destroyed = false; this.closed = false }
  relayTo (other) { this.remote = other; return this }
  destroy () {
    if (this.destroyed) return
    this.destroyed = true
    queueMicrotask(() => { this.closed = true; this.emit('close') })
  }
}

async function fixture (t, opts = {}, hooks = {}) {
  const raw = []
  const peers = []
  let connection
  let listeners = 0
  const dht = {
    createRawStream (streamOpts) {
      if (hooks.failRawAt === raw.length) throw new Error('injected raw stream failure')
      const stream = new RawStream(raw.length + 1, streamOpts)
      raw.push(stream)
      return stream
    },
    createServer (accept) {
      connection = accept
      listeners++
      return {
        publicKey: b4a.alloc(32, 3),
        async listen () { await hooks.listen?.() },
        async close () { await hooks.close?.() }
      }
    }
  }
  const transport = new PearBlindRelayTransport({
    dht,
    keyPair: { publicKey: b4a.alloc(32, 3), secretKey: b4a.alloc(64, 4) },
    ...opts
  })
  t.teardown(async () => {
    for (const { client, clientSocket, serverSocket } of peers) {
      client?.destroy()
      clientSocket.destroy()
      serverSocket.destroy()
    }
    for (const stream of raw) stream.destroy()
    await transport.stop()
  })
  async function connect (open = true) {
    const [serverSocket, clientSocket] = duplexPair()
    serverSocket.remotePublicKey = b4a.alloc(32, peers.length + 7)
    serverSocket.setKeepAlive = ms => { serverSocket.keepAlive = ms }
    for (const socket of [serverSocket, clientSocket]) socket.on('error', () => {})
    const peer = { serverSocket, clientSocket, client: null }
    peers.push(peer)
    connection(serverSocket)
    if (!open) return peer
    peer.client = new blindRelay.Client(clientSocket, { id: serverSocket.remotePublicKey })
    peer.client.on('error', () => {})
    await new Promise((resolve, reject) => {
      peer.client.once('open', resolve)
      peer.client.once('error', reject)
    })
    return peer
  }
  await transport.start()
  return { transport, raw, peers, connect, listeners: () => listeners }
}

function pair (peer, n, initiator = true) {
  const request = peer.client.pair(initiator, token(n), { id: n + 1 })
  request.on('error', () => {})
  request.resume()
  return request
}

// The adapter reaches into the exact pinned library for admission BEFORE its
// raw allocation. Any dependency drift requires a fresh semantic audit.
test('Pear relay private admission adapter binds the reviewed dependency source', t => {
  for (const [name, version, digest] of [
    ['blind-relay', '1.6.1', '3ec1ffbe6599f12cef96c5100785ae699e4c67d33a3dc9ed33a90d7418d6a863'],
    ['protomux', '3.12.1', '320abfe32f73e8389b9a5e7e8d15741ff1ff132d58b705e67a8c5e2b9b796fc2']
  ]) {
    t.is(require(`${name}/package.json`).version, version)
    t.is(createHash('sha256').update(readFileSync(require.resolve(name))).digest('hex'), digest)
  }
})

test('Pear relay real-library sessions preserve framed streams, identity and counters', async t => {
  const f = await fixture(t, { maxSessions: 2, keepAliveMs: 1234 })
  const key = f.transport.getStats().publicKey
  const a = await f.connect(); const b = await f.connect()
  pair(a, 1); pair(b, 1, false)
  await until(() => f.transport.getStats().pairings.matched === 1)
  t.is(key.length, 52)
  t.is(a.serverSocket.keepAlive, 1234)
  t.is(f.raw.length, 2)
  t.ok(f.raw.every(stream => stream.opts.framed === true))
  t.is(f.transport.getStats().streams.active, 2)
  await f.transport.stop()
  t.is(f.transport.getStats().sockets.active, 0)
  t.is(f.transport.getStats().streams.active, 0)
  t.is(f.transport.getStats().pairings.pending, 0)
  t.is(f.transport.getStats().sessions.accepted, 2, 'counters survive stop')
  await f.transport.start()
  t.is(f.transport.getStats().publicKey, key, 'same stable identity on restart')
})

test('Pear relay bounds pending tokens before allocating a thousand requests', async t => {
  const f = await fixture(t, { maxPendingPerSession: 4 })
  let high = 0
  const a = await f.connect()
  const receive = f.transport._pair.bind(f.transport)
  f.transport._pair = (...args) => { receive(...args); high = Math.max(high, f.transport.relay.stats.pairings.pending) }
  for (let i = 0; i < 1000; i++) pair(a, i)
  await until(() => a.serverSocket.destroyed)
  t.ok(high <= 4, 'pre-allocation ceiling applies inside same decoded batch')
  t.is(f.raw.length, 0)
  t.is(f.transport.getStats().pairings.refused, 1)
  t.is(f.transport.getStats().pairings.pending, 0)
})

test('Pear relay enforces global pending budget across clients', async t => {
  const f = await fixture(t, { maxPendingPairings: 2, maxPendingPerSession: 4 })
  const a = await f.connect(); const b = await f.connect()
  pair(a, 1); pair(a, 2)
  await until(() => f.transport.getStats().pairings.pending === 2)
  pair(b, 3)
  await until(() => b.serverSocket.destroyed)
  t.is(f.transport.getStats().pairings.pending, 2)
  t.absent(a.serverSocket.destroyed)
})

for (const limits of [{ maxActiveLinks: 2 }, { maxActiveLinksPerSession: 1 }]) {
  test(`Pear relay enforces ${Object.keys(limits)[0]} before raw stream allocation`, async t => {
    const f = await fixture(t, limits)
    const a = await f.connect(); const b = await f.connect()
    pair(a, 1); pair(b, 1, false)
    await until(() => f.raw.length === 2)
    pair(a, 2); pair(b, 2, false)
    await until(() => b.serverSocket.destroyed)
    t.is(f.raw.length, 2, 'no over-budget raw streams ever created')
    await until(() => f.transport.getStats().streams.active === 0)
    t.is(f.transport.getStats().pairings.active, 0)
  })
}

test('Pear relay rejects same-session pairing and active-token overwrite', async t => {
  const f = await fixture(t)
  const a = await f.connect()
  a.client._pair.send({ token: token(1), isInitiator: true, id: 1, seq: 0 })
  a.client._pair.send({ token: token(1), isInitiator: false, id: 2, seq: 0 })
  await until(() => a.serverSocket.destroyed)
  t.is(f.raw.length, 0)
  const b = await f.connect(); const c = await f.connect()
  pair(b, 2); pair(c, 2, false)
  await until(() => f.raw.length === 2)
  b.client._pair.send({ token: token(2), isInitiator: true, id: 4, seq: 0 })
  await until(() => b.serverSocket.destroyed)
  t.is(f.raw.length, 2)
  await until(() => f.transport.getStats().streams.active === 0)
})

test('Pear relay expires unmatched requests and idle channels', async t => {
  const f = await fixture(t, { pairingTimeoutMs: 30, idleTimeoutMs: 80 })
  const a = await f.connect(); const b = await f.connect()
  pair(a, 1)
  await until(() => a.serverSocket.destroyed)
  t.is(f.transport.getStats().expired.pending, 1)
  t.is(f.transport.getStats().pairings.pending, 0)
  await until(() => b.serverSocket.destroyed)
  t.is(f.transport.getStats().expired.idle, 1)
})

test('Pear relay expires active raw links and tears down their counterpart', async t => {
  const f = await fixture(t, { maxLinkLifetimeMs: 30 })
  const a = await f.connect(); const b = await f.connect()
  pair(a, 1); pair(b, 1, false)
  await until(() => f.raw.length === 2)
  await until(() => f.transport.getStats().streams.active === 0)
  t.ok(f.transport.getStats().expired.links >= 1)
  t.is(f.transport.getStats().pairings.active, 0)
  t.ok(f.raw.every(stream => stream.destroyed))
})

test('Pear relay protocol close destroys owned sockets and both raw links', async t => {
  const f = await fixture(t, { maxSessions: 2 })
  const a = await f.connect(); const b = await f.connect()
  const refused = await f.connect(false)
  t.ok(refused.serverSocket.destroyed)
  pair(a, 1); pair(b, 1, false)
  await until(() => f.raw.length === 2)
  a.client.destroy()
  await until(() => a.serverSocket.destroyed && f.transport.getStats().streams.active === 0)
  t.is(f.transport.getStats().sessions.refused, 1)
  t.is(f.transport.getStats().sockets.active, 1)
  const c = await f.connect()
  t.absent(c.serverSocket.destroyed)
})

test('Pear relay raw allocation failure cleans up the first stream and both sessions', async t => {
  const f = await fixture(t, {}, { failRawAt: 1 })
  const a = await f.connect(); const b = await f.connect()
  pair(a, 1); pair(b, 1, false)
  await until(() => a.serverSocket.destroyed && b.serverSocket.destroyed)
  await until(() => f.transport.getStats().streams.active === 0)
  t.is(f.raw.length, 1)
  t.is(f.transport.getStats().pairings.pending, 0)
})

test('Pear relay concurrent stop drains pending work and preserves completion ownership', async t => {
  const f = await fixture(t)
  const a = await f.connect()
  pair(a, 1)
  await until(() => f.transport.getStats().pairings.pending === 1)
  const stopping = f.transport.stop()
  t.is(f.transport.stop(), stopping)
  await stopping
  t.ok(a.serverSocket.destroyed)
  t.is(f.transport.getStats().sessions.active, 0)
  t.is(f.transport.getStats().pairings.pending, 0)
  t.is(f.transport.getStats().sockets.active, 0)
})

test('Pear relay stop timeout retains listener ownership for cleanup retry', async t => {
  let closeResolve
  let block = true
  const f = await fixture(t, { stopTimeoutMs: 30 }, { close: () => block ? new Promise(resolve => { closeResolve = resolve }) : undefined })
  await t.exception(f.transport.stop(), /shutdown deadline/)
  t.ok(f.transport.server, 'failed close is retained, not reported complete')
  await t.exception(f.transport.start(), /cleanup incomplete/)
  block = false
  closeResolve()
  await f.transport.stop()
  t.absent(f.transport.server)
})

test('Pear relay finite operator limits fail closed', async t => {
  for (const name of Object.keys(PEAR_BLIND_RELAY_DEFAULTS)) {
    await t.exception.all(() => new PearBlindRelayTransport({ dht: {}, keyPair: { publicKey: 1, secretKey: 1 }, [name]: 0 }), new RegExp(name))
  }
  await t.exception.all(() => new PearBlindRelayTransport({}), /dht is required/)
})

test('Pear relay coalesces starts and a stop during listen cannot become running', async t => {
  const f = await fixture(t)
  await f.transport.stop()
  let release
  const barrier = new Promise(resolve => { release = resolve })
  const createServer = f.transport.dht.createServer
  f.transport.dht.createServer = accept => {
    const server = createServer(accept)
    server.listen = () => barrier
    return server
  }
  const starting = f.transport.start()
  t.is(f.transport.start(), starting)
  const stopping = f.transport.stop()
  t.is(f.transport.stop(), stopping)
  release()
  await Promise.all([starting, stopping])
  t.absent(f.transport.running)
  t.absent(f.transport.server)
  t.is(f.listeners(), 2, 'one initial listener and one coalesced restart')
})

test('Pear relay cancellation releases token expiry before reuse', async t => {
  const f = await fixture(t, { pairingTimeoutMs: 80 })
  const a = await f.connect(); const b = await f.connect()
  pair(a, 1)
  await until(() => f.transport.getStats().pairings.pending === 1)
  await delay(30)
  a.client.unpair(token(1))
  await until(() => f.transport.getStats().pairings.pending === 0)
  pair(b, 1)
  await until(() => f.transport.getStats().pairings.pending === 1)
  await delay(55)
  t.absent(b.serverSocket.destroyed, 'original owner timer cannot close the successor')
  await until(() => b.serverSocket.destroyed)
  t.is(f.transport.getStats().expired.pending, 1)
})

test('Pear relay shutdown deadline also bounds a pending listen', async t => {
  const f = await fixture(t, { stopTimeoutMs: 30 })
  await f.transport.stop()
  let release
  const createServer = f.transport.dht.createServer
  f.transport.dht.createServer = accept => {
    const server = createServer(accept)
    server.listen = () => new Promise(resolve => { release = resolve })
    return server
  }
  const starting = f.transport.start()
  await t.exception(f.transport.stop(), /shutdown deadline/)
  t.ok(f.transport.getStats().stopping)
  release()
  await starting
  t.absent(f.transport.running, 'late listen cannot advertise a stopped generation')
  await f.transport.stop()
  t.absent(f.transport.server)
  t.absent(f.transport.getStats().stopping)
})
