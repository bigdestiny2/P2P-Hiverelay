import test from 'brittle'
import b4a from 'b4a'
import { EventEmitter } from 'events'
import { PearBlindRelayTransport } from 'p2p-hiverelay/transports/pear-blind-relay/index.js'

class FakeSession extends EventEmitter {}

class FakeRelayServer {
  constructor ({ createStream }) {
    this.createStream = createStream
    this.accepted = []
    this.closed = false
    this.stats = {
      sessions: { accepted: 0, opened: 0, closed: 0, active: 0 },
      pairings: { requested: 0, matched: 0, cancelled: 0, pending: 0, active: 0 },
      streams: { opened: 0, closed: 0, errors: 0, active: 0 }
    }
  }

  accept (socket, opts) {
    const session = new FakeSession()
    this.accepted.push({ socket, opts, session })
    this.stats.sessions.accepted++
    this.stats.sessions.active++
    session.once('close', () => {
      this.stats.sessions.active--
      this.stats.sessions.closed++
    })
    return session
  }

  async close () { this.closed = true }
}

class FakeSocket extends EventEmitter {
  constructor (remotePublicKey = b4a.alloc(32, 7)) {
    super()
    this.remotePublicKey = remotePublicKey
    this.keepAliveMs = null
    this.destroyed = false
  }

  setKeepAlive (ms) { this.keepAliveMs = ms }
  destroy () { this.destroyed = true }
}

function fixture (opts = {}) {
  const rawStreams = []
  const dht = {
    createRawStream (rawOpts) {
      rawStreams.push(rawOpts)
      return { rawOpts }
    },
    createServer (onconnection) {
      return {
        publicKey: b4a.alloc(32, 3),
        onconnection,
        listenedWith: null,
        closed: false,
        async listen (keyPair) { this.listenedWith = keyPair },
        async close () { this.closed = true }
      }
    }
  }
  const keyPair = { publicKey: b4a.alloc(32, 3), secretKey: b4a.alloc(64, 4) }
  const transport = new PearBlindRelayTransport({
    dht,
    keyPair,
    RelayServer: FakeRelayServer,
    ...opts
  })
  return { transport, dht, keyPair, rawStreams }
}

test('Pear blind relay uses the v3.4 framed UDX contract and reports a z32 key', async (t) => {
  const { transport, keyPair, rawStreams } = fixture({ maxSessions: 2, keepAliveMs: 1234 })
  await transport.start()

  t.ok(transport.running)
  t.is(transport.server.listenedWith, keyPair)
  const stream = transport.relay.createStream({ firewall: 'allow' })
  t.alike(rawStreams, [{ firewall: 'allow', framed: true }])
  t.is(stream.rawOpts.framed, true)

  const socket = new FakeSocket()
  transport.server.onconnection(socket)
  t.is(socket.keepAliveMs, 1234)
  t.is(transport.relay.accepted[0].opts.id, socket.remotePublicKey)

  const stats = transport.getStats()
  t.is(stats.publicKey.length, 52)
  t.is(stats.maxSessions, 2)
  t.is(stats.sessions.accepted, 1)
  t.is(stats.sessions.refused, 0)

  await transport.stop()
  t.absent(transport.running)
})

test('Pear blind relay refuses sessions beyond its independent ceiling', async (t) => {
  const { transport } = fixture({ maxSessions: 1 })
  await transport.start()

  const first = new FakeSocket()
  const second = new FakeSocket()
  transport.server.onconnection(first)
  transport.server.onconnection(second)

  t.absent(first.destroyed)
  t.ok(second.destroyed)
  t.is(transport.getStats().sessions.refused, 1)

  transport.relay.accepted[0].session.emit('close')
  const third = new FakeSocket()
  transport.server.onconnection(third)
  t.absent(third.destroyed)
  t.is(transport.getStats().sessions.accepted, 2)

  await transport.stop()
})

test('Pear blind relay validates finite operator limits', async (t) => {
  await t.exception.all(() => fixture({ maxSessions: 0 }), /maxSessions/)
  await t.exception.all(() => fixture({ keepAliveMs: 0 }), /keepAliveMs/)
  await t.exception.all(() => new PearBlindRelayTransport({}), /dht is required/)
})
