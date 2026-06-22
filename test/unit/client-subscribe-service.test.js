import test from 'brittle'
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { EventEmitter } from 'events'
import { randomBytes } from 'crypto'

// subscribeService — the streaming counterpart to callService. Sends
// MSG_SUBSCRIBE (type 4) for the first local listener on a (relay, topic),
// routes incoming MSG_EVENT (type 6) to onEvent, and MSG_UNSUBSCRIBE (type 5)
// when the last listener detaches. Mirrors the server's topic-based pubsub.

function mockSwarm () {
  const s = new EventEmitter()
  s.keyPair = { publicKey: Buffer.alloc(32, 0xaa), secretKey: null }
  s.connections = new Set(); s.join = () => ({ destroy: () => {} })
  s.leave = async () => {}; s.flush = async () => {}; s.destroy = async () => {}
  return s
}
const mockStore = () => ({ close: async () => {}, get: () => ({ key: Buffer.alloc(32), ready: async () => {} }) })
function makeClient () {
  const c = new HiveRelayClient({ swarm: mockSwarm(), store: mockStore() })
  c._started = true
  return c
}
function fakeServiceChannel () {
  const sent = []
  return { channel: { close: () => {} }, msg: { send: (m) => sent.push(m) }, _sent: sent }
}
function withRelay (client) {
  const pubkey = randomBytes(32).toString('hex')
  const svc = fakeServiceChannel()
  client.relays.set(pubkey, { conn: {}, channels: { seed: {}, circuit: {}, service: svc }, connectedAt: Date.now(), lastSeen: Date.now() })
  client._relayScores.set(pubkey, { successes: 1, failures: 0, latency: 10, connectedSince: Date.now() })
  return { pubkey, svc }
}

test('subscribeService sends MSG_SUBSCRIBE for the topic <service>/<event>', (t) => {
  const client = makeClient()
  const { pubkey, svc } = withRelay(client)
  client.subscribeService('arbitration', 'resolved', () => {}, { relay: pubkey })
  t.is(svc._sent.length, 1)
  t.is(svc._sent[0].type, 4, 'MSG_SUBSCRIBE')
  t.alike(svc._sent[0].topics, ['arbitration/resolved'])
})

test('MSG_EVENT is routed to the matching subscriber only', (t) => {
  const client = makeClient()
  const { pubkey } = withRelay(client)
  const got = []
  client.subscribeService('sla', 'created', (data, topic) => got.push([topic, data]), { relay: pubkey })

  client._onServiceMessage(pubkey, { type: 6, topic: 'sla/created', data: { id: 7 } })
  client._onServiceMessage(pubkey, { type: 6, topic: 'sla/expired', data: { id: 9 } }) // not subscribed
  t.is(got.length, 1, 'only the subscribed topic fires')
  t.alike(got[0], ['sla/created', { id: 7 }])
})

test('second listener on same topic does NOT resend MSG_SUBSCRIBE; both receive', (t) => {
  const client = makeClient()
  const { pubkey, svc } = withRelay(client)
  let a = 0; let b = 0
  client.subscribeService('arbitration', 'resolved', () => a++, { relay: pubkey })
  client.subscribeService('arbitration', 'resolved', () => b++, { relay: pubkey })
  t.is(svc._sent.filter(m => m.type === 4).length, 1, 'deduped to one MSG_SUBSCRIBE')
  client._onServiceMessage(pubkey, { type: 6, topic: 'arbitration/resolved', data: {} })
  t.is(a, 1); t.is(b, 1)
})

test('unsubscribe removes the listener; MSG_UNSUBSCRIBE sent only when last detaches', (t) => {
  const client = makeClient()
  const { pubkey, svc } = withRelay(client)
  let hits = 0
  const off1 = client.subscribeService('events', 'tick', () => hits++, { relay: pubkey })
  const off2 = client.subscribeService('events', 'tick', () => hits++, { relay: pubkey })

  off1()
  t.is(svc._sent.filter(m => m.type === 5).length, 0, 'no unsubscribe while a listener remains')
  client._onServiceMessage(pubkey, { type: 6, topic: 'events/tick', data: {} })
  t.is(hits, 1, 'only the remaining listener fires')

  off2()
  const unsub = svc._sent.filter(m => m.type === 5)
  t.is(unsub.length, 1, 'MSG_UNSUBSCRIBE on last detach')
  t.alike(unsub[0].topics, ['events/tick'])
  hits = 0
  client._onServiceMessage(pubkey, { type: 6, topic: 'events/tick', data: {} })
  t.is(hits, 0, 'no delivery after full unsubscribe')
})

test('a throwing subscriber does not break the message loop', (t) => {
  const client = makeClient()
  const { pubkey } = withRelay(client)
  let good = 0
  client.subscribeService('x', 'y', () => { throw new Error('boom') }, { relay: pubkey })
  client.subscribeService('x', 'y', () => good++, { relay: pubkey })
  client._onServiceMessage(pubkey, { type: 6, topic: 'x/y', data: {} }) // must not throw
  t.is(good, 1, 'the well-behaved subscriber still fires')
})

test('channel close drops the relay subscriptions', (t) => {
  const client = makeClient()
  const { pubkey } = withRelay(client)
  let hits = 0
  client.subscribeService('a', 'b', () => hits++, { relay: pubkey })
  client._dropRelaySubscriptions(pubkey)
  client._onServiceMessage(pubkey, { type: 6, topic: 'a/b', data: {} })
  t.is(hits, 0, 'no delivery after the channel closed')
})

test('validation: NO_RELAY, NO_SERVICE_CHANNEL, non-function onEvent', (t) => {
  const client = makeClient()
  t.exception(() => client.subscribeService('a', 'b', () => {}), /NO_RELAY/)
  const pubkey = randomBytes(32).toString('hex')
  client.relays.set(pubkey, { conn: {}, channels: { seed: {} }, connectedAt: Date.now(), lastSeen: Date.now() })
  t.exception(() => client.subscribeService('a', 'b', () => {}, { relay: pubkey }), /NO_SERVICE_CHANNEL/)
  const r2 = withRelay(client)
  t.exception(() => client.subscribeService('a', 'b', 'not-a-fn', { relay: r2.pubkey }), /must be a function/)
})
