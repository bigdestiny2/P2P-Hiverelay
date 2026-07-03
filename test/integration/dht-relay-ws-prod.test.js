/**
 * Prod-readiness (Phase 5 pure-pipe) integration tests for DHTRelayWS.
 *
 * Covers the content-neutral bounds added for 24/7 operation:
 *   - first-frame deadline (slot-squatter reaping — upstream's heartbeat
 *     failsafe never arms for a client that never speaks the protocol)
 *   - WS ping/pong keepalive (healthy clients stay connected)
 *   - byte accounting (frame-length totals in getStats)
 *   - per-connection ingress rate cap (optional, off by default)
 *   - maxPayload single-frame cap (ws parser enforced, 1009)
 *   - pending-reservation expiry (verifyClient slot leak fix)
 *
 * Same conventions as dht-relay-ws-load.test.js: raw ws clients that never
 * speak the framed dht-relay protocol, a stand-in DHT, tiny configured
 * windows so reaping is fast and deterministic.
 */

import test from 'brittle'
import { WebSocket } from 'ws'
import { DHTRelayWS } from 'p2p-hiverelay/transports/dht-relay-ws/index.js'

function pickPort () {
  return 50000 + Math.floor(Math.random() * 10000)
}

function fakeDHT () {
  return {}
}

function openClient (port) {
  const socket = new WebSocket(`ws://127.0.0.1:${port}`)
  const result = { socket, opened: false, closed: false, closeCode: null, closeReason: null, error: null }
  socket.on('open', () => { result.opened = true })
  socket.on('close', (code, reason) => {
    result.closed = true
    result.closeCode = code
    result.closeReason = reason ? reason.toString() : ''
  })
  socket.on('error', (err) => { result.error = err })
  return result
}

function until (predicate, timeoutMs = 5000, everyMs = 25) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs
    const tick = () => {
      if (predicate()) return resolve()
      if (Date.now() > deadline) return reject(new Error('until: timed out'))
      setTimeout(tick, everyMs)
    }
    tick()
  })
}

test('prod: connection that never sends a frame is reaped at the first-frame deadline', async (t) => {
  const port = pickPort()
  const relay = new DHTRelayWS({
    dht: fakeDHT(),
    port,
    keepalive: { intervalMs: 100, firstFrameTimeoutMs: 150 }
  })
  const reaped = []
  relay.on('connection-reaped', (e) => reaped.push(e))
  await relay.start()
  t.teardown(() => relay.stop())

  const client = openClient(port)
  await until(() => client.opened)
  t.is(relay.getStats().activeConnections, 1, 'client connected')

  // Never send anything: within a couple of supervisor sweeps the slot
  // squatter must be closed with the policy code.
  await until(() => client.closed, 3000)
  t.is(client.closeCode, 1008, 'closed with policy violation')
  t.is(client.closeReason, 'DHT_RELAY_NO_HANDSHAKE')
  t.is(reaped.length, 1, 'one reap event')
  t.is(reaped[0].reason, 'no-first-frame')
  t.ok(reaped[0].info && reaped[0].info.remoteAddressHash, 'reap event carries hashed address, not raw IP')
  t.is(relay.getStats().totalReaped, 1)
  t.is(relay.getStats().activeConnections, 0, 'slot released')
})

test('prod: frame-sending client survives many supervisor sweeps (ws auto-pong keeps it alive)', async (t) => {
  const port = pickPort()
  const relay = new DHTRelayWS({
    dht: fakeDHT(),
    port,
    keepalive: { intervalMs: 60, firstFrameTimeoutMs: 100 }
  })
  await relay.start()
  t.teardown(() => relay.stop())

  const client = openClient(port)
  await until(() => client.opened)
  // One early frame satisfies the first-frame deadline; ws clients answer
  // WS pings automatically (RFC 6455), so liveness sweeps keep passing.
  client.socket.send(Buffer.from('hello-frame'))

  await new Promise(resolve => setTimeout(resolve, 500)) // ~8 sweeps
  t.is(client.closed, false, 'client still connected after many sweeps')
  t.is(relay.getStats().totalReaped, 0, 'nothing reaped')
  t.ok(relay.getStats().totalBytesIn >= 11, 'ingress bytes accounted (length only)')
  client.socket.close()
})

test('prod: ingress rate cap closes a flooding connection (content untouched, lengths only)', async (t) => {
  const port = pickPort()
  const relay = new DHTRelayWS({
    dht: fakeDHT(),
    port,
    keepalive: { intervalMs: 5000 }, // supervisor idle — the cap fires inline
    flow: { maxRxBytesPerSec: 1024 }
  })
  const reaped = []
  relay.on('connection-reaped', (e) => reaped.push(e))
  await relay.start()
  t.teardown(() => relay.stop())

  const client = openClient(port)
  await until(() => client.opened)
  // A single 32 KiB frame blows the 1 KiB/s window on arrival.
  client.socket.send(Buffer.alloc(32 * 1024))

  await until(() => client.closed, 3000)
  t.is(client.closeCode, 1008)
  t.is(client.closeReason, 'DHT_RELAY_RX_RATE')
  t.is(reaped.length, 1)
  t.is(reaped[0].reason, 'rx-rate')
})

test('prod: maxPayload caps a single frame at the ws parser (1009 message too big)', async (t) => {
  const port = pickPort()
  const relay = new DHTRelayWS({
    dht: fakeDHT(),
    port,
    flow: { maxPayloadBytes: 1024 }
  })
  await relay.start()
  t.teardown(() => relay.stop())

  const client = openClient(port)
  await until(() => client.opened)
  client.socket.send(Buffer.alloc(4 * 1024)) // 4 KiB > 1 KiB cap

  await until(() => client.closed, 3000)
  t.is(client.closeCode, 1009, 'ws closes with message-too-big')
})

test('prod: aborted upgrades no longer leak concurrency slots (pending reservations expire)', async (t) => {
  const port = pickPort()
  const relay = new DHTRelayWS({
    dht: fakeDHT(),
    port,
    rateLimit: { maxConcurrentPerIp: 2, pendingTtlMs: 50 }
  })
  await relay.start()
  t.teardown(() => relay.stop())

  // Simulate two upgrades that pass verifyClient but never mature into a
  // 'connection' event (client aborted mid-upgrade). Before the fix these
  // slots leaked until restart and locked the IP out at max-concurrent.
  const ip = '203.0.113.9'
  t.is(relay._checkRateLimit(ip), null, 'first reservation accepted')
  t.is(relay._checkRateLimit(ip), null, 'second reservation accepted')
  t.is(relay._checkRateLimit(ip), 'max-concurrent', 'cap reached — a third upgrade is refused')

  // After pendingTtlMs the sweeper releases the orphaned reservations.
  await new Promise(resolve => setTimeout(resolve, 80))
  relay._cleanupStaleBuckets()
  t.is(relay._checkRateLimit(ip), null, 'slot available again after expiry — no leak')
})

test('prod: trustProxy keys rate limiting on X-Forwarded-For, not the shared proxy socket IP', async (t) => {
  const port = pickPort()
  // Behind a proxy every socket IP is the proxy's; without trustProxy the
  // limiter collapses to one bucket. With it, distinct XFF hops are distinct
  // clients. Drive _checkRateLimit through fake reqs to assert the keying.
  const relay = new DHTRelayWS({ dht: fakeDHT(), port, trustProxy: true, rateLimit: { maxConcurrentPerIp: 1 } })
  await relay.start()
  t.teardown(() => relay.stop())

  const proxyReq = (xff) => ({ headers: { 'x-forwarded-for': xff }, socket: { remoteAddress: '10.0.0.254' } })
  // clientIpFromRequest is what verifyClient calls; exercise the same path.
  const { clientIpFromRequest } = await import('p2p-hiverelay/core/relay-node/api-rate-limit.js')
  t.is(clientIpFromRequest(proxyReq('198.51.100.7, 10.0.0.254'), true), '198.51.100.7', 'first XFF hop is the client')

  // Two different real clients behind the same proxy get independent buckets.
  t.is(relay._checkRateLimit(clientIpFromRequest(proxyReq('198.51.100.7'), true)), null, 'client A allowed')
  t.is(relay._checkRateLimit(clientIpFromRequest(proxyReq('198.51.100.7'), true)), 'max-concurrent', 'client A capped')
  t.is(relay._checkRateLimit(clientIpFromRequest(proxyReq('198.51.100.8'), true)), null, 'client B has its own bucket — no proxy collapse')
})

test('prod: getStats exposes aggregate-only metering (bytes, reaps, bounds config)', async (t) => {
  const port = pickPort()
  const relay = new DHTRelayWS({ dht: fakeDHT(), port })
  await relay.start()
  t.teardown(() => relay.stop())

  const client = openClient(port)
  await until(() => client.opened)
  client.socket.send(Buffer.alloc(2048))
  await until(() => relay.getStats().totalBytesIn >= 2048, 3000)

  const stats = relay.getStats()
  t.ok(stats.totalBytesIn >= 2048, 'ingress total counted')
  t.is(typeof stats.totalBytesOut, 'number')
  t.is(typeof stats.totalReaped, 'number')
  t.is(stats.flow.maxPayloadBytes, 8 * 1024 * 1024, 'default frame cap surfaced')
  t.is(stats.keepalive.intervalMs, 30_000, 'default keepalive surfaced')
  // The neutrality contract: aggregates only — nothing per-IP, no raw
  // addresses anywhere in the stats surface.
  t.absent(JSON.stringify(stats).includes('127.0.0.1'), 'no raw IP in stats')
  client.socket.close()
})
