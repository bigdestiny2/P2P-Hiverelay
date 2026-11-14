import test from 'brittle'
import { EventEmitter } from 'events'
import { mkdtemp, readFile, writeFile, symlink, stat, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import {
  BootstrapCache,
  DEFAULT_BOOTSTRAP_CACHE_PEERS,
  MAX_BOOTSTRAP_CACHE_FILE_BYTES,
  MAX_BOOTSTRAP_CACHE_PEERS,
  normalizeBootstrapHost,
  normalizeBootstrapPeer,
  parseBootstrapCachePeers
} from '../../packages/core/core/bootstrap-cache.js'

async function tempCache (opts = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'hr-bootstrap-cache-'))
  return { dir, cache: new BootstrapCache(dir, opts) }
}

function connection (host, port) {
  return { rawStream: { remoteHost: host, remotePort: port } }
}

test('bootstrap cache peer cap uses a strict bounded parser', async (t) => {
  t.is(parseBootstrapCachePeers(), DEFAULT_BOOTSTRAP_CACHE_PEERS)
  t.is(parseBootstrapCachePeers(1), 1)
  t.is(parseBootstrapCachePeers(10_000), MAX_BOOTSTRAP_CACHE_PEERS)
  for (const value of ['50', 1.5, 0, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await t.exception.all(() => parseBootstrapCachePeers(value), /positive safe integer/)
  }
})

test('bootstrap hosts share strict IPv4, IPv6 and IDNA canonicalization', (t) => {
  t.is(normalizeBootstrapHost('192.0.2.10').host, '192.0.2.10')
  t.is(normalizeBootstrapHost('::').host, '::')
  t.is(normalizeBootstrapHost('2001:db8::').host, '2001:db8::')
  t.is(normalizeBootstrapHost('2001:0DB8:0:0:0:0:0:1').host, '2001:db8::1')
  t.is(normalizeBootstrapHost('::ffff:192.0.2.1').host, '::ffff:c000:201')
  t.is(normalizeBootstrapHost('BÜCHER.Example.').host, 'xn--bcher-kva.example')
  for (const host of [
    '', '01.2.3.4', '192.0.2.1::', '[::1]', 'fe80::1%lo0', 'user@example.com',
    'example.com/path', 'example.com..', '-bad.example', 'bad-.example',
    'bad host', '\ud800', 'a'.repeat(1025)
  ]) {
    t.is(normalizeBootstrapHost(host), null, `rejects ${JSON.stringify(host)}`)
  }
  t.is(normalizeBootstrapPeer({ host: '::1', port: 49737, lastSeen: 1 }).key, '[::1]:49737')
  t.is(normalizeBootstrapPeer({ host: 'example.com', port: 0, lastSeen: 1 }), null)
  t.is(normalizeBootstrapPeer({ host: 'example.com', port: 1, lastSeen: -1 }), null)
})

test('bootstrap cache is a hard LRU under 100,000 unique peers', async (t) => {
  const { dir, cache } = await tempCache({ maxPeers: 50 })
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  for (let i = 0; i < 100_000; i++) {
    cache._insert({
      host: `peer-${i}.example`,
      port: 1024 + (i % 60_000),
      lastSeen: i
    })
  }
  const stats = cache.getStats()
  t.is(stats.size, 50)
  t.is(stats.evictions, 99_950)
  t.is(cache._collectPeers()[0].host, 'peer-99999.example')

  cache._insert({ host: 'peer-99950.example', port: 1024 + (99_950 % 60_000), lastSeen: 100_001 })
  t.is(cache._collectPeers()[0].host, 'peer-99950.example', 'refresh moves a peer to newest')
  t.is(cache.getStats().size, 50)
  t.is(cache.getStats().refreshes, 1)
})

test('save/load preserves oldest-to-newest LRU and compact lastSeen data', async (t) => {
  const { dir, cache } = await tempCache({ maxPeers: 3 })
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  cache._insert({ host: 'one.example', port: 1, lastSeen: 10 })
  cache._insert({ host: 'two.example', port: 2, lastSeen: 20 })
  cache._insert({ host: 'three.example', port: 3, lastSeen: 30 })
  cache._insert({ host: 'one.example', port: 1, lastSeen: 40 })
  t.ok(await cache.save())

  const raw = await readFile(join(dir, 'bootstrap-cache.json'), 'utf8')
  t.absent(raw.includes('\n  '), 'canonical JSON is compact')
  t.alike(JSON.parse(raw).peers, [
    { host: 'two.example', port: 2, lastSeen: 20 },
    { host: 'three.example', port: 3, lastSeen: 30 },
    { host: 'one.example', port: 1, lastSeen: 40 }
  ])

  const loaded = new BootstrapCache(dir, { maxPeers: 2 })
  t.ok(await loaded.load())
  t.alike(loaded._collectPeers().map(peer => peer.host), ['one.example', 'three.example'])
  t.is(loaded.getStats().size, 2)
})

test('load is bounded, no-follow and rejects malformed or duplicate rows', async (t) => {
  const { dir, cache } = await tempCache({ maxPeers: 3 })
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'bootstrap-cache.json')
  await writeFile(path, JSON.stringify({
    peers: [
      { host: 'one.example', port: 1, lastSeen: 1 },
      { host: 'ONE.EXAMPLE.', port: 1, lastSeen: 2 },
      { host: '[::1]', port: 2, lastSeen: 3 },
      { host: 'two.example', port: 2, lastSeen: 4 }
    ]
  }))
  t.ok(await cache.load())
  t.alike(cache._collectPeers().map(peer => peer.host), ['two.example', 'one.example'])
  t.is(cache.getStats().invalid, 2, 'duplicate and malformed rows do not affect order')

  await writeFile(path, 'x'.repeat(MAX_BOOTSTRAP_CACHE_FILE_BYTES + 1))
  t.absent(await cache.load(), 'oversized file is rejected before read')
  t.is(cache.getStats().size, 0)

  const target = join(dir, 'target.json')
  await writeFile(target, JSON.stringify({ peers: [{ host: 'linked.example', port: 1, lastSeen: 1 }] }))
  await rm(path)
  await symlink(target, path)
  t.absent(await cache.load(), 'symlink cache is not followed')
  t.is(cache.getStats().size, 0)
})

test('configured merge validates at most 256 rows and preserves priority', async (t) => {
  const { dir, cache } = await tempCache({ maxPeers: 3 })
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  cache._insert({ host: 'cached.example', port: 9, lastSeen: 9 })
  cache._insert({ host: 'duplicate.example', port: 8, lastSeen: 8 })
  const configured = [
    { host: 'duplicate.example.', port: 8 },
    { host: '[::1]', port: 7 },
    ...Array.from({ length: 300 }, (_, i) => ({ host: `configured-${i}.example`, port: i + 1000 }))
  ]
  const merged = cache.merge(configured)
  t.is(merged.length, 256)
  t.alike(merged[0], { host: 'duplicate.example', port: 8 })
  t.alike(merged[1], { host: 'configured-0.example', port: 1000 })
  t.ok(cache.getStats().overflow > 0)
  t.ok(cache.getStats().invalid > 0)
})

test('connection ingress detaches before async idempotent final save', async (t) => {
  const { dir, cache } = await tempCache({ maxPeers: 1 })
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const swarm = new EventEmitter()
  cache.start(swarm)
  swarm.emit('connection', connection('before.example', 1))
  const first = cache.stop()
  const second = cache.stop()
  t.is(first, second, 'duplicate stop joins one drain')
  swarm.emit('connection', connection('after.example', 2))
  await first
  t.is(cache.getStats().stops, 1)
  t.is(cache._collectPeers()[0].host, 'before.example')
  const saved = JSON.parse(await readFile(join(dir, 'bootstrap-cache.json'), 'utf8'))
  t.is(saved.peers[0].host, 'before.example')
  t.ok((await stat(join(dir, 'bootstrap-cache.json'))).isFile())
})
