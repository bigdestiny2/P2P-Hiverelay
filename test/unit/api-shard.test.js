import test from 'brittle'
import http from 'http'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { BUILTIN_SERVICE_NAMES } from 'p2p-hiverelay/core/plugin-loader.js'
import {
  ShardStoreService, shardHash, normalizeShardAddress, signShardPin
} from '../../packages/services/builtin/shard-store/index.js'

const API_KEY = 'shard-test-key'
const NOW = 2000000000000

function keyPair (seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seed))
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}

const custodyPin = (hash, kp, { custodyIntentId, shareIndex, nonce = 'b'.repeat(32) }) =>
  signShardPin({ reason: 'custody', hash: normalizeShardAddress(hash), custodyIntentId, shareIndex, retainUntil: NOW + 3600000, nonce }, kp)

async function tmpStore (t) {
  const dir = await mkdtemp(join(tmpdir(), 'api-shard-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const store = new Corestore(dir)
  t.teardown(() => store.close())
  return store
}

// A running shard-store service whose custody resolver assigns `intentId` a
// single (shareIndex, hash). Mirrors what the relay's seeding-registry-backed
// resolver produces, without needing a full registry.
async function runningShardService (t, { hash, intentId = 'ci1', shareIndex = 3, relay = keyPair(1) }) {
  const store = await tmpStore(t)
  const resolveCustodyAssignment = async (id) => id === intentId ? { shareIndex, shard: 'shard:' + hash } : null
  const svc = new ShardStoreService({ putAuth: ['custody'], resolveCustodyAssignment })
  await svc.start({ store, node: { keyPair: relay } })
  t.teardown(() => svc.stop())
  return svc
}

function shardRegistry (provider) {
  const entry = { name: 'shard-store', version: '0.1.0', status: 'running', capabilities: ['put', 'get', 'has', 'prove'], provider }
  return { services: new Map([['shard-store', entry]]) }
}

function mockNode (opts = {}) {
  return {
    running: true,
    config: { storage: null, plugins: opts.plugins || [], trustProxy: true },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    serviceRegistry: opts.registry || null,
    async stop () {},
    async start () {},
    on () {},
    emit () {}
  }
}

function request (port, method, path, opts = {}) {
  return new Promise((resolve, reject) => {
    const headers = { ...(opts.headers || {}) }
    let payload = null
    if (opts.raw != null) {
      payload = opts.raw
    } else if (opts.body != null) {
      payload = JSON.stringify(opts.body)
      headers['Content-Type'] = headers['Content-Type'] || 'application/json'
    }
    const req = http.request({ hostname: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const buf = Buffer.concat(chunks)
        let body
        if ((res.headers['content-type'] || '').includes('application/json')) {
          try { body = JSON.parse(buf.toString()) } catch { body = buf.toString() }
        } else {
          body = buf
        }
        resolve({ statusCode: res.statusCode, body, headers: res.headers })
      })
    })
    req.on('error', reject)
    if (payload != null) req.write(payload)
    req.end()
  })
}

async function serverWithApi (t, node, opts = {}) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY, ...opts })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => { await api.stop() })
  return { api, port }
}

test('shard-store is a builtin service provider', (t) => {
  t.ok(BUILTIN_SERVICE_NAMES.includes('shard-store'))
})

test('/api/v1/shard returns 503 when the shard store is not enabled', async (t) => {
  const { port } = await serverWithApi(t, mockNode({ registry: null }))
  const res = await request(port, 'POST', '/api/v1/shard')
  t.is(res.statusCode, 503)
  t.alike(res.body, { error: 'Shard store service is not enabled on this relay' })
})

test('/api/v1/shard redacts adapter load failures and emits internals', async (t) => {
  const svc = await runningShardService(t, { hash: 'a'.repeat(64) })
  const { api, port } = await serverWithApi(t, mockNode({ registry: shardRegistry(svc) }))
  const events = []
  api.on('shard-http-adapter-error', (event) => events.push(event))
  api._loadShardHttpAdapter = async function () {
    throw new Error('internal adapter path /data/hiverelay/private/shard/http-adapter.js failed')
  }
  // GET (not HEAD) so the redacted JSON body is returned to the client.
  const res = await request(port, 'GET', '/api/v1/shard/' + 'a'.repeat(64))
  t.is(res.statusCode, 503)
  t.is(res.body.error, 'unsupported: shard HTTP adapter unavailable')
  t.is(res.body.errorCode, 'shard-http-adapter-unavailable')
  t.absent(JSON.stringify(res.body).includes('/data/hiverelay/private'))
  t.is(events.length, 1)
  t.ok(events[0].error.message.includes('/data/hiverelay/private'))
})

test('HEAD + GET serve a stored shard through RelayAPI (content-neutral, no auth)', async (t) => {
  const publisher = keyPair(9)
  const sealed = b4a.from('opaque-encrypted-share-bytes', 'utf8')
  const hash = shardHash(sealed)
  const svc = await runningShardService(t, { hash })
  // pre-store the shard directly (authorized custody pin)
  await svc.put({ ciphertext: b4a.toString(sealed, 'base64'), pin: custodyPin(hash, publisher, { custodyIntentId: 'ci1', shareIndex: 3 }) })

  const { port } = await serverWithApi(t, mockNode({ registry: shardRegistry(svc) }))

  const head = await request(port, 'HEAD', '/api/v1/shard/' + hash)
  t.is(head.statusCode, 200)
  t.is(head.headers['content-length'], String(sealed.length))

  const get = await request(port, 'GET', '/api/v1/shard/' + hash)
  t.is(get.statusCode, 200)
  t.ok(b4a.equals(get.body, sealed), 'GET returns the exact opaque bytes')

  const miss = await request(port, 'HEAD', '/api/v1/shard/' + 'f'.repeat(64))
  t.is(miss.statusCode, 404)
})

test('PUT authorizes a custody pin over HTTP and rejects an unbacked one', async (t) => {
  const publisher = keyPair(9)
  const sealed = b4a.from('another-opaque-share', 'utf8')
  const hash = shardHash(sealed)
  const svc = await runningShardService(t, { hash })
  const { port } = await serverWithApi(t, mockNode({ registry: shardRegistry(svc) }))

  // correct custody pin -> 201
  const ok = await request(port, 'POST', '/api/v1/shard', {
    raw: sealed,
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Shard-Pin': JSON.stringify(custodyPin(hash, publisher, { custodyIntentId: 'ci1', shareIndex: 3 }))
    }
  })
  t.is(ok.statusCode, 201)
  t.is(ok.body.ok, true)
  t.is(ok.body.shard, 'shard:' + hash)

  // pin naming an intent this relay wasn't assigned -> 403 UNAUTHORIZED_PIN
  const bad = await request(port, 'POST', '/api/v1/shard', {
    raw: sealed,
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Shard-Pin': JSON.stringify(custodyPin(hash, publisher, { custodyIntentId: 'nope', shareIndex: 3 }))
    }
  })
  t.is(bad.statusCode, 403)
  t.is(bad.body.error, 'UNAUTHORIZED_PIN')
})

test('relay _resolveShardCustodyAssignment binds relayPubkey -> shareIndex -> shard', (t) => {
  const relayHex = 'aa'.repeat(32)
  const otherHex = 'bb'.repeat(32)
  const hash = 'c'.repeat(64)
  const intent = {
    shareAssignments: [{ relayPubkey: relayHex, shareIndex: 3 }, { relayPubkey: otherHex, shareIndex: 4 }],
    shareManifest: [{ shareIndex: 3, shard: 'shard:' + hash }, { shareIndex: 4, shard: 'shard:' + 'd'.repeat(64) }]
  }
  const node = { seedingRegistry: { getCustodyIntent: (id) => id === 'ci1' ? intent : null } }
  const call = (id, rp) => RelayNode.prototype._resolveShardCustodyAssignment.call(node, id, rp)

  t.alike(call('ci1', relayHex), { shareIndex: 3, shard: 'shard:' + hash }, 'assigned relay resolves its own share')
  t.is(call('ci1', 'ee'.repeat(32)), null, 'unassigned relay gets nothing')
  t.is(call('missing', relayHex), null, 'unknown intent -> null')
  t.is(RelayNode.prototype._resolveShardCustodyAssignment.call({ seedingRegistry: null }, 'ci1', relayHex), null, 'no registry -> null')
})
