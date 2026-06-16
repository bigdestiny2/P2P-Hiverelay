/**
 * Index-room Tier-0 (relay side): the relay advertises a schema-sheets index
 * room published by the out-of-process sidecar, and reverse-proxies the
 * read-only query routes so the desktop hits a single gatewayUrl.
 *
 * Covers: capability-doc additive+signed indexRoom, RelayNode persistence,
 * /catalog.json envelope, the /index/* proxy, and the publish endpoint.
 */

import test from 'brittle'
import http from 'http'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import z32 from 'z32'
import { rm, readFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { buildCapabilityDoc, verifyCapabilityDoc } from 'p2p-hiverelay/core/capability-doc.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'

const API_KEY = 'index-room-test-key'
const ROOM = z32.encode(b4a.alloc(32, 7)) // a valid 52-char z32 key
const ROOM2 = z32.encode(b4a.alloc(32, 9))

function signKeyPair () {
  const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pk, sk)
  return { publicKey: pk, secretKey: sk }
}

// ── capability-doc: additive + signed ──────────────────────────────────
test('capability-doc: indexRoom is signed, additive, schemaVersion stays 1', (t) => {
  const kp = signKeyPair()
  const doc = buildCapabilityDoc({
    relay: { publicKey: kp.publicKey, indexRoom: ROOM, config: {} },
    identitySecretKey: kp.secretKey,
    version: '9.9.9',
    attestedAt: 1
  })
  t.is(doc.indexRoom, ROOM, 'indexRoom present in the doc')
  t.is(doc.schemaVersion, 1, 'schemaVersion not bumped')
  t.ok(verifyCapabilityDoc(doc).valid, 'signature valid with indexRoom present')
  const tampered = { ...doc, indexRoom: ROOM2 }
  t.absent(verifyCapabilityDoc(tampered).valid, 'tampering indexRoom breaks the signature')
})

test('capability-doc: null indexRoom (no sidecar) still verifies', (t) => {
  const kp = signKeyPair()
  const doc = buildCapabilityDoc({
    relay: { publicKey: kp.publicKey, config: {} },
    identitySecretKey: kp.secretKey,
    attestedAt: 1
  })
  t.is(doc.indexRoom, null)
  t.ok(verifyCapabilityDoc(doc).valid)
})

// ── RelayNode persistence (isolated, no full node construction) ─────────
test('setIndexRoom persists + _loadIndexRoom restores; rejects bad z32', async (t) => {
  const dir = join(tmpdir(), 'idxroom-' + ROOM.slice(0, 10))
  await rm(dir, { recursive: true, force: true })
  const events = []
  const _indexRoomPath = RelayNode.prototype._indexRoomPath
  const stub = { config: { storage: dir }, indexRoom: null, _indexRoomPath, emit (e) { events.push(e) } }

  await RelayNode.prototype.setIndexRoom.call(stub, ROOM)
  t.is(stub.indexRoom, ROOM)
  t.ok(events.includes('index-room'), 'emits index-room')
  const file = JSON.parse(await readFile(join(dir, 'index-room.json'), 'utf8'))
  t.is(file.room, ROOM, 'persisted to index-room.json')

  const fresh = { config: { storage: dir }, indexRoom: null, _indexRoomPath, emit () {} }
  await RelayNode.prototype._loadIndexRoom.call(fresh)
  t.is(fresh.indexRoom, ROOM, 'restored across restart')

  await t.exception(() => RelayNode.prototype.setIndexRoom.call(stub, 'not-a-z32-key'))
  await rm(dir, { recursive: true, force: true })
})

// ── API: envelope + proxy + publish ─────────────────────────────────────
function mockNode (opts = {}) {
  return {
    running: true,
    config: { storage: null },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    async start () {},
    seeder: null,
    swarm: null,
    federation: null,
    catalogBeeKey: null,
    indexRoom: opts.indexRoom || null,
    indexSidecarUrl: opts.indexSidecarUrl || null,
    _setRooms: [],
    async setIndexRoom (r) { this._setRooms.push(r); this.indexRoom = r; return r },
    on () {},
    emit () {}
  }
}

function request (port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method, path, headers: { 'Content-Type': 'application/json', ...headers } }, (res) => {
      let d = ''
      res.on('data', c => { d += c })
      res.on('end', () => { let p; try { p = JSON.parse(d) } catch { p = d } resolve({ statusCode: res.statusCode, body: p }) })
    })
    req.on('error', reject)
    if (body != null) req.write(JSON.stringify(body))
    req.end()
  })
}

async function server (t, node) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: API_KEY })
  await api.start()
  const port = api.server.address().port
  t.teardown(async () => {
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) { try { api._dashboardFeed.stop() } catch (_) {} }
    await new Promise(resolve => api.server.close(resolve))
  })
  return port
}

test('catalog.json surfaces indexRoom (and null when no sidecar)', async (t) => {
  const p1 = await server(t, mockNode({ indexRoom: ROOM }))
  const r1 = await request(p1, 'GET', '/catalog.json')
  t.is(r1.body.indexRoom, ROOM)
  const p2 = await server(t, mockNode())
  const r2 = await request(p2, 'GET', '/catalog.json')
  t.is(r2.body.indexRoom, null)
})

test('GET /index/* returns 501 when no sidecar configured', async (t) => {
  const port = await server(t, mockNode())
  const res = await request(port, 'GET', '/index/relays')
  t.is(res.statusCode, 501)
  t.is(res.body.errorCode, 'index-disabled')
})

test('GET /index/* reverse-proxies to the configured sidecar (path+query only)', async (t) => {
  let seenUrl = null
  const upstream = http.createServer((req, res) => {
    seenUrl = req.url
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ rows: [{ pubkey: 'x' }], via: 'sidecar' }))
  })
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve))
  const upPort = upstream.address().port
  t.teardown(() => new Promise(resolve => upstream.close(resolve)))

  const port = await server(t, mockNode({ indexSidecarUrl: `http://127.0.0.1:${upPort}` }))
  const res = await request(port, 'GET', '/index/relays?region=eu')
  t.is(res.statusCode, 200)
  t.is(res.body.via, 'sidecar')
  t.is(seenUrl, '/index/relays?region=eu', 'forwarded path + query verbatim')
})

test('POST /api/manage/index-room: auth + z32 validation + publish', async (t) => {
  const node = mockNode()
  const port = await server(t, node)
  // no auth
  const unauth = await request(port, 'POST', '/api/manage/index-room', { room: ROOM })
  t.is(unauth.statusCode, 401)
  // bad z32
  const bad = await request(port, 'POST', '/api/manage/index-room', { room: 'nope' }, { Authorization: 'Bearer ' + API_KEY })
  t.is(bad.statusCode, 400)
  // valid
  const ok = await request(port, 'POST', '/api/manage/index-room', { room: ROOM }, { Authorization: 'Bearer ' + API_KEY })
  t.is(ok.statusCode, 200)
  t.is(ok.body.indexRoom, ROOM)
  t.alike(node._setRooms, [ROOM], 'setIndexRoom called once')
})
