/**
 * R9 — Public HTTPS Hive gateway conformance suite.
 *
 * Executable conformance harness for the frozen public-gateway contract in
 * docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md (§7.4 policy table, §12.3 production
 * posture). Any relay build can run this file headlessly before admission:
 * every enforceable frozen limit is asserted against an in-process
 * GatewayServer/HyperGateway with stubbed drive/proxy edges, and the two
 * behaviors that live one hop out in the TLS-terminating proxy carry
 * gate-named skips at the bottom.
 *
 * Frozen tuple (PUBLIC_T1_GATEWAY_FINITE_LIMITS):
 *   response cap 64 MiB (legacy) / 4 MiB transform cell class,
 *   egress 256 MiB per client-IP × app per 60 s window,
 *   15-minute response lifetime.
 *
 * Edge discipline: default-421 for misdirected/unknown SNI, SNI==Host
 * binding, exactly one canonical z32 label per app origin, GET/HEAD-only
 * with no request bodies, 30 s drive-op timeout, 20 s empty-drive wait,
 * drive LRU 20, directory listing ≤ 1000 entries / ≤ 1 MiB, in-flight
 * concurrency 256 global / 32 per app, 10 s headersTimeout.
 *
 * Scoping notes (honesty, not aspiration):
 *   - The frozen egress tuple is keyed per client-IP × app origin. The
 *     legacy /v1/hyper/KEY compatibility lane deliberately keeps only its
 *     request-rate limit (spec §15 Phase 1: the path gateway stays
 *     unchanged), so egress is asserted on the app-origin lane.
 *   - Wall-clock ceilings (30 s drive-op, 20 s empty-drive wait, 10 s
 *     header reaping) are asserted at full scale. The 15-minute response
 *     lifetime is asserted by exact static value plus a scaled destroy
 *     probe; the full-scale soak belongs to the canary window (G8 skip).
 *   - The nginx default_server 421 vhost is proxy-runtime configuration,
 *     not gateway-process behavior (G12 skip). Its in-process halves —
 *     misdirected Host → 421 and forwarded-SNI≠Host → 421 — are asserted.
 */

import test from 'brittle'
import http from 'http'
import net from 'net'
import { Readable } from 'stream'
import { randomBytes } from 'crypto'
import { mkdtemp, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import Corestore from 'corestore'
import { GatewayServer, assertHiveAppGatewayIsolation } from 'p2p-hiverelay/core/relay-node/gateway-server.js'
import { HyperGateway } from 'p2p-hiverelay/gateway'
import { encodeHiveAppKey } from 'p2p-hiverelay/gateway/hive-host.js'
import {
  PUBLIC_T1_GATEWAY_FINITE_LIMITS,
  assertPublicHiveGatewayFiniteLimits
} from '../../packages/core/config/public-hive-gateway-env.js'

const SUFFIX = 'hive-conformance.test'
// Restated from the spec so the suite fails on drift in either direction
// (code ≠ spec or spec ≠ code).
const FROZEN_FINITE_LIMITS = {
  gatewayMaxResponseBytes: 64 * 1024 * 1024,
  gatewayMaxTransformBytes: 4 * 1024 * 1024,
  gatewayEgressBytesPerWindow: 256 * 1024 * 1024,
  gatewayEgressWindowMs: 60 * 1000,
  gatewayMaxResponseLifetimeMs: 15 * 60 * 1000
}
const FROZEN_MAX_IN_FLIGHT = 256
const FROZEN_MAX_IN_FLIGHT_PER_APP = 32
const FROZEN_DRIVE_OPERATION_TIMEOUT_MS = 30_000
const FROZEN_EMPTY_DRIVE_WAIT_MS = 20_000
const FROZEN_MAX_CACHED_DRIVES = 20
const FROZEN_HEADERS_TIMEOUT_MS = 10_000
const FROZEN_MAX_LISTING_ENTRIES = 1000
const FROZEN_MAX_LISTING_BYTES = 1024 * 1024

function newAppKey () {
  return randomBytes(32).toString('hex')
}

function appHostFor (keyHex) {
  return `${encodeHiveAppKey(Buffer.from(keyHex, 'hex'))}.${SUFFIX}`
}

function appHeaders (host, extra = {}) {
  return { Host: host, 'X-Hive-Forwarded-SNI': host, ...extra }
}

function fakeDrive (files = {}, sizes = {}) {
  return {
    closed: false,
    closing: false,
    version: 1,
    async ready () {},
    async update () {},
    async close () { this.closed = true },
    async entry (filePath) {
      const data = files[filePath]
      if (!data) return null
      return { value: { blob: { byteLength: sizes[filePath] ?? data.byteLength } } }
    },
    async get (filePath) {
      return files[filePath] || null
    },
    createReadStream (filePath, opts = {}) {
      const data = files[filePath] || Buffer.alloc(0)
      const start = opts.start || 0
      const end = opts.length == null ? data.length : start + opts.length
      return Readable.from([data.subarray(start, end)])
    },
    checkout () { return fakeDrive(files, sizes) },
    async * list () {}
  }
}

function seededEntry (drive) {
  return {
    drive,
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    storageProvedDriveVersion: drive.version
  }
}

function mockPublicNode (seededApps = new Map()) {
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    store: null,
    seededApps
  }
  node.appLifecycle = {
    acquireDriveReadLease (key) {
      const drive = node.seededApps.get(key)?.drive
      if (!drive || drive.closed || drive.closing) return null
      return { drive, release () {} }
    }
  }
  return node
}

function request (port, path, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: opts.method || 'GET',
      path,
      agent: false,
      headers: opts.headers || {}
    }, (res) => {
      const chunks = []
      res.on('data', chunk => { chunks.push(chunk) })
      res.on('end', () => {
        const raw = Buffer.concat(chunks)
        let body = raw
        try { body = JSON.parse(raw.toString('utf8')) } catch (_) {}
        resolve({ statusCode: res.statusCode, headers: res.headers, body, raw })
      })
      res.on('error', reject)
    })
    req.on('error', reject)
    req.end(opts.body)
  })
}

async function startGatewayServer (t, opts = {}) {
  const { node = mockPublicNode(), ...serverOpts } = opts
  const server = new GatewayServer(node, {
    gatewayPort: 0,
    gatewayHost: '127.0.0.1',
    ...serverOpts
  })
  await server.start()
  t.teardown(async () => {
    try { await server.stop() } catch (_) {}
  })
  return server
}

// App-origin lane through the production wiring: GatewayServer builds its own
// HyperGateway with requireLifecycleDriveAuthority, so the served bytes cross
// the same admission/lease/proof chain a public-t1 relay would use.
async function bootAppGateway (t, apps, serverOpts = {}) {
  const seededApps = new Map()
  for (const { keyHex, drive } of apps) seededApps.set(keyHex, seededEntry(drive))
  const server = await startGatewayServer(t, {
    node: mockPublicNode(seededApps),
    hiveAppHostSuffix: SUFFIX,
    hiveAppPublicKeys: apps.map(app => app.keyHex),
    hiveAppPublicVersions: Object.fromEntries(apps.map(app => [app.keyHex, app.drive.version])),
    trustProxy: true,
    trustedProxyAddresses: ['127.0.0.1'],
    ...serverOpts
  })
  return server
}

// Legacy /v1/hyper/KEY lane: HyperGateway in front of a bare HTTP server.
async function bootLegacyGateway (t, drive, gatewayOpts = {}) {
  const keyHex = newAppKey()
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[keyHex, { drive, blind: false, privacyTier: 'public' }]])
  }
  const gateway = new HyperGateway(node, gatewayOpts)
  const server = http.createServer((req, res) => gateway.handle(req, res))
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections() } catch (_) {}
    }
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
  })
  return {
    gateway,
    port: server.address().port,
    path: (filePath) => `/v1/hyper/${keyHex}${filePath}`
  }
}

test('conformance: frozen limits tuple is pinned exactly and config drift fails closed', (t) => {
  t.ok(Object.isFrozen(PUBLIC_T1_GATEWAY_FINITE_LIMITS), 'tuple object is frozen')
  t.alike({ ...PUBLIC_T1_GATEWAY_FINITE_LIMITS }, FROZEN_FINITE_LIMITS,
    'frozen tuple matches the spec integers')

  t.is(
    assertPublicHiveGatewayFiniteLimits({ ...FROZEN_FINITE_LIMITS, productProfile: 'public-t1-gateway' }).gatewayMaxResponseBytes,
    FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes,
    'frozen values pass validation under the production profile'
  )
  for (const [field, expected] of Object.entries(FROZEN_FINITE_LIMITS)) {
    t.exception(() => assertPublicHiveGatewayFiniteLimits({
      ...FROZEN_FINITE_LIMITS,
      productProfile: 'public-t1-gateway',
      [field]: expected - 1
    }), new RegExp(`${field} must equal ${expected}`), `${field} cannot drift below the frozen value`)
    t.exception(() => assertPublicHiveGatewayFiniteLimits({
      ...FROZEN_FINITE_LIMITS,
      productProfile: 'public-t1-gateway',
      [field]: null
    }), new RegExp(`Invalid ${field}`), `${field} cannot be nulled out`)
  }
  t.exception(() => assertPublicHiveGatewayFiniteLimits({
    ...FROZEN_FINITE_LIMITS,
    gatewayMaxTransformBytes: FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes + 1
  }), /must not exceed gatewayMaxResponseBytes/, 'transform class cannot outgrow the response cap')
})

test('conformance: public-t1 isolation contract pins the frozen tuple and the G1 admission gate', (t) => {
  const appKey = newAppKey()
  const t1 = {
    hiveAppHostSuffix: SUFFIX,
    hiveAppPublicKeys: [appKey],
    hiveAppPublicVersions: { [appKey]: 7 },
    gatewayPort: 9200,
    gatewayHost: '127.0.0.1',
    gatewayTrustProxy: true,
    gatewayRequireForwardedSNI: true,
    ...FROZEN_FINITE_LIMITS,
    apiPort: 9100,
    apiHost: '127.0.0.1',
    enableAPI: true,
    enableSeeding: true,
    enableRelay: false,
    enableServices: false,
    plugins: [],
    custody: { enabled: false },
    requirePhysicalEnforcement: true,
    mode: 'public-t1-gateway',
    productProfile: 'public-t1-gateway',
    enforceCompiledAdmission: false
  }
  t.is(assertHiveAppGatewayIsolation(t1), SUFFIX, 'frozen reference posture is admitted')
  for (const [field, expected] of Object.entries(FROZEN_FINITE_LIMITS)) {
    t.exception(() => assertHiveAppGatewayIsolation({ ...t1, [field]: expected + 1 }),
      new RegExp(`${field} to equal ${expected}`), `isolation refuses a weakened ${field}`)
  }
  // G1 role boundary: the compiled admission capability in this build is
  // still the transitional operator allowlist, so a fleet posture must keep
  // refusing to boot until the blind substrate ships the frozen T1 predicate.
  t.exception(() => assertHiveAppGatewayIsolation({ ...t1, enforceCompiledAdmission: true }),
    /fleet-ready non-transitional admission/, 'fleet posture stays closed while admission is transitional')
})

test('conformance: runtime defaults materialize the frozen values', (t) => {
  const server = new GatewayServer(mockPublicNode(), { gatewayPort: 0, gatewayHost: '127.0.0.1' })
  t.is(server._maxInFlight, FROZEN_MAX_IN_FLIGHT, 'global in-flight ceiling is 256')
  t.is(server._maxInFlightPerApp, FROZEN_MAX_IN_FLIGHT_PER_APP, 'per-app in-flight ceiling is 32')
  t.is(server._egressBytesPerWindow, FROZEN_FINITE_LIMITS.gatewayEgressBytesPerWindow, 'egress budget is 256 MiB')
  t.is(server._egressWindowMs, FROZEN_FINITE_LIMITS.gatewayEgressWindowMs, 'egress window is 60 s')
  t.is(server._maxResponseLifetimeMs, FROZEN_FINITE_LIMITS.gatewayMaxResponseLifetimeMs, 'response lifetime is 15 min')

  const gateway = new HyperGateway({ config: {} })
  t.is(gateway._maxResponseBytes, FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes, 'response cap is 64 MiB')
  t.is(gateway._maxTransformBytes, FROZEN_FINITE_LIMITS.gatewayMaxTransformBytes, 'transform class is 4 MiB')
  t.is(gateway._driveOperationTimeout, FROZEN_DRIVE_OPERATION_TIMEOUT_MS, 'drive-op timeout is 30 s')
  t.is(gateway._drives.maxSize, FROZEN_MAX_CACHED_DRIVES, 'drive LRU is 20')
})

test('conformance: over-64-MiB legacy responses are refused, ranges stay the bounded paging path', async (t) => {
  const overCap = FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes + 1
  const small = Buffer.from('conformance-small\n')
  const drive = fakeDrive(
    { '/huge.bin': Buffer.alloc(1024, 0x62), '/small.bin': small },
    { '/huge.bin': overCap }
  )
  const { port, path } = await bootLegacyGateway(t, drive)

  const full = await request(port, path('/huge.bin'))
  t.is(full.statusCode, 413, 'over-cap full response is refused')
  t.is(full.body.error, 'A bounded single byte range is required')
  t.is(full.body.maxResponseBytes, FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes)

  const head = await request(port, path('/huge.bin'), { method: 'HEAD' })
  t.is(head.statusCode, 413, 'over-cap HEAD representation is refused')

  const openRange = await request(port, path('/huge.bin'), { headers: { Range: 'bytes=0-' } })
  t.is(openRange.statusCode, 416, 'a range spanning past the cap is refused')
  t.is(openRange.headers['content-range'], `bytes */${overCap}`)

  const multiRange = await request(port, path('/huge.bin'), { headers: { Range: 'bytes=0-1,2-3' } })
  t.is(multiRange.statusCode, 416, 'multi-range cannot launder an over-cap object into a full 200')

  const paged = await request(port, path('/huge.bin'), { headers: { Range: 'bytes=0-99' } })
  t.is(paged.statusCode, 206, 'a bounded range inside the cap is served')
  t.is(paged.headers['content-range'], `bytes 0-99/${overCap}`)
  t.is(paged.raw.byteLength, 100)

  // RFC 9110 §14.2: an in-cap legacy object may ignore an unsupported range
  // with a full 200. The frozen app surface is stricter — the exact-lane 416
  // is asserted in the app-origin test below.
  const legacyMulti = await request(port, path('/small.bin'), { headers: { Range: 'bytes=0-1,2-3' } })
  t.is(legacyMulti.statusCode, 200, 'in-cap legacy multi-range keeps the RFC allowance')
})

test('conformance: transform cell class refuses HTML rewrite inputs over 4 MiB', async (t) => {
  const drive = fakeDrive(
    { '/big.html': Buffer.from('<!doctype html><h1>conformance</h1>') },
    { '/big.html': FROZEN_FINITE_LIMITS.gatewayMaxTransformBytes + 1 }
  )
  const { port, path } = await bootLegacyGateway(t, drive)

  const res = await request(port, path('/big.html'))
  t.is(res.statusCode, 413)
  t.is(res.body.error, 'Response exceeds gateway transform limit')
  t.is(res.body.maxResponseBytes, FROZEN_FINITE_LIMITS.gatewayMaxTransformBytes)
})

test('conformance: app origin enforces the same caps and proof mode stays closed', async (t) => {
  const keyHex = newAppKey()
  const host = appHostFor(keyHex)
  const overCap = FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes + 1
  const indexBytes = Buffer.from('<!doctype html><h1>conformance</h1>')
  const drive = fakeDrive(
    { '/index.html': indexBytes, '/huge.bin': Buffer.alloc(1024, 0x63) },
    { '/huge.bin': overCap }
  )
  const server = await bootAppGateway(t, [{ keyHex, drive }])
  const port = server.server.address().port

  const exact = await request(port, '/', { headers: appHeaders(host) })
  t.is(exact.statusCode, 200, 'approved app origin serves exact bytes')
  t.is(exact.headers['x-hive-byte-mode'], 'exact')
  t.is(exact.headers['x-hive-app-key'], keyHex)

  const full = await request(port, '/huge.bin', { headers: appHeaders(host) })
  t.is(full.statusCode, 413, 'over-cap exact response is refused')
  t.is(full.body.maxResponseBytes, FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes)

  const head = await request(port, '/huge.bin', { method: 'HEAD', headers: appHeaders(host) })
  t.is(head.statusCode, 413, 'over-cap exact HEAD is refused')

  const multi = await request(port, '/index.html', { headers: appHeaders(host, { Range: 'bytes=0-1,2-3' }) })
  t.is(multi.statusCode, 416, 'exact lane rejects multi-range even inside the cap')
  t.is(multi.headers['content-range'], `bytes */${indexBytes.byteLength}`)

  const proof = await request(port, '/', {
    headers: appHeaders(host, { Accept: 'application/vnd.hiverelay.proof+binary;version=1' })
  })
  t.is(proof.statusCode, 406, 'deferred proof media type stays refused')
  t.is(proof.body.error, 'Proof-carrying HTTP mode is not available')
})

test('conformance: exactly one canonical z32 label selects the app, deformations fail closed', async (t) => {
  const keyHex = newAppKey()
  const host = appHostFor(keyHex)
  const label = host.slice(0, host.indexOf('.'))
  const indexBytes = Buffer.from('<!doctype html><h1>conformance</h1>')
  const drive = fakeDrive({ '/index.html': indexBytes })
  const server = await bootAppGateway(t, [{ keyHex, drive }])
  const port = server.server.address().port

  const ok = await request(port, '/', { headers: appHeaders(host) })
  t.is(ok.statusCode, 200)
  t.ok(ok.raw.equals(indexBytes), 'canonical 52-char z32 label serves the pinned app')

  // DNS case-folding is canonicalized before decoding, so an uppercase
  // spelling of the same label is the same origin, not a second app.
  const folded = await request(port, '/', { headers: appHeaders(host.toUpperCase()) })
  t.is(folded.statusCode, 200, 'DNS case-fold canonicalizes to the same origin')

  const cases = [
    [`${label.slice(0, 26)}.${label.slice(26)}.${SUFFIX}`, 'two labels'],
    [SUFFIX, 'suffix without a label'],
    [`${label.slice(0, 51)}.${SUFFIX}`, 'truncated 51-char label'],
    [`0${label.slice(1)}.${SUFFIX}`, 'label outside the z32 alphabet']
  ]
  for (const [badHost, name] of cases) {
    const res = await request(port, '/', { headers: { Host: badHost } })
    t.is(res.statusCode, 400, `${name} is refused`)
  }

  const stranger = appHostFor(newAppKey())
  const unapproved = await request(port, '/', { headers: { Host: stranger } })
  t.is(unapproved.statusCode, 403, 'well-formed but unapproved key fails closed')
  t.is(unapproved.body.error, 'App unavailable through public Hive gateway')
})

test('conformance: only GET/HEAD serve and request bodies are refused', async (t) => {
  const keyHex = newAppKey()
  const host = appHostFor(keyHex)
  const drive = fakeDrive({ '/index.html': Buffer.from('<!doctype html>') })
  const server = await bootAppGateway(t, [{ keyHex, drive }])
  const port = server.server.address().port

  const post = await request(port, '/', { method: 'POST', headers: appHeaders(host) })
  t.is(post.statusCode, 405)
  t.is(post.headers.allow, 'GET, HEAD')

  const put = await request(port, `/v1/hyper/${keyHex}/index.html`, {
    method: 'PUT',
    headers: { Host: '127.0.0.1' }
  })
  t.is(put.statusCode, 405, 'legacy content lane refuses mutations too')
  t.is(put.headers.allow, 'GET, HEAD')

  const body = await request(port, '/', { headers: appHeaders(host, { 'Content-Length': '1' }), body: 'x' })
  t.is(body.statusCode, 400)
  t.is(body.body.error, 'Request body is not allowed')
  t.is(body.headers.connection, 'close')

  const chunked = await request(port, '/', {
    headers: appHeaders(host, { 'Transfer-Encoding': 'chunked' }),
    body: 'x'
  })
  t.is(chunked.statusCode, 400)
  t.is(chunked.body.error, 'Request body is not allowed')

  const options = await request(port, '/', { method: 'OPTIONS', headers: appHeaders(host) })
  t.is(options.statusCode, 204, 'preflight stays non-mutating')
  t.is(options.headers['access-control-allow-methods'], 'GET, HEAD, OPTIONS')
})

test('conformance: misdirected Host gets 421 and forwarded SNI must bind to Host', async (t) => {
  const keyHex = newAppKey()
  const host = appHostFor(keyHex)
  const otherHost = appHostFor(newAppKey())
  const drive = fakeDrive({ '/index.html': Buffer.from('<!doctype html>') })
  const server = await bootAppGateway(t, [{ keyHex, drive }], { requireForwardedSNI: true })
  const port = server.server.address().port

  const misdirected = await request(port, '/', { headers: { Host: 'unrelated.example' } })
  t.is(misdirected.statusCode, 421, 'unknown Host on the app listener is misdirected')
  t.is(misdirected.body.error, 'Misdirected request')

  const compatibility = await request(port, '/health', { headers: { Host: '127.0.0.1' } })
  t.is(compatibility.statusCode, 200, 'allowlisted compatibility host keeps legacy routes')

  const missing = await request(port, '/', { headers: { Host: host } })
  t.is(missing.statusCode, 421, 'missing forwarded SNI is refused')
  t.is(missing.body.error, 'TLS SNI and Host must match')

  const mismatch = await request(port, '/', { headers: { Host: host, 'X-Hive-Forwarded-SNI': otherHost } })
  t.is(mismatch.statusCode, 421, 'SNI naming a sibling app is refused')

  const foreign = await request(port, '/', { headers: { Host: host, 'X-Hive-Forwarded-SNI': 'example.com' } })
  t.is(foreign.statusCode, 421, 'non-app SNI is refused')

  const bound = await request(port, '/', { headers: appHeaders(host) })
  t.is(bound.statusCode, 200, 'edge-bound SNI==Host is admitted')

  // A forwarded-SNI header is only meaningful from a trusted proxy peer; a
  // loopback peer outside the proxy allowlist cannot present one.
  const untrusted = await startGatewayServer(t, {
    node: mockPublicNode(new Map([[keyHex, seededEntry(drive)]])),
    hiveAppHostSuffix: SUFFIX,
    hiveAppPublicKeys: [keyHex],
    hiveAppPublicVersions: { [keyHex]: drive.version },
    trustProxy: true,
    trustedProxyAddresses: ['10.9.9.9'],
    requireForwardedSNI: true
  })
  const forged = await request(untrusted.server.address().port, '/', { headers: appHeaders(host) })
  t.is(forged.statusCode, 421, 'untrusted peer cannot forward SNI')
})

test('conformance: 256 MiB per client-IP x app per 60 s egress budget trips 429', async (t) => {
  const keyHexA = newAppKey()
  const keyHexB = newAppKey()
  const hostA = appHostFor(keyHexA)
  const hostB = appHostFor(keyHexB)
  const cap = FROZEN_FINITE_LIMITS.gatewayMaxResponseBytes
  const big = Buffer.alloc(cap, 0x61)
  const small = Buffer.from('egress-probe\n')
  const server = await bootAppGateway(t, [
    { keyHex: keyHexA, drive: fakeDrive({ '/big.bin': big, '/small.txt': small }) },
    { keyHex: keyHexB, drive: fakeDrive({ '/small.txt': small }) }
  ], { requireForwardedSNI: true })
  const port = server.server.address().port

  // Four 64 MiB responses exactly fill the frozen 256 MiB window.
  for (let i = 1; i <= 4; i++) {
    const res = await request(port, '/big.bin', { headers: appHeaders(hostA) })
    t.is(res.statusCode, 200, `window response ${i}/4 is inside budget`)
    t.is(res.raw.byteLength, cap)
  }

  const tripped = await request(port, '/small.txt', { headers: appHeaders(hostA) })
  t.is(tripped.statusCode, 429, 'the next byte over 256 MiB is refused')
  t.is(tripped.body.error, 'Gateway byte-rate limit exceeded')
  t.is(tripped.headers['retry-after'], '60', 'refusal names the frozen 60 s window')

  const head = await request(port, '/big.bin', { method: 'HEAD', headers: appHeaders(hostA) })
  t.is(head.statusCode, 200, 'body-free HEAD is not charged egress')

  const otherClient = await request(port, '/small.txt', {
    headers: appHeaders(hostA, { 'X-Forwarded-For': '203.0.113.9' })
  })
  t.is(otherClient.statusCode, 200, 'budget is keyed per client IP')

  const otherApp = await request(port, '/small.txt', { headers: appHeaders(hostB) })
  t.is(otherApp.statusCode, 200, 'budget is keyed per app')
})

test('conformance: egress window rolls over (scaled probe, frozen 60 s asserted above)', async (t) => {
  const keyHex = newAppKey()
  const host = appHostFor(keyHex)
  const drive = fakeDrive({ '/small.txt': Buffer.alloc(600, 0x73) })
  const server = await bootAppGateway(t, [{ keyHex, drive }], {
    egressBytesPerWindow: 1024,
    egressWindowMs: 300
  })
  const port = server.server.address().port
  const headers = { Host: host }

  t.is((await request(port, '/small.txt', { headers })).statusCode, 200)
  const tripped = await request(port, '/small.txt', { headers })
  t.is(tripped.statusCode, 429, 'scaled budget trips like the frozen one')
  t.is(tripped.headers['retry-after'], '1', 'retry-after reflects the configured window')

  await new Promise(resolve => setTimeout(resolve, 350))
  t.is((await request(port, '/small.txt', { headers })).statusCode, 200, 'window rollover admits again')
})

test('conformance: response lifetime destroys stalled responses (scaled probe)', async (t) => {
  const hanging = {
    async close () {},
    handle (req, res) {
      return new Promise(resolve => res.once('close', resolve))
    }
  }
  const server = await startGatewayServer(t, { gateway: hanging, maxResponseLifetimeMs: 150 })
  const timeouts = []
  server.on('request-timeout', event => timeouts.push(event))

  const startedAt = Date.now()
  await new Promise((resolve) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: server.server.address().port,
      path: `/v1/hyper/${'a'.repeat(64)}/slow.bin`,
      agent: false
    }, (res) => {
      res.resume()
      res.on('close', resolve)
      res.on('end', resolve)
    })
    req.on('error', () => resolve())
    req.end()
  })
  const elapsed = Date.now() - startedAt

  t.ok(elapsed >= 150 && elapsed < 10_000, `stalled response is destroyed at the configured ceiling (${elapsed}ms)`)
  t.is(timeouts.length, 1, 'operator observes the lifetime trip once')
  t.is(timeouts[0].bucket, 'compatibility')
  // The slot release rides the server-side 'close' one event-loop turn after
  // the client's ECONNRESET; wait for the drain instead of racing it.
  let released = false
  const drainDeadline = Date.now() + 5_000
  while (!released && Date.now() < drainDeadline) {
    await new Promise(resolve => setImmediate(resolve))
    released = server._activeRequests === 0
  }
  t.ok(released, 'destroyed response releases its admission slot')
})

test('conformance: concurrency ceilings of 32 per app and 256 global return 503', async (t) => {
  let handleCalls = 0
  const hanging = {
    async close () {},
    handle (req, res) {
      handleCalls++
      return new Promise(resolve => res.once('close', resolve))
    }
  }
  const server = await startGatewayServer(t, { gateway: hanging, hiveAppHostSuffix: SUFFIX })
  const port = server.server.address().port
  const appHosts = Array.from({ length: 9 }, (_, i) => appHostFor(Buffer.alloc(32, i + 1).toString('hex')))

  const inFlight = []
  const fire = (host) => {
    const promise = new Promise((resolve) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: '/',
        agent: false,
        headers: { Host: host }
      }, (res) => {
        const chunks = []
        res.on('data', chunk => { chunks.push(chunk) })
        res.on('end', () => {
          const raw = Buffer.concat(chunks)
          let body = raw
          try { body = JSON.parse(raw.toString('utf8')) } catch (_) {}
          resolve({ statusCode: res.statusCode, headers: res.headers, body })
        })
      })
      req.on('error', () => resolve({ statusCode: 0 }))
      req.end()
      inFlight.push(req)
    })
    return promise
  }
  const waitForHandleCalls = async (expected) => {
    const startedAt = Date.now()
    while (Date.now() - startedAt < 10_000) {
      if (handleCalls >= expected) return
      await new Promise(resolve => setImmediate(resolve))
    }
    throw new Error(`gateway saw ${handleCalls}/${expected} in-flight requests`)
  }

  const answered = []
  for (let i = 0; i < FROZEN_MAX_IN_FLIGHT_PER_APP; i++) answered.push(fire(appHosts[0]))
  await waitForHandleCalls(FROZEN_MAX_IN_FLIGHT_PER_APP)

  const perApp = await request(port, '/', { headers: { Host: appHosts[0] } })
  t.is(perApp.statusCode, 503, '33rd in-flight request on one app origin is refused')
  t.is(perApp.body.error, 'Gateway busy')
  t.is(perApp.headers['retry-after'], '1')

  for (let app = 1; app < appHosts.length - 1; app++) {
    for (let i = 0; i < FROZEN_MAX_IN_FLIGHT_PER_APP; i++) answered.push(fire(appHosts[app]))
  }
  await waitForHandleCalls(FROZEN_MAX_IN_FLIGHT)

  const global = await request(port, '/', { headers: { Host: appHosts[appHosts.length - 1] } })
  t.is(global.statusCode, 503, '257th in-flight request across origins hits the global ceiling')
  t.is(global.body.error, 'Gateway busy')

  for (const req of inFlight) req.destroy()
  await Promise.allSettled(answered)
  let drained = false
  for (let i = 0; i < 100 && !drained; i++) {
    await new Promise(resolve => setImmediate(resolve))
    drained = server._activeRequests === 0
  }
  t.ok(drained, 'every admission slot drains when clients disconnect')
})

test('conformance: drive LRU holds at most 20 drives and retires evictions', async (t) => {
  const gateway = new HyperGateway({ config: {} })
  t.teardown(async () => { await gateway.close() })

  const opened = new Map()
  gateway._openDrive = async (keyHex) => {
    const drive = fakeDrive({})
    opened.set(keyHex, drive)
    gateway._drives.set(keyHex, drive)
    return drive
  }

  const keys = Array.from({ length: FROZEN_MAX_CACHED_DRIVES + 1 }, () => newAppKey())
  for (const keyHex of keys) {
    const lease = await gateway._acquireDrive(keyHex)
    t.ok(lease && lease.drive, 'dynamic open answers')
    lease.release()
  }

  t.is(gateway._drives.size, FROZEN_MAX_CACHED_DRIVES, 'cache is capped at the frozen 20')
  t.absent(gateway._drives.has(keys[0]), 'least recently used drive is evicted first')
  t.ok(gateway._drives.has(keys[keys.length - 1]), 'newest drive stays cached')

  for (let i = 0; i < 100 && !opened.get(keys[0]).closed; i++) {
    await new Promise(resolve => setImmediate(resolve))
  }
  t.ok(opened.get(keys[0]).closed, 'evicted drive is retired and closed')
  t.absent(opened.get(keys[keys.length - 1]).closed, 'cached drive stays open')
})

test('conformance: directory listing is bounded to 1000 entries and 1 MiB', async (t) => {
  const manyEntries = fakeDrive({})
  manyEntries.list = async function * () {
    for (let i = 0; i < 1500; i++) yield { key: `dir/file-${String(i).padStart(4, '0')}.txt` }
  }
  const capped = await bootLegacyGateway(t, manyEntries)
  const counted = await request(capped.port, capped.path('/'))
  t.is(counted.statusCode, 200)
  t.is(counted.body.entries.length, FROZEN_MAX_LISTING_ENTRIES + 1,
    'listing stops at 1000 entries plus the truncation marker')
  t.is(counted.body.entries[FROZEN_MAX_LISTING_ENTRIES], '... (truncated)')

  const wideEntries = fakeDrive({})
  wideEntries.list = async function * () {
    for (let i = 0; i < 2000; i++) yield { key: `dir/${'x'.repeat(1400)}${i}` }
  }
  const wide = await bootLegacyGateway(t, wideEntries)
  const bounded = await request(wide.port, wide.path('/'))
  t.is(bounded.statusCode, 200)
  t.ok(bounded.raw.byteLength <= FROZEN_MAX_LISTING_BYTES,
    `listing payload stays within 1 MiB (${bounded.raw.byteLength} bytes)`)
  t.ok(bounded.body.entries.includes('... (truncated by byte limit)'), 'byte-bound marker is emitted')
  t.absent(bounded.body.entries.includes('... (truncated)'), 'byte bound trips before the entry count')
})

test('conformance: drive operation timeout fails a hung read at the frozen 30 s', async (t) => {
  const hung = fakeDrive({})
  hung.entry = () => new Promise(() => {})
  const { port, path } = await bootLegacyGateway(t, hung)

  const startedAt = Date.now()
  const res = await request(port, path('/hang.bin'))
  const elapsed = Date.now() - startedAt
  t.is(res.statusCode, 502, 'hung read fails closed')
  t.is(res.body.error, 'Gateway read failed')
  t.ok(
    elapsed >= FROZEN_DRIVE_OPERATION_TIMEOUT_MS - 1000 && elapsed < 45_000,
    `read gave up at the 30 s drive-op ceiling (${elapsed}ms)`
  )
})

test('conformance: empty-drive wait abandons an unknown drive inside the frozen 20 s', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-gateway-conformance-'))
  const store = new Corestore(join(root, 'store'))
  const peer = new Corestore(join(root, 'peer'))
  const replication = { store: null, peer: null }
  t.teardown(async () => {
    if (replication.store) {
      try { replication.store.destroy() } catch (_) {}
      try { replication.peer.destroy() } catch (_) {}
    }
    try { await store.close() } catch (_) {}
    try { await peer.close() } catch (_) {}
    await rm(root, { recursive: true, force: true })
  })
  await store.ready()
  await peer.ready()

  // A one-directional replication pipe opens the core's channel but never
  // delivers an answer, so the empty drive's update pends exactly the way it
  // does behind a peer that advertises but never delivers.
  replication.store = store.replicate(true)
  replication.peer = peer.replicate(false)
  replication.store.pipe(replication.peer)

  const gateway = new HyperGateway({ config: {} }, { store })
  const server = http.createServer((req, res) => gateway.handle(req, res))
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections() } catch (_) {}
    }
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
  })

  const startedAt = Date.now()
  const res = await request(server.address().port, `/v1/hyper/${newAppKey()}/index.html`)
  const elapsed = Date.now() - startedAt
  t.is(res.statusCode, 404, 'a drive no peer delivers never fabricates content')
  t.is(res.body.error, 'Drive not available yet — still replicating')
  t.ok(
    elapsed >= FROZEN_EMPTY_DRIVE_WAIT_MS - 1000 && elapsed < FROZEN_DRIVE_OPERATION_TIMEOUT_MS,
    `empty drive is abandoned inside the 20 s wait, below the 30 s drive-op ceiling (${elapsed}ms)`
  )
})

test('conformance: incomplete headers are reaped at the frozen 10 s headersTimeout', async (t) => {
  const server = await startGatewayServer(t, {})
  t.is(server.server.headersTimeout, FROZEN_HEADERS_TIMEOUT_MS, 'listener pins the frozen headers timeout')

  const startedAt = Date.now()
  const received = await new Promise((resolve) => {
    const socket = net.connect(server.server.address().port, '127.0.0.1')
    const chunks = []
    socket.setTimeout(30_000, () => socket.destroy())
    socket.on('connect', () => socket.write('GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n'))
    socket.on('data', chunk => chunks.push(chunk))
    socket.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')))
    socket.on('error', () => {})
  })
  const elapsed = Date.now() - startedAt

  t.ok(
    elapsed >= FROZEN_HEADERS_TIMEOUT_MS - 500 && elapsed < 25_000,
    `incomplete headers are reaped at 10 s (${elapsed}ms)`
  )
  // The gateway answers every client error with one bounded 400 + close, so
  // the reaped socket must not hang open or answer with anything richer.
  t.ok(received.startsWith('HTTP/1.1 400 Bad Request'), 'reaped socket gets the bounded client-error answer')
  t.ok(received.includes('Connection: close'), 'reaped socket is closed')
})

// ─── TLS-edge items that need the pinned proxy runtime ─────────────────────
// Every limit above is enforced by the gateway process itself. Two frozen
// behaviors live one hop out, in the TLS-terminating proxy, and cannot be
// exercised headlessly against an in-process gateway; they keep gate-named
// skips so a relay build reports them honestly instead of claiming coverage.

// Gate G12 (proxy runtime): the default `421` vhost for unrelated TLS SNI is
// nginx configuration in the pinned production image; the spec owns its
// evidence through `nginx -T` structural inspection plus a pinned-IP TLS
// probe. The in-process halves — misdirected Host → 421 and forwarded
// SNI≠Host → 421 — are asserted above, and the simulated TLS edge in
// public-hive-gateway-live.test.js covers the same contract over a real
// handshake.
test.skip('conformance: default_server returns 421 for unrelated TLS SNI (G12 proxy runtime)', async (t) => {})

// Gate G8 (release evidence / canary observation window): the frozen 15-minute
// value and the destroy mechanism are asserted above (static tuple + scaled
// probe); holding one response open for 15 wall-clock minutes belongs to the
// canary soak, not a pre-admission suite.
test.skip('conformance: full-scale 15-minute response lifetime soak (G8 observation window)', async (t) => {})
