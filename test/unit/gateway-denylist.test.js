import test from 'brittle'
import http from 'http'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { Readable } from 'stream'
import { tmpdir } from 'os'
import { join } from 'path'
import { mkdtemp, rm, writeFile } from 'fs/promises'
import { HyperGateway } from 'p2p-hiverelay/gateway'
import { Federation } from 'p2p-hiverelay/core/federation.js'
import {
  GatewayDenylist,
  GATEWAY_DENYLIST_VERSION,
  GATEWAY_DENYLIST_REASONS,
  hashDriveKeyForDenylist,
  signDenylistEntry,
  verifyDenylistEntry
} from 'p2p-hiverelay/core/gateway-denylist.js'
import { issueExactAppContext } from '../../packages/core/gateway/exact-app-context.js'

const KEY = 'a'.repeat(64)
const OTHER_KEY = 'b'.repeat(64)

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function adminPubkeyHex (pair) {
  return b4a.toString(pair.publicKey, 'hex')
}

function entryFor (pair, fields = {}) {
  return signDenylistEntry({
    driveKey: KEY,
    reason: 'legal-order',
    expiresAt: Date.now() + 60_000,
    ...fields
  }, pair)
}

function fakeDrive (files = {}) {
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
      return { value: { blob: { byteLength: data.length } } }
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
    checkout () { return fakeDrive(files) },
    async * list () {}
  }
}

async function bootGatewayWithDrive (t, drive, gatewayOpts = {}, nodeOverrides = {}) {
  const denylist = new GatewayDenylist({ trustedAdmins: nodeOverrides.trustedAdmins || [] })
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true },
    seededApps: new Map([[KEY, { drive, blind: false, privacyTier: 'public' }]]),
    gatewayDenylist: denylist
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
    denylist,
    port: server.address().port,
    path: (filePath = '/data.bin') => `/v1/hyper/${KEY}${filePath}`
  }
}

async function bootGateway (t, files = { '/data.bin': Buffer.from('0123456789abcdef') }, gatewayOpts = {}, nodeOverrides = {}) {
  return bootGatewayWithDrive(t, fakeDrive(files), gatewayOpts, nodeOverrides)
}

async function bootExactGateway (t, files = { '/index.html': Buffer.from('<h1>hello</h1>') }, nodeOverrides = {}) {
  const drive = fakeDrive(files)
  const denylist = new GatewayDenylist({ trustedAdmins: nodeOverrides.trustedAdmins || [] })
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: false, hiveAppPublicKeys: [KEY] },
    seededApps: new Map([[KEY, {
      drive,
      blind: false,
      privacyTier: 'public',
      storageClass: 'persistent',
      availabilityClass: 'always-on'
    }]]),
    gatewayDenylist: denylist
  }
  const gateway = new HyperGateway(node)
  const server = http.createServer((req, res) => {
    const path = new URL(req.url, 'http://localhost').pathname
    gateway.handle(req, res, issueExactAppContext({
      appKey: KEY,
      path,
      byteMode: 'exact',
      publicAppKeys: [KEY]
    }))
  })

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

  return { gateway, denylist, port: server.address().port }
}

function request (port, method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path,
      agent: false,
      headers: { Connection: 'close', ...headers }
    }, (res) => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => {
        const raw = Buffer.concat(chunks)
        let body = raw
        try { body = JSON.parse(raw.toString('utf8')) } catch (_) {}
        resolve({ statusCode: res.statusCode, headers: res.headers, body, raw })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

// Starts a GET against a never-ending stream. Resolves { statusCode } once
// response headers arrive; the returned `finished` promise settles when the
// socket dies (abort) or completes.
function requestInFlight (port, path) {
  let resolveStarted
  let resolveFinished
  const started = new Promise(resolve => { resolveStarted = resolve })
  const finished = new Promise(resolve => { resolveFinished = resolve })
  let settled = false
  const finish = (value) => {
    if (settled) return
    settled = true
    resolveFinished(value)
  }
  const req = http.get({ hostname: '127.0.0.1', port, path, agent: false }, (res) => {
    resolveStarted(res.statusCode)
    res.on('data', () => {})
    res.on('end', () => finish({ statusCode: res.statusCode, aborted: false }))
    res.on('aborted', () => finish({ statusCode: res.statusCode, aborted: true }))
    res.on('close', () => finish({ statusCode: res.statusCode, aborted: true }))
    res.on('error', () => finish({ statusCode: res.statusCode, aborted: true }))
  })
  req.on('error', err => {
    if (err.code === 'ECONNRESET') finish({ statusCode: null, aborted: true })
    else finish({ statusCode: null, aborted: true, error: err.message })
  })
  return { started, finished }
}

// ─── Entry format ────────────────────────────────────────────────────

test('GatewayDenylist - entry format is versioned, hashed, signed, expiring, bounded-reason', (t) => {
  const admin = keyPair()
  const expiresAt = Date.now() + 60_000
  const entry = entryFor(admin, { expiresAt })

  t.is(entry.version, GATEWAY_DENYLIST_VERSION, 'envelope is versioned')
  t.is(entry.target.kind, 'drive', 'target kind is the bounded drive enum')
  t.is(entry.target.keyHash, hashDriveKeyForDenylist(KEY), 'target names the hashed drive key')
  t.is(entry.target.keyHash.length, 64, 'key hash is 64 hex')
  t.is(entry.reason, 'legal-order', 'reason is a bounded code')
  t.ok(Number.isFinite(entry.issuedAt), 'issuedAt present')
  t.is(entry.expiresAt, expiresAt, 'expiry present')
  t.ok(/^[0-9a-f]{64}$/.test(entry.admin.pubkey), 'admin pubkey in envelope')
  t.ok(/^[0-9a-f]{128}$/.test(entry.admin.signature), 'detached Ed25519 signature in envelope')

  const verify = verifyDenylistEntry(entry)
  t.ok(verify.valid, 'round-trip envelope verifies')
  t.is(verify.admin, adminPubkeyHex(admin), 'verified admin identity returned')
})

test('GatewayDenylist - channel never carries the plaintext drive key', (t) => {
  const admin = keyPair()
  const denylist = new GatewayDenylist({ trustedAdmins: [adminPubkeyHex(admin)] })
  const result = denylist.issue({ driveKey: KEY, reason: 'csam', expiresAt: Date.now() + 60_000 }, admin)
  t.ok(result.ok && result.added, 'issue ingests locally')

  const wire = JSON.stringify({ entries: denylist.list() })
  t.absent(wire.includes(KEY), 'no plaintext drive key anywhere in the gossip payload')
  t.ok(wire.includes(hashDriveKeyForDenylist(KEY)), 'hashed identifier present instead')
  t.absent(wire.includes(OTHER_KEY), 'unrelated keys absent')

  // A reader holding only the denylist cannot reverse the hash, but a
  // gateway holding a requested key can recompute it for enforcement.
  t.ok(denylist.isDenied(KEY), 'gateway-side hash check enforces')
  t.absent(denylist.isDenied(OTHER_KEY), 'other drives unaffected')
})

test('GatewayDenylist - tampered and badly-signed envelopes rejected', (t) => {
  const admin = keyPair()
  const denylist = new GatewayDenylist({ trustedAdmins: [adminPubkeyHex(admin)] })
  const good = entryFor(admin)

  const tamperedReason = { ...good, reason: 'copyright' }
  const v1 = verifyDenylistEntry(tamperedReason)
  t.absent(v1.valid, 'tampered reason breaks the signature')

  const tamperedHash = { ...good, target: { kind: 'drive', keyHash: hashDriveKeyForDenylist(OTHER_KEY) } }
  t.absent(verifyDenylistEntry(tamperedHash).valid, 'tampered key hash breaks the signature')

  const badSig = { ...good, admin: { ...good.admin, signature: '0'.repeat(128) } }
  t.absent(verifyDenylistEntry(badSig).valid, 'wrong signature rejected')

  const forged = entryFor(keyPair()) // valid signature, but from a key that did not sign THIS envelope shape
  forged.admin = { ...forged.admin, signature: good.admin.signature }
  t.absent(verifyDenylistEntry(forged).valid, 'transplanted signature rejected')

  const added = denylist.add(badSig)
  t.absent(added.ok, 'store refuses a badly-signed envelope')
  t.absent(denylist.isDenied(KEY), 'rejected envelope is never enforced')
})

test('GatewayDenylist - untrusted admin keys fail closed', (t) => {
  const admin = keyPair()
  const untrusted = keyPair()
  const denylist = new GatewayDenylist({ trustedAdmins: [adminPubkeyHex(admin)] })

  const entry = entryFor(untrusted) // cryptographically valid, wrong key
  t.ok(verifyDenylistEntry(entry).valid, 'envelope itself verifies')
  const result = denylist.add(entry)
  t.absent(result.ok, 'store refuses a non-allow-listed admin')
  t.is(result.reason, 'admin not on trusted allow-list', 'fail-closed reason surfaced')
  t.absent(denylist.isDenied(KEY), 'untrusted takedown never enforced')

  const emptyTrust = new GatewayDenylist()
  const again = emptyTrust.add(entryFor(admin))
  t.absent(again.ok, 'empty trusted-admin list merges nothing')
  t.absent(emptyTrust.isDenied(KEY), 'default posture cannot be used to censor')
})

test('GatewayDenylist - expired and future-dated entries rejected; lapsed entries stop enforcing', (t) => {
  const admin = keyPair()
  const pub = adminPubkeyHex(admin)
  const now = Date.now()
  const denylist = new GatewayDenylist({ trustedAdmins: [pub] })

  const expired = entryFor(admin, { issuedAt: now - 120_000, expiresAt: now - 60_000 })
  const vexp = verifyDenylistEntry(expired)
  t.absent(vexp.valid, 'already-expired envelope fails verification')
  t.is(vexp.reason, 'entry expired', 'expiry is the failure reason')
  t.absent(denylist.add(expired).ok, 'store refuses expired entries')

  const future = entryFor(admin, { issuedAt: now + 60 * 60_000, expiresAt: now + 2 * 60 * 60_000 })
  t.absent(verifyDenylistEntry(future).valid, 'future-dated issuance rejected (skew bound)')
  t.absent(denylist.add(future).ok, 'store refuses future-dated entries')

  const short = entryFor(admin, { issuedAt: now - 1000, expiresAt: now + 5000 })
  t.ok(denylist.add(short).ok, 'live entry merges')
  t.ok(denylist.isDenied(KEY, now), 'enforced while live')
  t.absent(denylist.isDenied(KEY, now + 5001), 'expiry lifts enforcement without any removal path')
  t.is(denylist.list(now + 5001).length, 0, 'lapsed entries pruned from the gossip view')
})

test('GatewayDenylist - reason codes are a bounded enum with no free text', (t) => {
  const admin = keyPair()
  t.ok(GATEWAY_DENYLIST_REASONS.includes('legal-order'), 'legal-order is a code')
  t.exception(() => entryFor(admin, { reason: 'this drive hosts illegal content, see case #42' }),
    /reason must be one of/, 'free-text reasons cannot be signed')

  const crafted = entryFor(admin)
  crafted.reason = 'defamatory nonsense not in the enum'
  const verify = verifyDenylistEntry(crafted)
  t.absent(verify.valid, 'out-of-enum reason rejected at verify')
  t.is(verify.reason, 'reason is not a bounded code', 'enum failure surfaced')

  crafted.reason = 'csam'
  crafted.target = { kind: 'app', keyHash: crafted.target.keyHash }
  t.absent(verifyDenylistEntry(crafted).valid, 'unknown target kind rejected')
})

test('GatewayDenylist - renewal with a newer issuedAt supersedes, older is idempotent', (t) => {
  const admin = keyPair()
  const pub = adminPubkeyHex(admin)
  const now = Date.now()
  const denylist = new GatewayDenylist({ trustedAdmins: [pub] })

  const first = entryFor(admin, { issuedAt: now - 1000, expiresAt: now + 1000 })
  t.ok(denylist.add(first).added, 'first entry stored')

  const duplicate = denylist.add(first)
  t.ok(duplicate.ok && !duplicate.added, 're-ingest is idempotent')

  const stale = entryFor(admin, { issuedAt: now - 2000, expiresAt: now + 10 * 60_000 })
  t.absent(denylist.add(stale).added, 'older issuance cannot widen')

  const renewed = entryFor(admin, { issuedAt: now, expiresAt: now + 10 * 60_000 })
  t.ok(denylist.add(renewed).added, 'newer issuance supersedes')
  t.ok(denylist.isDenied(KEY, now + 5000), 'renewed expiry governs enforcement')
})

// ─── Gateway enforcement ─────────────────────────────────────────────

test('GatewayDenylist - local takedown: immediate 451 on the path lane and LRU purged', async (t) => {
  const admin = keyPair()
  const ctx = await bootGateway(t, undefined, {}, { trustedAdmins: [adminPubkeyHex(admin)] })

  const before = await request(ctx.port, 'GET', ctx.path())
  t.is(before.statusCode, 200, 'drive served before takedown')

  // Simulate a warm legacy-path cache entry for the drive.
  const cachedDrive = fakeDrive({ '/data.bin': Buffer.from('0123456789abcdef') })
  ctx.gateway._drives.set(KEY, cachedDrive)
  t.is(ctx.gateway.getStats().cachedDrives, 1, 'LRU holds the drive before takedown')

  const events = []
  ctx.denylist.on('entry-added', event => events.push(event))
  const result = ctx.denylist.issue({ driveKey: KEY, reason: 'legal-order', expiresAt: Date.now() + 60_000 }, admin)
  t.ok(result.ok && result.added, 'operator takedown ingested')
  t.is(events.length, 1, 'entry-added fired for the purge hook')
  t.is(events[0].keyHash, hashDriveKeyForDenylist(KEY), 'event carries the hashed id only')

  const after = await request(ctx.port, 'GET', ctx.path())
  t.is(after.statusCode, 451, 'takedown drive is Unavailable For Legal Reasons')
  t.ok(after.body.takedown, 'response marks the takedown')
  t.is(after.body.reason, 'legal-order', 'bounded reason code surfaced')
  t.is(after.headers['cache-control'], 'no-store, max-age=0', '451 responses are not cached')

  const head = await request(ctx.port, 'HEAD', ctx.path())
  t.is(head.statusCode, 451, 'HEAD is denied identically')

  t.is(ctx.gateway.getStats().cachedDrives, 0, 'LRU purged synchronously on entry-added')
  await new Promise(resolve => setImmediate(resolve))
  t.ok(cachedDrive.closed, 'evicted drive is retired and closed')

  const other = await request(ctx.port, 'GET', `/v1/hyper/${'c'.repeat(64)}/data.bin`)
  t.absent(other.statusCode === 451, 'unrelated drives not collaterally denied')
})

test('GatewayDenylist - exact app-origin lane is denied before serving', async (t) => {
  const admin = keyPair()
  const ctx = await bootExactGateway(t, undefined, { trustedAdmins: [adminPubkeyHex(admin)] })

  const before = await request(ctx.port, 'GET', '/index.html')
  t.is(before.statusCode, 200, 'app bytes served before takedown')

  ctx.denylist.issue({ driveKey: KEY, reason: 'copyright', expiresAt: Date.now() + 60_000 }, admin)

  const after = await request(ctx.port, 'GET', '/index.html')
  t.is(after.statusCode, 451, 'exact app lane enforces the same takedown')
  t.ok(after.body.takedown, 'takedown marker on the exact lane')
  t.is(after.headers['x-hive-app-key'], KEY, 'app-origin headers preserved on the denial')
})

test('GatewayDenylist - in-flight stream for a taken-down drive is stopped', async (t) => {
  const admin = keyPair()
  const body = Buffer.alloc(1024, 7)
  const drive = fakeDrive({ '/big.bin': body })
  let streamStarted
  const streaming = new Promise(resolve => { streamStarted = resolve })
  drive.createReadStream = () => {
    streamStarted()
    // One chunk flushes the 200 headers, then the stream hangs mid-flight
    // (a slow origin drive) — long enough for the takedown to land.
    let pushed = false
    return new Readable({
      read () {
        if (pushed) return
        pushed = true
        this.push(body.subarray(0, 100))
      }
    })
  }
  const ctx = await bootGatewayWithDrive(t, drive, {}, { trustedAdmins: [adminPubkeyHex(admin)] })

  const inFlight = requestInFlight(ctx.port, ctx.path('/big.bin'))
  const statusAtHeaders = await inFlight.started
  t.is(statusAtHeaders, 200, 'stream started before the takedown')
  await streaming

  ctx.denylist.issue({ driveKey: KEY, reason: 'malware', expiresAt: Date.now() + 60_000 }, admin)

  const result = await inFlight.finished
  t.ok(result.aborted, 'in-flight stream torn down on takedown')

  const after = await request(ctx.port, 'GET', ctx.path('/big.bin'))
  t.is(after.statusCode, 451, 'subsequent requests fail closed')
})

// ─── Federation distribution ─────────────────────────────────────────

async function bootDenylistPeer (t, entries) {
  const server = http.createServer((req, res) => {
    if (req.url !== '/api/gateway/denylist') {
      res.statusCode = 404
      res.end()
      return
    }
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ schemaVersion: GATEWAY_DENYLIST_VERSION, entries, count: entries.length }))
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections() } catch (_) {}
    }
    await new Promise(resolve => server.close(resolve))
  })
  return { port: server.address().port }
}

test('GatewayDenylist - federation receipt from a peer relay is enforced without local config', async (t) => {
  const admin = keyPair()
  const pub = adminPubkeyHex(admin)
  const entry = entryFor(admin, { reason: 'legal-order' })
  const peer = await bootDenylistPeer(t, [entry])

  // Receiving relay: denylist store with ONLY the trust anchor configured —
  // no local takedown entries at all. Federation gossip must be enough.
  const node = new EventEmitter()
  node.config = { gatewayPublicOnlyPrivacyTier: true }
  node.seededApps = new Map([[KEY, { drive: fakeDrive({ '/data.bin': Buffer.from('0123456789abcdef') }), blind: false, privacyTier: 'public' }]])
  node.gatewayDenylist = new GatewayDenylist({ trustedAdmins: [pub] })
  const federation = new Federation({ node })

  const merged = []
  federation.on('denylist-merged', event => merged.push(event))
  await federation._pullGatewayDenylist(`http://127.0.0.1:${peer.port}`)

  t.ok(node.gatewayDenylist.isDenied(KEY), 'peer takedown merged from gossip')
  t.is(merged.length, 1, 'denylist-merged event fired')
  t.is(merged[0].count, 1, 'one entry merged')
  t.is(merged[0].rejected, 0, 'nothing rejected')

  // The merged entry is enforced at the receiving relay's gateway with no
  // local operator action.
  const gateway = new HyperGateway(node, {})
  const server = http.createServer((req, res) => gateway.handle(req, res))
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
  })
  const res = await request(server.address().port, 'GET', `/v1/hyper/${KEY}/data.bin`)
  t.is(res.statusCode, 451, 'gossiped takedown enforced on the receiving relay')
  t.is(res.body.reason, 'legal-order', 'reason code survives federation')
})

test('GatewayDenylist - federation gossip rejects forged, expired, and wrong-key entries', async (t) => {
  const admin = keyPair()
  const pub = adminPubkeyHex(admin)
  const rogue = keyPair()
  const now = Date.now()

  const forged = entryFor(admin)
  forged.admin = { ...forged.admin, signature: 'f'.repeat(128) }
  const wrongKey = entryFor(rogue, { driveKey: OTHER_KEY })
  const expired = entryFor(admin, { issuedAt: now - 120_000, expiresAt: now - 60_000 })
  const good = entryFor(admin, { driveKey: OTHER_KEY, reason: 'csam', expiresAt: now + 60_000 })

  const peer = await bootDenylistPeer(t, [forged, wrongKey, expired, good])

  const node = new EventEmitter()
  node.gatewayDenylist = new GatewayDenylist({ trustedAdmins: [pub] })
  const federation = new Federation({ node })

  const rejections = []
  federation.on('denylist-entry-rejected', event => rejections.push(event))
  const merged = []
  federation.on('denylist-merged', event => merged.push(event))
  await federation._pullGatewayDenylist(`http://127.0.0.1:${peer.port}`)

  t.is(rejections.length, 3, 'forged + wrong-key + expired each rejected')
  t.absent(node.gatewayDenylist.isDenied(KEY), 'forged entry never enforced')
  t.ok(node.gatewayDenylist.isDenied(OTHER_KEY), 'the one valid entry merged')
  t.is(merged[0].count, 1, 'exactly one merge')
  t.is(merged[0].rejected, 3, 'rejection accounting surfaced')
})

test('GatewayDenylist - federation pull is a no-op without a node denylist and skips junk payloads', async (t) => {
  const bareNode = new EventEmitter()
  const fed = new Federation({ node: bareNode })
  await fed._pullGatewayDenylist('http://127.0.0.1:1') // must not throw

  const junk = await bootDenylistPeer(t, [])
  const server = http.createServer((req, res) => {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end('{"notEntries":true}')
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    await new Promise(resolve => server.close(resolve))
  })

  const node = new EventEmitter()
  node.gatewayDenylist = new GatewayDenylist({ trustedAdmins: [] })
  const federation = new Federation({ node })
  await federation._pullGatewayDenylist(`http://127.0.0.1:${server.address().port}`)
  t.is(node.gatewayDenylist.list().length, 0, 'malformed payload merges nothing')

  await federation._pullGatewayDenylist(`http://127.0.0.1:${junk.port}`)
  t.is(node.gatewayDenylist.list().length, 0, 'empty channel merges nothing')
})

// ─── Persistence ─────────────────────────────────────────────────────

test('GatewayDenylist - takedowns survive restart with the trust gate re-applied', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-denylist-'))
  t.teardown(async () => { await rm(dir, { recursive: true, force: true }) })
  const storagePath = join(dir, 'gateway-denylist.json')

  const admin = keyPair()
  const pub = adminPubkeyHex(admin)
  const other = keyPair()
  const otherPub = adminPubkeyHex(other)

  const first = new GatewayDenylist({ trustedAdmins: [pub, otherPub], storagePath })
  t.ok(first.issue({ driveKey: KEY, reason: 'legal-order', expiresAt: Date.now() + 60_000 }, admin).added, 'admin entry stored')
  t.ok(first.issue({ driveKey: OTHER_KEY, reason: 'csam', expiresAt: Date.now() + 60_000 }, other).added, 'second admin entry stored')
  await first.save({ throwOnError: true })

  // Restart with the same trust anchors: both takedowns still enforced.
  const restarted = new GatewayDenylist({ trustedAdmins: [pub, otherPub], storagePath })
  await restarted.load()
  t.ok(restarted.isDenied(KEY), 'local takedown persisted across restart')
  t.ok(restarted.isDenied(OTHER_KEY), 'federated takedown persisted across restart')

  // Restart after removing one admin from the allow-list: that admin's
  // entries must not come back — the gate is re-evaluated on load.
  const narrowed = new GatewayDenylist({ trustedAdmins: [pub], storagePath })
  const skipped = []
  narrowed.on('persistence-error', event => skipped.push(event))
  await narrowed.load()
  t.ok(narrowed.isDenied(KEY), 'still-trusted admin entry survives')
  t.absent(narrowed.isDenied(OTHER_KEY), 'distrusted admin entry dropped on load')
  t.ok(skipped.some(event => event.phase === 'load-skip-invalid'), 'drop is observable')

  // A corrupted file must never crash startup.
  await writeFile(storagePath, '{not json', 'utf8')
  const corrupt = new GatewayDenylist({ trustedAdmins: [pub], storagePath })
  const errors = []
  corrupt.on('persistence-error', event => errors.push(event))
  await corrupt.load()
  t.is(corrupt.list().length, 0, 'corrupt file loads empty')
  t.ok(errors.some(event => event.phase === 'parse'), 'corruption is observable')
})
