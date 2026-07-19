/**
 * End-to-end gateway-denylist federation test against a real testnet.
 *
 * Verifies the full takedown-propagation path with two real RelayNodes:
 * a takedown issued on the source relay is served as signed envelopes at
 * /api/gateway/denylist, pulled by the following relay through the normal
 * federation poll, and enforced by the receiving relay's HTTP gateway —
 * without any local takedown config on the receiver beyond the trust anchor.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { hashDriveKeyForDenylist } from 'p2p-hiverelay/core/gateway-denylist.js'
import http from 'http'
import path from 'path'
import { tmpdir } from 'os'
import { randomBytes } from 'crypto'
import { mkdirSync } from 'fs'

function tmpStorage () {
  const storage = path.join(tmpdir(), 'hiverelay-denylist-fed-' + randomBytes(8).toString('hex'))
  mkdirSync(storage, { recursive: true })
  return storage
}

function pickPort () {
  return 50000 + Math.floor(Math.random() * 10000)
}

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function createNode (testnet, overrides = {}) {
  return new RelayNode({
    storage: tmpStorage(),
    bootstrapNodes: testnet.bootstrap,
    enableMetrics: false,
    ...overrides
  })
}

function getJson (port, route) {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port, path: route, agent: false }, (res) => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8')
        let body = null
        try { body = JSON.parse(raw) } catch (_) {}
        resolve({ statusCode: res.statusCode, body, raw })
      })
    })
    req.on('error', reject)
  })
}

test('e2e gateway denylist: takedown on one relay propagates through federation and is enforced on the follower', async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const admin = keyPair()
  const adminPub = b4a.toString(admin.publicKey, 'hex')
  const takenDownKey = randomBytes(32).toString('hex')

  const srcPort = pickPort()
  const src = createNode(testnet, { enableAPI: true, apiPort: srcPort, acceptMode: 'open' })
  // Follower: trusts ONLY the admin pubkey — no local takedown entries.
  const sub = createNode(testnet, {
    acceptMode: 'review',
    enableAPI: false,
    gatewayDenylist: { trustedAdmins: [adminPub] }
  })

  t.teardown(async () => {
    await src.stop()
    await sub.stop()
    await testnet.destroy()
  })

  await src.start()
  await sub.start()

  // Source relay itself does not trust the admin key — its own gateway would
  // keep serving. The signed channel is what carries authority, not the
  // relay that issued it.
  t.absent(src.gatewayDenylist.isDenied(takenDownKey), 'source does not enforce without local trust')
  t.absent(sub.gatewayDenylist.isDenied(takenDownKey), 'follower clean before gossip')

  // Operator issues the takedown on the source relay. Until the relay's own
  // trust list names the admin key, even a locally-signed entry is refused.
  const issued = src.gatewayDenylist.issue({
    driveKey: takenDownKey,
    reason: 'legal-order',
    expiresAt: Date.now() + 60 * 60_000
  }, admin)
  t.absent(issued.ok, 'untrusted source relay refuses its own admin issue')
  src.gatewayDenylist.trustedAdmins.add(adminPub)
  const issuedTrusted = src.gatewayDenylist.issue({
    driveKey: takenDownKey,
    reason: 'legal-order',
    expiresAt: Date.now() + 60 * 60_000
  }, admin)
  t.ok(issuedTrusted.ok && issuedTrusted.added, 'takedown issued once trusted')

  // The gossip surface serves signed envelopes naming hashed keys only.
  const wire = await getJson(srcPort, '/api/gateway/denylist')
  t.is(wire.statusCode, 200, 'denylist endpoint served')
  t.is(wire.body.count, 1, 'one entry published')
  t.is(wire.body.entries[0].target.keyHash, hashDriveKeyForDenylist(takenDownKey), 'hashed target on the wire')
  t.absent(wire.raw.includes(takenDownKey), 'no plaintext drive key on the wire')
  t.is(wire.body.entries[0].reason, 'legal-order', 'bounded reason on the wire')

  // Follower pulls through the normal federation poll path.
  sub.federation.follow(`http://127.0.0.1:${srcPort}`)
  let merged = null
  sub.federation.on('denylist-merged', (event) => { merged = event })
  await sub.federation._pollAll()

  t.ok(sub.gatewayDenylist.isDenied(takenDownKey), 'takedown enforced on follower after gossip')
  t.ok(merged && merged.count === 1 && merged.rejected === 0, 'merge accounting reported')

  // Restart persistence: the merged entry survives a follower restart.
  await sub.gatewayDenylist.save({ throwOnError: true })
  const { GatewayDenylist } = await import('p2p-hiverelay/core/gateway-denylist.js')
  const reloaded = new GatewayDenylist({
    trustedAdmins: [adminPub],
    storagePath: sub.gatewayDenylist.storagePath
  })
  await reloaded.load()
  t.ok(reloaded.isDenied(takenDownKey), 'gossiped takedown persists across restart')
})

test('e2e gateway denylist: follower with no trust anchors merges nothing', async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const admin = keyPair()
  const adminPub = b4a.toString(admin.publicKey, 'hex')
  const takenDownKey = randomBytes(32).toString('hex')

  const srcPort = pickPort()
  const src = createNode(testnet, {
    enableAPI: true,
    apiPort: srcPort,
    acceptMode: 'open',
    gatewayDenylist: { trustedAdmins: [adminPub] }
  })
  const sub = createNode(testnet, { acceptMode: 'review', enableAPI: false })

  t.teardown(async () => {
    await src.stop()
    await sub.stop()
    await testnet.destroy()
  })

  await src.start()
  await sub.start()

  src.gatewayDenylist.issue({
    driveKey: takenDownKey,
    reason: 'csam',
    expiresAt: Date.now() + 60 * 60_000
  }, admin)

  sub.federation.follow(`http://127.0.0.1:${srcPort}`)
  let rejected = null
  sub.federation.on('denylist-entry-rejected', (event) => { rejected = event })
  await sub.federation._pollAll()

  t.absent(sub.gatewayDenylist.isDenied(takenDownKey), 'default-trust follower cannot be censored by gossip')
  t.ok(rejected && rejected.reason === 'admin not on trusted allow-list', 'fail-closed rejection observed')
})
