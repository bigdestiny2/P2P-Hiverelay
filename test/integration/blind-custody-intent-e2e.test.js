/**
 * FULL custody-path dispersal over live relays — the exact flow the fleet run
 * executes, with NO stub authorization.
 *
 * A publisher builds a real signed custody intent (createCustodyIntent) binding
 * shareAssignments (relay -> shareIndex) + shareManifest (shareIndex -> shard),
 * "publishes" it to each relay, and disperse() PUTs each shard. Each relay
 * authorizes the PUT through the PRODUCTION resolver
 * (RelayNode._resolveShardCustodyAssignment reading its seeding registry) — so
 * this proves intent-create -> publish -> custody-authorized PUT -> recover end
 * to end against the real custody machinery. Swap the in-process relays for the
 * fleet's URLs + real publishCustodyIntent and it's the same code.
 */
import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { ShardStoreService, signShardPin, normalizeShardAddress } from '../../packages/services/builtin/shard-store/index.js'
import { disperse, recover } from '../../packages/client/blind-custody.js'
// The CORE signer supports the v2 PVSS custody fields (shareScheme/shareManifest/
// shareAssignments). The client mirror (packages/client/custody.js) does NOT yet
// (pending task: mirror shareManifest into the client signer) — so a node-run
// dealer uses core; a Bare/client-only dealer is blocked until that lands.
import { createCustodyIntent } from '../../packages/core/core/custody-signing.js'

function keyPair (seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seed))
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}
async function tmpStore (t) {
  const dir = await mkdtemp(join(tmpdir(), 'custody-intent-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const store = new Corestore(dir)
  t.teardown(() => store.close())
  return store
}
function shardRegistry (p) {
  return { services: new Map([['shard-store', { name: 'shard-store', status: 'running', capabilities: ['put', 'get', 'has', 'prove'], provider: p }]]) }
}
function mockNode (registry) {
  return { running: true, config: { plugins: [], trustProxy: true }, metrics: { getSummary () { return {} } }, seededApps: new Map(), appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } }, getStats () { return {} }, getHealthStatus () { return { healthy: true } }, serviceRegistry: registry, async stop () {}, async start () {}, on () {}, emit () {} }
}

const H = (c) => c.repeat(64)
const nonceFor = (i) => i.toString(16).padStart(32, '0')

test('blind-custody dispersal via a REAL signed custody intent + production resolver', async (t) => {
  // Shared "published custody intents" — stands in for each relay's seeding
  // registry. On the fleet this is populated by client.publishCustodyIntent().
  const published = new Map() // intentId -> signed intent
  const registryLike = { getCustodyIntent: (id) => published.get(id) || null }

  // n live relays; each authorizes via the ACTUAL production resolver.
  const relays = []
  for (let i = 1; i <= 4; i++) {
    const store = await tmpStore(t)
    const kp = keyPair(i)
    const relay = { kp, pubkey: kp.hex }
    relay.svc = new ShardStoreService({
      putAuth: ['custody'],
      resolveCustodyAssignment: (intentId, relayPubkey) =>
        RelayNode.prototype._resolveShardCustodyAssignment.call({ seedingRegistry: registryLike }, intentId, relayPubkey)
    })
    await relay.svc.start({ store, node: { keyPair: kp } })
    const api = new RelayAPI(mockNode(shardRegistry(relay.svc)), { apiPort: 0, apiHost: '127.0.0.1' })
    await api.start()
    relay.baseUrl = 'http://127.0.0.1:' + api.server.address().port
    t.teardown(async () => { await api.stop(); await relay.svc.stop() })
    relays.push(relay)
  }

  const publisher = keyPair(200)
  let intent = null

  // Build + sign the real custody intent from the dispersal plan, then "publish"
  // it to the relay (fleet: await client.publishCustodyIntent(relay.baseUrl, intent, {apiKey})).
  const publishIntent = async (_relay, fields) => {
    if (!intent) {
      intent = createCustodyIntent({
        version: 2, // unlocks the PVSS share-field allowlist (custody-signing.js:1031)
        blindContentId: H('b'),
        ciphertextRoot: fields.commitmentRoot,
        contentVersion: 1,
        requiredReplicas: fields.count,
        shareScheme: 'pvss-secp256k1-v1',
        shareThreshold: fields.threshold,
        commitmentRoot: fields.commitmentRoot,
        shareBundleKey: H('d'),
        shareAssignments: fields.shareAssignments,
        shareManifest: fields.shareManifest
      }, publisher)
      published.set(intent.intentId, intent)
    }
  }
  const signPin = ({ hash, shareIndex }) => signShardPin({
    reason: 'custody',
    hash: normalizeShardAddress(hash),
    custodyIntentId: intent.intentId,
    shareIndex,
    retainUntil: Date.now() + 3600000,
    nonce: nonceFor(shareIndex)
  }, publisher)

  // 3-of-4 dispersal across the live relays, authorized by the real intent.
  const out = await disperse(undefined, { relays, threshold: 3, signPin, publishIntent })
  t.ok(intent && /^[0-9a-f]{64}$/.test(intent.intentId), 'a real signed custody intent was built + published')
  t.is(out.shareManifest.length, 4)
  t.alike(out.shareManifest, intent.shareManifest, 'the intent binds exactly what was dispersed')

  // Reader reconstructs from any 3 of 4 relays over HTTP.
  const rec = await recover({ relays: [relays[0], relays[1], relays[3]], shareManifest: out.shareManifest, threshold: 3 })
  t.is(rec.ok, true)
  t.is(rec.key, out.key, 'reader reconstructs the exact secret through the real custody path')

  // 2 relays is below threshold.
  const two = await recover({ relays: [relays[0], relays[1]], shareManifest: out.shareManifest, threshold: 3 })
  t.is(two.ok, false)

  // A PUT whose intent was never published is refused by the production resolver.
  const orphanPin = signShardPin({
    reason: 'custody',
    hash: normalizeShardAddress(out.shareManifest[0].shard),
    custodyIntentId: H('f'),
    shareIndex: 1,
    retainUntil: Date.now() + 3600000,
    nonce: nonceFor(9)
  }, publisher)
  await t.exception(
    relays[0].svc.put({ ciphertext: b4a.toString(b4a.from('x'), 'base64'), pin: orphanPin }),
    /UNAUTHORIZED_PIN/
  )
})
