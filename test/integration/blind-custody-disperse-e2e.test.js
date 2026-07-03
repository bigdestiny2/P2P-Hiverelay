/**
 * App-facing blind-custody orchestration over live relays.
 *
 * planDispersal (blind-shards) computes every shard address without storing
 * anything; disperse()/recover() (blind-custody) tie planning + relay assignment
 * + the HTTP shard transport together so an app disperses a secret across a relay
 * set and a reader reconstructs it — with one call each.
 */
import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import {
  ShardStoreService, signShardPin, normalizeShardAddress
} from '../../packages/services/builtin/shard-store/index.js'
import { planDispersal } from '../../packages/client/blind-shards.js'
import { disperse, recover } from '../../packages/client/blind-custody.js'

function keyPair (seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seed))
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}

async function tmpStore (t) {
  const dir = await mkdtemp(join(tmpdir(), 'blind-custody-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const store = new Corestore(dir)
  t.teardown(() => store.close())
  return store
}

function shardRegistry (provider) {
  const entry = { name: 'shard-store', version: '0.1.0', status: 'running', capabilities: ['put', 'get', 'has', 'prove'], provider }
  return { services: new Map([['shard-store', entry]]) }
}

function mockNode (registry) {
  return {
    running: true,
    config: { storage: null, plugins: [], trustProxy: true },
    metrics: { getSummary () { return { uptime: 1 } } },
    seededApps: new Map(),
    appRegistry: { apps: new Map(), catalog () { return [] }, catalogForBroadcast () { return [] } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    serviceRegistry: registry,
    async stop () {},
    async start () {},
    on () {},
    emit () {}
  }
}

const INTENT_ID = 'face'.repeat(16)
const nonceFor = (i) => i.toString(16).padStart(32, '0')

// A relay object shaped for disperse() ({ baseUrl, pubkey }) that also carries the
// live ShardStoreService + its just-in-time custody assignment.
async function makeRelay (t, seed) {
  const store = await tmpStore(t)
  const kp = keyPair(seed)
  const relay = { kp, pubkey: kp.hex, assigned: null }
  relay.svc = new ShardStoreService({ putAuth: ['custody'], resolveCustodyAssignment: async () => relay.assigned })
  await relay.svc.start({ store, node: { keyPair: kp } })
  const api = new RelayAPI(mockNode(shardRegistry(relay.svc)), { apiPort: 0, apiHost: '127.0.0.1' })
  await api.start()
  relay.baseUrl = 'http://127.0.0.1:' + api.server.address().port
  t.teardown(async () => { await api.stop(); await relay.svc.stop() })
  return relay
}

test('planDispersal computes every shard address without storing anything', async (t) => {
  const plan = await planDispersal({ count: 5, threshold: 3 })
  t.is(plan.shares.length, 5)
  t.is(new Set(plan.shares.map((s) => s.shard)).size, 5, 'five distinct content addresses')
  for (const s of plan.shares) {
    t.ok(Number.isInteger(s.shareIndex) && s.shareIndex >= 1)
    t.ok(s.bytes && s.bytes.length, 'shard bytes are computed')
    t.ok(/^shard:[0-9a-f]{64}$/.test(s.shard))
    t.ok(/^[0-9a-f]{66}$/.test(s.shareCommitment))
  }
  t.ok(/^[0-9a-f]{64}$/.test(plan.key), 'dealer-private key derived')
})

test('disperse() + recover() one-call over a live relay set', async (t) => {
  const relays = []
  for (let i = 1; i <= 3; i++) relays.push(await makeRelay(t, i))
  const dealer = keyPair(300)

  const publishCalls = []
  // The app publishes its signed intent to each relay before PUTs. (These test
  // relays authorize via a stub resolver set in signPin, so this asserts the
  // orchestration calls publish once per relay, before any shard is stored.)
  let putsStarted = false
  const publishIntent = async (relay, intent) => {
    t.absent(putsStarted, 'intent is published before any shard PUT')
    publishCalls.push({ pubkey: relay.pubkey, shareCount: intent.shareManifest.length })
  }
  const signPin = async ({ hash, address, shareIndex, relay }) => {
    putsStarted = true
    relay.assigned = { shareIndex, shard: address } // stub authorization for the test relay
    return signShardPin({
      reason: 'custody',
      hash: normalizeShardAddress(hash),
      custodyIntentId: INTENT_ID,
      shareIndex,
      retainUntil: Date.now() + 3600000,
      nonce: nonceFor(shareIndex)
    }, dealer)
  }

  const out = await disperse(undefined, { relays, threshold: 2, signPin, publishIntent })

  t.is(out.shareManifest.length, 3)
  t.is(out.shareAssignments.length, 3)
  t.alike(out.shareAssignments.map((a) => a.relayPubkey), relays.map((r) => r.pubkey), 'share i assigned to relay i')
  t.is(publishCalls.length, 3, 'intent published to every relay first')

  // reader reconstructs from ANY 2 of the 3 relays
  const rec = await recover({ relays: [relays[0], relays[2]], shareManifest: out.shareManifest, threshold: 2 })
  t.is(rec.ok, true)
  t.is(rec.key, out.key, 'reader reconstructs the exact dealer-private key over the wire')

  // one relay is not enough
  const one = await recover({ relays: [relays[1]], shareManifest: out.shareManifest, threshold: 2 })
  t.is(one.ok, false)
  t.is(one.collected, 1)
})
