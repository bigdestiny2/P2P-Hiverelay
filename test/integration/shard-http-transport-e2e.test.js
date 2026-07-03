/**
 * Over-the-wire proof: blind-shard dispersal + recovery through the REAL mounted
 * /api/v1/shard HTTP surface (not in-process svc calls).
 *
 * A dealer disperses a secret across 3 live RelayAPI servers via createHttpShardPut
 * (signs a custody pin, POSTs opaque bytes); a reader reconstructs from any k via
 * createHttpShardFetch (GETs by content address). Proves the client transport
 * composes with disperseSecret/recoverSecret against the actual relay adapter.
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
import { disperseSecret, recoverSecret } from '../../packages/client/blind-shards.js'
import { createHttpShardPut, createHttpShardFetch } from '../../packages/client/shard-transport.js'

function keyPair (seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seed))
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}

async function tmpStore (t) {
  const dir = await mkdtemp(join(tmpdir(), 'shard-http-'))
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

const INTENT_ID = 'c0de'.repeat(16)
const nonceFor = (i) => i.toString(16).padStart(32, '0')

// One relay = a real ShardStoreService behind a real RelayAPI HTTP server.
async function makeRelay (t, seed) {
  const store = await tmpStore(t)
  const kp = keyPair(seed)
  const relay = { kp, assigned: null }
  relay.svc = new ShardStoreService({ putAuth: ['custody'], resolveCustodyAssignment: async () => relay.assigned })
  await relay.svc.start({ store, node: { keyPair: kp } })
  const api = new RelayAPI(mockNode(shardRegistry(relay.svc)), { apiPort: 0, apiHost: '127.0.0.1' })
  await api.start()
  relay.baseUrl = 'http://127.0.0.1:' + api.server.address().port
  t.teardown(async () => { await api.stop(); await relay.svc.stop() })
  return relay
}

test('blind-shard dispersal + recovery over the real /api/v1/shard HTTP transport', async (t) => {
  const relays = []
  for (let i = 1; i <= 3; i++) relays.push(await makeRelay(t, i))
  const dealer = keyPair(200)

  // signPin binds the shard to its assigned relay just-in-time, then signs the pin.
  const mkSignPin = (relay, shareIndex) => async ({ hash, address }) => {
    relay.assigned = { shareIndex, shard: address }
    return signShardPin({
      reason: 'custody',
      hash: normalizeShardAddress(hash),
      custodyIntentId: INTENT_ID,
      shareIndex,
      retainUntil: Date.now() + 3600000,
      nonce: nonceFor(shareIndex)
    }, dealer)
  }
  // route share i -> relay i, POST over HTTP via the transport
  const put = (bytes, meta) => {
    const relay = relays[meta.shareIndex - 1]
    return createHttpShardPut({ baseUrl: relay.baseUrl, signPin: mkSignPin(relay, meta.shareIndex) })(bytes, meta)
  }

  // 1. Disperse 2-of-3 across the live relays, entirely over HTTP.
  const dispersed = await disperseSecret({ count: 3, threshold: 2, put })
  t.is(dispersed.shareManifest.length, 3)

  // 2. A reader reconstructs from ANY k relays over HTTP (here relays 1 and 3).
  const recovered = await recoverSecret({
    shareManifest: dispersed.shareManifest,
    threshold: 2,
    fetch: createHttpShardFetch({ baseUrls: [relays[0].baseUrl, relays[2].baseUrl] })
  })
  t.is(recovered.ok, true)
  t.is(recovered.key, dispersed.key, 'reader reconstructs the exact secret over the wire')
  t.is(recovered.used, 2)

  // 3. A single relay is not enough (blind-custody invariant holds over HTTP too).
  const one = await recoverSecret({
    shareManifest: dispersed.shareManifest,
    threshold: 2,
    fetch: createHttpShardFetch({ baseUrls: [relays[1].baseUrl] })
  })
  t.is(one.ok, false)
  t.is(one.collected, 1)

  // 4. Content-neutral GET: a shard is retrievable by content address, no auth.
  const bytes = await createHttpShardFetch({ baseUrls: relays.map(r => r.baseUrl) })(dispersed.shareManifest[0].shard)
  t.ok(bytes && bytes.length, 'shard is retrievable by content address over HTTP')
})

test('createHttpShardPut rejects when the relay refuses the pin', async (t) => {
  const relay = await makeRelay(t, 7)
  const dealer = keyPair(201)
  // relay is assigned share 2; a pin claiming share 5 must be refused (403 -> throw)
  const put = createHttpShardPut({
    baseUrl: relay.baseUrl,
    signPin: async ({ hash, address }) => {
      relay.assigned = { shareIndex: 2, shard: address }
      return signShardPin({
        reason: 'custody',
        hash: normalizeShardAddress(hash),
        custodyIntentId: INTENT_ID,
        shareIndex: 5,
        retainUntil: Date.now() + 3600000,
        nonce: nonceFor(5)
      }, dealer)
    }
  })
  await t.exception(put(b4a.from('opaque-share', 'utf8'), { shareIndex: 5 }), /shard PUT failed \(403/)
})
