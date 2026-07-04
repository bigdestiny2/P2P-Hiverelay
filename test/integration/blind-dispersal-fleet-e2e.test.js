/**
 * The live fleet run, in miniature: blind-shard dispersal across FOUR real
 * RelayNode instances over their HTTP APIs — NO stub anywhere.
 *
 * Each relay runs the shard-store service, ingests a published custody intent
 * into its real seeding registry, and authorizes each PUT through the PRODUCTION
 * resolver (RelayNode._resolveShardCustodyAssignment). This is exactly what
 * scripts/blind-dispersal-live.mjs does against the fleet — same code, real
 * nodes, on a local testnet DHT.
 *
 *   planDispersal → createCustodyIntent → POST /api/custody/intent (each relay)
 *     → PUT /api/v1/shard (custody-pin, real auth) → GET → reconstruct
 */
import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { planDispersal, recoverSecret } from '../../packages/client/blind-shards.js'
import { createHttpShardPut, createHttpShardFetch } from '../../packages/client/shard-transport.js'
import { signShardPin, normalizeShardAddress } from '../../packages/services/builtin/shard-store/index.js'
import { createCustodyIntent } from '../../packages/core/core/custody-signing.js'

// @hyperswarm/testnet teardown can throw a benign "Node destroyed" after asserts.
function benign (err) { return /Node destroyed|REQUEST_DESTROYED|Request destroyed|IO_SUSPENDED|Node was destroyed/i.test(String((err && (err.message || err.code)) || '')) }
process.on('uncaughtException', (e) => { if (!benign(e)) { console.error(e); process.exit(1) } })
process.on('unhandledRejection', (e) => { if (!benign(e)) { console.error(e); process.exit(1) } })

async function bringUpRelay (t, baseDir, testnet, i) {
  const apiKey = 'shard-e2e-' + randomBytes(6).toString('hex')
  const node = new RelayNode({
    storage: join(baseDir, 'relay-' + i),
    bootstrapNodes: testnet.bootstrap,
    enableAPI: true,
    apiPort: 0,
    apiHost: '127.0.0.1',
    apiKey,
    enableSeeding: true,
    enableServices: true,
    plugins: ['shard-store'],
    enableNetworkDiscovery: false,
    enableHolesail: false,
    gatewayServeBlind: false
  })
  await node.start()
  t.teardown(async () => { try { await node.stop() } catch {} })
  return {
    node,
    apiKey,
    baseUrl: 'http://127.0.0.1:' + node.api.server.address().port,
    pubkey: b4a.toString(node.swarm.keyPair.publicKey, 'hex')
  }
}

async function publishIntent (baseUrl, apiKey, intent) {
  const res = await fetch(baseUrl + '/api/custody/intent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + apiKey },
    body: JSON.stringify(intent)
  })
  if (!res.ok) throw new Error('publish intent failed: ' + res.status + ' ' + (await res.text()).slice(0, 200))
}

test('live blind-shard dispersal across 4 real RelayNodes (no stub)', { timeout: 120000 }, async (t) => {
  const baseDir = join(tmpdir(), 'shard-fleet-e2e-' + randomBytes(4).toString('hex'))
  await mkdir(baseDir, { recursive: true })
  const testnet = await createTestnet(3)
  t.teardown(async () => { try { await testnet.destroy() } catch {}; try { await rm(baseDir, { recursive: true, force: true }) } catch {} })

  const N = 4
  const K = 3
  const relays = []
  for (let i = 0; i < N; i++) relays.push(await bringUpRelay(t, baseDir, testnet, i))
  t.pass('brought up ' + N + ' real relay nodes with shard-store enabled')

  const publisher = (() => { const pk = b4a.alloc(32); const sk = b4a.alloc(64); sodium.crypto_sign_seed_keypair(pk, sk, b4a.alloc(32, 7)); return { publicKey: pk, secretKey: sk } })()

  // 1. plan (no storage) — learn addresses up front
  const plan = await planDispersal({ count: N, threshold: K })
  const shareAssignments = plan.shares.map((s) => ({ relayPubkey: relays[s.shareIndex - 1].pubkey, shareIndex: s.shareIndex }))
  const shareManifest = plan.shares.map((s) => ({ shareIndex: s.shareIndex, shard: s.shard, shareCommitment: s.shareCommitment }))

  // 2. sign the custody intent binding relay -> shareIndex -> shard
  const H = (c) => c.repeat(64)
  const intent = createCustodyIntent({
    version: 2,
    blindContentId: H('a'),
    ciphertextRoot: plan.commitmentRoot,
    contentVersion: 1,
    requiredReplicas: N,
    candidateRelays: relays.map((r) => r.pubkey),
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: K,
    commitmentRoot: plan.commitmentRoot,
    shareBundleKey: H('d'),
    shareAssignments,
    shareManifest
  }, publisher)

  // 3. publish it to EVERY relay's real seeding registry
  for (const r of relays) await publishIntent(r.baseUrl, r.apiKey, intent)
  t.pass('custody intent ' + intent.intentId.slice(0, 12) + '… published to all relays')

  // 4. PUT each opaque shard to its assigned relay over /api/v1/shard (real auth)
  for (const s of plan.shares) {
    const r = relays[s.shareIndex - 1]
    const put = createHttpShardPut({
      baseUrl: r.baseUrl,
      signPin: ({ hash }) => signShardPin({ reason: 'custody', hash: normalizeShardAddress(hash), custodyIntentId: intent.intentId, shareIndex: s.shareIndex, retainUntil: Date.now() + 3600000, nonce: s.shareIndex.toString(16).padStart(32, '0') }, publisher)
    })
    const addr = await put(s.bytes, { shareIndex: s.shareIndex })
    t.is(addr, s.shard, 'share ' + s.shareIndex + ' stored at its content address on relay ' + s.shareIndex)
  }

  // 5. reconstruct from ANY k relays over the wire
  const rec = await recoverSecret({ shareManifest, threshold: K, fetch: createHttpShardFetch({ baseUrls: [relays[0].baseUrl, relays[2].baseUrl, relays[3].baseUrl] }) })
  t.is(rec.ok, true, 'reader gathered k shards from real relays')
  t.is(rec.key, plan.key, 'reconstructed the exact secret across the live relay set')

  // 6. below threshold cannot reconstruct
  const under = await recoverSecret({ shareManifest, threshold: K, fetch: createHttpShardFetch({ baseUrls: [relays[0].baseUrl, relays[1].baseUrl] }) })
  t.is(under.ok, false, 'k-1 relays cannot reconstruct')
})
