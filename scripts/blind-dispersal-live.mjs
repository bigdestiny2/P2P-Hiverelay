#!/usr/bin/env node
/**
 * Live blind-shard dispersal across a REAL relay set.
 *
 * Splits a secret k-of-n, publishes a signed custody intent to each relay, PUTs
 * one opaque shard to each over /api/v1/shard, then reconstructs from any k — end
 * to end over the network. This is the fleet run of test/integration/
 * blind-custody-intent-e2e.test.js (same code path, real URLs).
 *
 *   node scripts/blind-dispersal-live.mjs <config.json>
 *
 * The config is YOURS and is never embedded here (keep it out of git):
 *   {
 *     "threshold": 3,                     // k
 *     "secret": "<optional 64-hex>",      // random if omitted
 *     "publisherSeed": "<optional 64-hex>",
 *     "relays": [                         // n custodians, in share-index order
 *       { "baseUrl": "https://relay-a:9100", "pubkey": "<relay node pubkey hex>", "apiKey": "<relay admin key>" },
 *       ...
 *     ]
 *   }
 *
 * PREREQS per target relay: running a build with the /api/v1/shard mount
 * (>= the v0.24.0 line), the `shard-store` service ENABLED, reachable over HTTPS.
 *
 * HONEST NOTE: dispersing across boxes ONE ENTITY controls proves the MECHANISM
 * live; it does NOT yet provide the security property (no single operator can
 * reconstruct) — that needs independent operators. This tool makes the mechanism
 * demonstrable; independence makes the guarantee real.
 */
import fs from 'node:fs'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { planDispersal, recoverSecret, shardAddressOf } from '../packages/client/blind-shards.js'
import { createHttpShardPut, createHttpShardFetch } from '../packages/client/shard-transport.js'
import { signShardPin, normalizeShardAddress } from '../packages/services/builtin/shard-store/index.js'
import { createCustodyIntent } from '../packages/core/core/custody-signing.js'

const cfgPath = process.argv[2]
if (!cfgPath) { console.error('usage: node scripts/blind-dispersal-live.mjs <config.json>'); process.exit(2) }
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'))
const relays = Array.isArray(cfg.relays) ? cfg.relays : []
const k = cfg.threshold
if (relays.length < 2 || !Number.isInteger(k) || k < 1 || k > relays.length) {
  console.error('config needs >=2 relays and 1 <= threshold <= relays.length'); process.exit(2)
}
for (const r of relays) {
  if (!r.baseUrl || !/^[0-9a-f]{64}$/i.test(r.pubkey || '')) {
    console.error('each relay needs { baseUrl, pubkey(64-hex), apiKey }'); process.exit(2)
  }
}

function keyPairFromSeed (seed) {
  const publicKey = b4a.alloc(32); const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}
const seed = cfg.publisherSeed ? b4a.from(cfg.publisherSeed, 'hex') : (() => { const s = b4a.alloc(32); sodium.randombytes_buf(s); return s })()
const publisher = keyPairFromSeed(seed)
const H = (c) => c.repeat(64)
const nonce = () => { const b = b4a.alloc(16); sodium.randombytes_buf(b); return b4a.toString(b, 'hex') }
const RETAIN = Date.now() + 30 * 24 * 60 * 60 * 1000

async function publishIntent (baseUrl, apiKey, intent) {
  const res = await fetch(baseUrl.replace(/\/+$/, '') + '/api/custody/intent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(apiKey ? { Authorization: 'Bearer ' + apiKey } : {}) },
    body: JSON.stringify(intent)
  })
  if (!res.ok) throw new Error('publish intent -> ' + baseUrl + ' failed: ' + res.status + ' ' + (await res.text()).slice(0, 120))
}

async function main () {
  const n = relays.length
  console.log(`\n▶ dispersing a secret ${k}-of-${n} across ${n} relays\n`)

  // 1. plan (no storage yet) — learn every shard address up front
  const plan = await planDispersal({ count: n, threshold: k, secret: cfg.secret })
  const shareAssignments = plan.shares.map((s) => ({ relayPubkey: relays[s.shareIndex - 1].pubkey.toLowerCase(), shareIndex: s.shareIndex }))
  const shareManifest = plan.shares.map((s) => ({ shareIndex: s.shareIndex, shard: s.shard, shareCommitment: s.shareCommitment }))

  // 2. one signed custody intent binding relay -> shareIndex -> shard
  const intent = createCustodyIntent({
    version: 2,
    blindContentId: H('b'),
    ciphertextRoot: plan.commitmentRoot,
    contentVersion: 1,
    requiredReplicas: n,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: k,
    commitmentRoot: plan.commitmentRoot,
    shareBundleKey: shardAddressOf(b4a.from(plan.commitmentRoot, 'hex')).slice('shard:'.length),
    shareAssignments,
    shareManifest,
    retainUntil: RETAIN
  }, publisher)
  console.log(`  custody intent ${intent.intentId}`)

  // 3. publish to every relay so its PUT authorizes
  for (const r of relays) { await publishIntent(r.baseUrl, r.apiKey, intent); console.log(`  ✓ intent published → ${r.baseUrl}`) }

  // 4. PUT each shard to its assigned relay
  for (const s of plan.shares) {
    const r = relays[s.shareIndex - 1]
    const put = createHttpShardPut({
      baseUrl: r.baseUrl,
      signPin: ({ hash }) => signShardPin({ reason: 'custody', hash: normalizeShardAddress(hash), custodyIntentId: intent.intentId, shareIndex: s.shareIndex, retainUntil: RETAIN, nonce: nonce() }, publisher)
    })
    const addr = await put(s.bytes, { shareIndex: s.shareIndex })
    console.log(`  ✓ share ${s.shareIndex} → ${r.baseUrl}  ${addr}`)
  }

  // 5. reconstruct from the FIRST k relays only (prove any-k works)
  const readSet = relays.slice(0, k)
  const rec = await recoverSecret({ shareManifest, threshold: k, fetch: createHttpShardFetch({ baseUrls: readSet.map((r) => r.baseUrl) }) })
  console.log(`\n  reader used ${readSet.length} relays → ${rec.ok ? 'reconstructed' : 'FAILED: ' + rec.reason}`)
  const ok = rec.ok && rec.key === plan.key
  console.log(`  key matches the dealer's secret: ${ok ? 'YES' : 'NO'}`)

  // 6. sanity: k-1 relays must NOT reconstruct
  const under = await recoverSecret({ shareManifest, threshold: k, fetch: createHttpShardFetch({ baseUrls: relays.slice(0, k - 1).map((r) => r.baseUrl) }) })
  console.log(`  ${k - 1} relays (below threshold) reconstruct: ${under.ok ? 'YES ✗ (BUG)' : 'no ✓'}`)

  console.log(`\n${ok && !under.ok ? '✅ LIVE DISPERSAL OK' : '❌ CHECK FAILED'} — mechanism proven across ${n} relays.`)
  console.log('   (Reminder: same-operator relays prove the mechanism, not the security property — that needs independent operators.)\n')
  process.exit(ok && !under.ok ? 0 : 1)
}

main().catch((e) => { console.error('\n✗ ' + (e && e.message)); process.exit(1) })
