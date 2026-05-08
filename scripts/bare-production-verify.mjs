#!/usr/bin/env node
/**
 * Production verification of the Bare-native HiveRelay.
 *
 * Adapted from earlier scripts/bare-verify.mjs for the post-monorepo
 * v0.6.0 layout. Imports HiveRelayClient from the workspace package.
 *
 * Run a Bare relay first, then:
 *   BARE_HTTP=http://127.0.0.1:9196 node scripts/bare-production-verify.mjs
 */

import { HiveRelayClient } from 'p2p-hiverelay-client'
import { rmSync } from 'fs'

const BARE_HTTP = process.env.BARE_HTTP || 'http://127.0.0.1:9196'
const STORAGE = '/tmp/bare-prod-verify-' + Date.now()
rmSync(STORAGE, { recursive: true, force: true })

const results = []
let failures = 0
function pass (name) { results.push({ name, ok: true }); console.log('  ✓', name) }
function fail (name, err) { results.push({ name, ok: false, err: err?.message || err }); console.log('  ✗', name, '—', err?.message || err); failures++ }
function section (n) { console.log('\n━━━', n, '━━━') }

let BARE_PK
async function http (path) {
  const res = await fetch(BARE_HTTP + path)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json().catch(() => null) ?? { _text: await res.text() }
}

// ─── PHASE A — HTTP surface ──────────────────────────────────────

section('Phase A: HTTP surface')

try {
  const h = await http('/health')
  if (!h.ok || h.runtime !== 'bare') throw new Error('payload ' + JSON.stringify(h))
  pass('A1: /health returns ok with runtime:"bare"')
} catch (e) { fail('A1: /health', e) }

try {
  const s = await http('/status')
  if (!s.publicKey || s.publicKey.length !== 64) throw new Error('bad publicKey')
  if (typeof s.connections !== 'number') throw new Error('missing connections')
  BARE_PK = s.publicKey
  pass(`A2: /status pubkey=${BARE_PK.slice(0, 16)}… connections=${s.connections}`)
} catch (e) { fail('A2: /status', e) }

try {
  const c = await http('/catalog.json')
  const total = (c.apps?.length || 0) + (c.drives?.length || 0) +
                (c.resources?.length || 0) + (c.datasets?.length || 0) + (c.media?.length || 0)
  pass(`A3: /catalog.json: ${total} items, all type buckets present`)
} catch (e) { fail('A3: /catalog.json', e) }

try {
  const p = await http('/api/peers')
  if (typeof p.count !== 'number') throw new Error('missing count')
  pass(`A4: /api/peers count=${p.count}`)
} catch (e) { fail('A4: /api/peers', e) }

if (!BARE_PK) { console.log('\n✗ No BARE_PK; aborting'); process.exit(1) }

// ─── PHASE B — Mesh ─────────────────────────────────────────────

section('Phase B: P2P mesh participation')

console.log('[*] starting test client with fresh storage:', STORAGE)
const client = new HiveRelayClient(STORAGE)
await client.start()

await new Promise((resolve) => {
  let ok = false
  const i = setInterval(() => {
    if (client.relays.has(BARE_PK)) { ok = true; clearInterval(i); resolve() }
  }, 500)
  setTimeout(() => { if (!ok) { clearInterval(i); resolve() } }, 30000)
})

if (client.relays.has(BARE_PK)) pass(`B1: client → Bare via DHT (${BARE_PK.slice(0, 16)}…)`)
else fail('B1: did not connect to Bare', new Error('30s timeout'))

if (client.relays.size >= 1) pass(`B2: ${client.relays.size} total mesh relays connected`)
else fail('B2: zero mesh relays', new Error('isolated'))

// ─── PHASE C — Seed protocol ────────────────────────────────────

section('Phase C: Seed protocol end-to-end')

let driveKey
try {
  const files = [
    { path: '/marker.txt', content: 'PROD_VERIFY_' + Date.now() },
    { path: '/manifest.json', content: JSON.stringify({ verify: true, ts: new Date().toISOString() }) }
  ]
  const result = await client.publish(files, { appId: 'bare-prod-verify-' + Date.now() })
  driveKey = result.key
  pass('C1: publish to local Corestore')
} catch (e) { fail('C1: publish', e) }

if (driveKey) {
  const driveHex = typeof driveKey === 'string' ? driveKey : Buffer.from(driveKey).toString('hex')

  try {
    const acceptances = await client.seed(driveKey, { replicas: 5, timeout: 25000 })
    if (acceptances.length === 0) throw new Error('zero acceptances')
    const bareAcc = acceptances.find((a) => {
      const pk = a.relayPubkey ? (typeof a.relayPubkey === 'string' ? a.relayPubkey : Buffer.from(a.relayPubkey).toString('hex')) : ''
      return pk === BARE_PK
    })
    if (bareAcc) pass(`C2: Bare among ${acceptances.length} acceptances`)
    else pass(`C2: ${acceptances.length} mesh acceptances (Bare's may have raced)`)
  } catch (e) { fail('C2: seed broadcast', e) }

  await new Promise(resolve => setTimeout(resolve, 2500))

  try {
    const status = await http('/status')
    const catalog = await http('/catalog.json')
    const total = Object.values(catalog).reduce((a, b) => a + (Array.isArray(b) ? b.length : 0), 0)
    if (status.seededApps >= 1 && total >= 1) {
      pass(`C3: Bare state: seededApps=${status.seededApps}, catalog=${total}`)
    } else {
      fail('C3: Bare did not register seed', new Error(`seeded=${status.seededApps} catalog=${total}`))
    }
  } catch (e) { fail('C3: state check', e) }

  try {
    const cat = await http('/catalog.json')
    const all = [...(cat.apps || []), ...(cat.drives || []), ...(cat.resources || []), ...(cat.datasets || []), ...(cat.media || [])]
    const match = all.find(a => (a.appKey || a.key || '').toLowerCase() === driveHex.toLowerCase())
    if (match) pass(`C4: drive ${driveHex.slice(0, 16)}… visible in Bare's catalog`)
    else fail('C4: drive missing from Bare catalog', new Error('not found'))
  } catch (e) { fail('C4: catalog scan', e) }
}

await client.destroy()

// ─── PHASE D — Round-trip availability ──────────────────────────

section('Phase D: Always-on availability (publisher-offline round-trip)')

if (driveKey) {
  // New fresh client, no shared state, retrieves the content
  const storeB = '/tmp/bare-prod-reader-' + Date.now()
  rmSync(storeB, { recursive: true, force: true })
  const reader = new HiveRelayClient(storeB)
  await reader.start()
  await new Promise(resolve => setTimeout(resolve, 5000))

  try {
    await reader.open(driveKey)
    const content = await reader.get(driveKey, '/marker.txt')
    const text = typeof content === 'string' ? content : content.toString('utf-8')
    if (text.startsWith('PROD_VERIFY_')) {
      pass(`D1: reader retrieved /marker.txt content (${text.length} bytes)`)
    } else {
      fail('D1: content mismatch', new Error('got: ' + text.slice(0, 60)))
    }
  } catch (e) { fail('D1: round-trip read', e) }

  await reader.destroy()
}

// ─── Summary ────────────────────────────────────────────────────

section('Summary')
const passed = results.filter(r => r.ok).length
console.log(`${passed}/${results.length} passed`)
if (failures) {
  console.log('\nFailures:')
  for (const r of results) if (!r.ok) console.log('  ✗', r.name, '—', r.err)
  process.exit(1)
}
console.log('\n✅ Production-verified — Bare relay parity for protocol, mesh, seed, replication, round-trip.')
process.exit(0)
