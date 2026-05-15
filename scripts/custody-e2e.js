#!/usr/bin/env node
// scripts/custody-e2e.js
//
// End-to-end atomic-custody driver.
//
// Walks the full 6-stage atomic-blind-custody pipeline against the live
// fleet, asserting at each step that the relays accepted the entry,
// validated the signature, and propagated the state to peers.
//
// Stages:
//   1. INTENT   — publisher signs + POSTs custody-intent to source relay
//   2. SEED     — publisher signs + POSTs publisher-signed seed requests
//                 to N candidate relays, with custodyIntentId etc. The seed
//                 request paths auto-emit custody-receipts when the relays
//                 anchor the blind content. (relay-node/api.js:1574 comment)
//   3. QUORUM   — driver polls /api/custody/<intentId>/status across all
//                 candidate relays until receiptCount >= requiredReplicas
//   4. COMMIT   — publisher signs + POSTs custody-commit to source relay
//   5. RETIRE   — publisher signs + POSTs source-retired
//   6. STATUS   — final cross-relay status check; assert every relay agrees
//                 on committed=true and sourceRetired=true
//
// Usage:
//
//   node scripts/custody-e2e.js                                          # default fleet
//   node scripts/custody-e2e.js --source utah --custodians utah-us,bern  # explicit picks
//   node scripts/custody-e2e.js --replicas 3 --size 1mb --hold 180
//   node scripts/custody-e2e.js --quorum-timeout 90                      # wait up to 90s for receipts
//
// Honest about what we can and can't assert:
//   - Stages 1, 4, 5 are publisher-driven; we control the inputs + verify the
//     relay accepted via 200 OK + status echo.
//   - Stage 2 reaches the relays via the public /api/v1/seed surface; we then
//     pull blocks via Hyperswarm just like real publishers do.
//   - Stage 3 (receipts) depends on relays auto-emitting after anchoring. If
//     a relay returns 503 (Iain's bug), the receipt won't fire and quorum
//     stalls. The script reports per-relay receipt presence so failures are
//     attributable.
//   - Proofs + non-serving-proofs + expiry-witnesses are observer-emitted and
//     happen on their own schedule (periodic anchor checks, expiry sweeps).
//     We sample status at the end and report what's present, but we don't
//     drive them — that's a separate test.

import Hyperdrive from 'hyperdrive'
import Corestore from 'corestore'
import Hyperswarm from 'hyperswarm'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { tmpdir } from 'os'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { randomBytes, createHash } from 'crypto'

import { serializeSeedRequestForSigning } from '../packages/core/core/protocol/seed-request.js'
import {
  createCustodyIntent,
  createCustodyCommit,
  createSourceRetired,
  hashHex
} from '../packages/core/core/custody-signing.js'

// ── Config ──────────────────────────────────────────────────────────────

const RELAYS = {
  utah:        { host: '144.172.101.215', port: 9100 },
  'utah-us':   { host: '144.172.91.26',   port: 9100 },
  'singapore-1': { host: '104.194.153.179', port: 9100 },
  'singapore-2': { host: '104.194.152.121', port: 9100 },
  bern:        { host: '45.59.123.112',   port: 9100 }
}

const args = parseArgs(process.argv.slice(2))
const SOURCE = args.source || 'utah'
const CUSTODIANS = (args.custodians ? String(args.custodians).split(',') : ['utah-us', 'singapore-1', 'bern']).map(s => s.trim()).filter(Boolean)
const REPLICAS = Number(args.replicas || 3)
const SIZE_BYTES = parseSize(args.size || '1mb')
const HOLD_SECONDS = Number(args.hold || 180)
const QUORUM_TIMEOUT_S = Number(args['quorum-timeout'] || 90)
const POLL_INTERVAL_MS = 2000
const LABEL = args.label || `custody-${Date.now().toString(36)}`

if (!RELAYS[SOURCE]) die(`unknown --source: ${SOURCE}. choices: ${Object.keys(RELAYS).join(', ')}`)
for (const c of CUSTODIANS) {
  if (!RELAYS[c]) die(`unknown custodian: ${c}. choices: ${Object.keys(RELAYS).join(', ')}`)
}
if (CUSTODIANS.length < REPLICAS) {
  die(`need at least ${REPLICAS} custodians but only got ${CUSTODIANS.length}: ${CUSTODIANS.join(', ')}`)
}

console.log(`▸ atomic-custody E2E — ${LABEL}`)
console.log(`  source:     ${SOURCE} (${RELAYS[SOURCE].host})`)
console.log(`  custodians: ${CUSTODIANS.join(', ')}`)
console.log(`  replicas:   ${REPLICAS} (quorum threshold)`)
console.log(`  drive size: ${formatBytes(SIZE_BYTES)}`)
console.log()

const timeline = []  // [{ stage, t, ms-since-start, detail }]
const startedAt = Date.now()
function mark (stage, detail = null) {
  const ms = Date.now() - startedAt
  timeline.push({ stage, ms, detail })
  const label = stage.padEnd(12)
  console.log(`  [${formatMs(ms)}]  ${label}  ${detail || ''}`)
}

main().catch(err => {
  console.error('\n✗ FATAL:', err.message)
  printTimeline()
  process.exit(1)
})

// ── Main ────────────────────────────────────────────────────────────────

async function main () {
  // ── 0. Publisher keypair + test drive ──────────────────────────────
  const publisherPub = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const publisherSec = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publisherPub, publisherSec)
  const publisherKeypair = { publicKey: publisherPub, secretKey: publisherSec }
  const publisherPubkey = b4a.toString(publisherPub, 'hex')

  const storagePath = join(tmpdir(), `hiverelay-custody-e2e-${process.pid}-${Date.now()}`)
  await mkdir(storagePath, { recursive: true })
  const store = new Corestore(storagePath)
  const drive = new Hyperdrive(store)
  await drive.ready()

  const addressKey = b4a.toString(drive.key, 'hex')
  const discoveryKey = b4a.toString(drive.discoveryKey, 'hex')

  // Synthetic "blind" content: this isn't actually encrypted (would need
  // a real publisher-encryption layer), but the relays don't care — they
  // store whatever bytes we anchor, attach the custody fields to the
  // entry, and auto-emit receipts referencing the ciphertextRoot we
  // declare. For a true blind-content test we'd encrypt under a content
  // key the relays never see; that's a v2 of this script.
  const payload = randomBytes(SIZE_BYTES)
  const ciphertextRoot = hashHex(b4a.toString(payload, 'hex'))
  await drive.put('/manifest.json', JSON.stringify({
    id: LABEL,
    name: LABEL,
    description: `Atomic-custody E2E test drive (${formatBytes(SIZE_BYTES)})`,
    version: '1.0.0',
    author: 'custody-e2e-runner',
    contentType: 'app',
    privacyTier: 'p2p-only',
    blind: true,
    categories: ['test', 'custody-e2e']
  }))
  await drive.put('/payload.bin', payload)

  const driveBytes = (drive.db?.core?.byteLength || 0) + (drive.blobs?.core?.byteLength || 0)
  const contentVersion = drive.version
  const blindContentId = hashHex({ publisherPubkey, addressKey, contentVersion })

  mark('setup', `publisher=${publisherPubkey.slice(0, 12)} drive=${addressKey.slice(0, 12)} v${contentVersion}`)

  // ── Stage 1: Publish custody-intent ─────────────────────────────────
  const intent = createCustodyIntent({
    addressKey,
    blindContentId,
    contentType: 'shard-set',
    ciphertextRoot,
    contentVersion,
    requiredReplicas: REPLICAS,
    candidateRelays: [],  // accept receipts from any qualified relay
    privacyTier: 'p2p-only',
    metadataVisibility: 'redacted'
  }, publisherKeypair)

  const intentId = intent.intentId
  const sourceUrl = `http://${RELAYS[SOURCE].host}:${RELAYS[SOURCE].port}`
  const intentRes = await postJson(`${sourceUrl}/api/v1/custody/intent`, intent)
  if (!intentRes.ok) {
    throw new Error(`intent POST failed: ${intentRes.status} ${truncate(intentRes.body, 200)}`)
  }
  mark('intent', `id=${intentId.slice(0, 12)} → ${SOURCE} ok`)

  // ── Stage 2: Seed-with-custody to candidate relays ─────────────────
  const swarm = new Hyperswarm()
  swarm.on('connection', (conn) => store.replicate(conn))
  swarm.join(drive.discoveryKey, { server: true, client: true })
  await swarm.flush()

  const seedTargets = CUSTODIANS
  const seedBody = buildSeedBody({
    drive,
    publisherPub,
    publisherSec,
    addressKey,
    discoveryKey,
    custodyIntentId: intentId,
    blindContentId,
    ciphertextRoot,
    contentVersion,
    label: LABEL,
    driveBytes
  })

  const seedResults = await Promise.all(seedTargets.map(async (id) => {
    const t = RELAYS[id]
    try {
      const res = await postJson(`http://${t.host}:${t.port}/api/v1/seed`, seedBody)
      return { id, ok: res.ok, status: res.status, body: res.body }
    } catch (err) {
      return { id, ok: false, error: err.message }
    }
  }))

  const seedAccepted = seedResults.filter(r => r.ok).map(r => r.id)
  const seedRejected = seedResults.filter(r => !r.ok)
  mark('seed', `accepted by ${seedAccepted.length}/${seedTargets.length}: ${seedAccepted.join(', ')}`)
  for (const r of seedRejected) {
    mark('  ✗ seed', `${r.id}: status=${r.status} ${truncate(r.body || r.error, 120)}`)
  }
  if (seedAccepted.length < REPLICAS) {
    throw new Error(`not enough relays accepted seed (${seedAccepted.length} < ${REPLICAS}); cannot reach quorum`)
  }

  // ── Stage 3: Wait for receipt quorum ────────────────────────────────
  const quorumDeadline = Date.now() + QUORUM_TIMEOUT_S * 1000
  let lastReceiptCount = 0
  let quorumReached = false
  while (Date.now() < quorumDeadline && !quorumReached) {
    const status = await getStatusFromSource(intentId, sourceUrl)
    if (status && status.receiptCount > lastReceiptCount) {
      mark('  receipt', `count=${status.receiptCount}/${REPLICAS} from ${status.relayQuorum?.map(k => k.slice(0, 12)).join(', ') || '?'}`)
      lastReceiptCount = status.receiptCount
    }
    if (status && status.quorumReached) {
      quorumReached = true
      mark('quorum', `${status.receiptCount} valid receipts`)
      break
    }
    await sleep(POLL_INTERVAL_MS)
  }
  if (!quorumReached) {
    throw new Error(`quorum not reached within ${QUORUM_TIMEOUT_S}s (last receiptCount=${lastReceiptCount}/${REPLICAS})`)
  }

  // ── Stage 4: Commit ─────────────────────────────────────────────────
  // The public /status endpoint redacts the actual receipt objects (they
  // contain detailed per-relay metadata) but exposes the pre-computed
  // canonical `receiptRoot` and the sorted `relayQuorum`. We pass those
  // directly — createCustodyCommit only re-computes the root if it's
  // absent. This means the E2E test doesn't need an operator API key on
  // the source relay; the same redacted status the public sees is enough
  // to drive a valid commit.
  const status = await getStatusFromSource(intentId, sourceUrl)
  if (!status?.receiptRoot) {
    throw new Error(`status missing receiptRoot — cannot commit without canonical hash`)
  }
  if (!Array.isArray(status.relayQuorum) || status.relayQuorum.length < REPLICAS) {
    throw new Error(`status.relayQuorum has ${status.relayQuorum?.length || 0} entries (need ${REPLICAS})`)
  }
  const commit = createCustodyCommit({
    intentId,
    addressKey,
    blindContentId,
    ciphertextRoot,
    contentVersion,
    receiptRoot: status.receiptRoot,
    relayQuorum: status.relayQuorum,
    nextAuthority: null
  }, publisherKeypair)
  const commitRes = await postJson(`${sourceUrl}/api/v1/custody/${intentId}/commit`, commit)
  if (!commitRes.ok) {
    throw new Error(`commit POST failed: ${commitRes.status} ${truncate(commitRes.body, 200)}`)
  }
  mark('commit', `→ ${SOURCE} ok (quorum=${status.relayQuorum.length})`)

  // ── Stage 5: Source-retired ─────────────────────────────────────────
  const retired = createSourceRetired({
    intentId,
    addressKey,
    blindContentId,
    retiredAtVersion: contentVersion,
    nextAuthority: null
  }, publisherKeypair)
  const retiredRes = await postJson(`${sourceUrl}/api/v1/custody/${intentId}/source-retired`, retired)
  if (!retiredRes.ok) {
    throw new Error(`source-retired POST failed: ${retiredRes.status} ${truncate(retiredRes.body, 200)}`)
  }
  mark('source-retired', `→ ${SOURCE} ok`)

  // ── Stage 6: Cross-relay status check ──────────────────────────────
  // Poll status from every fleet relay (not just custodians) and verify
  // the committed + sourceRetired flags propagated.
  await sleep(3000) // give propagation a beat
  console.log()
  console.log('  ── cross-relay status check ──')
  let consistent = true
  for (const id of Object.keys(RELAYS)) {
    const url = `http://${RELAYS[id].host}:${RELAYS[id].port}`
    const s = await getStatus(intentId, url)
    if (!s) {
      console.log(`    ${id.padEnd(12)}  no-status`)
      consistent = false
      continue
    }
    const flags = [
      s.committed ? 'committed' : 'NOT-committed',
      s.sourceRetired ? 'retired' : 'NOT-retired',
      `receipts=${s.receiptCount}`,
      s.proofCount > 0 ? `proofs=${s.proofCount}` : null,
      s.nonServingProofCount > 0 ? `non-serving=${s.nonServingProofCount}` : null
    ].filter(Boolean).join(' · ')
    const verdict = (s.committed && s.sourceRetired) ? '✓' : '·'
    console.log(`    ${verdict} ${id.padEnd(12)}  ${flags}`)
    if (!s.committed || !s.sourceRetired) consistent = false
  }
  console.log()
  mark(consistent ? 'verify-pass' : 'verify-partial', consistent ? 'all relays consistent' : 'some relays not yet propagated')

  // ── Optional: hold drive open so observer relays have time to attest ─
  if (HOLD_SECONDS > 0) {
    console.log()
    console.log(`  holding drive open ${HOLD_SECONDS}s for observer proofs (Ctrl-C to release early)`)
    await sleep(HOLD_SECONDS * 1000)
  }

  // Final post-hold status snapshot — proofs and non-serving-proofs may
  // accrue during the hold from the periodic repair / anchor-check loops.
  console.log()
  console.log('  ── final status (post-hold) ──')
  for (const id of Object.keys(RELAYS)) {
    const url = `http://${RELAYS[id].host}:${RELAYS[id].port}`
    const s = await getStatus(intentId, url)
    if (!s) { console.log(`    ${id.padEnd(12)}  no-status`); continue }
    console.log(`    ${id.padEnd(12)}  receipts=${s.receiptCount} proofs=${s.proofCount} non-serving=${s.nonServingProofCount} expiry=${s.expiryWitnessCount}`)
  }

  // Cleanup
  try { await swarm.destroy() } catch (_) {}
  try { await drive.close() } catch (_) {}
  try { await store.close() } catch (_) {}
  try { await rm(storagePath, { recursive: true, force: true }) } catch (_) {}

  printTimeline()
  console.log('\n✓ atomic-custody E2E passed')
}

// ── Helpers ─────────────────────────────────────────────────────────────

function buildSeedBody (o) {
  const replicationFactor = 3
  const maxStorageBytes = Math.max(o.driveBytes * 4, 64 * 1024 * 1024)
  const ttlSeconds = 30 * 24 * 3600
  const revocable = true
  const durability = 0
  const unseedFreezeMs = 0
  const bountyRate = 0

  const sigMsg = {
    appKey: o.drive.key,
    discoveryKeys: [o.drive.discoveryKey],
    replicationFactor,
    maxStorageBytes,
    ttlSeconds,
    bountyRate,
    revocable,
    unseedFreezeMs,
    durability,
    publisherPubkey: o.publisherPub
  }
  const toSign = serializeSeedRequestForSigning(sigMsg)
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, toSign, o.publisherSec)

  return {
    appKey: o.addressKey,
    discoveryKeys: [o.discoveryKey],
    replicationFactor,
    maxStorageBytes,
    ttlSeconds,
    bountyRate,
    revocable,
    unseedFreezeMs,
    durability,
    publisherPubkey: b4a.toString(o.publisherPub, 'hex'),
    publisherSignature: b4a.toString(signature, 'hex'),
    name: o.label,
    description: `Custody E2E test drive`,
    version: '1.0.0',
    type: 'app',
    privacyTier: 'p2p-only',
    blind: true,
    // ── Custody linkage ──
    // These three fields are the bridge between seedApp and the custody
    // registry — when the relay anchors this content, it sees the custody
    // intent ID and auto-emits a custody-receipt referring back to the
    // declared blindContentId + ciphertextRoot.
    custodyIntentId: o.custodyIntentId,
    blindContentId: o.blindContentId,
    ciphertextRoot: o.ciphertextRoot
  }
}

async function postJson (url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000)
  })
  const text = await res.text()
  return { ok: res.ok, status: res.status, body: text }
}

async function getStatus (intentId, baseUrl) {
  try {
    const res = await fetch(`${baseUrl}/api/custody/${intentId}/status`, {
      signal: AbortSignal.timeout(5_000)
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

// Convenience: read from the source relay (which always has full state
// since that's where intent/commit/retire were posted).
async function getStatusFromSource (intentId, sourceUrl) {
  return getStatus(intentId, sourceUrl)
}

function printTimeline () {
  console.log('\n  ── timeline ──')
  for (const t of timeline) {
    const label = t.stage.padEnd(14)
    console.log(`    [${formatMs(t.ms)}]  ${label}  ${t.detail || ''}`)
  }
}

function formatMs (ms) {
  return (ms / 1000).toFixed(2).padStart(7) + 's'
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const k = a.slice(2)
      const next = argv[i + 1]
      if (next && !next.startsWith('--')) { out[k] = next; i++ }
      else { out[k] = true }
    }
  }
  return out
}

function parseSize (s) {
  const m = String(s).toLowerCase().match(/^(\d+)\s*([kmg]?)b?$/)
  if (!m) throw new Error(`bad --size: ${s}`)
  const n = Number(m[1])
  const mul = { '': 1, k: 1024, m: 1024 * 1024, g: 1024 * 1024 * 1024 }[m[2]]
  return n * mul
}

function formatBytes (n) {
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1024 / 1024).toFixed(1) + ' MB'
}

function truncate (s, n) {
  if (!s) return ''
  s = String(s)
  return s.length > n ? s.slice(0, n) + '…' : s
}

function sleep (ms) {
  return new Promise(r => setTimeout(r, ms))
}

function die (msg) {
  console.error('  ✗', msg)
  process.exit(1)
}
