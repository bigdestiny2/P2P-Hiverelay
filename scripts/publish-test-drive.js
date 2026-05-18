#!/usr/bin/env node
// scripts/publish-test-drive.js
//
// Synthetic publisher for end-to-end fleet testing.
//
// Creates an ephemeral publisher keypair, builds a small Hyperdrive with
// deterministic content, signs a /api/v1/seed request, posts it to a chosen
// relay, and prints the appKey + publisher pubkey so subsequent tooling
// (observatory, custody-e2e) can watch the result propagate.
//
// Usage:
//
//   node scripts/publish-test-drive.js                          # default: utah, 1MB
//   node scripts/publish-test-drive.js --target singapore-1     # different relay
//   node scripts/publish-test-drive.js --size 10mb              # bigger drive
//   node scripts/publish-test-drive.js --label my-test          # custom appId
//   node scripts/publish-test-drive.js --roundrobin             # post to every relay
//   node scripts/publish-test-drive.js --watch 90               # poll observatory for 90s after publish
//
// What the relay sees:
//   POST /api/v1/seed
//   {
//     appKey, publisherPubkey, publisherSignature,
//     replicationFactor: 3, maxStorageBytes: <drive size * 4>,
//     ttlSeconds: 30 days, bountyRate: 0, revocable: true, durability: 0,
//     name, description, version, type: 'app'
//   }
//
// The drive itself sits in a tmpdir on this machine; the relay pulls blocks
// from us over Hyperswarm just like a real publisher. Drive is held open
// for --hold-seconds (default 300) so the relay has time to pull, then we
// exit and the drive becomes unreachable (deliberate: matches real
// publisher-goes-offline behavior, lets us watch how the fleet handles it).

import Hyperdrive from 'hyperdrive'
import Corestore from 'corestore'
import Hyperswarm from 'hyperswarm'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { tmpdir } from 'os'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { randomBytes } from 'crypto'

import { serializeSeedRequestForSigning } from '../packages/core/core/protocol/seed-request.js'

// ── Config ──────────────────────────────────────────────────────────────

const RELAYS = {
  utah:        { host: '144.172.101.215', port: 9100 },
  'utah-us':   { host: '144.172.91.26',   port: 9100 },
  'singapore-1': { host: '104.194.153.179', port: 9100 },
  'singapore-2': { host: '104.194.152.121', port: 9100 },
  bern:        { host: '45.59.123.112',   port: 9100 }
}

const args = parseArgs(process.argv.slice(2))
const TARGETS = resolveTargets(args)
const SIZE_BYTES = parseSize(args.size || '1mb')
const HOLD_SECONDS = Number(args['hold-seconds'] || 300)
// Synthetic drives self-expire: relay's _runCustodyExpiryPass unseeds
// storageClass:temporary entries once retainUntil passes. Default 60 min;
// --retain-mins 0 disables (permanent — only for deliberate load tests).
const RETAIN_MINS = args['retain-mins'] != null ? Number(args['retain-mins']) : 60
const RETAIN_MS = RETAIN_MINS > 0 ? RETAIN_MINS * 60 * 1000 : 0
const LABEL = args.label || `test-${Date.now().toString(36)}`
const OBSERVATORY_URL = args.observatory || process.env.OBSERVATORY_URL || 'http://45.59.123.112:9200'
const WATCH_SECONDS = args.watch != null ? Number(args.watch) : 0

console.log(`▸ Synthetic publish — ${LABEL}, ${formatBytes(SIZE_BYTES)} → ${TARGETS.join(', ')}\n`)

main().catch(err => {
  console.error('FATAL:', err.message)
  process.exit(1)
})

// ── Main ────────────────────────────────────────────────────────────────

async function main () {
  const storagePath = join(tmpdir(), `hiverelay-publish-${process.pid}-${Date.now()}`)
  await mkdir(storagePath, { recursive: true })

  const store = new Corestore(storagePath)
  const drive = new Hyperdrive(store)
  await drive.ready()

  const appKey = b4a.toString(drive.key, 'hex')
  const discoveryKey = b4a.toString(drive.discoveryKey, 'hex')

  console.log(`  drive ready`)
  console.log(`    appKey:       ${appKey}`)
  console.log(`    discoveryKey: ${discoveryKey}`)

  // Write content. /manifest.json describes the drive so the relay can
  // index it the same way real publishers do.
  await drive.put('/manifest.json', JSON.stringify({
    id: LABEL,
    name: LABEL,
    description: `Synthetic test drive (${formatBytes(SIZE_BYTES)}) — created ${new Date().toISOString()}`,
    version: '1.0.0',
    author: 'observatory-test-runner',
    contentType: 'app',
    privacyTier: 'public',
    categories: ['test', 'observatory']
  }))

  // Fill /payload.bin with deterministic-but-different-per-run bytes
  const payload = b4a.alloc(SIZE_BYTES)
  randomBytes(SIZE_BYTES).copy(payload)
  await drive.put('/payload.bin', payload)

  await drive.put('/README.md', `# ${LABEL}\n\nSynthetic drive for fleet end-to-end testing.\nPublished at ${new Date().toISOString()}.\nSize: ${formatBytes(SIZE_BYTES)}.\n`)

  const driveBytes = (drive.db?.core?.byteLength || 0) + (drive.blobs?.core?.byteLength || 0)
  console.log(`    size:         ${formatBytes(driveBytes)} (${drive.version} versions)`)

  // ── Publisher keypair ────────────────────────────────────────────────
  const publisherPub = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const publisherSec = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publisherPub, publisherSec)
  const publisherPubkey = b4a.toString(publisherPub, 'hex')
  console.log(`    publisher:    ${publisherPubkey}`)

  // ── Build + sign the seed request ───────────────────────────────────
  const replicationFactor = 3
  const maxStorageBytes = Math.max(driveBytes * 4, 64 * 1024 * 1024) // headroom × 4
  const ttlSeconds = 30 * 24 * 3600
  const revocable = true
  const durability = 0
  const unseedFreezeMs = 0
  const bountyRate = 0

  const sigMsg = {
    appKey: drive.key,
    discoveryKeys: [drive.discoveryKey],
    replicationFactor,
    maxStorageBytes,
    ttlSeconds,
    bountyRate,
    revocable,
    unseedFreezeMs,
    durability,
    publisherPubkey: publisherPub
  }
  const toSign = serializeSeedRequestForSigning(sigMsg)
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, toSign, publisherSec)

  const body = {
    appKey,
    discoveryKeys: [discoveryKey],
    replicationFactor,
    maxStorageBytes,
    ttlSeconds,
    bountyRate,
    revocable,
    unseedFreezeMs,
    durability,
    publisherPubkey,
    publisherSignature: b4a.toString(signature, 'hex'),
    name: LABEL,
    description: `Synthetic test drive (${formatBytes(SIZE_BYTES)})`,
    version: '1.0.0',
    type: 'app',
    privacyTier: 'public',
    // Self-expiring: storageClass:temporary + a short retainUntil makes
    // the relay's existing 60s _runCustodyExpiryPass auto-unseed this
    // entry once retainUntil passes — so synthetic test drives never
    // accumulate as permanent junk on the fleet. --retain-mins 0 opts
    // out (permanent; only for deliberate load tests). storageClass/
    // retainUntil are unsigned metadata (not in
    // serializeSeedRequestForSigning) so this does not affect the
    // publisher signature.
    ...(RETAIN_MS > 0
      ? { storageClass: 'temporary', retainUntil: Date.now() + RETAIN_MS }
      : {})
  }

  // ── Start swarm so the relay can actually pull blocks ────────────────
  const swarm = new Hyperswarm()
  swarm.on('connection', (conn) => store.replicate(conn))
  swarm.join(drive.discoveryKey, { server: true, client: true })
  await swarm.flush()
  console.log(`  swarm announced, awaiting relay pulls`)
  console.log()

  // ── POST to each target relay ────────────────────────────────────────
  for (const targetId of TARGETS) {
    const target = RELAYS[targetId]
    if (!target) {
      console.error(`  ✗ unknown target: ${targetId}`)
      continue
    }
    const url = `http://${target.host}:${target.port}/api/v1/seed`
    process.stdout.write(`  → ${targetId} (${target.host})  ... `)
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body)
      })
      const text = await res.text()
      let parsed = null
      try { parsed = JSON.parse(text) } catch (_) {}
      if (res.ok) {
        console.log(`OK ${res.status}  dk=${parsed?.discoveryKey?.slice(0, 12) || '?'} alreadySeeded=${parsed?.alreadySeeded === true}`)
      } else {
        console.log(`FAIL ${res.status}  ${text.slice(0, 200)}`)
      }
    } catch (err) {
      console.log(`ERR  ${err.message}`)
    }
  }
  console.log()

  // ── Optional observatory watch ──────────────────────────────────────
  if (WATCH_SECONDS > 0) {
    await watchObservatory(appKey, WATCH_SECONDS)
  }

  // ── Hold the drive open so relays can pull ───────────────────────────
  console.log(`  holding drive open for ${HOLD_SECONDS}s so relays can pull blocks ...`)
  console.log(`  (Ctrl-C to release early)`)
  await new Promise(resolve => setTimeout(resolve, HOLD_SECONDS * 1000))

  console.log(`  releasing drive`)
  try { await swarm.destroy() } catch (_) {}
  try { await drive.close() } catch (_) {}
  try { await store.close() } catch (_) {}
  try { await rm(storagePath, { recursive: true, force: true }) } catch (_) {}
  console.log(`done.`)
}

// ── Helpers ─────────────────────────────────────────────────────────────

async function watchObservatory (appKey, seconds) {
  // Bypass the observatory's truncated app list — query each relay's
  // catalog directly with a generous pageSize so we see anchors even
  // when the relay has hundreds of apps. The observatory is still the
  // right aggregation point for top-level metrics; per-app lookups go
  // straight to the source.
  console.log(`  watching fleet for anchor propagation (${seconds}s, polling every 5s) ...`)
  const start = Date.now()
  const seenAnchored = new Set()
  while ((Date.now() - start) / 1000 < seconds) {
    const checks = Object.entries(RELAYS).map(async ([id, target]) => {
      if (seenAnchored.has(id)) return
      try {
        const res = await fetch(`http://${target.host}:${target.port}/catalog.json?pageSize=1000`, {
          signal: AbortSignal.timeout(4000)
        })
        const cat = await res.json()
        const ours = (cat.apps || []).find(a => a.appKey === appKey)
        if (ours && ours.anchored) {
          seenAnchored.add(id)
          const elapsed = ((Date.now() - start) / 1000).toFixed(1)
          console.log(`    ✓ anchored on ${id} after ${elapsed}s (anchoredLength=${ours.anchoredLength})`)
        }
      } catch (err) {
        // transient — retry next tick
      }
    })
    await Promise.all(checks)
    if (seenAnchored.size === Object.keys(RELAYS).length) {
      console.log(`    all relays anchored — exiting watch early`)
      break
    }
    await new Promise(r => setTimeout(r, 5000))
  }
  console.log(`  watch finished. anchored on ${seenAnchored.size}/${Object.keys(RELAYS).length} relays: ${[...seenAnchored].join(', ') || '(none)'}`)
  console.log()
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

function resolveTargets (args) {
  if (args.roundrobin) return Object.keys(RELAYS)
  if (args.target) return [args.target]
  return ['utah'] // default
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
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB'
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}
