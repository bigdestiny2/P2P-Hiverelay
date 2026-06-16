#!/usr/bin/env node

/**
 * publish-catalog-bee.js — build a REPLICABLE, SIGNED Hyperbee catalog from a
 * relay's HTTP /catalog.json and PIN it on that relay.
 *
 * Why: today a relay's catalog is only reachable by polling HTTP
 * /catalog.json. A catalog *bee* is a Hyperbee (B-tree over a Hypercore)
 * that peers / PearBrowser can replicate over the P2P stack and verify
 * offline — keyed by appKey → the relay's catalog entry. This script is the
 * E2E that produces a real one and pins it, unblocking the relay migration
 * off HTTP-polled catalogs.
 *
 * Trust model: the bee's Hypercore is authored by a persisted Ed25519 keypair
 * (saved in <storage>/catalog-bee-key.json and REUSED across runs, so updates
 * are appends to the same key, not a new catalog). The core key == the
 * publisher pubkey == the trust anchor a consumer subscribes to. A signed
 * `\x00meta` record (Ed25519 detached over sha256(pubkey || canonicalJson),
 * the same shape as the relay's subsidy/signed-directory claims) attests the
 * snapshot (source relay, entry count, appKeys hash, timestamp) so a consumer
 * has an explicit integrity manifest.
 *
 * "Pinned" = the relay seeds the bee's bare Hypercore via POST /seed-core
 * (NOT /seed — that opens a Hyperdrive). The script stays online so the relay
 * can replicate the blocks, then the relay serves them itself.
 *
 * Usage:
 *   node scripts/publish-catalog-bee.js --relay http://host:9100 [options]
 *
 * Options:
 *   --relay <url>        Relay to read /catalog.json from AND pin the bee on (required)
 *   --storage <path>     Corestore path (default: .catalog-bee-storage)
 *   --api-key <key>      Operator API key for POST /seed-core
 *                        (fallback: HIVERELAY_API_KEY env var)
 *   --page-size <n>      /catalog.json page size, 1..500 (default: 500)
 *   --bootstrap <nodes>  Comma-separated DHT bootstrap nodes (host:port)
 *   --no-stay            Exit after pinning (don't stay online to serve blocks)
 *   --hold-seconds <n>   With --no-stay, seconds to stay online first (default: 30)
 *
 * Example:
 *   HIVERELAY_API_KEY=... node scripts/publish-catalog-bee.js --relay http://127.0.0.1:9100
 */

import Hyperswarm from 'hyperswarm'
import Corestore from 'corestore'
import Hyperbee from 'hyperbee'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { readFile, writeFile, mkdir } from 'fs/promises'
import { join } from 'path'
import { existsSync } from 'fs'

const META_KEY = '\x00meta' // sorts before any 64-hex appKey; read by exact key

function parseArgs (argv) {
  const args = { storage: '.catalog-bee-storage', pageSize: 500, stay: true, holdSeconds: 30 }
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    const next = () => argv[++i]
    if (a === '--relay') args.relay = next()
    else if (a === '--storage') args.storage = next()
    else if (a === '--api-key') args.apiKey = next()
    else if (a === '--page-size') args.pageSize = Math.min(Math.max(parseInt(next()) || 500, 1), 500)
    else if (a === '--bootstrap') args.bootstrap = next()
    else if (a === '--no-stay') args.stay = false
    else if (a === '--hold-seconds') args.holdSeconds = Math.max(parseInt(next()) || 30, 0)
    else if (a === '--help' || a === '-h') args.help = true
  }
  args.apiKey = args.apiKey || process.env.HIVERELAY_API_KEY || null
  return args
}

// Deterministic JSON (sorted keys, no whitespace) — identical bytes for signer
// and verifier. Matches incentive/subsidy/index.js canonicalJson.
function canonicalJson (obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj)
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']'
  const keys = Object.keys(obj).sort()
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}'
}

function sha256 (buf) {
  const out = b4a.alloc(32)
  sodium.crypto_hash_sha256(out, buf)
  return out
}

// Same digest-then-detached-sign shape the relay uses (subsidy claimDigest):
// sha256(publicKey || canonicalJson(body)), Ed25519 detached.
function signBody (keyPair, body) {
  const digest = sha256(b4a.concat([keyPair.publicKey, b4a.from(canonicalJson(body), 'utf8')]))
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, digest, keyPair.secretKey)
  return b4a.toString(sig, 'hex')
}

async function loadOrCreateKeyPair (storage) {
  const p = join(storage, 'catalog-bee-key.json')
  if (existsSync(p)) {
    const j = JSON.parse(await readFile(p, 'utf8'))
    return { publicKey: b4a.from(j.publicKey, 'hex'), secretKey: b4a.from(j.secretKey, 'hex') }
  }
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  await mkdir(storage, { recursive: true })
  await writeFile(p, JSON.stringify({
    publicKey: b4a.toString(publicKey, 'hex'),
    secretKey: b4a.toString(secretKey, 'hex')
  }))
  return { publicKey, secretKey }
}

async function fetchCatalog (relayUrl, pageSize) {
  const base = relayUrl.replace(/\/+$/, '')
  const entries = []
  let relayKey = null
  let page = 1
  for (;;) {
    const u = `${base}/catalog.json?page=${page}&pageSize=${pageSize}`
    const r = await fetch(u, { headers: { Accept: 'application/json' } })
    if (!r.ok) throw new Error(`catalog fetch failed: HTTP ${r.status} from ${u}`)
    const j = await r.json()
    relayKey = j.relayKey || relayKey
    // `entries` is the full per-page set across all types; fall back to `apps`
    // for older relays that predate the typed envelope.
    const got = Array.isArray(j.entries) ? j.entries : (Array.isArray(j.apps) ? j.apps : [])
    for (const e of got) entries.push(e)
    if (!j.pagination || !j.pagination.hasNext) break
    page++
    if (page > 100000) throw new Error('catalog pagination runaway — aborting')
  }
  return { entries, relayKey }
}

async function pinOnRelay (relayUrl, coreKeyHex, apiKey) {
  const base = relayUrl.replace(/\/+$/, '')
  const headers = { 'Content-Type': 'application/json' }
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`
  const r = await fetch(`${base}/seed-core`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ coreKey: coreKeyHex })
  })
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(`seed-core failed: HTTP ${r.status} ${j && j.error ? '— ' + j.error : ''}`)
  return j
}

async function main () {
  const args = parseArgs(process.argv)
  if (args.help || !args.relay) {
    console.error('Usage: node scripts/publish-catalog-bee.js --relay <url> [--storage path] [--api-key key] [--page-size n] [--bootstrap nodes] [--no-stay] [--hold-seconds n]')
    process.exit(args.help ? 0 : 1)
  }

  console.log(`[catalog-bee] reading catalog from ${args.relay} …`)
  const { entries, relayKey } = await fetchCatalog(args.relay, args.pageSize)
  const withKeys = entries.filter(e => e && typeof e.appKey === 'string' && /^[0-9a-f]{64}$/i.test(e.appKey))
  console.log(`[catalog-bee] ${entries.length} catalog entries (${withKeys.length} with valid appKey)` +
    (relayKey ? `, relayKey ${relayKey.slice(0, 12)}…` : ''))

  // Build the bee, authored by the persisted publisher keypair so the core
  // key is stable across runs and == the signing identity.
  const keyPair = await loadOrCreateKeyPair(args.storage)
  const store = new Corestore(args.storage)
  await store.ready()
  const core = store.get({ keyPair })
  await core.ready()
  const bee = new Hyperbee(core, { keyEncoding: 'utf-8', valueEncoding: 'json' })
  await bee.ready()
  const coreKeyHex = b4a.toString(core.key, 'hex')

  // Write entries keyed by appKey. A batch keeps the appends ordered + atomic.
  const batch = bee.batch()
  const appKeys = []
  for (const e of withKeys) {
    const k = e.appKey.toLowerCase()
    appKeys.push(k)
    await batch.put(k, e)
  }
  appKeys.sort()
  const meta = {
    v: 1,
    type: 'hiverelay-catalog-bee',
    sourceRelay: args.relay.replace(/\/+$/, ''),
    relayKey: relayKey || null,
    publisherPubkey: coreKeyHex, // == core.key — the trust anchor
    entryCount: appKeys.length,
    appKeysHash: b4a.toString(sha256(b4a.from(appKeys.join(''), 'hex')), 'hex'),
    generatedAt: Date.now()
  }
  const signedMeta = { ...meta, signature: signBody(keyPair, meta) }
  await batch.put(META_KEY, signedMeta)
  await batch.flush()

  console.log(`[catalog-bee] bee built: ${appKeys.length} entries + signed meta, core length ${core.length}`)
  console.log('')
  console.log(`  CATALOG BEE KEY:  ${coreKeyHex}`)
  console.log('  (subscribe to this key as a Hyperbee; read the \\x00meta record for the signed manifest)')
  console.log('')

  // Join the swarm so the relay can replicate the bee's core from us.
  const swarmOpts = {}
  if (args.bootstrap) {
    swarmOpts.bootstrap = args.bootstrap.split(',').map(s => s.trim()).filter(Boolean)
  }
  const swarm = new Hyperswarm(swarmOpts)
  swarm.on('connection', (conn) => store.replicate(conn))
  swarm.join(core.discoveryKey, { server: true, client: true })
  // Bounded flush — don't let DHT announce latency block the pin. The relay's
  // seedCore re-announces + retries the download, so it finds us regardless.
  await Promise.race([
    swarm.flush(),
    new Promise(resolve => setTimeout(resolve, 8000))
  ])

  // Pin on the relay (bare-core seed).
  console.log(`[catalog-bee] pinning on ${args.relay} via POST /seed-core …`)
  try {
    const res = await pinOnRelay(args.relay, coreKeyHex, args.apiKey)
    console.log(`[catalog-bee] pinned ✓ (relay reports core length ${res.length ?? '?'})`)
  } catch (err) {
    console.error(`[catalog-bee] pin failed: ${err.message}`)
    console.error('  The bee is built + announced; you can retry the pin, or the relay')
    console.error('  may need the /seed-core endpoint (HiveRelay ≥ this release).')
  }

  if (args.stay) {
    console.log('[catalog-bee] staying online to serve the bee (Ctrl-C to stop)…')
    process.on('SIGINT', async () => {
      console.log('\n[catalog-bee] shutting down…')
      try { await swarm.destroy() } catch {}
      try { await store.close() } catch {}
      process.exit(0)
    })
    // keep the event loop alive
    await new Promise(() => {})
  } else {
    console.log(`[catalog-bee] holding ${args.holdSeconds}s for initial replication…`)
    await new Promise(resolve => setTimeout(resolve, args.holdSeconds * 1000))
    try { await swarm.destroy() } catch {}
    try { await store.close() } catch {}
    console.log('[catalog-bee] done.')
    process.exit(0)
  }
}

main().catch(err => {
  console.error('[catalog-bee] fatal:', err && err.stack ? err.stack : err)
  process.exit(1)
})
