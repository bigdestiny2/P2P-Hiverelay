#!/usr/bin/env node

/**
 * Publish a local directory to a Hyperdrive and seed it on live HiveRelay nodes.
 *
 * Automatically reuses the same drive key for the same app (by --name/appId).
 * Subsequent publishes are version updates, not duplicates.
 *
 * Usage:
 *   node scripts/publish-app.js <directory> [options]
 *
 * Options:
 *   --name <name>        App name (also used as appId for deduplication)
 *   --id <id>            Explicit appId (overrides name-derived id)
 *   --desc <description> App description
 *   --version <version>  App version (default: 1.0.0)
 *   --relays <urls>      Comma-separated relay API URLs to seed on
 *   --storage <path>     Corestore path (default: .publisher-storage)
 *   --key <hex>          Explicit drive key (overrides appId lookup)
 *   --storage-budget <n> Rotate before the drive exceeds this size (default: 1GiB)
 *   --rollback-window <n> Number of signed releases to retain (default: 3, max: 32)
 *   --bootstrap <nodes>  Comma-separated DHT bootstrap nodes (host:port)
 *   --api-key <key>      Shared operator API key sent to every relay
 *                        (fallback: HIVERELAY_API_KEY env var)
 *   --api-keys <map>     Per-relay keys as url=key,url=key — needed when each
 *                        relay runs its own key (fallback: HIVERELAY_API_KEYS)
 *   --blind              Encrypt content (relay can't read it, P2P only)
 *   --no-stay            Exit after publishing (don't stay online)
 *   --hold-seconds <n>   Seconds to stay online with --no-stay (default: 30)
 *
 * Examples:
 *   # First publish — creates new drive, saves key mapping
 *   node scripts/publish-app.js ../pear-pos/frontend/dist --name "Pear POS"
 *
 *   # Update — reuses same drive key automatically (same --name + --storage)
 *   node scripts/publish-app.js ../pear-pos/frontend/dist --name "Pear POS" --version 1.1.0
 */

import Hyperswarm from 'hyperswarm'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { readdir, readFile, writeFile, stat, mkdir, rename } from 'fs/promises'
import { join, relative, resolve } from 'path'
import { existsSync } from 'fs'
import { hashReleaseTree } from '../packages/core/core/release-lifecycle.js'
import { planPublishedFiles, syncPublishedFiles } from './lib/publish-drive-sync.mjs'
import {
  DEFAULT_RELEASE_ROLLBACK_WINDOW,
  DEFAULT_RELEASE_STORAGE_BUDGET,
  createSignedSeedRequest,
  createPublisherRelease,
  driveLogicalBytes,
  estimateReleaseAppendBytes,
  formatStorageBytes,
  loadReleaseState,
  parseStorageBytes,
  publisherKeyPairForApp,
  saveReleaseState,
  shouldRotateReleaseDrive
} from './lib/release-publisher.mjs'

const RELAY_DISCOVERY_TOPIC = b4a.alloc(32)
sodium.crypto_generichash(RELAY_DISCOVERY_TOPIC, b4a.from('hiverelay-discovery-v1'))

// Default relay endpoints — set HIVERELAY_RELAYS env var or pass --relay flags
// Example: HIVERELAY_RELAYS="http://host1:9100,http://host2:9100"
const DEFAULT_RELAYS = process.env.HIVERELAY_RELAYS
  ? process.env.HIVERELAY_RELAYS.split(',').map(s => s.trim())
  : ['http://127.0.0.1:9100']
const DEFAULT_BOOTSTRAP = parseBootstrapNodes(process.env.HIVERELAY_BOOTSTRAP)

function parseArgs (argv) {
  const args = argv.slice(2)
  const opts = {
    directory: null,
    name: null,
    id: null,
    description: null,
    version: '1.0.0',
    relays: DEFAULT_RELAYS,
    storage: '.publisher-storage',
    storageBudgetBytes: DEFAULT_RELEASE_STORAGE_BUDGET,
    rollbackWindow: DEFAULT_RELEASE_ROLLBACK_WINDOW,
    key: null,
    bootstrap: DEFAULT_BOOTSTRAP,
    apiKey: process.env.HIVERELAY_API_KEY || null,
    apiKeys: parseApiKeyMap(process.env.HIVERELAY_API_KEYS),
    blind: false,
    stay: true,
    holdSeconds: 30
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '--name') { opts.name = args[++i]; continue }
    if (arg === '--id') { opts.id = args[++i]; continue }
    if (arg === '--desc') { opts.description = args[++i]; continue }
    if (arg === '--version') { opts.version = args[++i]; continue }
    if (arg === '--relays') { opts.relays = args[++i].split(',').map(s => s.trim()).filter(Boolean); continue }
    if (arg === '--storage') { opts.storage = args[++i]; continue }
    if (arg === '--storage-budget') {
      const bytes = parseStorageBytes(args[++i])
      if (bytes === null) {
        console.error('Error: --storage-budget must be a positive size such as 500MiB or 2GiB')
        process.exit(1)
      }
      opts.storageBudgetBytes = bytes
      continue
    }
    if (arg === '--rollback-window') {
      const count = Number(args[++i])
      if (!Number.isInteger(count) || count < 1 || count > 32) {
        console.error('Error: --rollback-window must be an integer from 1 to 32')
        process.exit(1)
      }
      opts.rollbackWindow = count
      continue
    }
    if (arg === '--key') { opts.key = args[++i]; continue }
    if (arg === '--bootstrap') {
      try {
        opts.bootstrap = parseBootstrapNodes(args[++i])
      } catch (err) {
        console.error('Error: ' + err.message)
        process.exit(1)
      }
      continue
    }
    if (arg === '--api-key') { opts.apiKey = args[++i]; continue }
    if (arg === '--api-keys') {
      try {
        opts.apiKeys = parseApiKeyMap(args[++i])
      } catch (err) {
        console.error('Error: ' + err.message)
        process.exit(1)
      }
      continue
    }
    if (arg === '--blind') { opts.blind = true; continue }
    if (arg === '--encryption-key') {
      const keyVal = args[++i]
      if (!keyVal || !/^[0-9a-f]{64}$/i.test(keyVal)) {
        console.error('Error: --encryption-key must be exactly 64 hex characters (32 bytes)')
        process.exit(1)
      }
      opts.encryptionKey = keyVal
      continue
    }
    if (arg === '--no-stay') { opts.stay = false; continue }
    if (arg === '--hold-seconds') {
      const seconds = Number(args[++i])
      if (!Number.isFinite(seconds) || seconds < 0) {
        console.error('Error: --hold-seconds must be a non-negative number')
        process.exit(1)
      }
      opts.holdSeconds = seconds
      continue
    }
    if (!arg.startsWith('-') && !opts.directory) { opts.directory = arg; continue }
  }

  // --encryption-key without --blind is almost certainly a mistake
  if (opts.encryptionKey && !opts.blind) {
    console.error('Error: --encryption-key requires --blind flag (otherwise content is published unencrypted)')
    process.exit(1)
  }

  return opts
}

/**
 * Parse a per-relay API key map: "http://host1:9100=KEY1,http://host2:9100=KEY2".
 * Split on the FIRST '=' so keys containing '=' (base64 padding) survive.
 * URLs are normalized (trailing slash stripped) for lookup.
 */
function parseApiKeyMap (input) {
  if (!input) return null
  const map = new Map()
  for (const pair of String(input).split(',').map(s => s.trim()).filter(Boolean)) {
    const sep = pair.indexOf('=')
    if (sep <= 0 || sep === pair.length - 1) {
      throw new Error('--api-keys entries must be url=key, got: ' + pair)
    }
    map.set(pair.slice(0, sep).replace(/\/+$/, ''), pair.slice(sep + 1))
  }
  return map.size > 0 ? map : null
}

/**
 * Resolve the API key for one relay URL: per-relay map first (the fleet runs
 * a distinct key per relay), then the shared key as fallback.
 */
function resolveApiKey (relayUrl, opts) {
  const normalized = relayUrl.replace(/\/+$/, '')
  if (opts.apiKeys && opts.apiKeys.has(normalized)) return opts.apiKeys.get(normalized)
  return opts.apiKey || null
}

function deriveAppId (name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}

function createReleaseDrive (store, driveOpts) {
  const suffix = b4a.alloc(8)
  sodium.randombytes_buf(suffix)
  const namespace = store.namespace('app-release-' + Date.now() + '-' + b4a.toString(suffix, 'hex'))
  return new Hyperdrive(namespace, null, driveOpts)
}

function parseBootstrapNodes (input) {
  if (!input) return null
  const nodes = String(input)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map((value) => {
      const sep = value.lastIndexOf(':')
      if (sep <= 0 || sep === value.length - 1) {
        throw new Error('--bootstrap entries must be host:port')
      }
      const host = value.slice(0, sep)
      const port = Number(value.slice(sep + 1))
      if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
        throw new Error('--bootstrap entries must be host:port with a valid port')
      }
      return { host, port }
    })
  return nodes.length ? nodes : null
}

async function loadDriveMap (storagePath) {
  try {
    const mapPath = join(storagePath, 'app-drives.json')
    return JSON.parse(await readFile(mapPath, 'utf8'))
  } catch (_) {
    return {}
  }
}

async function saveDriveMap (storagePath, map) {
  await mkdir(storagePath, { recursive: true })
  const mapPath = join(storagePath, 'app-drives.json')
  const temporary = mapPath + '.tmp'
  await writeFile(temporary, JSON.stringify(map, null, 2))
  await rename(temporary, mapPath)
}

async function walkDir (dir, base) {
  base = base || dir
  const entries = await readdir(dir, { withFileTypes: true })
  const files = []

  for (const entry of entries) {
    const fullPath = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue
      files.push(...await walkDir(fullPath, base))
    } else if (entry.isFile()) {
      // Skip macOS resource fork files
      if (entry.name.startsWith('._')) continue
      const relPath = '/' + relative(base, fullPath).replace(/\\/g, '/')
      const content = await readFile(fullPath)
      const stats = await stat(fullPath)
      files.push({ path: relPath, content, size: stats.size })
    }
  }

  return files
}

async function loadOrCreateEncryptionKey (storagePath, appId) {
  await mkdir(storagePath, { recursive: true })
  const keyFile = join(storagePath, 'encryption-keys.json')
  let keys = {}
  try {
    const data = await readFile(keyFile, 'utf8')
    keys = JSON.parse(data)
  } catch (err) {
    // Warn if file exists but is corrupted (not just missing)
    if (err.code !== 'ENOENT') {
      console.error(`Warning: ${keyFile} exists but could not be parsed — generating new keys`)
      console.error('  If you had existing blind apps, their encryption keys may be lost')
    }
  }

  const id = appId || '_default'
  if (keys[id]) {
    return b4a.from(keys[id], 'hex')
  }

  // Generate new 32-byte encryption key
  const key = b4a.alloc(32)
  sodium.randombytes_buf(key)
  keys[id] = b4a.toString(key, 'hex')

  // Write with restricted permissions (owner-only) — these are secret keys
  const tmpFile = keyFile + '.tmp'
  await writeFile(tmpFile, JSON.stringify(keys, null, 2), { mode: 0o600 })
  await rename(tmpFile, keyFile)
  return key
}

async function resolveFromRelay (relays, appId) {
  for (const url of relays) {
    try {
      const res = await fetch(url + '/api/resolve/' + encodeURIComponent(appId), { signal: AbortSignal.timeout(5000) })
      if (res.ok) {
        const data = await res.json()
        if (data.driveKey) return data.driveKey
      }
    } catch (_) {}
  }
  return null
}

async function seedOnRelay (relayUrl, appKey, appId, version, blind, apiKey, maxStorageBytes, keyPair) {
  try {
    const publisherRequest = createSignedSeedRequest({ appKey, maxStorageBytes, blind, keyPair })
    const body = apiKey
      ? {
          appKey,
          appId,
          version,
          blind,
          maxStorageBytes,
          opts: {
            publisherPubkey: publisherRequest.publisherPubkey,
            publisherSignature: publisherRequest.publisherSignature,
            seedSignatureProfile: 'replay-v1'
          }
        }
      : publisherRequest
    const headers = { 'Content-Type': 'application/json' }
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`
    const route = apiKey ? '/seed' : '/api/v1/seed'
    const res = await fetch(relayUrl + route, {
      method: 'POST',
      headers,
      body: JSON.stringify(body)
    })
    let data
    try { data = await res.json() } catch (_) { data = {} }
    return {
      url: relayUrl,
      ok: data.ok || false,
      status: res.status,
      replaced: data.alreadySeeded ? 'same-key' : null,
      canonicalKey: data.canonicalKey || null,
      error: data.error || (res.ok ? null : 'HTTP ' + res.status),
      // 'auth-required' → the relay wants its operator API key; keyed
      // separately so the summary can print an actionable fix.
      authFailure: res.status === 401 || (data.errorCode === 'auth-required'),
      keySent: Boolean(apiKey)
    }
  } catch (err) {
    return { url: relayUrl, ok: false, status: 0, error: err.message, authFailure: false, keySent: Boolean(apiKey) }
  }
}

async function run () {
  const opts = parseArgs(process.argv)

  if (!opts.directory) {
    console.error('Usage: node scripts/publish-app.js <directory> [options]')
    console.error('')
    console.error('Options:')
    console.error('  --name <name>        App name (used for deduplication)')
    console.error('  --id <id>            Explicit appId (overrides name-derived id)')
    console.error('  --desc <description> App description')
    console.error('  --version <version>  App version (default: 1.0.0)')
    console.error('  --storage <path>     Publisher storage path')
    console.error('  --key <hex>          Explicit drive key')
    console.error('  --storage-budget <n> Per-drive budget before signed rotation (default: 1GiB)')
    console.error('  --rollback-window <n> Signed releases to retain (default: 3, max: 32)')
    console.error('  --api-key <key>      Shared operator API key (env: HIVERELAY_API_KEY)')
    console.error('  --api-keys <map>     Per-relay keys url=key,url=key (env: HIVERELAY_API_KEYS)')
    console.error('  --blind              Encrypt content (relay can\'t read, P2P only)')
    console.error('  --encryption-key <h> Use explicit encryption key (hex, for recovery)')
    console.error('  --no-stay            Exit after publishing')
    process.exit(1)
  }

  const dir = resolve(opts.directory)
  if (!existsSync(dir)) {
    console.error('Directory not found:', dir)
    process.exit(1)
  }

  const appId = opts.id || (opts.name ? deriveAppId(opts.name) : null)
  if (!appId) {
    console.error('Error: --name or --id is required for signed, bounded app releases')
    process.exit(1)
  }

  console.log()
  console.log('=== HiveRelay App Publisher ===')
  console.log()
  console.log('  Directory:', dir)
  console.log('  Storage:  ', opts.storage)
  console.log('  Relays:   ', opts.relays.length)
  if (opts.bootstrap) console.log('  Bootstrap:', opts.bootstrap.map(n => `${n.host}:${n.port}`).join(', '))
  if (appId) console.log('  App ID:   ', appId)
  console.log('  Budget:   ', formatStorageBytes(opts.storageBudgetBytes), 'per drive')
  console.log('  Rollback: ', opts.rollbackWindow, 'release' + (opts.rollbackWindow === 1 ? '' : 's'))
  if (opts.version !== '1.0.0') console.log('  Version:  ', opts.version)
  if (opts.blind) console.log('  Mode:      BLIND (encrypted, P2P only)')
  console.log()

  // Scan files
  console.log('  Scanning files...')
  const files = await walkDir(dir)
  const totalSize = files.reduce((sum, f) => sum + f.size, 0)
  console.log('  Found', files.length, 'files (' + (totalSize / 1024 / 1024).toFixed(1) + ' MB)')
  console.log()

  // Boot P2P stack
  console.log('  Starting P2P stack...')
  const store = new Corestore(opts.storage)
  await store.ready()

  const networkEnabled = opts.stay || opts.relays.length > 0
  const swarm = networkEnabled
    ? (opts.bootstrap ? new Hyperswarm({ bootstrap: opts.bootstrap }) : new Hyperswarm())
    : null
  if (swarm) swarm.on('connection', (conn) => store.replicate(conn))

  // For blind mode: use explicit key, load saved key, or generate new one
  let encryptionKey = null
  if (opts.blind) {
    if (opts.encryptionKey) {
      encryptionKey = b4a.from(opts.encryptionKey, 'hex')
      console.log('  Encryption key: ' + opts.encryptionKey.slice(0, 16) + '... (provided)')
    } else {
      encryptionKey = await loadOrCreateEncryptionKey(opts.storage, appId)
      console.log('  Encryption key: ' + b4a.toString(encryptionKey, 'hex').slice(0, 16) + '... (from storage)')
    }
    console.log('  (share this key with authorized peers for decryption)')
    console.log()
  }

  // Hyperdrive constructor options (with optional encryption)
  const driveOpts = encryptionKey ? { encryptionKey } : {}

  // One stable Ed25519 identity signs both seed requests and release-key
  // transitions. Persist it before touching a drive so a crash cannot publish
  // a release whose signing authority is immediately lost.
  const releaseState = await loadReleaseState(opts.storage)
  const releaseKeyPair = publisherKeyPairForApp(releaseState, appId)
  await saveReleaseState(opts.storage, releaseState)
  let appReleaseState = releaseState.apps[appId]

  // Resolve drive key: explicit --key > saved mapping > new drive
  let drive
  let isUpdate = false

  if (opts.key) {
    // Explicit key
    console.log('  Reopening drive:', opts.key.slice(0, 16) + '...')
    drive = new Hyperdrive(store, Buffer.from(opts.key, 'hex'), driveOpts)
    isUpdate = true
  } else if (appId) {
    // Check saved appId → key mapping
    const driveMap = await loadDriveMap(opts.storage)
    const savedDriveKey = appReleaseState.currentDriveKey || driveMap[appId]
    if (savedDriveKey) {
      console.log('  Found existing drive for "' + appId + '": ' + savedDriveKey.slice(0, 16) + '...')
      drive = new Hyperdrive(store, Buffer.from(savedDriveKey, 'hex'), driveOpts)
      isUpdate = true
    } else {
      // No local mapping — check relay registry (handles publisher storage loss)
      // Skip relay recovery for blind apps unless --encryption-key was explicitly provided
      // (a new publisher instance generates a different encryption key, can't write to old drive)
      const canRecover = !opts.blind || opts.encryptionKey
      if (canRecover) {
        const resolvedKey = await resolveFromRelay(opts.relays, appId)
        if (resolvedKey) {
          console.log('  Relay registry has key for "' + appId + '": ' + resolvedKey.slice(0, 16) + '...')
          console.log('  (recovered from relay — publisher storage was likely lost)')
          drive = new Hyperdrive(store, Buffer.from(resolvedKey, 'hex'), driveOpts)
          isUpdate = true
          // Save locally so we don't need relay lookup next time
          const map = await loadDriveMap(opts.storage)
          map[appId] = resolvedKey
          await saveDriveMap(opts.storage, map)
        }
      } else if (opts.blind) {
        console.log('  Blind mode: creating new drive (use --encryption-key to recover existing)')
      }
    }
  }

  if (!drive) {
    console.log('  Creating new Hyperdrive...')
    drive = createReleaseDrive(store, driveOpts)
  }

  await drive.ready()

  if (!drive.writable) {
    throw new Error('publisher storage does not hold the secret key for this drive; restore the original publisher storage or publish a new app id')
  }

  let driveKey = b4a.toString(drive.key, 'hex')
  if (appReleaseState.currentDriveKey && appReleaseState.currentDriveKey !== driveKey) {
    throw new Error('explicit drive key does not match signed release state; automatic storage-budget rotation is the only supported key transition')
  }

  // Build the user-facing portion of manifest.json once. The signed release
  // envelope is attached only after the final (possibly rotated) key is known.
  const manifestBase = {
    id: appId,
    name: opts.name || 'Unknown App',
    description: opts.description || (opts.name ? opts.name + ' — published via HiveRelay' : ''),
    version: opts.version,
    main: '/index.html',
    files: files.length,
    totalBytes: totalSize,
    publishedAt: new Date().toISOString()
  }

  // Check if manifest.json already exists in the dist (user-provided)
  const hasUserManifest = files.some(f => f.path === '/manifest.json')
  if (hasUserManifest) {
    // Merge user's manifest with our fields (user fields take priority)
    try {
      const userManifest = JSON.parse(files.find(f => f.path === '/manifest.json').content.toString())
      Object.assign(manifestBase, userManifest)
      // The CLI app id is the stable publisher identity and cannot drift in a
      // user-supplied manifest between releases.
      manifestBase.id = appId
      console.log('  Using user-provided manifest.json (merged with publisher metadata)')
    } catch (_) {
      console.log('  Warning: could not parse user manifest.json, using generated one')
    }
  }

  const contentFiles = files.filter(file => file.path !== '/manifest.json')
  const treeHash = hashReleaseTree(contentFiles)
  const buildRelease = (key, previousDriveKey = null) => createPublisherRelease({
    appState: appReleaseState,
    appId,
    version: String(manifestBase.version),
    driveKey: key,
    previousDriveKey,
    storageBudgetBytes: opts.storageBudgetBytes,
    rollbackWindow: opts.rollbackWindow,
    treeHash,
    keyPair: releaseKeyPair
  })
  const buildFiles = (signedRelease) => {
    const existingHiveRelay = manifestBase.hiverelay && typeof manifestBase.hiverelay === 'object' && !Array.isArray(manifestBase.hiverelay)
      ? manifestBase.hiverelay
      : {}
    const manifest = {
      ...manifestBase,
      hiverelay: { ...existingHiveRelay, release: signedRelease }
    }
    return {
      manifest,
      releaseFiles: [
        ...contentFiles,
        { path: '/manifest.json', content: b4a.from(JSON.stringify(manifest, null, 2)) }
      ]
    }
  }

  let previousDrive = null
  let previousDriveKey = null
  let builtRelease = buildRelease(driveKey)
  let builtFiles = buildFiles(builtRelease.release)
  let publishPlan = await planPublishedFiles(drive, builtFiles.releaseFiles)
  const budgetPlan = shouldRotateReleaseDrive({
    driveBytes: driveLogicalBytes(drive),
    plan: publishPlan,
    storageBudgetBytes: opts.storageBudgetBytes
  })

  if (budgetPlan.rotate) {
    if (!isUpdate || drive.version === 0) {
      const required = driveLogicalBytes(drive) + estimateReleaseAppendBytes(publishPlan)
      throw new Error(`release needs approximately ${formatStorageBytes(required)}, above the ${formatStorageBytes(opts.storageBudgetBytes)} drive budget`)
    }
    previousDrive = drive
    previousDriveKey = driveKey
    console.log('  Storage budget reached at projected', formatStorageBytes(budgetPlan.projectedBytes))
    console.log('  Rotating to a new publisher-signed release key...')
    drive = createReleaseDrive(store, driveOpts)
    await drive.ready()
    driveKey = b4a.toString(drive.key, 'hex')
    builtRelease = buildRelease(driveKey, previousDriveKey)
    builtFiles = buildFiles(builtRelease.release)
    publishPlan = await planPublishedFiles(drive, builtFiles.releaseFiles)
    const freshBudgetPlan = shouldRotateReleaseDrive({
      driveBytes: driveLogicalBytes(drive),
      plan: publishPlan,
      storageBudgetBytes: opts.storageBudgetBytes
    })
    if (freshBudgetPlan.rotate) {
      throw new Error(`release plus rotation reserve needs ${formatStorageBytes(freshBudgetPlan.projectedBytes)}, above the ${formatStorageBytes(opts.storageBudgetBytes)} drive budget`)
    }
  }

  const manifest = builtFiles.manifest
  console.log('  Drive key:', driveKey)
  console.log('  Mode:     ', previousDrive ? 'ROTATED (signed storage-budget transition)' : (isUpdate ? 'UPDATE (same key, delta)' : 'NEW DRIVE'))
  console.log('  Release:  ', '#' + builtRelease.release.sequence, 'generation', builtRelease.release.generation)
  console.log()

  // Mirror the release tree instead of blindly appending every file. This
  // skips byte-identical files, block-deduplicates changed files, and removes
  // paths that disappeared from the build.
  console.log('  Synchronizing release files to Hyperdrive...')
  const sync = await syncPublishedFiles(drive, builtFiles.releaseFiles, { plan: publishPlan })
  console.log('  Added:', sync.added, 'Changed:', sync.changed, 'Removed:', sync.removed, 'Unchanged:', sync.unchanged)
  console.log('  Drive version:', drive.version)
  console.log()

  if (previousDrive) {
    await previousDrive.put(
      '/.hiverelay/rotation.json',
      b4a.from(JSON.stringify(builtRelease.release, null, 2))
    )
    console.log('  Signed rotation pointer written to predecessor:', previousDriveKey)
    console.log()
  }

  // Commit publisher state only after the content and predecessor pointer are
  // durable. A failed relay request can be retried without re-signing history.
  appReleaseState = builtRelease.appState
  releaseState.apps[appId] = appReleaseState
  await saveReleaseState(opts.storage, releaseState)
  const driveMap = await loadDriveMap(opts.storage)
  driveMap[appId] = driveKey
  await saveDriveMap(opts.storage, driveMap)

  // Join DHT
  if (swarm) {
    console.log('  Joining DHT...')
    swarm.join(drive.discoveryKey, { server: true, client: true })
    if (previousDrive) swarm.join(previousDrive.discoveryKey, { server: true, client: true })
    swarm.join(RELAY_DISCOVERY_TOPIC, { server: true, client: false })
    await swarm.flush()
    console.log('  Announced on DHT.')
  } else {
    console.log('  Offline publish: DHT announcement skipped (no relays, --no-stay).')
  }
  console.log()

  // Seed on relays (pass appId + version for deduplication)
  console.log('  Seeding on relays...')
  const seedResults = await Promise.all(
    opts.relays.map(url => seedOnRelay(
      url,
      driveKey,
      manifest.id,
      manifest.version,
      opts.blind,
      resolveApiKey(url, opts),
      opts.storageBudgetBytes,
      releaseKeyPair
    ))
  )

  let seeded = 0
  const authFailures = []
  for (const result of seedResults) {
    let status = result.ok ? 'OK' : 'FAIL: ' + result.error
    if (result.replaced) status += ' (already seeded)'
    if (result.canonicalKey) status += ' [canonical: ' + result.canonicalKey.slice(0, 16) + '...]'
    console.log('    ' + result.url + ' — ' + status)
    if (result.ok) seeded++
    if (result.authFailure) authFailures.push(result)
  }
  console.log()
  console.log('  Seeded on', seeded + '/' + opts.relays.length, 'relays')
  console.log()

  if (authFailures.length > 0) {
    console.error('  ┌─────────────────────────────────────────────────────────────────┐')
    console.error('  │  AUTH FAILURE: ' + authFailures.length + '/' + opts.relays.length + ' relay(s) returned 401 Unauthorized.            │')
    console.error('  └─────────────────────────────────────────────────────────────────┘')
    console.error('  The relay rejected both publisher ingress and operator authorization. Refused by:')
    for (const f of authFailures) {
      console.error('    ' + f.url + (f.keySent ? '  (a key WAS sent — wrong key for this relay?)' : '  (no key sent)'))
    }
    console.error()
    console.error('  Fix — per-relay keys (fleets run a distinct key per relay):')
    console.error('    --api-keys "http://relay1:9100=KEY1,http://relay2:9100=KEY2"')
    console.error('    or env HIVERELAY_API_KEYS in the same url=key,url=key format.')
    console.error('  Or a single shared key: --api-key KEY / env HIVERELAY_API_KEY.')
    console.error()
  }
  if (seeded === 0 && opts.relays.length > 0) {
    console.error('  WARNING: no relay accepted this publish — the app is NOT seeded anywhere.')
    console.error()
    process.exitCode = 1
  }

  // Print access info
  if (opts.blind) {
    console.log('  === BLIND / ENCRYPTED APP ===')
    console.log()
    const ekHex = b4a.toString(encryptionKey, 'hex')
    console.log('    Drive key:       ', driveKey)
    console.log('    Encryption key:  ', ekHex.slice(0, 8) + '...' + ekHex.slice(-8) + '  (use --show-key for full key)')
    if (process.argv.includes('--show-key')) {
      console.log('    Full enc key:    ', ekHex)
    }
    console.log()
    console.log('    Access: P2P only (PearBrowser / Hyperswarm)')
    console.log('    HTTP gateway:    BLOCKED (relay has ciphertext only)')
    console.log()
    console.log('    Share BOTH keys with authorized users:')
    console.log('      Drive key = which app to open')
    console.log('      Encryption key = how to decrypt it')
    console.log()
    console.log('    Catalog: https://relay-us.p2phiverelay.xyz/catalog.json')
    console.log()
  } else {
    console.log('  === Access URLs ===')
    console.log()
    for (const url of opts.relays) {
      console.log('    ' + url + '/v1/hyper/' + driveKey + '/index.html')
    }
    console.log()
    console.log('    Gateway: https://relay-us.p2phiverelay.xyz/v1/hyper/' + driveKey + '/index.html')
    console.log()
    console.log('    Catalog: https://relay-us.p2phiverelay.xyz/catalog.json')
    console.log()
  }

  // Monitor replication
  let peerCount = 0
  if (swarm) {
    swarm.on('connection', () => {
      peerCount++
      console.log('  [' + new Date().toISOString().slice(11, 19) + '] Peer connected (total: ' + peerCount + ')')
    })
    swarm.on('connection', (conn) => {
      conn.on('close', () => { peerCount-- })
    })
  }

  if (opts.stay) {
    console.log('  Publisher staying online for replication. Ctrl+C to exit.')
    console.log()

    setInterval(() => {
      console.log('  [' + new Date().toISOString().slice(11, 19) + '] Peers: ' + swarm.connections.size + ', Drive version: ' + drive.version)
    }, 30000)

    process.on('SIGINT', async () => {
      console.log('\n  Shutting down publisher...')
      await swarm.destroy()
      await store.close()
      process.exit(0)
    })
  } else {
    console.log('  Waiting ' + opts.holdSeconds + 's for initial replication...')
    await new Promise(resolve => setTimeout(resolve, opts.holdSeconds * 1000))
    if (swarm) await swarm.destroy()
    await store.close()
  }
}

try {
  await run()
} catch (err) {
  console.error('Fatal:', err)
  process.exit(1)
}
