#!/usr/bin/env node

/**
 * One-command PearBrowser marketplace demo.
 *
 * Starts a local HyperDHT testnet, starts a HiveRelay node on that testnet,
 * publishes examples/pearbrowser-marketplace-demo through scripts/publish-app.js,
 * waits until the relay catalog and gateway can serve it, then prints the exact
 * PearBrowser handoff URLs, keys, and relay capabilities.
 */

import { spawn } from 'child_process'
import { createServer } from 'net'
import { mkdir, rm } from 'fs/promises'
import { existsSync } from 'fs'
import { dirname, join, resolve } from 'path'
import { tmpdir } from 'os'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(__dirname, '..')
const DEFAULT_FIXTURE = join(REPO_ROOT, 'examples', 'pearbrowser-marketplace-demo')
const DEFAULT_TIMEOUT_SECONDS = 120

const args = parseArgs(process.argv.slice(2))

main().catch((err) => {
  console.error('\nDemo failed: ' + (err && err.message ? err.message : String(err)))
  process.exit(1)
})

async function main () {
  const timeoutMs = args.timeoutSeconds * 1000
  const apiPort = args.port || await findFreePort()
  const dhtRelayWsPort = args.dhtRelayWsPort || await findFreePort()
  const relayBaseUrl = `http://127.0.0.1:${apiPort}`
  const dhtRelayWsUrl = `ws://127.0.0.1:${dhtRelayWsPort}`
  const storageRoot = args.storage
    ? resolve(args.storage)
    : join(tmpdir(), `hiverelay-pearbrowser-demo-${process.pid}-${Date.now()}`)

  if (!existsSync(args.fixture)) {
    throw new Error('fixture directory not found: ' + args.fixture)
  }

  const state = {
    relay: null,
    publisher: null,
    testnet: null,
    storageRoot,
    ownsStorage: !args.storage && !args.keepStorage,
    cleaned: false
  }

  installShutdownHandlers(state)

  const { default: createTestnet } = await import('@hyperswarm/testnet')

  await mkdir(storageRoot, { recursive: true })
  await mkdir(join(storageRoot, 'home'), { recursive: true })

  console.log('=== HiveRelay PearBrowser Marketplace Demo ===\n')
  console.log('Starting local DHT testnet...')
  state.testnet = await createTestnet(3)
  const bootstrapArg = state.testnet.bootstrap.map(node => `${node.host}:${node.port}`).join(',')
  console.log('  Bootstrap: ' + bootstrapArg)
  console.log('  Storage:   ' + storageRoot)
  console.log()

  state.relay = startRelay({
    apiPort,
    dhtRelayWsPort,
    bootstrapArg,
    storageRoot
  })
  await waitForRelay(state.relay, relayBaseUrl, timeoutMs)
  console.log('Relay API is ready: ' + relayBaseUrl)
  console.log()

  const publishInfo = await startPublisher({
    state,
    bootstrapArg,
    relayBaseUrl,
    timeoutSeconds: args.timeoutSeconds,
    once: args.once
  })

  const appKey = publishInfo.driveKey
  const gatewayUrl = `${relayBaseUrl}/v1/hyper/${appKey}/index.html`
  const catalogUrl = `${relayBaseUrl}/catalog.json`
  const capabilityUrl = `${relayBaseUrl}/.well-known/hiverelay.json`
  const statusUrl = `${relayBaseUrl}/status`

  console.log()
  console.log('Waiting for relay catalog + gateway readiness...')
  const ready = await waitForPearBrowserReady({
    gatewayUrl,
    catalogUrl,
    appKey,
    timeoutMs
  })

  const capabilities = await fetchJson(capabilityUrl)
  const status = await fetchJson(statusUrl)
  const handoff = buildHandoff({
    relayBaseUrl,
    catalogUrl,
    gatewayUrl,
    capabilityUrl,
    statusUrl,
    dhtRelayWsUrl,
    appKey,
    catalog: ready.catalog,
    catalogEntry: ready.entry,
    capabilities,
    status,
    storageRoot,
    bootstrapArg
  })

  printHandoff(handoff)

  if (args.once) {
    await cleanup(state)
    return
  }

  console.log()
  console.log('Demo is running. Open the gateway URL above in PearBrowser, or add the relay subscription URL to its catalog list.')
  console.log('Press Ctrl+C to stop the relay, publisher, and local testnet.')
  await new Promise(() => {})
}

function startRelay ({ apiPort, dhtRelayWsPort, bootstrapArg, storageRoot }) {
  const relayArgs = [
    'packages/core/cli/index.js',
    'start',
    '--storage', join(storageRoot, 'relay'),
    '--port', String(apiPort),
    '--api-host', '127.0.0.1',
    '--region', 'LOCAL',
    '--operator', 'pearbrowser-demo',
    '--bootstrap', bootstrapArg,
    '--dht-relay-ws',
    '--dht-relay-ws-port', String(dhtRelayWsPort),
    '--quiet'
  ]
  const child = spawn(process.execPath, relayArgs, {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      HOME: join(storageRoot, 'home'),
      HIVERELAY_DHT_RELAY_WS_HOST: '127.0.0.1'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  pipeChild(child, 'relay')
  return child
}

async function startPublisher ({ state, bootstrapArg, relayBaseUrl, timeoutSeconds, once }) {
  const publishArgs = [
    'scripts/publish-app.js',
    args.fixture,
    '--name', args.appName,
    '--id', args.appId,
    '--desc', 'Local PearBrowser marketplace smoke demo',
    '--version', args.version,
    '--relays', relayBaseUrl,
    '--storage', join(state.storageRoot, 'publisher'),
    '--bootstrap', bootstrapArg
  ]

  if (once) {
    publishArgs.push('--no-stay')
    publishArgs.push('--hold-seconds', String(Math.max(timeoutSeconds + 15, 30)))
  }

  const child = spawn(process.execPath, publishArgs, {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      HIVERELAY_BOOTSTRAP: bootstrapArg
    },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  state.publisher = child

  let driveKey = null
  const ready = new Promise((resolve, reject) => {
    const onLine = (line) => {
      const match = line.match(/\bDrive key:\s*([0-9a-f]{64})\b/i)
      if (match && !driveKey) {
        driveKey = match[1].toLowerCase()
        resolve({ driveKey })
      }
    }
    pipeChild(child, 'publish', onLine)
    child.once('exit', (code, signal) => {
      if (!driveKey) {
        reject(new Error(`publisher exited before printing a drive key (code=${code}, signal=${signal || 'none'})`))
      }
    })
  })

  return withTimeout(ready, timeoutSeconds * 1000, 'publisher drive key')
}

async function waitForRelay (child, relayBaseUrl, timeoutMs) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (child.exitCode !== null) {
      throw new Error('relay exited before /health became ready')
    }
    try {
      const health = await fetchJson(relayBaseUrl + '/health', { timeoutMs: 1500 })
      if (health && health.ok === true) return
    } catch (_) {}
    await sleep(300)
  }
  throw new Error('timed out waiting for relay /health at ' + relayBaseUrl)
}

async function waitForPearBrowserReady ({ gatewayUrl, catalogUrl, appKey, timeoutMs }) {
  const started = Date.now()
  let lastError = null
  while (Date.now() - started < timeoutMs) {
    try {
      const gateway = await fetchText(gatewayUrl, { timeoutMs: 4000 })
      const catalog = await fetchJson(catalogUrl + '?pageSize=500', { timeoutMs: 4000 })
      const entries = [
        ...(Array.isArray(catalog.items) ? catalog.items : []),
        ...(Array.isArray(catalog.apps) ? catalog.apps : []),
        ...(Array.isArray(catalog.entries) ? catalog.entries : [])
      ]
      const entry = entries.find(item => {
        const key = String(item.appKey || item.driveKey || '').toLowerCase()
        return key === appKey
      })

      if (gateway.includes('HiveRelay Marketplace Demo') && entry && entry.anchored === true) {
        return { catalog, entry }
      }
      lastError = new Error('gateway or catalog not anchored yet')
    } catch (err) {
      lastError = err
    }
    await sleep(1000)
  }
  throw new Error('timed out waiting for PearBrowser-ready app: ' + (lastError ? lastError.message : 'unknown delay'))
}

function buildHandoff ({
  relayBaseUrl,
  catalogUrl,
  gatewayUrl,
  capabilityUrl,
  statusUrl,
  dhtRelayWsUrl,
  appKey,
  catalog,
  catalogEntry,
  capabilities,
  status,
  storageRoot,
  bootstrapArg
}) {
  const dhtRelayWs = status && status.dhtRelayWs && status.dhtRelayWs.running
    ? {
        url: dhtRelayWsUrl,
        host: status.dhtRelayWs.host,
        port: status.dhtRelayWs.port,
        maxConnections: status.dhtRelayWs.maxConnections,
        rateLimit: status.dhtRelayWs.rateLimit
      }
    : null

  return {
    relaySubscriptionUrl: relayBaseUrl,
    catalogUrl,
    gatewayUrl,
    hyperUrl: `hyper://${appKey}/index.html`,
    capabilityUrl,
    statusUrl,
    app: {
      id: catalogEntry.id || catalogEntry.appId || args.appId,
      name: catalogEntry.name || args.appName,
      appKey,
      driveKey: catalogEntry.driveKey || appKey,
      discoveryKey: catalogEntry.discoveryKey || null,
      version: catalogEntry.version || args.version,
      privacyTier: catalogEntry.privacyTier || 'public',
      storageClass: catalogEntry.storageClass || null,
      availabilityClass: catalogEntry.availabilityClass || null,
      anchored: catalogEntry.anchored === true,
      encryptionKey: null
    },
    relay: {
      pubkey: capabilities.pubkey || status.publicKey || catalog.relayKey || null,
      acceptMode: capabilities.limitation ? capabilities.limitation.accept_mode : catalog.acceptMode,
      supportedTransports: capabilities.supported_transports || [],
      features: capabilities.features || [],
      catalogCount: capabilities.catalog || catalog.count || null,
      dhtRelayWs
    },
    localTestnet: {
      bootstrap: bootstrapArg,
      storageRoot
    }
  }
}

function printHandoff (handoff) {
  console.log()
  console.log('=== PearBrowser Demo Ready ===')
  console.log()
  console.log('Relay subscription URL: ' + handoff.relaySubscriptionUrl)
  console.log('Catalog URL:            ' + handoff.catalogUrl)
  console.log('Gateway URL:            ' + handoff.gatewayUrl)
  console.log('hyper:// URL:           ' + handoff.hyperUrl)
  console.log('Capability doc:         ' + handoff.capabilityUrl)
  console.log('Status URL:             ' + handoff.statusUrl)
  console.log()
  console.log('Keys:')
  console.log('  App key:        ' + handoff.app.appKey)
  console.log('  Discovery key:  ' + (handoff.app.discoveryKey || '(not published in catalog yet)'))
  console.log('  Relay pubkey:   ' + (handoff.relay.pubkey || '(unknown)'))
  console.log('  Encryption key: none (public demo)')
  console.log()
  console.log('Relay capabilities:')
  console.log('  Accept mode:          ' + (handoff.relay.acceptMode || '(unknown)'))
  console.log('  Supported transports: ' + listOrNone(handoff.relay.supportedTransports))
  console.log('  Features:             ' + listOrNone(handoff.relay.features))
  console.log('  DHT relay WS:         ' + (handoff.relay.dhtRelayWs ? handoff.relay.dhtRelayWs.url : 'disabled'))
  console.log()
  console.log('PearBrowser handoff JSON:')
  console.log(JSON.stringify(handoff, null, 2))
}

function parseArgs (argv) {
  const parsed = {
    once: false,
    keepStorage: false,
    fixture: DEFAULT_FIXTURE,
    storage: null,
    port: null,
    dhtRelayWsPort: null,
    timeoutSeconds: DEFAULT_TIMEOUT_SECONDS,
    appId: 'pearbrowser-marketplace-demo',
    appName: 'HiveRelay Marketplace Demo',
    version: '1.0.0'
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--once') { parsed.once = true; continue }
    if (arg === '--keep-storage') { parsed.keepStorage = true; continue }
    if (arg === '--fixture') { parsed.fixture = resolve(argv[++i]); continue }
    if (arg === '--storage') { parsed.storage = argv[++i]; continue }
    if (arg === '--port') { parsed.port = parsePort(argv[++i], '--port'); continue }
    if (arg === '--dht-relay-ws-port') { parsed.dhtRelayWsPort = parsePort(argv[++i], '--dht-relay-ws-port'); continue }
    if (arg === '--timeout') { parsed.timeoutSeconds = parsePositiveNumber(argv[++i], '--timeout'); continue }
    if (arg === '--app-id') { parsed.appId = String(argv[++i] || '').trim(); continue }
    if (arg === '--name') { parsed.appName = String(argv[++i] || '').trim(); continue }
    if (arg === '--version') { parsed.version = String(argv[++i] || '').trim(); continue }
    if (arg === '--help' || arg === '-h') {
      printUsage()
      process.exit(0)
    }
    throw new Error('unknown argument: ' + arg)
  }

  if (!parsed.appId) throw new Error('--app-id must not be empty')
  if (!parsed.appName) throw new Error('--name must not be empty')
  if (!parsed.version) throw new Error('--version must not be empty')
  return parsed
}

function printUsage () {
  console.log(`Usage: node scripts/pearbrowser-marketplace-demo.js [options]

Options:
  --once                         Verify end-to-end, print handoff, then stop
  --port <n>                     Relay API port (default: free port)
  --dht-relay-ws-port <n>        DHT relay WebSocket port (default: free port)
  --fixture <dir>                App directory to publish
  --storage <dir>                Demo runtime storage directory
  --keep-storage                 Keep auto-created runtime storage
  --timeout <seconds>            Readiness timeout (default: ${DEFAULT_TIMEOUT_SECONDS})
  --app-id <id>                  Catalog app id (default: pearbrowser-marketplace-demo)
  --name <name>                  Catalog app name
  --version <version>            Catalog app version
`)
}

function parsePort (value, label) {
  const port = Number(value)
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(label + ' must be a TCP port between 1 and 65535')
  }
  return port
}

function parsePositiveNumber (value, label) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) throw new Error(label + ' must be a positive number')
  return n
}

async function findFreePort () {
  const server = createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  const port = address && typeof address === 'object' ? address.port : null
  await new Promise(resolve => server.close(resolve))
  if (!port) throw new Error('could not allocate a free port')
  return port
}

function pipeChild (child, label, onLine = null) {
  pipeStream(child.stdout, label, onLine)
  pipeStream(child.stderr, label, onLine)
}

function pipeStream (stream, label, onLine) {
  let pending = ''
  stream.setEncoding('utf8')
  stream.on('data', (chunk) => {
    pending += chunk.replace(/\r/g, '\n')
    const lines = pending.split('\n')
    pending = lines.pop()
    for (const raw of lines) {
      const line = stripAnsi(raw).trimEnd()
      if (!line.trim()) continue
      if (onLine) onLine(line)
      console.log(`[${label}] ${line}`)
    }
  })
}

function stripAnsi (value) {
  // eslint-disable-next-line no-control-regex
  return String(value).replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '')
}

async function fetchJson (url, opts = {}) {
  const res = await fetchWithTimeout(url, opts.timeoutMs || 5000)
  if (!res.ok) throw new Error(url + ' returned HTTP ' + res.status)
  return res.json()
}

async function fetchText (url, opts = {}) {
  const res = await fetchWithTimeout(url, opts.timeoutMs || 5000)
  if (!res.ok) throw new Error(url + ' returned HTTP ' + res.status)
  return res.text()
}

async function fetchWithTimeout (url, timeoutMs) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  if (timer.unref) timer.unref()
  try {
    return await fetch(url, { signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

function withTimeout (promise, timeoutMs, label) {
  let timer
  return Promise.race([
    promise,
    new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('timed out waiting for ' + label)), timeoutMs)
      if (timer.unref) timer.unref()
    })
  ]).finally(() => {
    if (timer) clearTimeout(timer)
  })
}

function sleep (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function listOrNone (items) {
  return Array.isArray(items) && items.length ? items.join(', ') : '(none)'
}

function installShutdownHandlers (state) {
  const handler = async () => {
    await cleanup(state)
    process.exit(0)
  }
  process.once('SIGINT', handler)
  process.once('SIGTERM', handler)
}

async function cleanup (state) {
  if (state.cleaned) return
  state.cleaned = true
  await stopChild(state.publisher, 'publisher')
  await stopChild(state.relay, 'relay')
  if (state.testnet) {
    try { await state.testnet.destroy() } catch (_) {}
  }
  if (state.ownsStorage) {
    try { await rm(state.storageRoot, { recursive: true, force: true }) } catch (_) {}
  }
}

async function stopChild (child, label) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  child.kill('SIGTERM')
  try {
    await withTimeout(new Promise(resolve => child.once('exit', resolve)), 5000, label + ' exit')
  } catch (_) {
    try { child.kill('SIGKILL') } catch (_) {}
  }
}
