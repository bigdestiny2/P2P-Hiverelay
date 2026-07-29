/**
 * Standalone Hyper Gateway Server
 *
 * Runs alongside a relay node or standalone. Serves seeded Hyperdrive
 * content over HTTP for mobile clients (PearBrowser fast-path).
 *
 * Usage:
 *   node packages/core/gateway/server.js [--port 9100] [--host 127.0.0.1] [--storage ./storage] [--cors https://example.com]
 *
 * Or programmatically:
 *   const { startGateway } = await import('./server.js')
 *   const gateway = await startGateway({ port: 9100, host: '127.0.0.1', storage: './storage', corsOrigin: '*' })
 *
 * Security defaults:
 *   - binds loopback, not every interface;
 *   - POST /v1/seed is disabled unless allowDynamicSeed === true;
 *   - a non-loopback dynamic-seed listener requires a strong bearer token;
 *   - dynamic key count, request rate, body size, and open duration are bound.
 */

import { createServer } from 'http'
import { timingSafeEqual } from 'crypto'
import { isIP } from 'net'
import Hyperswarm from 'hyperswarm'
import { openCorestore } from '../core/persistence/storage-root-restore.js'
import Hyperdrive from 'hyperdrive'
import { HyperGateway } from './hyper-gateway.js'
import { RELAY_DISCOVERY_TOPIC } from '../core/constants.js'
import { readJsonBody } from '../core/relay-node/api-body.js'
import { sanitizeGatewayStats } from '../core/relay-node/api-gateway-stats.js'
import { getPostJsonContentTypeProblem } from '../core/relay-node/api-request.js'
import { writeJson } from '../core/relay-node/api-response.js'

const DEFAULT_PORT = 9100
const MAX_GATEWAY_SEED_BODY_BYTES = 4096
const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_MAX_SEEDED_DRIVES = 64
const MAX_SEEDED_DRIVES = 1024
const DEFAULT_MAX_SEED_REQUESTS_PER_MINUTE = 30
const MAX_SEED_REQUESTS_PER_MINUTE = 600
const DEFAULT_SEED_OPERATION_TIMEOUT_MS = 30_000
const MAX_SEED_OPERATION_TIMEOUT_MS = 120_000
const MAX_SEED_RATE_BUCKETS = 1024
const MAX_REQUEST_HEADER_BYTES = 16 * 1024

function httpError (message, statusCode = 400, close = false) {
  const err = new Error(message)
  err.statusCode = statusCode
  err.close = close
  err.expose = true
  return err
}

export function buildGatewaySeedErrorResponse (err) {
  if (err?.expose) {
    return {
      status: err.statusCode || 400,
      payload: { error: err.message },
      close: Boolean(err.close)
    }
  }
  return {
    status: 500,
    payload: { error: 'Gateway seed failed' },
    close: false
  }
}

export function validateGatewaySeedKey (key) {
  if (typeof key !== 'string' || !/^[0-9a-f]{64}$/i.test(key)) {
    throw httpError('key must be 64 hex characters')
  }
  return key.toLowerCase()
}

export async function readGatewaySeedBody (req) {
  const contentTypeProblem = getPostJsonContentTypeProblem(req)
  if (contentTypeProblem) {
    throw httpError(contentTypeProblem.error, 400, contentTypeProblem.close)
  }
  let body
  try {
    body = await readJsonBody(req, MAX_GATEWAY_SEED_BODY_BYTES)
  } catch (err) {
    throw httpError(err.message, err.message === 'Request body too large' ? 413 : 400)
  }
  return { key: validateGatewaySeedKey(body.key) }
}

export function validateStandaloneGatewayOptions (opts = {}) {
  const port = opts.port ?? DEFAULT_PORT
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) {
    throw new Error('port must be an integer from 0 to 65535')
  }
  const host = normalizeListenHost(opts.host ?? DEFAULT_HOST)
  if (!host) throw new Error('host must be a canonical IP address or localhost')

  const allowDynamicSeed = opts.allowDynamicSeed === true
  const enableDiscovery = opts.enableDiscovery !== false
  const maxSeededDrives = strictPositiveInteger(
    opts.maxSeededDrives,
    DEFAULT_MAX_SEEDED_DRIVES,
    'maxSeededDrives',
    MAX_SEEDED_DRIVES
  )
  const maxSeedRequestsPerMinute = strictPositiveInteger(
    opts.maxSeedRequestsPerMinute,
    DEFAULT_MAX_SEED_REQUESTS_PER_MINUTE,
    'maxSeedRequestsPerMinute',
    MAX_SEED_REQUESTS_PER_MINUTE
  )
  const seedOperationTimeoutMs = strictPositiveInteger(
    opts.seedOperationTimeoutMs,
    DEFAULT_SEED_OPERATION_TIMEOUT_MS,
    'seedOperationTimeoutMs',
    MAX_SEED_OPERATION_TIMEOUT_MS
  )
  const seedToken = opts.seedToken == null ? null : opts.seedToken
  if (seedToken !== null && (typeof seedToken !== 'string' || seedToken.length < 32 || seedToken.length > 4096)) {
    throw new Error('seedToken must contain 32 to 4096 characters')
  }
  if (allowDynamicSeed && !isLoopbackHost(host) && !seedToken) {
    throw new Error('non-loopback dynamic seed requires a configured seedToken')
  }

  const rawSeedKeys = opts.seedKeys ?? []
  if (!Array.isArray(rawSeedKeys)) throw new Error('seedKeys must be an array')
  const seedKeys = []
  const seen = new Set()
  for (const candidate of rawSeedKeys) {
    const key = validateGatewaySeedKey(candidate)
    if (seen.has(key)) continue
    seen.add(key)
    seedKeys.push(key)
  }
  if (seedKeys.length > maxSeededDrives) throw new Error('seedKeys exceeds maxSeededDrives')

  return {
    port,
    host,
    storagePath: opts.storage || './gateway-storage',
    corsOrigin: opts.corsOrigin || '*',
    allowDynamicSeed,
    enableDiscovery,
    seedToken,
    seedKeys,
    maxSeededDrives,
    maxSeedRequestsPerMinute,
    seedOperationTimeoutMs
  }
}

export function isStandaloneSeedRequestAuthorized (req, seedToken) {
  if (!seedToken) return true
  const distinct = req?.headersDistinct?.authorization
  if (Array.isArray(distinct) && distinct.length !== 1) return false

  let count = 0
  for (let i = 0; i < (req?.rawHeaders?.length || 0); i += 2) {
    if (String(req.rawHeaders[i]).toLowerCase() === 'authorization') count++
  }
  if (count > 1) return false

  const header = Array.isArray(distinct) ? distinct[0] : req?.headers?.authorization
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false
  const supplied = Buffer.from(header.slice(7))
  const expected = Buffer.from(seedToken)
  return supplied.byteLength === expected.byteLength && timingSafeEqual(supplied, expected)
}

function strictPositiveInteger (value, fallback, label, max) {
  if (value === undefined) return fallback
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new Error(`${label} must be an integer from 1 to ${max}`)
  }
  return value
}

function normalizeListenHost (value) {
  if (typeof value !== 'string' || !value || value !== value.trim() || value.length > 253) return null
  const host = value.toLowerCase()
  if (host === 'localhost') return host
  return isIP(host) ? host : null
}

function isLoopbackHost (value) {
  if (value === 'localhost' || value === '::1') return true
  return isIP(value) === 4 && value.startsWith('127.')
}

function withTimeout (promise, timeoutMs, context) {
  let timer = null
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (fn, value) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      fn(value)
    }
    timer = setTimeout(() => finish(reject, new Error(`${context} timed out`)), timeoutMs)
    Promise.resolve(promise).then(
      value => finish(resolve, value),
      err => finish(reject, err)
    )
  })
}

export async function startGateway (opts = {}) {
  const config = validateStandaloneGatewayOptions(opts)
  const {
    port,
    host,
    storagePath,
    seedKeys,
    corsOrigin,
    allowDynamicSeed,
    enableDiscovery,
    seedToken,
    maxSeededDrives,
    maxSeedRequestsPerMinute,
    seedOperationTimeoutMs
  } = config

  const store = openCorestore(storagePath)
  let swarm = null
  let gateway = null
  let server = null
  let closing = false
  let closed = false
  let closePromise = null
  const seededDrives = new Map()
  const seededApps = new Map()
  const seedOpenPromises = new Map()
  const seedRateLimits = new Map()
  const activeSockets = new Set()

  const closeResources = async () => {
    if (closed) return
    if (closePromise) return closePromise
    closing = true
    const pending = (async () => {
      if (server) {
        const current = server
        for (const socket of activeSockets) {
          try { socket.destroy() } catch {}
        }
        if (typeof current.closeAllConnections === 'function') {
          try { current.closeAllConnections() } catch {}
        }
        if (current.listening) await new Promise(resolve => current.close(resolve))
        server = null
      }
      activeSockets.clear()
      if (gateway) {
        try { await gateway.close() } catch {}
      }
      if (seedOpenPromises.size > 0) {
        await Promise.allSettled([...seedOpenPromises.values()])
        seedOpenPromises.clear()
      }
      await Promise.allSettled([...seededDrives.values()].map(async drive => {
        try { await withTimeout(drive.close(), seedOperationTimeoutMs, 'drive.close()') } catch {}
      }))
      seededDrives.clear()
      seededApps.clear()
      seedRateLimits.clear()
      if (swarm) {
        try { await withTimeout(swarm.destroy(), seedOperationTimeoutMs, 'swarm.destroy()') } catch {}
        swarm = null
      }
      try { await withTimeout(store.close(), seedOperationTimeoutMs, 'Corestore.close()') } catch {}
    })()
    closePromise = pending
    try { await pending } finally { closed = true; closePromise = null }
  }

  try {
    await withTimeout(store.ready(), seedOperationTimeoutMs, 'Corestore.ready()')

    swarm = new Hyperswarm()
    swarm.on('connection', (conn) => store.replicate(conn))
    if (enableDiscovery) swarm.join(RELAY_DISCOVERY_TOPIC, { server: true, client: false })

    const openSeedDrive = async (key) => {
      const existing = seededDrives.get(key)
      if (existing) return { drive: existing, alreadySeeded: true }
      const inFlight = seedOpenPromises.get(key)
      if (inFlight) return inFlight
      if (seededDrives.size + seedOpenPromises.size >= maxSeededDrives) {
        throw httpError('Seeded drive limit reached', 429)
      }

      const pending = (async () => {
        let drive = null
        let joined = false
        try {
          drive = new Hyperdrive(store.session(), Buffer.from(key, 'hex'))
          await withTimeout(drive.ready(), seedOperationTimeoutMs, 'drive.ready()')
          if (closing) throw new Error('Gateway is closing')
          swarm.join(drive.discoveryKey, { server: true, client: true })
          joined = true
          await withTimeout(swarm.flush(), seedOperationTimeoutMs, 'swarm.flush()')
          if (closing) throw new Error('Gateway is closing')
          seededDrives.set(key, drive)
          seededApps.set(key, {
            drive,
            blind: false,
            privacyTier: 'public',
            storageClass: 'persistent',
            availabilityClass: 'always-on'
          })
          return { drive, alreadySeeded: false }
        } catch (err) {
          if (joined && drive) {
            try { await swarm.leave(drive.discoveryKey) } catch {}
          }
          if (drive) {
            try { await withTimeout(drive.close(), seedOperationTimeoutMs, 'failed drive.close()') } catch {}
          }
          throw err
        }
      })()
      seedOpenPromises.set(key, pending)
      pending.finally(() => {
        if (seedOpenPromises.get(key) === pending) seedOpenPromises.delete(key)
      }).catch(() => {})
      return pending
    }

    for (const keyHex of seedKeys) {
      await openSeedDrive(keyHex)
      console.log(`  Seeding: ${keyHex.slice(0, 16)}...`)
    }
    if (enableDiscovery || seedKeys.length > 0) {
      await withTimeout(swarm.flush(), seedOperationTimeoutMs, 'initial swarm.flush()')
    }

    // Share the already-open Corestore and seeded drives. The old standalone
    // path accidentally built a second Corestore/Hyperswarm inside
    // HyperGateway and ignored its own seededDrives map.
    const nodeProxy = { store, swarm, seededDrives, seededApps }
    gateway = new HyperGateway(nodeProxy, { store })

    const checkSeedRate = (address) => {
      const now = Date.now()
      let entry = seedRateLimits.get(address)
      if (!entry || now > entry.resetAt) {
        if (!entry && seedRateLimits.size >= MAX_SEED_RATE_BUCKETS) {
          for (const [key, value] of seedRateLimits) {
            if (!value || now > value.resetAt) seedRateLimits.delete(key)
          }
          if (seedRateLimits.size >= MAX_SEED_RATE_BUCKETS) return false
        }
        entry = { count: 0, resetAt: now + 60_000 }
        seedRateLimits.set(address, entry)
      }
      if (entry.count >= maxSeedRequestsPerMinute) return false
      entry.count++
      return true
    }

    const handleRequest = async (req, res) => {
      if (closing) {
        res.shouldKeepAlive = false
        writeJson(res, { error: 'Gateway shutting down' }, 503, { Connection: 'close', 'Retry-After': '1' })
        return
      }
      if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//')) {
        res.shouldKeepAlive = false
        writeJson(res, { error: 'Invalid request target' }, 400, { Connection: 'close' })
        return
      }

      const url = new URL(req.url, `http://localhost:${port}`)
      const origin = req.headers.origin
      if (corsOrigin === '*') {
        res.setHeader('Access-Control-Allow-Origin', '*')
      } else if (origin && origin === corsOrigin) {
        res.setHeader('Access-Control-Allow-Origin', corsOrigin)
        res.setHeader('Vary', 'Origin')
      }
      // Mutating seed management is intentionally not browser-CORS-enabled.
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')

      if (req.method === 'OPTIONS') {
        res.writeHead(204)
        res.end()
        return
      }

      if ((req.method === 'GET' || req.method === 'HEAD') && url.pathname === '/health') {
        writeJson(res, {
          ok: true,
          type: 'hiverelay-gateway',
          drives: seededDrives.size,
          dynamicSeedEnabled: allowDynamicSeed,
          ...sanitizeGatewayStats(gateway.getStats())
        })
        return
      }

      if (url.pathname.startsWith('/v1/hyper/')) {
        return gateway.handle(req, res)
      }

      if (req.method === 'POST' && url.pathname === '/v1/seed') {
        if (!allowDynamicSeed) {
          writeJson(res, { error: 'Not found' }, 404)
          return
        }
        const address = req.socket.remoteAddress || 'unknown'
        if (!checkSeedRate(address)) {
          writeJson(res, { error: 'Too many seed requests' }, 429, { 'Retry-After': '60' })
          return
        }
        if (!isStandaloneSeedRequestAuthorized(req, seedToken)) {
          writeJson(res, { error: 'Unauthorized' }, 401, {
            'WWW-Authenticate': 'Bearer realm="hiverelay-standalone-seed"'
          })
          return
        }
        try {
          const { key } = await readGatewaySeedBody(req)
          const result = await openSeedDrive(key)
          writeJson(res, { ok: true, seeding: key, alreadySeeded: result.alreadySeeded })
        } catch (err) {
          const result = buildGatewaySeedErrorResponse(err)
          if (result.close) res.shouldKeepAlive = false
          writeJson(res, result.payload, result.status, result.close ? { Connection: 'close' } : null)
        }
        return
      }

      writeJson(res, { error: 'Not found' }, 404)
    }

    server = createServer({
      maxHeaderSize: MAX_REQUEST_HEADER_BYTES,
      insecureHTTPParser: false,
      requireHostHeader: true,
      joinDuplicateHeaders: false
    }, (req, res) => {
      handleRequest(req, res).catch(() => {
        if (res.destroyed || res.writableEnded) return
        if (res.headersSent) {
          res.destroy()
          return
        }
        writeJson(res, { error: 'Internal error' }, 500)
      })
    })
    server.headersTimeout = 10_000
    server.requestTimeout = 60_000
    server.keepAliveTimeout = 5_000
    server.maxRequestsPerSocket = 100
    server.maxHeadersCount = 64
    server.maxConnections = 512
    server.on('connection', socket => {
      activeSockets.add(socket)
      socket.on('close', () => activeSockets.delete(socket))
    })

    await new Promise((resolve, reject) => {
      const onError = err => reject(err)
      server.once('error', onError)
      server.listen(port, host, () => {
        server.removeListener('error', onError)
        resolve()
      })
    })
    server.on('error', err => {
      gateway.emit('server-error', { error: err?.message || String(err) })
    })

    const actualPort = server.address().port
    console.log(`\n  HiveRelay Gateway running on http://${host}:${actualPort}`)
    console.log(`  Seeding ${seededDrives.size} drives`)
    console.log(`  Dynamic seed endpoint: ${allowDynamicSeed ? 'explicitly enabled' : 'disabled'}`)
    console.log(`  Fetch: GET http://${host}:${actualPort}/v1/hyper/{KEY}/{path}\n`)

    return {
      server,
      gateway,
      store,
      swarm,
      seededDrives,
      config: {
        host,
        allowDynamicSeed,
        maxSeededDrives,
        maxSeedRequestsPerMinute,
        seedOperationTimeoutMs,
        seedTokenRequired: Boolean(seedToken)
      },
      close: closeResources
    }
  } catch (err) {
    await closeResources()
    throw err
  }
}

// CLI mode
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2)
  const port = args.includes('--port') ? Number(args[args.indexOf('--port') + 1]) : DEFAULT_PORT
  const host = args.includes('--host') ? args[args.indexOf('--host') + 1] : DEFAULT_HOST
  const storage = args.includes('--storage') ? args[args.indexOf('--storage') + 1] : './gateway-storage'
  const corsOrigin = args.includes('--cors') ? args[args.indexOf('--cors') + 1] : '*'
  const allowDynamicSeed = args.includes('--allow-dynamic-seed')
  const seedToken = process.env.HIVERELAY_GATEWAY_SEED_TOKEN || null
  const maxSeededDrives = args.includes('--max-seeded-drives')
    ? Number(args[args.indexOf('--max-seeded-drives') + 1])
    : DEFAULT_MAX_SEEDED_DRIVES
  const maxSeedRequestsPerMinute = args.includes('--max-seed-requests-per-minute')
    ? Number(args[args.indexOf('--max-seed-requests-per-minute') + 1])
    : DEFAULT_MAX_SEED_REQUESTS_PER_MINUTE
  const seedKeys = args.filter(a => /^[a-f0-9]{64}$/i.test(a))

  startGateway({
    port,
    host,
    storage,
    seedKeys,
    corsOrigin,
    allowDynamicSeed,
    seedToken,
    maxSeededDrives,
    maxSeedRequestsPerMinute
  }).then((gw) => {
    let stopping = false
    const stop = async () => {
      if (stopping) return
      stopping = true
      console.log('\n  Shutting down...')
      await gw.close()
      process.exit(0)
    }
    process.once('SIGINT', stop)
    process.once('SIGTERM', stop)
  }).catch(err => {
    console.error('Failed:', err.message)
    process.exit(1)
  })
}
