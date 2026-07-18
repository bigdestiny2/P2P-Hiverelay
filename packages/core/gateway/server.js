/**
 * Standalone Hyper Gateway Server
 *
 * Runs alongside a relay node or standalone. Serves seeded Hyperdrive
 * content over HTTP for mobile clients (PearBrowser fast-path).
 *
 * Usage:
 *   node packages/core/gateway/server.js [--port 9100] [--storage ./storage] [--cors https://example.com]
 *
 * Or programmatically:
 *   const { startGateway } = await import('./server.js')
 *   const gateway = await startGateway({ port: 9100, storage: './storage', corsOrigin: '*' })
 */

import { createServer } from 'http'
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

export async function startGateway (opts = {}) {
  const port = opts.port || DEFAULT_PORT
  const storagePath = opts.storage || './gateway-storage'
  const seedKeys = opts.seedKeys || []
  const corsOrigin = opts.corsOrigin || '*'

  // Boot P2P
  const store = openCorestore(storagePath)
  await store.ready()

  const swarm = new Hyperswarm()
  swarm.on('connection', (conn) => store.replicate(conn))

  // Join relay discovery topic so clients can find us
  swarm.join(RELAY_DISCOVERY_TOPIC, { server: true, client: false })

  // Seed requested drives. Per-drive corestore session so a later
  // drive.close() / cleanup never cascades into the root store.close()
  // and wedges the standalone gateway. Matches v0.8.14's pattern.
  const seededDrives = new Map()
  for (const keyHex of seedKeys) {
    const drive = new Hyperdrive(store.session(), Buffer.from(keyHex, 'hex'))
    await drive.ready()
    swarm.join(drive.discoveryKey, { server: true, client: true })
    seededDrives.set(keyHex, drive)
    console.log(`  Seeding: ${keyHex.slice(0, 16)}...`)
  }

  await swarm.flush()

  // Create gateway with a minimal relay node interface
  const nodeProxy = { store, swarm, seededDrives }
  const gateway = new HyperGateway(nodeProxy)

  // HTTP server
  const server = createServer(async (req, res) => {
    const origin = req.headers.origin
    if (corsOrigin === '*') {
      res.setHeader('Access-Control-Allow-Origin', '*')
    } else if (origin && origin === corsOrigin) {
      res.setHeader('Access-Control-Allow-Origin', corsOrigin)
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    const url = new URL(req.url, `http://localhost:${port}`)

    if (url.pathname === '/health') {
      writeJson(res, {
        ok: true,
        type: 'hiverelay-gateway',
        drives: seededDrives.size,
        ...sanitizeGatewayStats(gateway.getStats())
      })
      return
    }

    if (url.pathname.startsWith('/v1/hyper/')) {
      return gateway.handle(req, res)
    }

    // Seed a new drive via POST
    if (req.method === 'POST' && url.pathname === '/v1/seed') {
      try {
        const { key } = await readGatewaySeedBody(req)
        // Per-drive session — see Seed-loop comment above.
        const drive = new Hyperdrive(store.session(), Buffer.from(key, 'hex'))
        await drive.ready()
        swarm.join(drive.discoveryKey, { server: true, client: true })
        seededDrives.set(key, drive)
        writeJson(res, { ok: true, seeding: key })
      } catch (err) {
        const result = buildGatewaySeedErrorResponse(err)
        if (result.close) res.shouldKeepAlive = false
        writeJson(res, result.payload, result.status, result.close ? { Connection: 'close' } : null)
      }
      return
    }

    writeJson(res, { error: 'Not found' }, 404)
  })

  await new Promise((resolve, reject) => {
    server.on('error', reject)
    server.listen(port, '0.0.0.0', resolve)
  })

  console.log(`\n  HiveRelay Gateway running on http://0.0.0.0:${port}`)
  console.log(`  Seeding ${seededDrives.size} drives`)
  console.log(`  Fetch: GET http://localhost:${port}/v1/hyper/{KEY}/{path}\n`)

  return {
    server,
    gateway,
    store,
    swarm,
    seededDrives,
    async close () {
      server.close()
      await gateway.close()
      for (const [, drive] of seededDrives) {
        try { await drive.close() } catch {}
      }
      await swarm.destroy()
      await store.close()
    }
  }
}

// CLI mode
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2)
  const port = args.includes('--port') ? parseInt(args[args.indexOf('--port') + 1]) : DEFAULT_PORT
  const storage = args.includes('--storage') ? args[args.indexOf('--storage') + 1] : './gateway-storage'
  const corsOrigin = args.includes('--cors') ? args[args.indexOf('--cors') + 1] : '*'
  const seedKeys = args.filter(a => /^[a-f0-9]{64}$/i.test(a))

  startGateway({ port, storage, seedKeys, corsOrigin }).then((gw) => {
    process.on('SIGINT', async () => {
      console.log('\n  Shutting down...')
      await gw.close()
      process.exit(0)
    })
  }).catch(err => {
    console.error('Failed:', err.message)
    process.exit(1)
  })
}
