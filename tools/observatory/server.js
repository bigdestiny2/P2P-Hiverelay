// HiveRelay Observatory — Layer 1+2: log aggregator + topology poller.
//
// Polls each relay's HTTP endpoints every POLL_INTERVAL_MS, holds the latest
// snapshot in memory, exposes /api/state (current) + /api/history (last N
// polls) + a static dashboard at /. No DB; restart loses history but the
// next poll fills the current state in seconds.
//
// Single Node process, no deps beyond stdlib. Runs as systemd service on
// the observatory host (currently Bern). Designed to fit in <1 KB of RAM
// per relay across the snapshot history ring buffer.

import http from 'http'
import { readFile } from 'fs/promises'
import { fileURLToPath } from 'url'
import path from 'path'
import { LogTailer } from './log-tail.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const PORT = Number(process.env.OBSERVATORY_PORT) || 9200
const POLL_INTERVAL_MS = Number(process.env.OBSERVATORY_POLL_MS) || 10_000
const HISTORY_LEN = Number(process.env.OBSERVATORY_HISTORY) || 360 // ~1 hour at 10s
const LOG_RING_SIZE = Number(process.env.OBSERVATORY_LOG_RING) || 2000
const LOG_TAIL_KEY = process.env.OBSERVATORY_TAIL_KEY || '/root/.ssh/observatory_tail'
const LOG_TAIL_ENABLED = process.env.OBSERVATORY_LOG_TAIL !== 'false'

// Fleet config. Per-relay API keys are intentionally NOT here — the
// observatory only hits public endpoints. If we later add authenticated
// pulls (/api/manage/*), we'll thread keys via env vars per relay.
//
// Each entry: { id, host, region, operator, baseUrl?, pubkey?, tailable? }.
//
//   baseUrl   overrides the default `http://${host}:9100` for hosts that
//             terminate TLS upstream — e.g. Fly.io apps reachable only
//             on https/:443.
//   pubkey    declared 12-char relay pubkey. Some relays don't expose it
//             via /.well-known/hiverelay.json (identity is null when the
//             capability doc is built without a swarm.keyPair handle).
//             Declaring it here lets the dashboard's known-peer labeller
//             still resolve `1e7d8b1ffe69` → `utah` etc. when those
//             pubkeys appear in OTHER relays' /peers lists.
//   tailable  default true. Set false for relays we can't reach over
//             port-22 SSH (Fly.io apps, anything behind a proxy that
//             doesn't expose sshd). Non-tailable relays still get
//             polled — they just don't contribute log lines.
const RELAYS = [
  { id: 'utah',        host: '144.172.101.215', region: 'NA', operator: 'hive-foundation-utah',        pubkey: '1e7d8b1ffe69' },
  { id: 'utah-us',     host: '144.172.91.26',   region: 'NA', operator: 'hive-foundation-utah-us',     pubkey: '37cf4bfbdf33' },
  { id: 'singapore-1', host: '104.194.153.179', region: 'AS', operator: 'hive-foundation-singapore',   pubkey: '17ba6ae38d69' },
  { id: 'singapore-2', host: '104.194.152.121', region: 'AS', operator: 'hive-foundation-singapore-2', pubkey: '6b11208ad547' },
  { id: 'bern',        host: '45.59.123.112',   region: 'EU', operator: 'hive-foundation-bern',        pubkey: 'bc421fedea8a' },
  { id: 'milkyb-fra',  host: 'milkyb-hiverelay-fra.fly.dev', region: 'EU', operator: 'milkyb', baseUrl: 'https://milkyb-hiverelay-fra.fly.dev', pubkey: '478462ed8597', tailable: false },
  { id: 'milkyb-iad',  host: 'milkyb-hiverelay-iad.fly.dev', region: 'NA', operator: 'milkyb', baseUrl: 'https://milkyb-hiverelay-iad.fly.dev', pubkey: '3a5082096400', tailable: false },
  { id: 'milkyb-syd',  host: 'milkyb-hiverelay-syd.fly.dev', region: 'OC', operator: 'milkyb', baseUrl: 'https://milkyb-hiverelay-syd.fly.dev', pubkey: '9ca3aa7ff6de', tailable: false }
]

// Current snapshot (overwritten every poll) + ring buffer of last N snapshots
// for trend lines. History is shallow on purpose: just the small derived
// metrics, not full peer lists, so the buffer doesn't grow unbounded.
let current = { updatedAt: null, relays: {} }
const history = []

async function fetchJson (url, timeoutMs = 5_000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: controller.signal })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return await res.json()
  } finally {
    clearTimeout(timer)
  }
}

async function pollRelay (relay) {
  // baseUrl overrides the default `http://${host}:9100` for relays that
  // terminate TLS upstream (Fly.io, Cloudflare, etc.) and don't expose
  // a per-relay port — see RELAYS comment.
  const base = relay.baseUrl || `http://${relay.host}:9100`
  const snap = {
    id: relay.id,
    host: relay.host,
    region: relay.region,
    operator: relay.operator,
    // Surface the declared pubkey in the snapshot so the dashboard's
    // KNOWN map can label peers regardless of whether the relay's own
    // capability doc exposes its identity.
    declaredPubkey: relay.pubkey || null,
    fetchedAt: Date.now(),
    up: false,
    errors: []
  }

  // Settle all five in parallel — slowest endpoint dictates wall time.
  // Using allSettled so one slow endpoint doesn't poison the snapshot.
  //
  // /catalog.json defaults to pageSize=50 with pagination; fetching with
  // pageSize=1000 grabs the whole catalog in one round-trip. Relays with
  // more than 1000 apps will need follow-the-pagination logic — fine for
  // now, the production fleet is well below that.
  const [health, peers, status, catalog, capability] = await Promise.allSettled([
    fetchJson(`${base}/health`),
    fetchJson(`${base}/peers`),
    fetchJson(`${base}/status`),
    fetchJson(`${base}/catalog.json?pageSize=1000`),
    fetchJson(`${base}/.well-known/hiverelay.json`)
  ])

  if (health.status === 'fulfilled') {
    snap.health = health.value
    snap.up = !!health.value.ok
    snap.running = !!health.value.running
    snap.uptimeMs = health.value.uptime?.ms ?? null
  } else {
    snap.errors.push({ endpoint: 'health', error: errorString(health.reason) })
  }

  if (peers.status === 'fulfilled') {
    snap.peerCount = peers.value.count ?? 0
    snap.peers = (peers.value.peers || []).map(p => ({
      pubkey: p.remotePublicKey ? p.remotePublicKey.slice(0, 12) : null
    }))
  } else {
    snap.errors.push({ endpoint: 'peers', error: errorString(peers.reason) })
  }

  if (status.status === 'fulfilled') {
    snap.status = status.value
  } else {
    snap.errors.push({ endpoint: 'status', error: errorString(status.reason) })
  }

  if (catalog.status === 'fulfilled') {
    const apps = catalog.value.apps || []
    snap.catalog = {
      relayKey: catalog.value.relayKey,
      total: catalog.value.count?.total ?? apps.length,
      anchored: apps.filter(a => a.anchored === true).length,
      apps: apps.slice(0, 50).map(a => ({
        key: a.appKey?.slice(0, 12),
        appId: a.appId || null,
        version: a.version || null,
        anchored: a.anchored === true,
        anchoredLength: a.anchoredLength || 0,
        type: a.type
      }))
    }
  } else {
    snap.errors.push({ endpoint: 'catalog', error: errorString(catalog.reason) })
  }

  if (capability.status === 'fulfilled') {
    snap.capability = {
      version: capability.value.version,
      schemaVersion: capability.value.schemaVersion,
      acceptMode: capability.value.acceptMode,
      transports: capability.value.transports,
      federation: capability.value.federation,
      identity: capability.value.identity?.publicKey?.slice(0, 12) || null
    }
  } else {
    snap.errors.push({ endpoint: 'capability', error: errorString(capability.reason) })
  }

  return snap
}

function errorString (err) {
  if (!err) return 'unknown'
  if (err.name === 'AbortError') return 'timeout'
  return err.message || String(err)
}

async function pollAll () {
  const results = await Promise.all(RELAYS.map(pollRelay))
  current = {
    updatedAt: Date.now(),
    relays: Object.fromEntries(results.map(s => [s.id, s]))
  }
  // Push compact derived metrics into the history ring.
  history.push({
    t: current.updatedAt,
    relays: Object.fromEntries(results.map(s => [s.id, {
      up: s.up,
      running: s.running,
      peers: s.peerCount,
      apps: s.catalog?.total ?? null,
      anchored: s.catalog?.anchored ?? null,
      version: s.capability?.version ?? null
    }]))
  })
  if (history.length > HISTORY_LEN) history.shift()
}

// First poll immediately, then on interval. Don't await the first one at
// boot — let the server come up so /api/state returns "still polling".
pollAll().catch(err => console.error('initial poll error:', err.message))
setInterval(() => {
  pollAll().catch(err => console.error('poll error:', err.message))
}, POLL_INTERVAL_MS)

// ── Log tailer ──────────────────────────────────────────────────────────
// Multiplexed SSH tail from each relay, fanned out to SSE subscribers.
// Off by default if the SSH key isn't present (e.g. running locally).

const sseClients = new Set()
let logTailer = null

if (LOG_TAIL_ENABLED) {
  // Filter to relays we can actually SSH-tail. Relays with `tailable:
  // false` are behind proxies that don't expose port-22 sshd (Fly.io,
  // Cloudflare tunnels, etc.) — attempting to connect to them produces
  // a `kex_exchange_identification: Connection reset by peer` every
  // ~8s, which drowns the real signal in the SSE log stream.
  //
  // For Bern→self tailing, the relay's HTTP host is its public IP. The
  // SSH host needs to be 127.0.0.1 for the self-tail. We rewrite Bern's
  // host here.
  const tailRelays = RELAYS
    .filter(r => r.tailable !== false)
    .map(r => ({
      id: r.id,
      host: r.host === '45.59.123.112' ? '127.0.0.1' : r.host
    }))
  const skipped = RELAYS.filter(r => r.tailable === false).map(r => r.id)
  logTailer = new LogTailer({
    relays: tailRelays,
    sshKey: LOG_TAIL_KEY,
    ringSize: LOG_RING_SIZE
  })
  logTailer.on('line', (entry) => {
    if (sseClients.size === 0) return
    const payload = `data: ${JSON.stringify(entry)}\n\n`
    for (const res of sseClients) {
      try { res.write(payload) } catch (_) { /* will be cleaned up on close */ }
    }
  })
  logTailer.start()
  console.log(`Log tailer started — tailing ${tailRelays.length} of ${RELAYS.length} relays (ring=${LOG_RING_SIZE})`)
  if (skipped.length > 0) {
    console.log(`Log tailer skipping non-tailable: ${skipped.join(', ')}`)
  }
}

// ── HTTP surface ─────────────────────────────────────────────────────────

const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml'
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
    const route = url.pathname

    if (route === '/api/state') {
      return json(res, current)
    }
    if (route === '/api/history') {
      return json(res, { points: history.length, history })
    }
    if (route === '/api/config') {
      return json(res, {
        relays: RELAYS,
        pollIntervalMs: POLL_INTERVAL_MS,
        logTailEnabled: !!logTailer,
        logRingSize: LOG_RING_SIZE
      })
    }
    if (route === '/healthz') {
      return json(res, { ok: true, pollAt: current.updatedAt, sseClients: sseClients.size })
    }

    // ── Log stream — Server-Sent Events ─────────────────────────────────
    if (route === '/api/logs/stream') {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
        connection: 'keep-alive',
        'x-accel-buffering': 'no' // disable proxy buffering if any
      })
      // Send the recent ring on connect so late joiners see context.
      const since = Number(url.searchParams.get('since')) || 0
      const recent = (logTailer?.recent(LOG_RING_SIZE) || [])
        .filter(e => e.ts > since)
      for (const entry of recent) {
        res.write(`data: ${JSON.stringify(entry)}\n\n`)
      }
      // Heartbeat every 20s to keep proxies happy.
      const heartbeat = setInterval(() => {
        try { res.write(`: heartbeat\n\n`) } catch (_) {}
      }, 20_000)
      sseClients.add(res)
      req.on('close', () => {
        clearInterval(heartbeat)
        sseClients.delete(res)
      })
      return
    }

    if (route === '/api/logs/recent') {
      const n = Number(url.searchParams.get('n')) || 200
      return json(res, { lines: logTailer?.recent(n) || [] })
    }

    // Static dashboard
    const file = route === '/' ? '/public/index.html' : route
    const safe = path.normalize(file).replace(/^(\.\.[\/])+/, '')
    const full = path.join(__dirname, safe)
    if (!full.startsWith(__dirname)) {
      res.writeHead(403); return res.end('forbidden')
    }
    const data = await readFile(full)
    const ct = STATIC_TYPES[path.extname(full)] || 'application/octet-stream'
    res.writeHead(200, { 'content-type': ct })
    return res.end(data)
  } catch (err) {
    res.writeHead(err.code === 'ENOENT' ? 404 : 500, { 'content-type': 'text/plain' })
    return res.end(err.code === 'ENOENT' ? 'not found' : 'error: ' + err.message)
  }
})

function json (res, obj) {
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(obj))
}

server.listen(PORT, () => {
  console.log(`HiveRelay Observatory v0.1 listening on http://0.0.0.0:${PORT}`)
  console.log(`Polling ${RELAYS.length} relays every ${POLL_INTERVAL_MS}ms`)
})
