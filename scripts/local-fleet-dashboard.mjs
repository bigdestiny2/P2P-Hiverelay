#!/usr/bin/env node
/**
 * Local operator proxy for the HiveRelay fleet dashboard.
 *
 * Serves dashboard HTML with an injected management token and proxies
 * /api/* + static dashboard assets to a remote relay. Keeps the API key
 * off the public :9100 surface (do not enable ui.exposeToken on open VPS).
 *
 *   HIVERELAY_DASHBOARD_UPSTREAM=http://144.172.116.110:9100 \
 *   HIVERELAY_API_KEY=... \
 *   node scripts/local-fleet-dashboard.mjs
 *
 * Then open http://127.0.0.1:9191/fleet
 */
import http from 'node:http'
import { readFileSync, existsSync } from 'node:fs'
import { join, extname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')
const DASH = join(ROOT, 'dashboard')

const PORT = Number(process.env.HIVERELAY_DASHBOARD_PORT || 9191)
const UPSTREAM = (process.env.HIVERELAY_DASHBOARD_UPSTREAM || 'http://144.172.116.110:9100').replace(/\/$/, '')
const API_KEY = process.env.HIVERELAY_API_KEY || ''

if (!API_KEY) {
  console.error('HIVERELAY_API_KEY is required')
  process.exit(1)
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
}

function injectToken (html) {
  const tag = `<meta name="hiverelay-ui-token" content="${API_KEY.replace(/"/g, '')}">`
  if (html.includes('hiverelay-ui-token')) {
    return html.replace(/<meta name="hiverelay-ui-token"[^>]*>/i, tag)
  }
  if (html.includes('</head>')) return html.replace('</head>', `  ${tag}\n</head>`)
  return tag + html
}

function mapPath (urlPath) {
  // Relay serves /fleet, /dashboard, /network, … — map to dashboard/*.html
  const p = urlPath.split('?')[0]
  const map = {
    '/': 'index.html',
    '/dashboard': 'index.html',
    '/fleet': 'fleet.html',
    '/network': 'network.html',
    '/catalog': 'catalog.html',
    '/payments': 'payments.html',
    '/calculator': 'calculator.html',
    '/leaderboard': 'leaderboard.html',
    '/docs': 'docs.html',
    '/wizard': 'wizard.html'
  }
  if (map[p]) return join(DASH, map[p])
  if (p.startsWith('/dashboard/')) return join(DASH, p.slice('/dashboard/'.length))
  // bare filename under dashboard
  if (/^\/[a-z0-9_.-]+\.html$/i.test(p)) return join(DASH, p.slice(1))
  return null
}

async function proxy (req, res) {
  const target = UPSTREAM + req.url
  const headers = { ...req.headers, host: new URL(UPSTREAM).host }
  delete headers['content-length']
  if (req.url.startsWith('/api/')) {
    headers.authorization = `Bearer ${API_KEY}`
  }
  const init = { method: req.method, headers }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks = []
    for await (const c of req) chunks.push(c)
    init.body = Buffer.concat(chunks)
  }
  const upstream = await fetch(target, init)
  res.writeHead(upstream.status, Object.fromEntries(upstream.headers))
  const buf = Buffer.from(await upstream.arrayBuffer())
  res.end(buf)
}

const server = http.createServer(async (req, res) => {
  try {
    const urlPath = req.url.split('?')[0]
    if (urlPath.startsWith('/api/')) {
      await proxy(req, res)
      return
    }
    const file = mapPath(urlPath)
    if (file && existsSync(file)) {
      let body = readFileSync(file)
      const ext = extname(file)
      if (ext === '.html') body = Buffer.from(injectToken(body.toString('utf8')), 'utf8')
      res.writeHead(200, {
        'content-type': MIME[ext] || 'application/octet-stream',
        'cache-control': 'no-store'
      })
      res.end(body)
      return
    }
    // fall through proxy for other paths (status, health, …)
    await proxy(req, res)
  } catch (err) {
    res.writeHead(502, { 'content-type': 'text/plain' })
    res.end('proxy error: ' + (err && err.message ? err.message : String(err)))
  }
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Fleet dashboard proxy on http://127.0.0.1:${PORT}/fleet`)
  console.log(`Upstream ${UPSTREAM}`)
})
