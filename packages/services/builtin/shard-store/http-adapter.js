/**
 * HTTP bridge for the shard store (M5). Mirrors the seed-core / outboxlog
 * adapter shape. The P2P service RPC is the primary transport; this is for
 * browsers / ops. Bodies are raw octet-stream ciphertext (never buffered
 * beyond maxShardBytes). The pin travels in the X-Shard-Pin header (JSON).
 */
import b4a from 'b4a'
import { normalizeShardAddress } from './shard-engine.js'

export const SHARD_HTTP_PREFIX = '/api/v1/shard'

// Per-IP rate limiting mirrors the outboxlog / witnesslog / repairticket
// adapters. On by default via a process-wide bucket store so the protection is
// live the moment this adapter is mounted; callers may pass their own `state`
// and `rateLimit` in opts to scope/override it.
const DEFAULT_RATE_LIMIT = { windowMs: 60000, max: 1200 }
const MAX_RATE_BUCKETS = 50000
const moduleRateState = createShardHttpState()

export function createShardHttpState () {
  return { buckets: new Map() }
}

function clientIp (req, opts) {
  if (opts && opts.trustProxy && req.headers && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim() || 'unknown'
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown'
}

function overLimit (ip, rateLimit, state) {
  if (!rateLimit || rateLimit.max === false || rateLimit.max === Infinity) return false
  const now = Date.now()
  let bucket = state.buckets.get(ip)
  if (!bucket || now - bucket.start > rateLimit.windowMs) {
    bucket = { start: now, count: 0 }
    state.buckets.set(ip, bucket)
  }
  bucket.count++
  if (state.buckets.size > MAX_RATE_BUCKETS) {
    for (const [key, value] of state.buckets) {
      if (now - value.start > rateLimit.windowMs) state.buckets.delete(key)
    }
  }
  return bucket.count > rateLimit.max
}

export function resolveShardRoute (method, path) {
  if (!path || !path.startsWith(SHARD_HTTP_PREFIX)) return null
  const rest = path.slice(SHARD_HTTP_PREFIX.length).split('?')[0]
  if (rest === '' || rest === '/') {
    if (method === 'POST') return { kind: 'put' }
    return null
  }
  const seg = rest.replace(/^\//, '')
  const proveMatch = seg.match(/^([0-9a-f]{64})\/prove$/i)
  if (proveMatch && method === 'POST') return { kind: 'prove', hash: proveMatch[1].toLowerCase() }
  const hash = normalizeShardAddress(seg)
  if (hash) {
    if (method === 'GET') return { kind: 'get', hash }
    if (method === 'HEAD') return { kind: 'head', hash }
    if (method === 'DELETE') return { kind: 'delete', hash }
  }
  return null
}

async function readBody (req, maxBytes) {
  return await new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    req.on('data', (c) => {
      total += c.length
      if (total > maxBytes) { reject(Object.assign(new Error('TOO_LARGE'), { code: 'TOO_LARGE' })); req.destroy?.(); return }
      chunks.push(c)
    })
    req.on('end', () => resolve(b4a.concat(chunks.map(c => b4a.from(c)))))
    req.on('error', reject)
  })
}

function sendJson (res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

const STATUS_BY_CODE = {
  HASH_MISMATCH: 400,
  TOO_LARGE: 413,
  UNAUTHORIZED_PIN: 403,
  QUOTA_EXHAUSTED: 429,
  NOT_HELD: 404,
  BAD_SIGNATURE: 400,
  BAD_ADDRESS: 400,
  BAD_REQUEST: 400,
  RATE_LIMITED: 429,
  SERVICE_UNAVAILABLE: 503,
  BAD_CIPHERTEXT: 400
}

/** Handle a resolved shard route. Returns true if handled. */
export async function handleShardHttp (service, route, req, res, opts = {}) {
  const url = opts.url
  const rateState = opts.state || moduleRateState
  const rateLimit = opts.rateLimit || DEFAULT_RATE_LIMIT
  if (overLimit(clientIp(req, opts), rateLimit, rateState)) {
    sendJson(res, 429, { error: 'RATE_LIMITED' })
    return true
  }
  try {
    if (route.kind === 'head') {
      const has = await service.has({ hash: route.hash })
      if (!has.present) { res.writeHead(404); res.end(); return true }
      res.writeHead(200, { 'Content-Length': String(has.byteLength) }); res.end()
      return true
    }
    if (route.kind === 'get') {
      const nonce = url && url.searchParams ? url.searchParams.get('nonce') : null
      const got = await service.get({ hash: route.hash, nonce: nonce || undefined })
      const headers = { 'Content-Type': 'application/octet-stream' }
      if (got.proof) headers['X-Shard-Proof'] = JSON.stringify(got.proof)
      res.writeHead(200, headers)
      res.end(b4a.from(got.ciphertext, 'base64'))
      return true
    }
    if (route.kind === 'put') {
      const pinHeader = req.headers && (req.headers['x-shard-pin'] || req.headers['X-Shard-Pin'])
      let pin = null
      try { pin = pinHeader ? JSON.parse(pinHeader) : null } catch { sendJson(res, 400, { error: 'BAD_PIN_HEADER' }); return true }
      const body = await readBody(req, service.maxShardBytes)
      const out = await service.put({ ciphertext: b4a.toString(body, 'base64'), pin })
      sendJson(res, 201, out)
      return true
    }
    if (route.kind === 'prove') {
      const body = await readBody(req, 4096)
      let params = {}
      try { params = body.length ? JSON.parse(b4a.toString(body, 'utf8')) : {} } catch { sendJson(res, 400, { error: 'BAD_JSON' }); return true }
      const out = await service.prove({ hash: route.hash, nonce: params.nonce }, { remotePubkey: req.remotePubkey })
      sendJson(res, 200, out)
      return true
    }
    if (route.kind === 'delete') {
      const body = await readBody(req, 8192)
      let params = {}
      try { params = body.length ? JSON.parse(b4a.toString(body, 'utf8')) : {} } catch { sendJson(res, 400, { error: 'BAD_JSON' }); return true }
      const out = await service.unpin({ hash: route.hash, pinRef: params.pinRef, removal: params.removal })
      sendJson(res, 200, out)
      return true
    }
  } catch (err) {
    const status = STATUS_BY_CODE[err && err.code] || 500
    sendJson(res, status, { error: (err && err.code) || 'INTERNAL' })
    return true
  }
  return false
}
