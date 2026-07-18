/**
 * Hyper Gateway — HTTP endpoint for serving Hyperdrive content
 *
 * Exposes seeded Hyperdrives over HTTP so mobile clients can fetch
 * content without a full P2P connection (fast-path).
 *
 * When a Corestore is provided via `opts.store`, the gateway creates a
 * namespaced session instead of spinning up a separate P2P stack — halving
 * memory usage. Falls back to a dedicated Corestore + Hyperswarm when no
 * store is given (standalone / backward-compatible mode).
 *
 * Designed to be mounted on the existing RelayAPI server.
 *
 * Usage:
 *   const gateway = new HyperGateway(relayNode, { store: relayNode.store })
 *   // Add routes to existing API server:
 *   // if (path.startsWith('/v1/hyper/')) return gateway.handle(req, res, path)
 */

import { openCorestore } from '../core/persistence/storage-root-restore.js'
import Hyperswarm from 'hyperswarm'
import Hyperdrive from 'hyperdrive'
import { EventEmitter } from 'events'
import { join } from 'path'

const CONTENT_TYPES = {
  html: 'text/html; charset=utf-8',
  htm: 'text/html; charset=utf-8',
  css: 'text/css; charset=utf-8',
  js: 'application/javascript; charset=utf-8',
  mjs: 'application/javascript; charset=utf-8',
  json: 'application/json; charset=utf-8',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  svg: 'image/svg+xml',
  ico: 'image/x-icon',
  webp: 'image/webp',
  woff: 'font/woff',
  woff2: 'font/woff2',
  ttf: 'font/ttf',
  mp4: 'video/mp4',
  webm: 'video/webm',
  mp3: 'audio/mpeg',
  wasm: 'application/wasm',
  pdf: 'application/pdf',
  txt: 'text/plain; charset=utf-8',
  md: 'text/markdown; charset=utf-8'
}

function guessType (filePath) {
  // Extract extension safely, handling edge cases
  const lastSlash = Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\'))
  const filename = filePath.slice(lastSlash + 1)
  const lastDot = filename.lastIndexOf('.')
  if (lastDot <= 0) return 'application/octet-stream' // No extension or hidden file
  const ext = filename.slice(lastDot + 1).toLowerCase()
  return CONTENT_TYPES[ext] || 'application/octet-stream'
}

/**
 * Parse an HTTP Range header for a single byte range.
 *
 * Returns:
 *   { start, end }  — inclusive byte offsets, both within [0, totalSize-1]
 *   null            — header absent / unsupported unit or multi-range (treat as full body)
 *   'invalid'       — malformed/unsatisfiable byte range (caller should send 416)
 *
 * Only single-range requests are supported (no multipart/byteranges).
 * Multi-range and unknown units fall back to a full 200 response, which is
 * RFC 9110 §14.2 compliant ("a server MAY ignore the Range header field").
 * Malformed byte-range syntax is rejected instead of being parsed with
 * JavaScript's permissive Number() rules (`1e3`, `+1`, decimals, etc.).
 */
function parseRange (rangeHeader, totalSize) {
  if (!rangeHeader || typeof rangeHeader !== 'string') return null
  if (!rangeHeader.startsWith('bytes=')) return null
  const spec = rangeHeader.slice(6).trim()
  if (!spec || spec.includes(',')) return null // multi-range unsupported

  const dash = spec.indexOf('-')
  if (dash === -1) return 'invalid'

  const startStr = spec.slice(0, dash).trim()
  const endStr = spec.slice(dash + 1).trim()

  let start, end

  if (startStr === '') {
    // Suffix range: bytes=-N (last N bytes)
    if (endStr === '') return 'invalid'
    const suffix = parseByteCount(endStr, totalSize)
    if (suffix === null || suffix <= 0) return 'invalid'
    start = Math.max(0, totalSize - suffix)
    end = totalSize - 1
  } else {
    start = parseBytePosition(startStr)
    if (start === null) return 'invalid'
    if (endStr === '') {
      end = totalSize - 1
    } else {
      end = parseBytePosition(endStr)
      if (end === null) return 'invalid'
    }
  }

  if (start > end) return 'invalid'
  if (start >= totalSize) return 'invalid'
  if (end >= totalSize) end = totalSize - 1

  return { start, end }
}

function parseBytePosition (value) {
  const text = String(value).trim()
  if (!/^\d+$/.test(text)) return null
  const n = Number(text)
  if (!Number.isSafeInteger(n)) return null
  return n
}

function parseByteCount (value, maxUsefulCount) {
  const text = String(value).trim()
  if (!/^\d+$/.test(text)) return null
  const n = Number(text)
  if (Number.isSafeInteger(n)) return n
  // Suffix ranges larger than the resource are equivalent to "the whole
  // resource"; avoid unsafe precision while preserving that common behavior.
  return maxUsefulCount
}

function decodePathComponent (value) {
  try {
    return { ok: true, value: decodeURIComponent(value) }
  } catch {
    return { ok: false, value: null }
  }
}

function writeGatewayJson (res, body, status = 200, headers = null, opts = {}) {
  let explicitCacheControl = false
  if (headers) {
    for (const [name, value] of Object.entries(headers)) {
      if (name.toLowerCase() === 'cache-control') explicitCacheControl = true
      res.setHeader(name, value)
    }
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  if (!explicitCacheControl) res.setHeader('Cache-Control', 'no-store, max-age=0')
  const payload = JSON.stringify(body) + '\n'
  res.setHeader('Content-Length', Buffer.byteLength(payload))
  res.writeHead(status)
  res.end(opts.head ? null : payload)
}

/**
 * Simple LRU cache for Hyperdrive instances
 * Tracks access order and evicts least recently used when limit exceeded
 *
 * @param {number} [maxSize=20] — maximum number of cached drives
 */
class DriveCache {
  constructor (maxSize = 20) {
    this.maxSize = maxSize
    this.cache = new Map() // key → { drive, lastAccess }
  }

  get (key) {
    const entry = this.cache.get(key)
    if (entry) {
      entry.lastAccess = Date.now()
      // Re-insert to maintain access order
      this.cache.delete(key)
      this.cache.set(key, entry)
    }
    return entry?.drive || null
  }

  set (key, drive) {
    // Evict oldest if at capacity
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const oldestKey = this.cache.keys().next().value
      const oldestEntry = this.cache.get(oldestKey)
      this.cache.delete(oldestKey)
      // Close the evicted drive (non-blocking)
      if (oldestEntry?.drive && !oldestEntry.drive.closed) {
        oldestEntry.drive.close().catch(err => {
          this.emit?.('drive-cache-error', { operation: 'evict-close', error: err.message })
        })
      }
    }
    this.cache.delete(key)
    this.cache.set(key, { drive, lastAccess: Date.now() })
  }

  has (key) {
    return this.cache.has(key)
  }

  delete (key) {
    this.cache.delete(key)
  }

  clear () {
    this.cache.clear()
  }

  get size () {
    return this.cache.size
  }

  entries () {
    return this.cache.entries()
  }
}

export class HyperGateway extends EventEmitter {
  constructor (relayNode, opts = {}) {
    super()
    this.node = relayNode
    this._drives = new DriveCache(opts.maxCachedDrives || 20) // LRU cache
    this._totalRequests = 0
    this._totalBytesServed = 0
    this._driveOperationTimeout = opts.driveOperationTimeout || 30000 // 30s default

    // If a Corestore is provided (e.g. the relay node's store), reuse that
    // same store so gateway reads hit the already-seeded Hyperdrive cores.
    // A separate namespace would isolate the data and make anchored drives
    // appear unavailable to the HTTP gateway.
    this._externalStore = opts.store || null
    this._store = null
    this._swarm = null
    this._ownsSwarm = false
    this._ready = false
  }

  /**
   * Wrap a promise with a timeout
   */
  _withTimeout (promise, ms, context) {
    let timer = null
    return new Promise((resolve, reject) => {
      const done = (fn, value) => {
        if (timer) {
          clearTimeout(timer)
          timer = null
        }
        fn(value)
      }
      timer = setTimeout(() => {
        timer = null
        reject(new Error(`${context} timed out after ${ms}ms`))
      }, ms)
      if (timer.unref) timer.unref()

      Promise.resolve(promise).then(
        value => done(resolve, value),
        err => done(reject, err)
      )
    })
  }

  /**
   * Initialize the gateway's own P2P stack for content delivery.
   * Called automatically on first request, or can be called explicitly.
   */
  async _ensureReady () {
    if (this._ready) return

    if (this._externalStore) {
      this._store = this._externalStore
      await this._store.ready()
      // The relay node's swarm already calls store.replicate(conn), so no
      // extra swarm is needed for gateway reads.
    } else {
      // Standalone / backward-compatible mode: own store + swarm
      const storagePath = this.node.config
        ? join(this.node.config.storage || './storage', 'gateway-store')
        : './gateway-store'

      this._store = openCorestore(storagePath)
      await this._store.ready()

      this._swarm = new Hyperswarm()
      this._swarm.on('connection', (conn) => this._store.replicate(conn))
      this._ownsSwarm = true
    }

    this._ready = true
    this.emit('ready')
  }

  /**
   * Handle an HTTP request for Hyperdrive content
   * Path format: /v1/hyper/KEY/file/path
   */
  async handle (req, res) {
    const url = new URL(req.url, 'http://localhost')
    const path = url.pathname

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.setHeader('Allow', 'GET, HEAD')
      writeGatewayJson(res, { error: 'Method Not Allowed' }, 405)
      return
    }
    const isHead = req.method === 'HEAD'
    const sendJson = (body, status = 200, headers = null) => {
      writeGatewayJson(res, body, status, headers, { head: isHead })
    }

    // Parse: /v1/hyper/KEY/path
    const prefix = '/v1/hyper/'
    if (!path.startsWith(prefix)) {
      sendJson({ error: 'Invalid path' }, 400)
      return
    }

    const rest = path.slice(prefix.length)
    const slashIdx = rest.indexOf('/')
    const keyHex = slashIdx === -1 ? rest : rest.slice(0, slashIdx)
    let filePath = slashIdx === -1 ? '/' : rest.slice(slashIdx)

    // Reject path traversal attempts
    // Block: .. (parent dir), null bytes, absolute paths, URL-encoded variants
    const decoded = decodePathComponent(filePath)
    if (!decoded.ok) {
      sendJson({ error: 'Malformed path encoding' }, 400)
      return
    }
    const decodedPath = decoded.value
    const doubleDecoded = decodePathComponent(decodedPath)
    if (!doubleDecoded.ok) {
      sendJson({ error: 'Malformed path encoding' }, 400)
      return
    }
    const doubleDecodedPath = doubleDecoded.value

    if (
      decodedPath.includes('..') ||
      doubleDecodedPath.includes('..') ||
      filePath.includes('\x00') ||
      decodedPath.includes('\x00') ||
      /^[a-zA-Z]:/.test(decodedPath) // Windows absolute paths
    ) {
      sendJson({ error: 'Forbidden: path traversal rejected' }, 403)
      return
    }

    if (!keyHex || keyHex.length !== 64 || !/^[0-9a-f]+$/i.test(keyHex)) {
      sendJson({ error: 'Invalid drive key' }, 400)
      return
    }

    // Check if this drive is seeded on the relay
    if (this.node.seededApps && !this.node.seededApps.has(keyHex)) {
      sendJson({ error: 'Drive not seeded on this relay' }, 404)
      return
    }

    // Blind apps: relay has encrypted ciphertext, can't serve over HTTP
    const appEntry = this.node.seededApps && this.node.seededApps.get(keyHex)
    if (appEntry && appEntry.blind) {
      sendJson({
        error: 'Private app — encrypted content, P2P access only',
        blind: true,
        hint: 'Use PearBrowser or Hyperswarm to access this app with the encryption key'
      }, 403)
      return
    }

    const privacyTier = String(appEntry?.privacyTier || 'public').toLowerCase()
    if (this.node.config?.gatewayPublicOnlyPrivacyTier !== false && privacyTier !== 'public') {
      sendJson({
        error: 'Gateway access blocked by privacy tier policy',
        privacyTier,
        hint: 'Use direct P2P access for non-public apps'
      }, 403)
      return
    }

    if (this.node.policyGuard && appEntry) {
      const policy = this.node.policyGuard.check(keyHex, privacyTier, 'serve-code')
      if (!policy.allowed) {
        sendJson({
          error: 'PolicyGuard blocked this app',
          privacyTier,
          reason: policy.reason
        }, 403)
        return
      }
    }

    this._totalRequests++

    try {
      const drive = await this._getDrive(keyHex)
      if (!drive) {
        sendJson({ error: 'Drive not available yet — still replicating' }, 404)
        return
      }

      // Resolve directory → index.html (with timeout)
      if (filePath.endsWith('/') || filePath === '') {
        const entry = await this._withTimeout(
          drive.entry((filePath || '/') + 'index.html'),
          this._driveOperationTimeout,
          'drive.entry()'
        ).catch(() => null)
        if (entry) {
          filePath = (filePath || '/') + 'index.html'
        } else {
          // Directory listing
          return this._serveDirectoryListing(res, drive, keyHex, filePath || '/', { head: isHead })
        }
      }

      // Check that the file exists via entry() — also gives us byte length
      const entry = await this._withTimeout(
        drive.entry(filePath),
        this._driveOperationTimeout,
        'drive.entry()'
      )
      if (!entry || !entry.value.blob) {
        sendJson({ error: 'File not found', path: filePath }, 404)
        return
      }

      const contentType = guessType(filePath)
      const byteLength = entry.value.blob.byteLength

      res.setHeader('Content-Type', contentType)
      res.setHeader('X-Hyper-Key', keyHex)
      res.setHeader('X-Served-By', 'hiverelay-gateway')
      res.setHeader('Cache-Control', 'public, max-age=60')
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('Accept-Ranges', 'bytes')

      // HTML needs base-URL rewriting so Vite-built apps resolve assets
      // through the gateway.  /assets/foo.js → ./assets/foo.js
      // This requires buffering the full response (typically small).
      // Range requests on HTML are not supported (rewriting needs full content).
      if (contentType.includes('text/html')) {
        const content = await this._withTimeout(
          drive.get(filePath),
          this._driveOperationTimeout,
          'drive.get()'
        )
        if (!content) {
          sendJson({ error: 'File not found', path: filePath }, 404)
          return
        }
        let html = content.toString('utf-8')
        html = html.replace(/href="\//g, 'href="./')
          .replace(/src="\//g, 'src="./')
          .replace(/href='\//g, "href='./")
          .replace(/src='\//g, "src='./")
        const buf = Buffer.from(html)
        res.writeHead(200, { 'Content-Length': buf.length })
        if (isHead) {
          res.end()
          return
        }
        this._totalBytesServed += buf.length
        res.end(buf)
        this.emit('served', { keyHex, filePath, bytes: buf.length })
        return
      }

      // ─── Range request handling ─────────────────────────────────
      // Stream non-HTML content directly — avoids buffering large
      // binaries (images, WASM, video, etc.) in memory (Fix 2.2).
      // Also supports HTTP byte ranges so browsers can seek in
      // video/audio without pulling the whole file.
      const rangeHeader = req.headers && req.headers.range
      let streamOpts = null
      let statusCode = 200
      let responseLength = byteLength

      if (rangeHeader && byteLength != null) {
        const parsed = parseRange(rangeHeader, byteLength)
        if (parsed === 'invalid') {
          res.setHeader('Content-Range', `bytes */${byteLength}`)
          sendJson({ error: 'Range Not Satisfiable' }, 416)
          return
        }
        if (parsed) {
          const { start, end } = parsed
          streamOpts = { start, length: end - start + 1 }
          statusCode = 206
          responseLength = end - start + 1
          res.setHeader('Content-Range', `bytes ${start}-${end}/${byteLength}`)
        }
      }

      if (responseLength != null) {
        res.setHeader('Content-Length', responseLength)
      }
      res.writeHead(statusCode)

      // HEAD requests: send headers only, no body
      if (req.method === 'HEAD') {
        res.end()
        return
      }

      const stream = streamOpts
        ? drive.createReadStream(filePath, streamOpts)
        : drive.createReadStream(filePath)
      let bytes = 0

      stream.on('data', (chunk) => { bytes += chunk.length })
      stream.on('end', () => {
        this._totalBytesServed += bytes
        this.emit('served', { keyHex, filePath, bytes })
      })
      stream.on('error', (err) => {
        // If headers are already on the wire we cannot rewrite them;
        // destroy the response so the client sees a truncated stream
        // instead of a hung socket.
        if (!res.headersSent) {
          try {
            sendJson({ error: 'Gateway stream failed' }, 502)
          } catch {}
        } else {
          try { res.destroy(err) } catch {}
        }
        this.emit('drive-error', { context: 'stream', key: keyHex, path: filePath, error: err.message })
      })

      // If the client disconnects mid-flight, tear down the drive stream
      // so we don't keep reading blocks into a dead socket.
      res.on('close', () => {
        if (!stream.destroyed) {
          try { stream.destroy() } catch {}
        }
      })

      stream.pipe(res)
    } catch (err) {
      this.emit('drive-error', { context: 'handle', key: keyHex, path: filePath, error: err.message })
      sendJson({ error: 'Gateway read failed' }, 502)
    }
  }

  async _getDrive (keyHex) {
    const seededEntry = this.node.seededApps && this.node.seededApps.get(keyHex)
    const seededDrive = seededEntry && seededEntry.drive
    if (seededDrive && !seededDrive.closed && !seededDrive.closing) {
      this._drives.set(keyHex, seededDrive)
      return seededDrive
    }

    // Return cached drive if already open and has content
    if (this._drives.has(keyHex)) {
      const cached = this._drives.get(keyHex)
      // Refresh in background for next request
      cached.update().catch(err => {
        this.emit('drive-update-error', { key: keyHex, error: err.message })
      })
      return cached
    }

    // Initialize our own P2P stack on first use
    await this._ensureReady()

    try {
      // Per-drive corestore session so cache eviction / drive.close()
      // tears down only this session's refs, not the root store. Without
      // .session(), hyperdrive._close() cascades to the externalStore
      // (the relay's node.store) and wedges the entire relay until
      // restart — same class as the v0.8.14 fix in
      // app-lifecycle.js:_seedAppInner. The captured trace from utah-us
      // canary 2026-05-18 confirms this path fires (DriveCache eviction
      // → hyperdrive._close → store.close on the wrapped root).
      const drive = new Hyperdrive(this._store.session(), Buffer.from(keyHex, 'hex'))
      await drive.ready()

      // Join the drive's discovery key on the swarm (only when we own it)
      if (this._swarm) {
        const done = drive.findingPeers()
        this._swarm.join(drive.discoveryKey, { server: true, client: true })
        this._swarm.flush().then(done, done)
      }

      // Wait for drive data to arrive from peers
      if (drive.version === 0) {
        try {
          await Promise.race([
            drive.update({ wait: true }),
            new Promise((_resolve, reject) => setTimeout(() => reject(new Error('timeout')), 20000))
          ])
        } catch (err) {
          this.emit('drive-wait-error', { key: keyHex, error: err.message })
        }
      }

      // Still no content
      if (drive.version === 0) {
        await drive.close()
        return null
      }

      // Eagerly download all files for future requests
      try {
        const dl = drive.download('/')
        // Don't await — let it download in background
        dl.done().catch(err => {
          this.emit('drive-download-error', { key: keyHex, error: err.message })
        })
      } catch (err) {
        this.emit('drive-download-init-error', { key: keyHex, error: err.message })
      }

      this._drives.set(keyHex, drive)
      return drive
    } catch (err) {
      this.emit('drive-error', { context: 'getDrive', key: keyHex, error: err })
      return null
    }
  }

  async _serveDirectoryListing (res, drive, keyHex, dirPath, opts = {}) {
    const entries = []
    const MAX_ENTRIES = 1000 // Prevent memory exhaustion from huge directories
    const startTime = Date.now()
    const TIMEOUT = this._driveOperationTimeout

    try {
      for await (const entry of drive.list(dirPath)) {
        // Check timeout
        if (Date.now() - startTime > TIMEOUT) {
          throw new Error('Directory listing timeout')
        }
        entries.push(entry.key)
        // Limit entries
        if (entries.length >= MAX_ENTRIES) {
          entries.push('... (truncated)')
          break
        }
      }
    } catch (err) {
      this.emit('drive-error', { context: 'directoryListing', key: keyHex, path: dirPath, error: err.message })
    }

    writeGatewayJson(res, { key: keyHex, path: dirPath, entries }, 200, {
      'X-Hyper-Key': keyHex,
      'X-Served-By': 'hiverelay-gateway',
      'Cache-Control': 'public, max-age=60'
    }, { head: !!opts.head })
  }

  getStats () {
    return {
      cachedDrives: this._drives.size,
      totalRequests: this._totalRequests,
      totalBytesServed: this._totalBytesServed
    }
  }

  async close () {
    // DriveCache is not directly iterable — iterate its entries(), and each
    // value is a { drive, lastAccess } wrapper, not the drive itself. The
    // previous `for (const [, drive] of this._drives)` threw
    // "this._drives is not iterable" on every close(), leaking the HTTP
    // server (EADDRINUSE on self-heal restart).
    for (const [, entry] of this._drives.entries()) {
      const drive = entry && entry.drive
      if (!drive || drive.closed) continue
      try { await drive.close() } catch (err) {
        this.emit('drive-close-error', { error: err.message })
      }
    }
    this._drives.clear()

    if (this._ownsSwarm && this._swarm) {
      try { await this._swarm.destroy() } catch (err) {
        this.emit('swarm-destroy-error', { error: err.message })
      }
    }
    if (this._store) {
      try { await this._store.close() } catch (err) {
        this.emit('store-close-error', { error: err.message })
      }
    }
  }
}
