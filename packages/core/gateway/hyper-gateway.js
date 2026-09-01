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

import { corestoreGenerationParticipantOptions, openCorestore } from '../core/persistence/storage-root-restore.js'
import Hyperswarm from 'hyperswarm'
import Hyperdrive from 'hyperdrive'
import Hyperblobs from 'hyperblobs'
import { EventEmitter } from 'events'
import { Transform } from 'stream'
import { join } from 'path'
import { isIssuedExactAppContext } from './exact-app-context.js'
import { updateWithTimeout } from '../core/relay-node/cancellable-drive-update.js'
import { admitPublicHiveAppEntry } from './public-app-admission.js'
import { isVerifyRequest, serveVerifyBundle } from './verify-bundle.js'
import {
  applyGatewayEdgeHeaders,
  buildHivePathLinkHeader,
  guardPathLaneStatelessHeaders,
  isOnionReadPlaneHost
} from './edge-headers.js'

function stableCoreProofState (core, attempts = 4) {
  if (!core) return null
  for (let attempt = 0; attempt < attempts; attempt++) {
    const forkBefore = Number(core.fork ?? 0)
    const lengthBefore = Number(core.length)
    const byteLengthBefore = Number(core.byteLength)
    const lengthAfter = Number(core.length)
    const byteLengthAfter = Number(core.byteLength)
    const forkAfter = Number(core.fork ?? 0)
    if (Number.isSafeInteger(forkBefore) && forkBefore >= 0 && forkBefore === forkAfter &&
        Number.isSafeInteger(lengthBefore) && lengthBefore >= 0 && lengthBefore === lengthAfter &&
        Number.isSafeInteger(byteLengthBefore) && byteLengthBefore >= 0 && byteLengthBefore === byteLengthAfter) {
      return { fork: forkAfter, length: lengthAfter, byteLength: byteLengthAfter }
    }
  }
  return null
}

function durableDriveProof (entry) {
  const proof = {
    driveVersion: entry?.storageProvedDriveVersion,
    metaLength: entry?.storageProvedMetaLength,
    blobLength: entry?.storageProvedBlobLength,
    totalBytes: entry?.storageProvedTotalBytes,
    metaFork: entry?.storageProvedMetaFork,
    blobFork: entry?.storageProvedBlobFork
  }
  if (entry?.anchored !== true || entry.anchoredLength !== proof.driveVersion ||
      !Number.isSafeInteger(proof.driveVersion) || proof.driveVersion <= 0 ||
      !Number.isSafeInteger(proof.metaLength) || proof.metaLength < 0 ||
      !Number.isSafeInteger(proof.blobLength) || proof.blobLength < 0 ||
      !Number.isSafeInteger(proof.totalBytes) || proof.totalBytes < 0 ||
      !Number.isSafeInteger(proof.metaFork) || proof.metaFork < 0 ||
      !Number.isSafeInteger(proof.blobFork) || proof.blobFork < 0 ||
      !Number.isSafeInteger(entry.maxStorage) || proof.totalBytes > entry.maxStorage) return null
  return proof
}

function nonClosingCoreView (core) {
  return new Proxy(core, {
    get (target, property) {
      if (property === 'close') return async () => {}
      const value = Reflect.get(target, property, target)
      return typeof value === 'function' ? value.bind(target) : value
    }
  })
}

// hyperdrive 11 reports version = max(1, bee length), so a `version === 0`
// emptiness probe can never fire and an unknown drive would be served (and
// LRU-cached) instead of waited out. The metadata core length is the honest
// "nothing replicated yet" signal; the version fallback only shapes stubbed
// drives without a bee core.
function driveHasContent (drive) {
  const length = drive?.db?.core?.length
  if (Number.isSafeInteger(length)) return length > 0
  return Number.isSafeInteger(drive?.version) && drive.version > 0
}

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

const DEFAULT_MAX_CACHED_DRIVES = 20
const MAX_CACHED_DRIVES = 256
const DEFAULT_DRIVE_OPERATION_TIMEOUT = 30_000
const MAX_DRIVE_OPERATION_TIMEOUT = 120_000
const DRIVE_CLOSE_TIMEOUT = 5_000
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
const MAX_RESPONSE_BYTES = 1024 * 1024 * 1024
const DEFAULT_MAX_TRANSFORM_BYTES = 4 * 1024 * 1024

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
 *   null            — header absent
 *   'unsupported'   — unsupported unit or multi-range
 *   'invalid'       — malformed/unsatisfiable byte range (caller should send 416)
 *
 * Only single-range requests are supported (no multipart/byteranges).
 * Legacy bounded responses may ignore multi-range and unknown units with a
 * full 200 as allowed by RFC 9110 §14.2. Exact-byte app responses and
 * oversized legacy responses reject them with 416 instead.
 * Malformed byte-range syntax is rejected instead of being parsed with
 * JavaScript's permissive Number() rules (`1e3`, `+1`, decimals, etc.).
 */
export function parseRange (rangeHeader, totalSize) {
  if (!rangeHeader || typeof rangeHeader !== 'string') return null
  if (!rangeHeader.startsWith('bytes=')) return 'unsupported'
  const spec = rangeHeader.slice(6).trim()
  if (!spec) return 'invalid'
  if (spec.includes(',')) return 'unsupported' // multi-range unsupported

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

export function selectExactByteRepresentation (payload, rangeHeader) {
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload)
  if (!rangeHeader) {
    return { ok: true, status: 200, payload: bytes, contentRange: null, totalSize: bytes.byteLength }
  }
  const parsed = parseRange(rangeHeader, bytes.byteLength)
  if (!parsed || parsed === 'invalid' || parsed === 'unsupported') {
    return { ok: false, status: 416, payload: null, contentRange: `bytes */${bytes.byteLength}`, totalSize: bytes.byteLength }
  }
  return {
    ok: true,
    status: 206,
    payload: bytes.subarray(parsed.start, parsed.end + 1),
    contentRange: `bytes ${parsed.start}-${parsed.end}/${bytes.byteLength}`,
    totalSize: bytes.byteLength
  }
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

function buildHiveAppLinkHeader (keyHex, filePath) {
  const canonical = new URL(`hive://${keyHex}/`)
  canonical.pathname = filePath
  return `<${canonical.href}>; rel="canonical", </.well-known/hiverelay-app.json>; rel="describedby"`
}

function boundedPositiveInteger (value, fallback, label, max) {
  if (value === undefined || value === null) return fallback
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new Error(`${label} must be an integer from 1 to ${max}`)
  }
  return value
}

function createAbortError (reason) {
  if (reason instanceof Error && reason.name === 'AbortError') return reason
  const err = new Error(reason instanceof Error ? reason.message : 'Gateway request aborted')
  err.name = 'AbortError'
  if (reason !== undefined) err.cause = reason
  return err
}

function isAbortError (err) {
  return err?.name === 'AbortError'
}

class ExactLengthTransform extends Transform {
  constructor (expectedBytes) {
    super()
    this.expectedBytes = expectedBytes
    this.seenBytes = 0
  }

  _transform (chunk, encoding, callback) {
    let bytes
    try {
      bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding)
    } catch (err) {
      callback(err)
      return
    }
    if (bytes.byteLength > this.expectedBytes - this.seenBytes) {
      callback(new Error('Gateway stream exceeded declared response length'))
      return
    }
    this.seenBytes += bytes.byteLength
    callback(null, bytes)
  }

  _flush (callback) {
    if (this.seenBytes !== this.expectedBytes) {
      callback(new Error('Gateway stream ended before declared response length'))
      return
    }
    callback()
  }
}

function writeGatewayJson (res, body, status = 200, headers = null, opts = {}) {
  const payload = Buffer.from(JSON.stringify(body) + '\n')
  writeGatewayBuffer(res, payload, status, headers, opts)
}

function writeGatewayBuffer (res, payload, status = 200, headers = null, opts = {}) {
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
  res.setHeader('Content-Length', payload.byteLength)
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
  constructor (maxSize = 20, onEvict = null) {
    this.maxSize = maxSize
    this.onEvict = onEvict
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
      if (oldestEntry?.drive && this.onEvict) this.onEvict(oldestEntry.drive)
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
    this._activeOwnedDrives = new Map()
    this._retiredOwnedDrives = new Set()
    this._driveOpenPromises = new Map()
    this._driveOpenControllers = new Map()
    this._driveOpenStates = new Map()
    this._driveRefreshPromises = new Map()
    this._seededDriveUpdateStates = new Map()
    this._driveClosePromises = new Set()
    this._ownedDriveTopics = new Map()
    this._ownedTopicRefs = new Map()
    this._pendingRequestCleanups = new Set()
    this._activeRequestStates = new Set()
    this._closing = false
    this._closePromise = null
    if (opts.requireLifecycleDriveAuthority !== undefined && typeof opts.requireLifecycleDriveAuthority !== 'boolean') {
      throw new Error('requireLifecycleDriveAuthority must be boolean')
    }
    // RelayNode-mounted routes may borrow only AppLifecycle-owned drives whose
    // persisted storage proof names the immutable version. Standalone gateway
    // mode keeps its explicit dynamic-open authority separate.
    this._requireLifecycleDriveAuthority = opts.requireLifecycleDriveAuthority === true
    const maxCachedDrives = boundedPositiveInteger(
      opts.maxCachedDrives,
      DEFAULT_MAX_CACHED_DRIVES,
      'maxCachedDrives',
      MAX_CACHED_DRIVES
    )
    this._drives = new DriveCache(maxCachedDrives, drive => this._retireOwnedDrive(drive))
    this._totalRequests = 0
    this._totalBytesServed = 0
    this._driveOperationTimeout = boundedPositiveInteger(
      opts.driveOperationTimeout,
      DEFAULT_DRIVE_OPERATION_TIMEOUT,
      'driveOperationTimeout',
      MAX_DRIVE_OPERATION_TIMEOUT
    )
    const configuredMaxResponseBytes = opts.maxResponseBytes !== undefined
      ? opts.maxResponseBytes
      : relayNode.config?.gatewayMaxResponseBytes
    if (configuredMaxResponseBytes === null) throw new Error('maxResponseBytes must be finite and non-null')
    this._maxResponseBytes = boundedPositiveInteger(
      configuredMaxResponseBytes,
      DEFAULT_MAX_RESPONSE_BYTES,
      'maxResponseBytes',
      MAX_RESPONSE_BYTES
    )
    this._maxTransformBytes = boundedPositiveInteger(
      opts.maxTransformBytes ?? relayNode.config?.gatewayMaxTransformBytes,
      Math.min(DEFAULT_MAX_TRANSFORM_BYTES, this._maxResponseBytes),
      'maxTransformBytes',
      this._maxResponseBytes
    )

    // If a Corestore is provided (e.g. the relay node's store), reuse that
    // same store so gateway reads hit the already-seeded Hyperdrive cores.
    // A separate namespace would isolate the data and make anchored drives
    // appear unavailable to the HTTP gateway.
    this._externalStore = opts.store || null
    this._hiverelayGeneration = opts.hiverelayGeneration ?? null
    if (this._externalStore && this._hiverelayGeneration != null) {
      throw new TypeError('hiverelayGeneration cannot be supplied with an externally owned Corestore')
    }
    this._store = null
    this._swarm = null
    this._ownsSwarm = false
    this._ready = false
    this._readyPromise = null
    this._readyController = null

    // Federated signed denylist (takedown channel). Defaults to the relay
    // node's shared store; a standalone gateway can take an explicit
    // opts.denylist (null disables enforcement). Every verified entry added
    // anywhere — local operator issue or federation gossip — purges the
    // drive from this gateway's caches and stops its in-flight streams.
    this._denylist = opts.denylist === undefined
      ? (relayNode && relayNode.gatewayDenylist) || null
      : opts.denylist
    this._onDenylistEntryAdded = null
    this._armDenylistListener()
  }

  // The purge listener is armed lazily and disarmed on close: the node-level
  // denylist outlives any single gateway instance across restarts, so a
  // closed gateway must not keep a stale listener (or its drive closures)
  // reachable through it. handle() re-arms on the next request.
  _armDenylistListener () {
    if (this._onDenylistEntryAdded || !this._denylist || typeof this._denylist.on !== 'function') return
    this._onDenylistEntryAdded = () => this._purgeDeniedDrives()
    this._denylist.on('entry-added', this._onDenylistEntryAdded)
  }

  _disarmDenylistListener () {
    if (!this._onDenylistEntryAdded || !this._denylist) return
    this._denylist.removeListener('entry-added', this._onDenylistEntryAdded)
    this._onDenylistEntryAdded = null
  }

  /**
   * Wrap a promise with a timeout
   */
  _withTimeout (promise, ms, context, signal = null) {
    let timer = null
    let abortHandler = null
    return new Promise((resolve, reject) => {
      let settled = false
      const source = Promise.resolve(promise)
      const done = (fn, value) => {
        if (settled) return
        settled = true
        if (timer) {
          clearTimeout(timer)
          timer = null
        }
        if (signal && abortHandler) signal.removeEventListener('abort', abortHandler)
        fn(value)
      }
      // Always observe the source, even when the signal was already aborted;
      // otherwise a later source rejection becomes process-level unhandled
      // rejection noise after the HTTP request is gone.
      source.then(
        value => done(resolve, value),
        err => done(reject, err)
      )
      if (signal?.aborted) {
        done(reject, createAbortError(signal.reason))
        return
      }
      timer = setTimeout(() => {
        timer = null
        done(reject, new Error(`${context} timed out after ${ms}ms`))
      }, ms)
      if (timer.unref) timer.unref()

      if (signal) {
        abortHandler = () => done(reject, createAbortError(signal.reason))
        signal.addEventListener('abort', abortHandler, { once: true })
        if (signal.aborted) abortHandler()
      }
    })
  }

  /**
   * Initialize the gateway's own P2P stack for content delivery.
   * Called automatically on first request, or can be called explicitly.
   */
  async _ensureReady (signal = null) {
    if (this._closing) throw createAbortError('Gateway is closing')
    if (this._ready) return
    if (this._readyPromise) {
      return this._withTimeout(
        this._readyPromise,
        this._driveOperationTimeout,
        'gateway initialization',
        signal
      )
    }

    const controller = new AbortController()
    const operationSignal = controller.signal
    const pending = (async () => {
      try {
        if (this._externalStore) {
          this._store = this._externalStore
          await this._withTimeout(
            this._store.ready(),
            this._driveOperationTimeout,
            'external Corestore.ready()',
            operationSignal
          )
          // The relay node's swarm already calls store.replicate(conn), so no
          // extra swarm is needed for gateway reads.
        } else {
          // Standalone / backward-compatible mode: own store + swarm
          const storagePath = this.node.config
            ? join(this.node.config.storage || './storage', 'gateway-store')
            : './gateway-store'

          this._store = openCorestore(storagePath,
            corestoreGenerationParticipantOptions(this._hiverelayGeneration, 'hyper-gateway'))
          await this._withTimeout(
            this._store.ready(),
            this._driveOperationTimeout,
            'gateway Corestore.ready()',
            operationSignal
          )

          this._swarm = new Hyperswarm()
          this._swarm.on('connection', (conn) => this._store.replicate(conn))
          this._ownsSwarm = true
        }

        if (this._closing || operationSignal.aborted) throw createAbortError(operationSignal.reason || 'Gateway is closing')
        this._ready = true
        this.emit('ready')
      } catch (err) {
        if (this._ownsSwarm && this._swarm) {
          try {
            await this._withTimeout(
              this._swarm.destroy(),
              Math.min(DRIVE_CLOSE_TIMEOUT, this._driveOperationTimeout),
              'failed swarm.destroy()'
            )
          } catch {}
        }
        if (this._store && !this._externalStore) {
          try {
            await this._withTimeout(
              this._store.close(),
              Math.min(DRIVE_CLOSE_TIMEOUT, this._driveOperationTimeout),
              'failed Corestore.close()'
            )
          } catch {}
        }
        this._store = null
        this._swarm = null
        this._ownsSwarm = false
        throw err
      }
    })()
    this._readyPromise = pending
    this._readyController = controller
    pending.finally(() => {
      if (this._readyPromise === pending) this._readyPromise = null
      if (this._readyController === controller) this._readyController = null
    }).catch(() => {})
    return this._withTimeout(
      pending,
      this._driveOperationTimeout,
      'gateway initialization',
      signal
    )
  }

  /**
   * Handle an HTTP request for Hyperdrive content
   * Path format: /v1/hyper/KEY/file/path
   */
  async handle (req, res, context = null) {
    if (this._closing) {
      if (!res.destroyed && !res.writableEnded) {
        writeGatewayJson(res, { error: 'Gateway shutting down' }, 503, { 'Retry-After': '1' }, {
          head: req.method === 'HEAD'
        })
      }
      return
    }

    this._armDenylistListener()

    const controller = new AbortController()
    let handlerSettled = false
    let responseSettled = res.destroyed || res.writableEnded || res.writableFinished
    let resolveSettled
    const settled = new Promise(resolve => { resolveSettled = resolve })
    const state = { controller, res, settled, forceResponseSettlement: null, keyHex: null }
    this._activeRequestStates.add(state)

    const maybeSettle = () => {
      if (!handlerSettled || !responseSettled) return
      this._activeRequestStates.delete(state)
      resolveSettled()
    }
    const onFinish = () => {
      responseSettled = true
      maybeSettle()
    }
    const onClose = () => {
      responseSettled = true
      if (!res.writableFinished && !controller.signal.aborted) {
        controller.abort(createAbortError('Client disconnected'))
      }
      maybeSettle()
    }
    state.forceResponseSettlement = () => {
      responseSettled = true
      maybeSettle()
    }
    res.once('finish', onFinish)
    res.once('close', onClose)

    try {
      await this._handleRequest(req, res, context, controller.signal, state)
    } finally {
      handlerSettled = true
      maybeSettle()
    }
  }

  async _handleRequest (req, res, context = null, signal = null, requestState = null) {
    const url = new URL(req.url, 'http://localhost')
    const path = url.pathname
    const exactBytes = isIssuedExactAppContext(context)
    // R3/R5/R6 edge policy (edge-headers.js documents the lane × ingress
    // matrix): the shared-origin path lane is stateless-only — Service-Worker-
    // Allowed is structurally stripped at response commit; COOP/CORP/
    // Referrer-Policy land on every gateway response; onion ingress adds its
    // restrictive CSP default.
    if (!exactBytes) guardPathLaneStatelessHeaders(res)
    applyGatewayEdgeHeaders(res, {
      exactBytes,
      onionIngress: isOnionReadPlaneHost(req.headers && req.headers.host)
    })
    if (context !== null && !exactBytes) {
      writeGatewayJson(res, { error: 'Gateway request context is not authorized' }, 403)
      return
    }
    // R1 verifiable retrieval: ?verify=1 (or the hc-block Accept type) returns a
    // proof bundle instead of raw bytes — same admission chain, same frozen limits.
    const verifyMode = isVerifyRequest(url, req.headers)

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.setHeader('Allow', 'GET, HEAD')
      const headers = exactBytes
        ? {
            'X-Hive-App-Key': context?.appKey,
            'X-Hive-Byte-Mode': 'generated',
            Vary: 'Host',
            'Origin-Agent-Cluster': '?1'
          }
        : null
      writeGatewayJson(res, { error: 'Method Not Allowed' }, 405, headers)
      return
    }
    const isHead = req.method === 'HEAD'
    const sendJson = (body, status = 200, headers = null) => {
      const responseHeaders = exactBytes
        ? {
            ...(headers || {}),
            'X-Hive-App-Key': context?.appKey,
            'X-Hive-Byte-Mode': 'generated',
            Vary: 'Host',
            'Origin-Agent-Cluster': '?1'
          }
        : headers
      writeGatewayJson(res, body, status, responseHeaders, { head: isHead })
    }

    let keyHex
    let filePath
    if (context) {
      keyHex = context.appKey
      filePath = context.path || '/'
    } else {
      // Parse: /v1/hyper/KEY/path
      const prefix = '/v1/hyper/'
      if (!path.startsWith(prefix)) {
        sendJson({ error: 'Invalid path' }, 400)
        return
      }

      const rest = path.slice(prefix.length)
      const slashIdx = rest.indexOf('/')
      keyHex = slashIdx === -1 ? rest : rest.slice(0, slashIdx)
      filePath = slashIdx === -1 ? '/' : rest.slice(slashIdx)
    }

    if (typeof filePath !== 'string' || !filePath.startsWith('/')) {
      sendJson({ error: 'Invalid path' }, 400)
      return
    }

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
    keyHex = keyHex.toLowerCase()
    if (requestState) requestState.keyHex = keyHex

    // Federated signed denylist — fail closed BEFORE any existence-specific
    // response or drive lookup, on both the /v1/hyper path lane and the
    // exact app-origin lane. 451 Unavailable For Legal Reasons is honest
    // signaling here: the channel is public by design (unlike the outboxlog
    // DO-NOT-SERVE tombstone, whose opaque-id suppression is deliberately
    // indistinguishable from absence).
    const deniedEntry = this._deniedDenylistEntry(keyHex)
    if (deniedEntry) {
      sendJson({
        error: 'Unavailable For Legal Reasons',
        takedown: true,
        reason: deniedEntry.reason
      }, 451)
      return
    }
    if (exactBytes) {
      res.setHeader('X-Hive-App-Key', keyHex)
      res.setHeader('Vary', 'Host')
      res.setHeader('Origin-Agent-Cluster', '?1')
      res.setHeader('Cache-Control', 'no-store, max-age=0')
      res.setHeader('Link', buildHiveAppLinkHeader(keyHex, filePath))
    } else {
      // R7 upgrade hint on the shared-origin lane: a capable client can leave
      // HTTPS for the canonical native P2P scheme — including on the blind/tier
      // 403s below, whose bodies already say exactly that.
      res.setHeader('Link', buildHivePathLinkHeader(keyHex, filePath))
    }

    // Exact app hosts fail closed before any existence-specific response. A
    // public caller must not be able to distinguish an unknown key from a
    // locally seeded private/custody key.
    const appEntry = this.node.seededApps && this.node.seededApps.get(keyHex)
    if (exactBytes && !admitPublicHiveAppEntry(appEntry, {
      appKey: keyHex,
      publicAppKeys: context?.publicAppKeys
    }).allowed) {
      sendJson({
        error: 'App unavailable through public Hive gateway',
        hint: 'Use the app\'s authorized native P2P transport'
      }, 403)
      return
    }

    let storageProvedDriveVersion = null
    if (this._requireLifecycleDriveAuthority) {
      storageProvedDriveVersion = appEntry?.storageProvedDriveVersion
      if (!Number.isSafeInteger(storageProvedDriveVersion) || storageProvedDriveVersion <= 0) {
        sendJson({ error: 'Drive not available yet — still replicating' }, 404)
        return
      }
      if (exactBytes && storageProvedDriveVersion !== context?.driveVersion) {
        sendJson({
          error: 'App unavailable through public Hive gateway',
          hint: 'Use the app\'s authorized native P2P transport'
        }, 403)
        return
      }
    }

    // Preserve the legacy path gateway's explicit not-seeded response. An
    // exact host reaches this only after local approval and public admission.
    if (this.node.seededApps && !this.node.seededApps.has(keyHex)) {
      sendJson({ error: 'Drive not seeded on this relay' }, 404)
      return
    }

    // Blind apps: relay has encrypted ciphertext, can't serve over HTTP
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
        if (exactBytes) {
          sendJson({
            error: 'App unavailable through public Hive gateway',
            hint: 'Use the app\'s authorized native P2P transport'
          }, 403)
        } else {
          sendJson({
            error: 'PolicyGuard blocked this app',
            privacyTier,
            reason: policy.reason
          }, 403)
        }
        return
      }
    }

    this._totalRequests++

    let requestDriveLease = null
    try {
      const driveLease = await this._acquireDrive(keyHex, {
        requireSeeded: exactBytes || this._requireLifecycleDriveAuthority,
        signal
      })
      if (!driveLease) {
        sendJson({ error: 'Drive not available yet — still replicating' }, 404)
        return
      }
      const drive = driveLease.drive
      requestDriveLease = this._holdDriveLeaseForRequest(res, driveLease)

      let readDrive = drive
      if (driveLease.immutable === true) {
        requestDriveLease.setCheckout(readDrive)
        res.setHeader('X-Hive-Drive-Version', String(driveLease.pinnedVersion))
      } else if (exactBytes || this._requireLifecycleDriveAuthority) {
        if (typeof drive.checkout !== 'function') {
          throw new Error('Immutable drive checkout is unavailable')
        }
        const pinnedVersion = exactBytes
          ? (context?.driveVersion == null ? null : context.driveVersion)
          : storageProvedDriveVersion
        if (pinnedVersion != null && (!Number.isSafeInteger(pinnedVersion) || pinnedVersion < 0)) {
          throw new Error('Configured public drive version is invalid')
        }
        if (
          !this._requireLifecycleDriveAuthority &&
          typeof drive.update === 'function' &&
          (pinnedVersion == null || !Number.isSafeInteger(drive.version) || drive.version < pinnedVersion)
        ) {
          // A timeout must detach the underlying Hypercore upgrade refs, not
          // merely release the HTTP request slot while replication keeps going.
          await this._updateSeededDrive(keyHex, drive, signal)
        }
        const latestVersion = drive.version
        if (!Number.isSafeInteger(latestVersion) || latestVersion < 0) throw new Error('Drive version unavailable for exact snapshot')
        if (pinnedVersion != null && latestVersion < pinnedVersion) {
          if (this._requireLifecycleDriveAuthority) {
            sendJson({ error: 'Drive not available yet — still replicating' }, 404)
            return
          }
          throw new Error('Configured public drive version is not available')
        }
        const version = pinnedVersion ?? latestVersion
        readDrive = drive.checkout(version)
        requestDriveLease.setCheckout(readDrive)
        await this._withTimeout(readDrive.ready(), this._driveOperationTimeout, 'drive.checkout().ready()', signal)
        res.setHeader('X-Hive-Drive-Version', String(version))
      }

      // Resolve directory → index.html (with timeout)
      if (filePath.endsWith('/') || filePath === '') {
        const entry = await this._withTimeout(
          readDrive.entry((filePath || '/') + 'index.html'),
          this._driveOperationTimeout,
          'drive.entry()',
          signal
        ).catch(() => null)
        if (entry) {
          filePath = (filePath || '/') + 'index.html'
        } else {
          if (verifyMode) {
            // A directory listing is generated JSON — no single block to prove.
            sendJson({ error: 'Verify mode proves file blocks only — request a file path', path: filePath || '/' }, 400)
            return
          }
          // Directory listing
          await this._serveDirectoryListing(res, readDrive, keyHex, filePath || '/', {
            head: isHead,
            byteMode: exactBytes ? 'generated' : null,
            rangeHeader: req.headers && req.headers.range,
            signal,
            reserveResponseBytes: context?.reserveResponseBytes,
            egressRetryAfterSeconds: context?.egressRetryAfterSeconds
          })
          return
        }
      }

      // Check that the file exists via entry() — also gives us byte length
      const entry = await this._withTimeout(
        readDrive.entry(filePath),
        this._driveOperationTimeout,
        'drive.entry()',
        signal
      )
      if (!entry || !entry.value.blob) {
        sendJson({ error: 'File not found', path: filePath }, 404)
        return
      }

      const contentType = guessType(filePath)
      const byteLength = entry.value.blob.byteLength
      if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
        throw new Error('Drive entry has an invalid byte length')
      }

      // Verifiable retrieval mode: proof bundle instead of raw bytes. Admission
      // (seeded/blind/tier/PolicyGuard) already ran; byte caps mirror the raw lane.
      if (verifyMode) {
        await serveVerifyBundle(this, res, readDrive, keyHex, filePath, entry, byteLength, {
          head: isHead,
          exactBytes,
          rangeHeader: req.headers && req.headers.range,
          driveVersion: readDrive.version,
          signal,
          sendJson,
          reserveResponseBytes: context?.reserveResponseBytes,
          egressRetryAfterSeconds: context?.egressRetryAfterSeconds
        })
        return
      }

      res.setHeader('Content-Type', contentType)
      res.setHeader('X-Hyper-Key', keyHex)
      res.setHeader('X-Served-By', 'hiverelay-gateway')
      res.setHeader('Cache-Control', exactBytes ? 'no-store, max-age=0' : 'public, max-age=60')
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('Accept-Ranges', 'bytes')
      if (exactBytes) {
        res.setHeader('X-Hive-App-Key', keyHex)
        res.setHeader('X-Hive-Byte-Mode', 'exact')
        res.setHeader('Vary', 'Host')
        res.setHeader('Origin-Agent-Cluster', '?1')
      }

      // HTML needs base-URL rewriting so Vite-built apps resolve assets
      // through the gateway.  /assets/foo.js → ./assets/foo.js
      // This requires buffering the full response (typically small).
      // Range requests on HTML are not supported (rewriting needs full content).
      if (contentType.includes('text/html') && !exactBytes) {
        if (byteLength > this._maxTransformBytes) {
          sendJson({
            error: 'Response exceeds gateway transform limit',
            maxResponseBytes: this._maxTransformBytes
          }, 413)
          return
        }
        res.setHeader('X-Hive-Byte-Mode', 'transformed')
        const content = await this._withTimeout(
          readDrive.get(filePath),
          this._driveOperationTimeout,
          'drive.get()',
          signal
        )
        if (!content) {
          sendJson({ error: 'File not found', path: filePath }, 404)
          return
        }
        if (!Buffer.isBuffer(content) || content.byteLength > this._maxTransformBytes) {
          throw new Error('Drive content exceeded its bounded transform input')
        }
        let html = content.toString('utf-8')
        html = html.replace(/href="\//g, 'href="./')
          .replace(/src="\//g, 'src="./')
          .replace(/href='\//g, "href='./")
          .replace(/src='\//g, "src='./")
        const buf = Buffer.from(html)
        if (buf.byteLength > this._maxResponseBytes) {
          sendJson({
            error: 'Response exceeds gateway byte limit',
            maxResponseBytes: this._maxResponseBytes
          }, 413)
          return
        }
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
        if (parsed === 'invalid' || (parsed === 'unsupported' && exactBytes)) {
          res.setHeader('Content-Range', `bytes */${byteLength}`)
          sendJson({ error: 'Range Not Satisfiable' }, 416)
          return
        }
        if (parsed && parsed !== 'unsupported') {
          const { start, end } = parsed
          streamOpts = { start, length: end - start + 1 }
          statusCode = 206
          responseLength = end - start + 1
          res.setHeader('Content-Range', `bytes ${start}-${end}/${byteLength}`)
        } else if (parsed === 'unsupported' && byteLength > this._maxResponseBytes) {
          // Unknown units and multi-ranges may normally be ignored, but doing
          // so for an oversized object would turn attacker input into the full
          // unbounded 200 response the byte ceiling is meant to prevent.
          res.setHeader('Content-Range', `bytes */${byteLength}`)
          sendJson({
            error: 'A bounded single byte range is required',
            maxResponseBytes: this._maxResponseBytes
          }, 416)
          return
        }
      }

      if (responseLength > this._maxResponseBytes) {
        if (streamOpts) res.setHeader('Content-Range', `bytes */${byteLength}`)
        sendJson({
          error: streamOpts ? 'Requested range exceeds gateway byte limit' : 'A bounded single byte range is required',
          maxResponseBytes: this._maxResponseBytes
        }, streamOpts ? 416 : 413)
        return
      }

      if (
        exactBytes &&
        req.method !== 'HEAD' &&
        responseLength > 0 &&
        typeof context?.reserveResponseBytes === 'function' &&
        context.reserveResponseBytes(responseLength) !== true
      ) {
        sendJson({ error: 'Gateway byte-rate limit exceeded' }, 429, {
          'Retry-After': String(context?.egressRetryAfterSeconds || 60)
        })
        return
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
        ? readDrive.createReadStream(filePath, streamOpts)
        : readDrive.createReadStream(filePath)
      const limiter = new ExactLengthTransform(responseLength)
      let bytes = 0
      let streamSettled = false
      let streamFailureReported = false

      const onStreamSettled = () => {
        if (streamSettled) return
        streamSettled = true
        if (signal) signal.removeEventListener('abort', onAbort)
      }
      const onAbort = () => {
        if (!stream.destroyed) {
          try { stream.destroy(createAbortError(signal?.reason)) } catch {}
        }
        if (!limiter.destroyed) {
          try { limiter.destroy(createAbortError(signal?.reason)) } catch {}
        }
        if (!res.destroyed && !res.writableEnded) {
          try { res.destroy(createAbortError(signal?.reason)) } catch {}
        }
      }

      limiter.on('data', (chunk) => { bytes += chunk.length })
      limiter.on('end', () => {
        onStreamSettled()
        this._totalBytesServed += bytes
        this.emit('served', { keyHex, filePath, bytes })
      })
      limiter.on('close', onStreamSettled)
      const onStreamError = (err) => {
        onStreamSettled()
        if (streamFailureReported) return
        streamFailureReported = true
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
        if (!isAbortError(err)) {
          this.emit('drive-error', { context: 'stream', key: keyHex, path: filePath, error: err.message })
        }
      }
      stream.on('error', onStreamError)
      limiter.on('error', (err) => {
        if (!stream.destroyed) {
          try { stream.destroy(err) } catch {}
        }
        onStreamError(err)
      })

      // If the client disconnects mid-flight, tear down the drive stream
      // so we don't keep reading blocks into a dead socket.
      res.on('close', () => {
        if (!stream.destroyed) {
          try { stream.destroy() } catch {}
        }
        if (!limiter.destroyed) {
          try { limiter.destroy() } catch {}
        }
      })

      if (signal) {
        signal.addEventListener('abort', onAbort, { once: true })
        if (signal.aborted) onAbort()
      }

      stream.pipe(limiter).pipe(res)
    } catch (err) {
      this.emit('drive-error', { context: 'handle', key: keyHex, path: filePath, error: err.message })
      if (isAbortError(err)) {
        if (!res.destroyed && !res.writableEnded) {
          try { res.destroy(err) } catch {}
        }
        return
      }
      if (res.destroyed || res.writableEnded) return
      if (res.headersSent) {
        try { res.destroy(err) } catch {}
        return
      }
      sendJson({ error: 'Gateway read failed' }, 502)
    } finally {
      if (requestDriveLease) requestDriveLease.settleHandler()
    }
  }

  _deniedDenylistEntry (keyHex) {
    const denylist = this._denylist
    if (!denylist || typeof denylist.entryFor !== 'function') return null
    try {
      return denylist.entryFor(keyHex)
    } catch {
      return null
    }
  }

  /**
   * Purge every denied drive from this gateway's caches and stop its
   * in-flight work. Triggered by the denylist's 'entry-added' event, so a
   * takedown — local or received over federation gossip — takes effect
   * immediately instead of at the next cache miss.
   */
  _purgeDeniedDrives () {
    const denylist = this._denylist
    if (!denylist || typeof denylist.isDenied !== 'function') return
    const isDenied = (keyHex) => {
      try {
        return denylist.isDenied(keyHex) === true
      } catch {
        return false
      }
    }

    // Stop in-flight request handling for denied drives first — aborting the
    // request controller tears down its drive stream through the normal
    // response-close path instead of racing it.
    const takedownError = createAbortError('Drive taken down by gateway denylist')
    for (const state of this._activeRequestStates) {
      if (state.keyHex && isDenied(state.keyHex) && !state.controller.signal.aborted) {
        state.controller.abort(takedownError)
      }
    }
    for (const [keyHex, controller] of this._driveOpenControllers) {
      if (isDenied(keyHex) && !controller.signal.aborted) controller.abort(takedownError)
    }
    for (const [keyHex, refresh] of this._driveRefreshPromises) {
      if (isDenied(keyHex) && !refresh.controller.signal.aborted) refresh.controller.abort(takedownError)
    }
    for (const [keyHex, state] of this._seededDriveUpdateStates) {
      if (isDenied(keyHex) && !state.controller.signal.aborted) state.controller.abort(takedownError)
    }

    // Evict denied drives from the LRU and retire them (closed once any
    // outstanding borrow drains) so a later request cannot hit a warm cache.
    for (const [keyHex, entry] of this._drives.entries()) {
      if (!isDenied(keyHex)) continue
      this._drives.delete(keyHex)
      if (entry?.drive) this._retireOwnedDrive(entry.drive)
    }
  }

  async _acquireDrive (keyHex, opts = {}) {
    const seededEntry = this.node.seededApps && this.node.seededApps.get(keyHex)
    const seededDrive = seededEntry && seededEntry.drive
    if (seededDrive && !seededDrive.closed && !seededDrive.closing) {
      // AppLifecycle owns seeded drives. The gateway borrows them for this
      // request but never inserts or closes them through its LRU.
      let lifecycleLease = null
      if (this.node.appLifecycle && typeof this.node.appLifecycle.acquireDriveReadLease === 'function') {
        lifecycleLease = this.node.appLifecycle.acquireDriveReadLease(keyHex)
        if (!lifecycleLease || lifecycleLease.drive !== seededDrive || typeof lifecycleLease.release !== 'function') {
          try {
            if (lifecycleLease && typeof lifecycleLease.release === 'function') lifecycleLease.release()
          } catch {}
          return null
        }
      } else if (this._requireLifecycleDriveAuthority) {
        return null
      } else {
        lifecycleLease = { drive: seededDrive, release: () => {} }
      }

      // A storage-aware relay serves only the exact immutable tuple accepted
      // by AppLifecycle's durable footprint proof. The mutable live drive is
      // never itself exposed to HTTP after proof, and its blob core is replaced
      // by the exact lifecycle-owned blob snapshot bound into that tuple.
      if (this.node.storageAdmission) {
        let checkout = null
        let accepted = false
        try {
          if (typeof this.node.storageAdmission.canAcknowledge !== 'function' ||
              !this.node.storageAdmission.canAcknowledge(`drive:${keyHex}`)) return null
          const proof = durableDriveProof(seededEntry)
          const proofCores = Array.isArray(seededEntry.downloadSnapshotCores)
            ? seededEntry.downloadSnapshotCores
            : null
          const metaProofCore = proofCores && proofCores[0]
          const blobProofCore = proofCores && proofCores[1]
          const metaProofState = stableCoreProofState(metaProofCore)
          const blobProofState = stableCoreProofState(blobProofCore)
          if (!proof || typeof seededDrive.checkout !== 'function' ||
              !metaProofState || metaProofState.length !== proof.metaLength || metaProofState.fork !== proof.metaFork ||
              !blobProofState || blobProofState.length !== proof.blobLength || blobProofState.fork !== proof.blobFork ||
              metaProofState.byteLength + blobProofState.byteLength !== proof.totalBytes) return null

          checkout = seededDrive.checkout(proof.driveVersion)
          if (checkout && typeof checkout.ready === 'function') {
            await this._withTimeout(
              checkout.ready(),
              this._driveOperationTimeout,
              'proved drive checkout',
              opts.signal
            )
          }
          const checkoutMeta = stableCoreProofState(checkout?.db?.core)
          const current = this.node.seededApps && this.node.seededApps.get(keyHex)
          const currentProof = durableDriveProof(current)
          if (!checkout || current !== seededEntry || current.drive !== seededDrive ||
              currentProof?.driveVersion !== proof.driveVersion ||
              currentProof?.metaLength !== proof.metaLength || currentProof?.blobLength !== proof.blobLength ||
              currentProof?.totalBytes !== proof.totalBytes || currentProof?.metaFork !== proof.metaFork ||
              currentProof?.blobFork !== proof.blobFork ||
              current.downloadSnapshotCores?.[0] !== metaProofCore || current.downloadSnapshotCores?.[1] !== blobProofCore ||
              !checkoutMeta || checkout.version !== proof.driveVersion ||
              checkoutMeta.length !== proof.metaLength || checkoutMeta.fork !== proof.metaFork ||
              !this.node.storageAdmission.canAcknowledge(`drive:${keyHex}`)) return null

          checkout.blobs = new Hyperblobs(nonClosingCoreView(blobProofCore))
          accepted = true
          return {
            drive: checkout,
            immutable: true,
            pinnedVersion: proof.driveVersion,
            release: lifecycleLease.release
          }
        } finally {
          // Ownership of a successfully returned checkout transfers to the
          // request cleanup path. Every rejected candidate closes here and
          // releases the lifecycle borrow before another unseed can proceed.
          if (!accepted) {
            if (checkout && checkout !== seededDrive && !checkout.closed && typeof checkout.close === 'function') {
              try { await checkout.close() } catch (_) {}
            }
            try { lifecycleLease.release() } catch {}
          }
        }
      }
      return lifecycleLease
    }

    // A recovered registry row with no live drive is a serve-only placeholder,
    // not permission for HTTP to open a second replication ingress.
    if (seededEntry && this.node.storageAdmission) return null

    // Exact public hosts are authorized against the live seeded entry above.
    // If unseed won that race, do not reopen the key through the gateway's LRU
    // after public admission has already disappeared.
    if (opts.requireSeeded || this._requireLifecycleDriveAuthority) return null

    // Return cached drive if already open and has content
    if (this._drives.has(keyHex)) {
      const cached = this._drives.get(keyHex)
      // Refresh in background for next request
      if (typeof cached.update === 'function') this._refreshOwnedDrive(keyHex, cached)
      return this._leaseOwnedDrive(cached)
    }

    let state = this._driveOpenStates.get(keyHex)
    if (!state) {
      const controller = new AbortController()
      state = { controller, promise: null, waiters: 0, settled: false }
      const opening = this._openDrive(keyHex, controller.signal)
      const promise = opening.finally(() => {
        state.settled = true
        if (this._driveOpenStates.get(keyHex) === state) this._driveOpenStates.delete(keyHex)
        if (this._driveOpenPromises.get(keyHex) === promise) this._driveOpenPromises.delete(keyHex)
        if (this._driveOpenControllers.get(keyHex) === controller) this._driveOpenControllers.delete(keyHex)
      })
      state.promise = promise
      this._driveOpenStates.set(keyHex, state)
      this._driveOpenPromises.set(keyHex, promise)
      this._driveOpenControllers.set(keyHex, controller)
      promise.catch(() => {})
    }

    state.waiters++
    try {
      const drive = await this._withTimeout(
        state.promise,
        this._driveOperationTimeout,
        'drive open',
        opts.signal
      )
      return drive ? this._leaseOwnedDrive(drive) : null
    } finally {
      state.waiters = Math.max(0, state.waiters - 1)
      if (state.waiters === 0 && !state.settled && !state.controller.signal.aborted) {
        state.controller.abort(createAbortError('No gateway readers remain'))
      }
    }
  }

  async _openDrive (keyHex, signal = null) {
    // Initialize our own P2P stack on first use. Per-key callers share this
    // promise through _driveOpenPromises, preventing session/download storms.
    await this._ensureReady(signal)
    let drive = null

    try {
      // Per-drive corestore session so cache eviction / drive.close()
      // tears down only this session's refs, not the root store. Without
      // .session(), hyperdrive._close() cascades to the externalStore
      // (the relay's node.store) and wedges the entire relay until
      // restart — same class as the v0.8.14 fix in
      // app-lifecycle.js:_seedAppInner. The captured trace from utah-us
      // canary 2026-05-18 confirms this path fires (DriveCache eviction
      // → hyperdrive._close → store.close on the wrapped root).
      drive = new Hyperdrive(this._store.session(), Buffer.from(keyHex, 'hex'))
      await this._withTimeout(drive.ready(), this._driveOperationTimeout, 'drive.ready()', signal)
      if (this._closing || signal?.aborted) throw createAbortError(signal?.reason || 'Gateway is closing')

      // Join the drive's discovery key on the swarm (only when we own it)
      if (this._swarm) {
        const done = drive.findingPeers()
        try {
          this._swarm.join(drive.discoveryKey, { server: true, client: true })
          this._trackOwnedDriveTopic(drive, drive.discoveryKey)
          await this._withTimeout(
            this._swarm.flush(),
            Math.min(5000, this._driveOperationTimeout),
            'Hyperswarm.flush()',
            signal
          )
        } catch (err) {
          if (isAbortError(err)) throw err
          this.emit('drive-wait-error', { key: keyHex, error: err.message })
        } finally {
          try { done() } catch {}
        }
      }

      // Wait for drive data to arrive from peers
      if (!driveHasContent(drive)) {
        try {
          await updateWithTimeout(drive, {
            timeoutMs: Math.min(20_000, this._driveOperationTimeout),
            signal
          })
        } catch (err) {
          this.emit('drive-wait-error', { key: keyHex, error: err.message })
        }
      }

      // Still no content
      if (!driveHasContent(drive)) {
        await this._closeOwnedDrive(drive, 'empty-close')
        return null
      }

      if (this._closing || signal?.aborted) throw createAbortError(signal?.reason || 'Gateway is closing')
      // Do not eagerly mirror an arbitrary drive requested through the legacy
      // compatibility path. createReadStream() fetches only the requested
      // extent; downloading '/' here let one public request consume unbounded
      // relay bandwidth and disk in the background after its socket closed.
      this._drives.set(keyHex, drive)
      return drive
    } catch (err) {
      if (drive && !drive.closed) {
        await this._closeOwnedDrive(drive, 'open-failure-close')
      }
      this.emit('drive-error', { context: 'getDrive', key: keyHex, error: err })
      return null
    }
  }

  _refreshOwnedDrive (keyHex, drive) {
    const existing = this._driveRefreshPromises.get(keyHex)
    if (existing) return existing.promise
    if (this._closing || !drive || drive.closed || drive.closing) return null

    const controller = new AbortController()
    // Treat a refresh as a reader so LRU eviction cannot close the session
    // while updateWithTimeout is still clearing its per-operation refs.
    const lease = this._leaseOwnedDrive(drive)
    const promise = updateWithTimeout(drive, {
      timeoutMs: this._driveOperationTimeout,
      wait: false,
      signal: controller.signal
    }).catch(err => {
      if (!isAbortError(err)) {
        this.emit('drive-update-error', { key: keyHex, error: err.message })
      }
    }).finally(() => {
      lease.release()
      const current = this._driveRefreshPromises.get(keyHex)
      if (current?.promise === promise) this._driveRefreshPromises.delete(keyHex)
    })

    this._driveRefreshPromises.set(keyHex, { promise, controller, drive })
    return promise
  }

  async _updateSeededDrive (keyHex, drive, signal = null) {
    let state = this._seededDriveUpdateStates.get(keyHex)
    if (!state || state.drive !== drive) {
      const controller = new AbortController()
      state = {
        drive,
        controller,
        promise: null,
        waiters: 0,
        settled: false
      }
      const promise = updateWithTimeout(drive, {
        timeoutMs: this._driveOperationTimeout,
        signal: controller.signal
      }).finally(() => {
        state.settled = true
        if (this._seededDriveUpdateStates.get(keyHex) === state) {
          this._seededDriveUpdateStates.delete(keyHex)
        }
      })
      state.promise = promise
      this._seededDriveUpdateStates.set(keyHex, state)
    }

    state.waiters++
    try {
      return await this._withTimeout(
        state.promise,
        this._driveOperationTimeout,
        'seeded drive update',
        signal
      )
    } finally {
      state.waiters = Math.max(0, state.waiters - 1)
      if (state.waiters === 0 && !state.settled && !state.controller.signal.aborted) {
        state.controller.abort(createAbortError('No gateway readers remain'))
      }
    }
  }

  _leaseOwnedDrive (drive) {
    this._activeOwnedDrives.set(drive, (this._activeOwnedDrives.get(drive) || 0) + 1)
    let released = false
    return {
      drive,
      release: () => {
        if (released) return
        released = true
        const remaining = (this._activeOwnedDrives.get(drive) || 1) - 1
        if (remaining <= 0) this._activeOwnedDrives.delete(drive)
        else this._activeOwnedDrives.set(drive, remaining)
        this._tryCloseRetiredDrive(drive)
      }
    }
  }

  _retireOwnedDrive (drive) {
    if (!drive || drive.closed) return
    this._retiredOwnedDrives.add(drive)
    // Defer close past promise continuations that may be acquiring the drive
    // returned by a just-completed singleflight open.
    setImmediate(() => this._tryCloseRetiredDrive(drive))
  }

  _tryCloseRetiredDrive (drive) {
    if (!this._retiredOwnedDrives.has(drive) || this._activeOwnedDrives.has(drive)) return
    this._retiredOwnedDrives.delete(drive)
    if (drive.closed || typeof drive.close !== 'function') return
    const pending = this._closeOwnedDrive(drive, 'evict-close')
    this._driveClosePromises.add(pending)
    pending.finally(() => this._driveClosePromises.delete(pending)).catch(() => {})
  }

  async _closeOwnedDrive (drive, operation = 'close') {
    if (!drive) return
    await this._releaseOwnedDriveTopic(drive)
    if (drive.closed || typeof drive.close !== 'function') return
    try {
      await this._withTimeout(
        Promise.resolve(drive.close()),
        Math.min(DRIVE_CLOSE_TIMEOUT, this._driveOperationTimeout),
        `drive.${operation}()`
      )
    } catch (err) {
      this.emit(operation === 'evict-close' ? 'drive-cache-error' : 'drive-close-error', {
        operation,
        error: err.message
      })
    }
  }

  _trackOwnedDriveTopic (drive, discoveryKey) {
    if (!drive || !discoveryKey || this._ownedDriveTopics.has(drive)) return
    const keyHex = Buffer.from(discoveryKey).toString('hex')
    const current = this._ownedTopicRefs.get(keyHex)
    if (current) current.count++
    else this._ownedTopicRefs.set(keyHex, { discoveryKey, count: 1 })
    this._ownedDriveTopics.set(drive, keyHex)
  }

  async _releaseOwnedDriveTopic (drive) {
    const keyHex = this._ownedDriveTopics.get(drive)
    if (!keyHex) return
    this._ownedDriveTopics.delete(drive)
    const current = this._ownedTopicRefs.get(keyHex)
    if (!current) return
    current.count = Math.max(0, current.count - 1)
    if (current.count > 0) return
    this._ownedTopicRefs.delete(keyHex)
    if (!this._swarm || typeof this._swarm.leave !== 'function') return
    try {
      await this._withTimeout(
        Promise.resolve(this._swarm.leave(current.discoveryKey)),
        Math.min(1000, this._driveOperationTimeout),
        'Hyperswarm.leave()'
      )
    } catch (err) {
      this.emit('drive-cache-error', { operation: 'topic-leave', error: err.message })
    }
  }

  _bindResponseCleanup (res, cleanup) {
    let cleaned = false
    const run = () => {
      if (cleaned) return
      cleaned = true
      res.removeListener('finish', run)
      res.removeListener('close', run)
      cleanup()
    }
    res.once('finish', run)
    res.once('close', run)
    if (res.destroyed || res.writableEnded || res.writableFinished) run()
  }

  _holdDriveLeaseForRequest (res, driveLease) {
    let handlerSettled = false
    let responseSettled = false
    let cleanupStarted = false
    let checkout = null

    const maybeCleanup = () => {
      if (!handlerSettled || !responseSettled || cleanupStarted) return
      cleanupStarted = true

      const pending = (async () => {
        try {
          if (checkout && !checkout.closed && typeof checkout.close === 'function') {
            await this._withTimeout(
              Promise.resolve(checkout.close()),
              Math.min(1000, this._driveOperationTimeout),
              'drive.checkout().close()'
            )
          }
        } catch (err) {
          this.emit('drive-close-error', { context: 'request-checkout', error: err.message })
        } finally {
          try { driveLease.release() } catch (err) {
            this.emit('drive-close-error', { context: 'request-lease', error: err.message })
          }
        }
      })()

      this._pendingRequestCleanups.add(pending)
      pending.then(
        () => this._pendingRequestCleanups.delete(pending),
        () => this._pendingRequestCleanups.delete(pending)
      )
    }

    this._bindResponseCleanup(res, () => {
      responseSettled = true
      maybeCleanup()
    })

    return {
      setCheckout: (drive) => { checkout = drive },
      settleHandler: () => {
        handlerSettled = true
        maybeCleanup()
      }
    }
  }

  async _serveDirectoryListing (res, drive, keyHex, dirPath, opts = {}) {
    const entries = []
    const MAX_ENTRIES = 1000 // Prevent memory exhaustion from huge directories
    const maxListingBytes = Math.min(this._maxResponseBytes, 1024 * 1024)
    let estimatedPayloadBytes = Buffer.byteLength(JSON.stringify({ key: keyHex, path: dirPath, entries: [] }) + '\n')
    const startTime = Date.now()
    const TIMEOUT = this._driveOperationTimeout
    let iterator = null
    let iteratorDone = false
    let failure = null

    try {
      const listing = drive.list(dirPath)
      if (!listing || typeof listing[Symbol.asyncIterator] !== 'function') {
        throw new Error('Directory listing unavailable')
      }
      iterator = listing[Symbol.asyncIterator]()
      while (true) {
        const elapsed = Date.now() - startTime
        if (elapsed >= TIMEOUT) throw new Error('Directory listing timeout')
        const next = await this._withTimeout(
          iterator.next(),
          Math.max(1, TIMEOUT - elapsed),
          'drive.list().next()',
          opts.signal
        )
        if (next.done) {
          iteratorDone = true
          break
        }
        const entryKey = next.value?.key
        if (typeof entryKey !== 'string') throw new Error('Directory entry key is invalid')
        const encodedEntryBytes = Buffer.byteLength(JSON.stringify(entryKey)) + (entries.length > 0 ? 1 : 0)
        if (estimatedPayloadBytes + encodedEntryBytes > maxListingBytes) {
          const marker = '... (truncated by byte limit)'
          const markerBytes = Buffer.byteLength(JSON.stringify(marker)) + (entries.length > 0 ? 1 : 0)
          if (estimatedPayloadBytes + markerBytes <= maxListingBytes) entries.push(marker)
          break
        }
        entries.push(entryKey)
        estimatedPayloadBytes += encodedEntryBytes
        if (entries.length >= MAX_ENTRIES) {
          entries.push('... (truncated)')
          break
        }
      }
    } catch (err) {
      failure = err
    } finally {
      if (iterator && !iteratorDone && typeof iterator.return === 'function') {
        try {
          await this._withTimeout(iterator.return(), Math.min(1000, TIMEOUT), 'drive.list().return()')
        } catch (err) {
          if (!failure) failure = err
        }
      }
    }

    const headers = {
      'X-Hyper-Key': keyHex,
      'X-Served-By': 'hiverelay-gateway'
    }
    if (opts.byteMode) {
      headers['X-Hive-App-Key'] = keyHex
      headers['X-Hive-Byte-Mode'] = opts.byteMode
      headers.Vary = 'Host'
      headers['Origin-Agent-Cluster'] = '?1'
    }
    if (failure) {
      this.emit('drive-error', { context: 'directoryListing', key: keyHex, path: dirPath, error: failure.message })
      if (isAbortError(failure)) {
        if (!res.destroyed && !res.writableEnded) {
          try { res.destroy(failure) } catch {}
        }
        return
      }
      if (res.destroyed || res.writableEnded) return
      writeGatewayJson(res, { error: 'Gateway directory listing failed' }, 502, headers, { head: !!opts.head })
      return
    }
    headers['Cache-Control'] = opts.byteMode ? 'no-store, max-age=0' : 'public, max-age=60'
    const body = { key: keyHex, path: dirPath, entries }
    const payload = Buffer.from(JSON.stringify(body) + '\n')
    const payloadBytes = payload.byteLength
    if (payloadBytes > maxListingBytes) {
      writeGatewayJson(res, { error: 'Gateway directory listing exceeds byte limit' }, 413, headers, { head: !!opts.head })
      return
    }
    let representation = { ok: true, status: 200, payload, contentRange: null }
    if (opts.byteMode) {
      headers['Accept-Ranges'] = 'bytes'
      representation = selectExactByteRepresentation(payload, opts.rangeHeader)
      if (!representation.ok) {
        headers['Content-Range'] = representation.contentRange
        writeGatewayJson(res, { error: 'Range Not Satisfiable' }, 416, headers, { head: !!opts.head })
        return
      }
      if (representation.contentRange) headers['Content-Range'] = representation.contentRange
    }
    if (
      !opts.head &&
      representation.payload.byteLength > 0 &&
      typeof opts.reserveResponseBytes === 'function' &&
      opts.reserveResponseBytes(representation.payload.byteLength) !== true
    ) {
      writeGatewayJson(res, { error: 'Gateway byte-rate limit exceeded' }, 429, {
        ...headers,
        'Retry-After': String(opts.egressRetryAfterSeconds || 60)
      }, { head: false })
      return
    }
    writeGatewayBuffer(res, representation.payload, representation.status, headers, { head: !!opts.head })
  }

  getStats () {
    return {
      cachedDrives: this._drives.size,
      totalRequests: this._totalRequests,
      totalBytesServed: this._totalBytesServed
    }
  }

  async close () {
    if (this._closePromise) return this._closePromise
    this._closing = true

    const pending = this._close()
    this._closePromise = pending
    try {
      await pending
    } finally {
      if (this._closePromise === pending) this._closePromise = null
      this._closing = false
    }
  }

  async _close () {
    const shutdownError = createAbortError('Gateway is shutting down')
    this._disarmDenylistListener()
    const requestStates = [...this._activeRequestStates]
    for (const state of requestStates) {
      if (!state.controller.signal.aborted) state.controller.abort(shutdownError)
      if (!state.res.destroyed && !state.res.writableEnded) {
        try { state.res.destroy(shutdownError) } catch {}
      }
      state.forceResponseSettlement?.()
    }
    if (this._readyController && !this._readyController.signal.aborted) {
      this._readyController.abort(shutdownError)
    }
    for (const controller of this._driveOpenControllers.values()) {
      if (!controller.signal.aborted) controller.abort(shutdownError)
    }
    for (const refresh of this._driveRefreshPromises.values()) {
      if (!refresh.controller.signal.aborted) refresh.controller.abort(shutdownError)
    }
    for (const state of this._seededDriveUpdateStates.values()) {
      if (!state.controller.signal.aborted) state.controller.abort(shutdownError)
    }

    if (requestStates.length > 0) {
      await Promise.allSettled(requestStates.map(state => state.settled))
    }
    if (this._readyPromise) await Promise.allSettled([this._readyPromise])
    if (this._driveOpenPromises.size > 0) {
      await Promise.allSettled(this._driveOpenPromises.values())
      this._driveOpenPromises.clear()
      this._driveOpenControllers.clear()
      this._driveOpenStates.clear()
    }
    if (this._driveRefreshPromises.size > 0) {
      await Promise.allSettled([...this._driveRefreshPromises.values()].map(value => value.promise))
      this._driveRefreshPromises.clear()
    }
    if (this._seededDriveUpdateStates.size > 0) {
      await Promise.allSettled([...this._seededDriveUpdateStates.values()].map(value => value.promise))
      this._seededDriveUpdateStates.clear()
    }
    if (this._pendingRequestCleanups.size > 0) {
      await Promise.allSettled([...this._pendingRequestCleanups])
      this._pendingRequestCleanups.clear()
    }
    if (this._driveClosePromises.size > 0) {
      await Promise.allSettled([...this._driveClosePromises])
      this._driveClosePromises.clear()
    }

    // DriveCache is not directly iterable — iterate its entries(), and each
    // value is a { drive, lastAccess } wrapper, not the drive itself. The
    // previous `for (const [, drive] of this._drives)` threw
    // "this._drives is not iterable" on every close(), leaking the HTTP
    // server (EADDRINUSE on self-heal restart).
    const ownedDrives = new Set(this._retiredOwnedDrives)
    for (const [, entry] of this._drives.entries()) {
      if (entry?.drive) ownedDrives.add(entry.drive)
    }
    this._drives.clear()
    this._retiredOwnedDrives.clear()
    this._activeOwnedDrives.clear()
    await Promise.allSettled([...ownedDrives].map(drive => this._closeOwnedDrive(drive)))

    if (this._ownsSwarm && this._swarm) {
      try {
        await this._withTimeout(
          this._swarm.destroy(),
          Math.min(DRIVE_CLOSE_TIMEOUT, this._driveOperationTimeout),
          'swarm.destroy()'
        )
      } catch (err) {
        this.emit('swarm-destroy-error', { error: err.message })
      }
    }
    // A RelayNode-provided Corestore is borrowed infrastructure. Closing it
    // here would wedge seeding, replication, and control-plane consumers that
    // outlive a gateway restart.
    if (this._store && !this._externalStore) {
      try {
        await this._withTimeout(
          this._store.close(),
          Math.min(DRIVE_CLOSE_TIMEOUT, this._driveOperationTimeout),
          'Corestore.close()'
        )
      } catch (err) {
        this.emit('store-close-error', { error: err.message })
      }
    }
    this._activeRequestStates.clear()
    this._ownedDriveTopics.clear()
    this._ownedTopicRefs.clear()
    this._store = null
    this._swarm = null
    this._ownsSwarm = false
    this._ready = false
    this._readyPromise = null
    this._readyController = null
  }
}
