/**
 * DHT-Relay WebSocket transport — lets browsers tunnel HyperDHT lookups
 * through this relay over a WebSocket.
 *
 * Browsers can't speak UDP, so they can't do native HyperDHT operations
 * (peer discovery, hole-punch announce, etc.) themselves. This transport
 * exposes the relay's HyperDHT instance to browser clients via a framed
 * WebSocket protocol — the browser instantiates `new DHT(stream)` from
 * `@hyperswarm/dht-relay` and gets a working DHT API end-to-end.
 *
 * Distinct from the existing Hypercore-over-WebSocket transport
 * (`transports/websocket/`), which carries replication streams. This one
 * carries DHT control traffic.
 *
 * ─── Threat model (v0.8.16 hardening) ─────────────────────────────────
 *
 * What an operator running this transport CAN see:
 *   - The fact that a client connected (counted in getStats aggregates)
 *   - Frame sizes + timing of Hypercore traffic flowing through the
 *     WebSocket after a peer match
 *
 * What an operator CANNOT see (Noise-tunneled end-to-end between the
 * client and its DHT peer):
 *   - Hypercore block contents
 *   - Hyperdrive contents / manifests
 *   - Anything the publisher encrypted
 *
 * What the transport KEEPS IN MEMORY (never emitted, never logged):
 *   - Raw client IP — held in the per-IP rate-limiter bucket
 *     (`_ipBuckets`) for `rateLimit.staleAfterMs` (5 minutes default)
 *     after the connection's last activity. This is the minimum needed
 *     for rate limiting to work. The bucket is opaque to anything
 *     outside this file.
 *
 * What the transport DOES NOT EXPOSE externally:
 *   - Emitted events (`client-connected`, `client-disconnected`,
 *     `client-error`, `relay-error`, `rate-limited`) carry a
 *     `remoteAddressHash` — a short SHA-256-derived prefix of the IP.
 *     This lets operators correlate same-client activity across a
 *     session for ops/debug, without exposing the raw IP through any
 *     downstream subscriber (ws-feed, observatory, /api/manage, logs).
 *   - getStats() returns only aggregates (active count, total served,
 *     total rate-limited) — never per-IP data.
 *
 * If you need to investigate a specific abuser, attach to the
 * `rate-limited` event in-process and read the bucket directly; the
 * raw IP is available there for the lifetime of the bucket. It is
 * intentionally never persisted or emitted.
 *
 * Usage:
 *   const dhtRelay = new DHTRelayWS({ dht: swarm.dht, port: 8766 })
 *   await dhtRelay.start()
 */

import { EventEmitter } from 'events'
import { createHash } from 'crypto'
import { WebSocketServer } from 'ws'
import { relay } from '@hyperswarm/dht-relay'
import Stream from '@hyperswarm/dht-relay/ws'

const DEFAULT_PORT = 8766
const DEFAULT_CONNECTIONS_PER_MINUTE_PER_IP = 10
const DEFAULT_MAX_CONCURRENT_PER_IP = 5
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000
const DEFAULT_CLEANUP_INTERVAL_MS = 60_000
const DEFAULT_STALE_AFTER_MS = 5 * 60_000

export class DHTRelayWS extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.dht - HyperDHT instance to expose (typically swarm.dht)
   * @param {number} [opts.port]
   * @param {string} [opts.host]
   * @param {number} [opts.maxConnections]
   * @param {object} [opts.rateLimit]
   * @param {number} [opts.rateLimit.connectionsPerMinutePerIp=10]
   * @param {number} [opts.rateLimit.maxConcurrentPerIp=5]
   * @param {number} [opts.rateLimit.windowMs=60000] - token bucket refill window
   * @param {number} [opts.rateLimit.cleanupIntervalMs=60000] - how often we sweep stale entries
   * @param {number} [opts.rateLimit.staleAfterMs=300000] - drop entries with no activity for this long
   */
  constructor (opts = {}) {
    super()
    if (!opts.dht) throw new Error('DHTRelayWS: dht is required')
    this.dht = opts.dht
    this.port = opts.port || DEFAULT_PORT
    this.host = opts.host || '0.0.0.0'
    this.maxConnections = opts.maxConnections || 256
    // Per-process random salt for the IP-hash exposed in events. Without
    // a salt, a hash prefix is a stable global identifier for the IP and
    // could be cross-correlated across relays. With a per-process salt,
    // the hash is only meaningful within one relay's session — useful
    // for in-session correlation, useless for cross-fleet tracking. The
    // salt is never persisted and changes on every restart.
    this._ipHashSalt = createHash('sha256').update(String(Math.random()) + String(process.hrtime.bigint())).digest()

    const rl = opts.rateLimit || {}
    this.rateLimit = {
      connectionsPerMinutePerIp: rl.connectionsPerMinutePerIp || DEFAULT_CONNECTIONS_PER_MINUTE_PER_IP,
      maxConcurrentPerIp: rl.maxConcurrentPerIp || DEFAULT_MAX_CONCURRENT_PER_IP,
      windowMs: rl.windowMs || DEFAULT_RATE_LIMIT_WINDOW_MS,
      cleanupIntervalMs: rl.cleanupIntervalMs || DEFAULT_CLEANUP_INTERVAL_MS,
      staleAfterMs: rl.staleAfterMs || DEFAULT_STALE_AFTER_MS
    }

    this.server = null
    this.connections = new Set()
    this.running = false
    this._totalConnectionsServed = 0
    this._totalRateLimited = 0
    // Map<ip, { tokens, lastRefill, concurrent, lastSeen }>
    this._ipBuckets = new Map()
    this._cleanupTimer = null
  }

  // Per-process salted prefix of SHA-256(ip). 16 hex chars is enough to
  // distinguish concurrent clients within a session without being
  // reversible. The salt rotates on every relay restart.
  _hashIp (ip) {
    if (!ip) return null
    return createHash('sha256').update(this._ipHashSalt).update(String(ip)).digest('hex').slice(0, 16)
  }

  // Build the event-safe info payload — `remoteAddressHash` (not raw IP),
  // remotePort, type. Anything external (ws-feed, observatory, /api/manage,
  // downstream loggers) sees only this shape.
  _safeInfo (ip, remotePort) {
    return {
      type: 'dht-relay-ws',
      remoteAddressHash: this._hashIp(ip),
      remotePort
    }
  }

  // Token-bucket check + decrement. Returns null if allowed, or a string
  // reason ('connections-per-minute' | 'max-concurrent') if rate-limited.
  _checkRateLimit (ip) {
    const now = Date.now()
    const cap = this.rateLimit.connectionsPerMinutePerIp
    const window = this.rateLimit.windowMs
    let bucket = this._ipBuckets.get(ip)
    if (!bucket) {
      bucket = { tokens: cap, lastRefill: now, concurrent: 0, lastSeen: now }
      this._ipBuckets.set(ip, bucket)
    }

    // Refill tokens based on elapsed time. Continuous refill: a full window
    // of inactivity restores the bucket to `cap`.
    const elapsed = now - bucket.lastRefill
    if (elapsed > 0) {
      const refill = (elapsed / window) * cap
      bucket.tokens = Math.min(cap, bucket.tokens + refill)
      bucket.lastRefill = now
    }
    bucket.lastSeen = now

    if (bucket.concurrent >= this.rateLimit.maxConcurrentPerIp) {
      return 'max-concurrent'
    }
    if (bucket.tokens < 1) {
      return 'connections-per-minute'
    }

    bucket.tokens -= 1
    bucket.concurrent += 1
    return null
  }

  _releaseConnection (ip) {
    const bucket = this._ipBuckets.get(ip)
    if (!bucket) return
    bucket.concurrent = Math.max(0, bucket.concurrent - 1)
    bucket.lastSeen = Date.now()
  }

  _cleanupStaleBuckets () {
    const now = Date.now()
    const stale = this.rateLimit.staleAfterMs
    for (const [ip, bucket] of this._ipBuckets) {
      if (bucket.concurrent === 0 && (now - bucket.lastSeen) > stale) {
        this._ipBuckets.delete(ip)
      }
    }
  }

  async start () {
    if (this.running) return

    this.server = new WebSocketServer({
      port: this.port,
      host: this.host,
      perMessageDeflate: false, // dht-relay carries its own framed binary
      // Reject rate-limited clients at HTTP upgrade time (before the WS
      // upgrade completes) so the client sees an HTTP error rather than an
      // open-then-close cycle. The connection-event handler still enforces
      // the global maxConnections cap.
      verifyClient: (info, cb) => {
        const ip = info.req.socket.remoteAddress
        const rateLimitReason = this._checkRateLimit(ip)
        if (rateLimitReason) {
          this._totalRateLimited++
          this.emit('rate-limited', { remoteAddressHash: this._hashIp(ip), reason: rateLimitReason })
          const status = rateLimitReason === 'max-concurrent' ? 503 : 429
          // eslint-disable-next-line n/no-callback-literal
          cb(false, status, rateLimitReason)
          return
        }
        // eslint-disable-next-line n/no-callback-literal
        cb(true)
      }
    })

    await new Promise((resolve, reject) => {
      this.server.on('listening', resolve)
      this.server.on('error', reject)
    })

    this.server.on('connection', (socket, req) => {
      const ip = req.socket.remoteAddress

      if (this.connections.size >= this.maxConnections) {
        // Rate-limit already accepted us in verifyClient; release the
        // concurrency slot we reserved before refusing on the global cap.
        this._releaseConnection(ip)
        socket.close(1013, 'DHT_RELAY_AT_CAPACITY')
        return
      }

      this.connections.add(socket)
      this._totalConnectionsServed++

      // External-safe info payload: salted-hash prefix instead of raw IP.
      // Raw IP stays in the in-process _ipBuckets Map for rate-limiting.
      // See threat model in the file header.
      const info = this._safeInfo(ip, req.socket.remotePort)

      // Hand the socket off to dht-relay. It speaks its own framed
      // protocol over the WebSocket and proxies DHT operations to our
      // local HyperDHT instance.
      try {
        relay(this.dht, new Stream(false, socket))
      } catch (err) {
        // Scrub error: only carry message/code/name, never the full Error
        // (whose .stack would expose server-side paths, and whose
        // .message could in rare upstream-library cases include an IP).
        this.emit('relay-error', { error: scrubError(err), info })
        try { socket.close(1011, 'DHT_RELAY_INIT_FAILED') } catch (_) {}
        this.connections.delete(socket)
        this._releaseConnection(ip)
        return
      }

      socket.on('close', () => {
        this.connections.delete(socket)
        this._releaseConnection(ip)
        this.emit('client-disconnected', info)
      })

      socket.on('error', (err) => {
        this.emit('client-error', { error: scrubError(err), info })
      })

      this.emit('client-connected', info)
    })

    this._cleanupTimer = setInterval(
      () => this._cleanupStaleBuckets(),
      this.rateLimit.cleanupIntervalMs
    )
    if (this._cleanupTimer.unref) this._cleanupTimer.unref()

    this.running = true
    this.emit('started', { port: this.port, host: this.host })
  }

  async stop () {
    if (!this.running) return
    this.running = false

    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer)
      this._cleanupTimer = null
    }

    for (const socket of this.connections) {
      try { socket.close(1001, 'SERVER_SHUTDOWN') } catch (_) {}
    }
    this.connections.clear()
    this._ipBuckets.clear()

    await new Promise((resolve) => {
      this.server.close(() => resolve())
    })
    this.server = null
    this.emit('stopped')
  }

  getStats () {
    return {
      running: this.running,
      port: this.port,
      host: this.host,
      activeConnections: this.connections.size,
      totalConnectionsServed: this._totalConnectionsServed,
      totalRateLimited: this._totalRateLimited,
      maxConnections: this.maxConnections,
      rateLimit: {
        connectionsPerMinutePerIp: this.rateLimit.connectionsPerMinutePerIp,
        maxConcurrentPerIp: this.rateLimit.maxConcurrentPerIp
      }
    }
  }
}

// Normalize an Error into an emit-safe shape. Strips .stack (server-side
// paths) and any unexpected own properties; keeps just {message, code,
// name}. Also runs a defensive IP-regex strip on the message in case an
// upstream library leaked an IP into an error string.
function scrubError (err) {
  if (!err) return { message: 'unknown', code: null, name: null }
  const message = String(err.message || err)
    // crude IPv4
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[ip]')
    // crude IPv6 (any string of hex-and-colons with at least one ::)
    .replace(/(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}/g, '[ip]')
    .replace(/::1\b/g, '[ip]')
  return { message, code: err.code || null, name: err.name || null }
}
