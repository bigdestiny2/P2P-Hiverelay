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
// VENDORED @hyperswarm/dht-relay@0.4.3 (upstream: "do not use in production").
// Pinned + vendored under ./vendor/dht-relay so the exact code that proxies
// browser DHT ops against the operator's real DHT is auditable in-tree and
// carries our prod-hardening patches (ingress/egress backpressure in the ws
// Stream; per-connection error containment + query drain in node-proxy). See
// ./vendor/dht-relay/VENDOR.md for the patch log. Its transitive deps
// (hyperdht, protomux, secret-stream, …) still resolve from node_modules.
import { relay } from './vendor/dht-relay/index.js'
import Stream from './vendor/dht-relay/ws.js'
import { clientIpFromRequest } from '../../core/relay-node/api-rate-limit.js'

const DEFAULT_PORT = 8766
const DEFAULT_CONNECTIONS_PER_MINUTE_PER_IP = 10
const DEFAULT_MAX_CONCURRENT_PER_IP = 5
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000
const DEFAULT_CLEANUP_INTERVAL_MS = 60_000
const DEFAULT_STALE_AFTER_MS = 5 * 60_000

// ─── Prod-readiness bounds (Phase 5 pure-pipe hardening) ────────────────
//
// All of these are CONTENT-NEUTRAL: they act on frame *lengths*, socket
// buffer *sizes*, and frame *arrival times* — never on payload bytes,
// which stay Noise-encrypted end-to-end. That neutrality is load-bearing
// for the operator's §512(a) transitory-conduit posture (see
// peerit/docs/OPERATOR-LIABILITY.md): the pipe may meter and bound, but
// must never inspect or branch on content.
//
// Why the transport must own liveness at all: upstream @hyperswarm/
// dht-relay only arms its heartbeat failsafe when a protocol ping/pong
// ARRIVES (protocol.js `alive()`), so a client that connects and never
// speaks the framed protocol is never reaped upstream — it holds a
// maxConnections slot forever while the relay pings into the void. And
// the upstream ws Stream `_write` ignores `socket.bufferedAmount`
// entirely, so a slow or half-open reader grows the process heap
// unboundedly. Both bounds land here, in our layer, working for any
// upstream version.
const DEFAULT_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024 // single-frame cap (ws default is 100 MiB)
const DEFAULT_KEEPALIVE_INTERVAL_MS = 30_000 // WS ping cadence; browsers auto-pong (RFC 6455)
const DEFAULT_FIRST_FRAME_TIMEOUT_MS = 30_000 // a real dht-relay client handshakes immediately
const DEFAULT_MAX_BUFFERED_BYTES = 16 * 1024 * 1024 // egress backpressure ceiling per connection
const DEFAULT_PENDING_RESERVATION_TTL_MS = 10_000 // verifyClient→connection upgrade window

export class DHTRelayWS extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.dht - HyperDHT instance to expose (typically swarm.dht)
   * @param {number} [opts.port=8766] - use 0 for a kernel-assigned ephemeral port
   * @param {string} [opts.host]
   * @param {number} [opts.maxConnections]
   * @param {boolean} [opts.trustProxy=false] - derive client IP from X-Forwarded-For (set when behind a TLS reverse proxy)
   * @param {object} [opts.rateLimit]
   * @param {number} [opts.rateLimit.connectionsPerMinutePerIp=10]
   * @param {number} [opts.rateLimit.maxConcurrentPerIp=5]
   * @param {number} [opts.rateLimit.windowMs=60000] - token bucket refill window
   * @param {number} [opts.rateLimit.cleanupIntervalMs=60000] - how often we sweep stale entries
   * @param {number} [opts.rateLimit.staleAfterMs=300000] - drop entries with no activity for this long
   * @param {number} [opts.rateLimit.pendingTtlMs=10000] - expire upgrade reservations that never became connections
   * @param {object} [opts.keepalive]
   * @param {number} [opts.keepalive.intervalMs=30000] - WS ping cadence + supervisor sweep period (0 disables supervision)
   * @param {number} [opts.keepalive.firstFrameTimeoutMs=30000] - reap connections that never send a frame (0 disables)
   * @param {number} [opts.keepalive.maxSessionMs=0] - optional absolute session ceiling (0 = unlimited)
   * @param {object} [opts.flow]
   * @param {number} [opts.flow.maxPayloadBytes=8388608] - single WS frame cap (ws parser enforced)
   * @param {number} [opts.flow.maxBufferedBytes=16777216] - egress buffer ceiling per connection (two-sweep rule)
   * @param {number} [opts.flow.maxRxBytesPerSec=0] - optional per-connection ingress rate cap (0 = unlimited)
   */
  constructor (opts = {}) {
    super()
    if (!opts.dht) throw new Error('DHTRelayWS: dht is required')
    this.dht = opts.dht
    // Keep the configured bind request separate from the effective port.
    // After a `port: 0` listen, `this.port` is materialized for callers while
    // a later start still asks the kernel for a fresh atomic allocation.
    this._bindPort = opts.port ?? DEFAULT_PORT
    this.port = this._bindPort
    this.host = opts.host || '0.0.0.0'
    this.maxConnections = opts.maxConnections || 256
    // When the pipe sits behind a TLS-terminating reverse proxy (the
    // supported deploy: Caddy → 127.0.0.1:8766), every connection's socket
    // IP is the proxy's, collapsing per-IP rate limiting into ONE global
    // bucket. With trustProxy on, the rate limiter (and the salted event
    // hash) key on the first X-Forwarded-For hop instead — reusing core's
    // clientIpFromRequest so the XFF parsing matches the rest of the relay.
    // This is still content-neutral: it reads a transport header for
    // metering identity, never the Noise-encrypted payload.
    this.trustProxy = opts.trustProxy || false
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
      staleAfterMs: rl.staleAfterMs || DEFAULT_STALE_AFTER_MS,
      pendingTtlMs: rl.pendingTtlMs || DEFAULT_PENDING_RESERVATION_TTL_MS
    }

    // Content-neutral prod bounds. Everything here is expressed in frame
    // lengths / buffer sizes / timings — never payload contents.
    const ka = opts.keepalive || {}
    this.keepalive = {
      // WS-level ping/pong liveness. Catches half-open TCP (peer vanished
      // without FIN) that neither the upstream protocol heartbeat nor an
      // idle timer would see. 0/false disables.
      intervalMs: ka.intervalMs === 0 || ka.intervalMs === false ? 0 : (ka.intervalMs || DEFAULT_KEEPALIVE_INTERVAL_MS),
      // A legit dht-relay client sends its protocol handshake right after
      // the socket opens. A connection that has NEVER produced an inbound
      // frame after this window is a slot-squatter — upstream will never
      // reap it (its failsafe only arms once a frame arrives). 0 disables.
      firstFrameTimeoutMs: ka.firstFrameTimeoutMs === 0 ? 0 : (ka.firstFrameTimeoutMs || DEFAULT_FIRST_FRAME_TIMEOUT_MS),
      // Optional absolute session ceiling (ms). Default off: legit browser
      // sessions are long-lived; operators can bound them for paid tiers.
      maxSessionMs: ka.maxSessionMs || 0
    }
    const flow = opts.flow || {}
    this.flow = {
      // Single WS frame cap, enforced by ws itself at the parser (the ws
      // default is 100 MiB — far beyond any dht-relay protocol frame).
      maxPayloadBytes: flow.maxPayloadBytes || DEFAULT_MAX_PAYLOAD_BYTES,
      // Egress ceiling: upstream's Stream._write never checks
      // socket.bufferedAmount, so a slow reader otherwise buffers without
      // bound. Sustained (two supervisor ticks) excess → terminate.
      maxBufferedBytes: flow.maxBufferedBytes || DEFAULT_MAX_BUFFERED_BYTES,
      // Optional per-connection ingress byte-rate cap (bytes/sec, sliding
      // 1s window, lengths only). Default off — bandwidth policy is an
      // operator/tier decision; the knob exists so paid pipes can meter.
      maxRxBytesPerSec: flow.maxRxBytesPerSec || 0
    }

    this.server = null
    // Serialize lifecycle calls so `running === false` cannot let concurrent
    // starts overwrite `this.server` and leak the first listener. Stops also
    // cancel every start requested before them; a later start remains queued
    // after that stop and is allowed to bind normally.
    this._lifecycleTail = Promise.resolve()
    this._lifecycleSequence = 0
    this._cancelStartThrough = 0
    // Map<socket, conn record> — see _newConn for the record shape.
    this.connections = new Map()
    this.running = false
    this._totalConnectionsServed = 0
    this._totalRateLimited = 0
    this._totalReaped = 0
    this._totalBytesIn = 0
    this._totalBytesOut = 0
    // Map<ip, { tokens, lastRefill, concurrent, pendingStamps, lastSeen }>
    // `concurrent` counts BOTH matured connections and in-flight upgrade
    // reservations; `pendingStamps` tracks the reservation timestamps so a
    // client that passes verifyClient but never completes the upgrade
    // (aborted socket) is released by the sweeper after pendingTtlMs
    // instead of leaking its slot until restart.
    this._ipBuckets = new Map()
    this._cleanupTimer = null
    this._supervisorTimer = null
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
  // On success, reserves a concurrency slot for the in-flight upgrade and
  // stamps it in `pendingStamps` — the stamp is consumed when the upgrade
  // matures into a 'connection' event, or expired by the sweeper after
  // pendingTtlMs if the client aborted between verifyClient and upgrade
  // (previously that abort leaked the slot until restart).
  _checkRateLimit (ip) {
    const now = Date.now()
    const cap = this.rateLimit.connectionsPerMinutePerIp
    const window = this.rateLimit.windowMs
    let bucket = this._ipBuckets.get(ip)
    if (!bucket) {
      bucket = { tokens: cap, lastRefill: now, concurrent: 0, pendingStamps: [], lastSeen: now }
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
    bucket.pendingStamps.push(now)
    return null
  }

  // The upgrade matured into a real connection: its reservation is no
  // longer pending (concurrent stays reserved for the connection's life).
  _consumePendingReservation (ip) {
    const bucket = this._ipBuckets.get(ip)
    if (bucket && bucket.pendingStamps.length > 0) bucket.pendingStamps.shift()
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
    const pendingTtl = this.rateLimit.pendingTtlMs
    for (const [ip, bucket] of this._ipBuckets) {
      // Expire upgrade reservations whose 'connection' event never came
      // (client aborted mid-upgrade) — release their concurrency slots.
      while (bucket.pendingStamps.length > 0 && (now - bucket.pendingStamps[0]) > pendingTtl) {
        bucket.pendingStamps.shift()
        bucket.concurrent = Math.max(0, bucket.concurrent - 1)
      }
      if (bucket.concurrent === 0 && (now - bucket.lastSeen) > stale) {
        this._ipBuckets.delete(ip)
      }
    }
  }

  start () {
    const sequence = ++this._lifecycleSequence
    return this._enqueueLifecycle(() => this._start(sequence))
  }

  _enqueueLifecycle (operation) {
    const result = this._lifecycleTail.then(operation)
    // A failed bind must reject its caller without poisoning later stop/start
    // requests. The internal tail recovers only for lifecycle serialization.
    this._lifecycleTail = result.catch(() => {})
    return result
  }

  async _start (sequence) {
    if (this.running || sequence <= this._cancelStartThrough) return

    const server = new WebSocketServer({
      port: this._bindPort,
      host: this.host,
      perMessageDeflate: false, // dht-relay carries its own framed binary
      // Single-frame ceiling, enforced by the ws parser before any payload
      // is buffered whole. The ws default is 100 MiB — no dht-relay
      // protocol frame is anywhere near that; oversized frames are a
      // memory-DoS vector, not legitimate traffic.
      maxPayload: this.flow.maxPayloadBytes,
      // Reject rate-limited clients at HTTP upgrade time (before the WS
      // upgrade completes) so the client sees an HTTP error rather than an
      // open-then-close cycle. The connection-event handler still enforces
      // the global maxConnections cap.
      verifyClient: (info, cb) => {
        const ip = clientIpFromRequest(info.req, this.trustProxy)
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
    this.server = server

    try {
      await new Promise((resolve, reject) => {
        server.on('listening', resolve)
        server.on('error', reject)
      })
    } catch (err) {
      if (this.server === server) this.server = null
      throw err
    }

    // stop() can be requested while the kernel bind is pending. It marks this
    // sequence cancelled immediately, then waits in the lifecycle queue. Close
    // the just-materialized listener before either promise resolves so stop()
    // can never return with an untracked live server.
    if (sequence <= this._cancelStartThrough) {
      await new Promise((resolve) => server.close(() => resolve()))
      if (this.server === server) this.server = null
      return
    }

    // Preserve the effective port in events/stats and give callers a safe
    // address for connecting when they requested an ephemeral port.
    const address = server.address()
    if (address && typeof address === 'object') this.port = address.port

    server.on('connection', (socket, req) => {
      // MUST match the verifyClient key exactly (same trustProxy/XFF
      // derivation) or the reservation consume + slot release would target
      // a different bucket than the one verifyClient reserved.
      const ip = clientIpFromRequest(req, this.trustProxy)
      // The verifyClient reservation matured into a live connection.
      this._consumePendingReservation(ip)

      if (this.connections.size >= this.maxConnections) {
        // Rate-limit already accepted us in verifyClient; release the
        // concurrency slot we reserved before refusing on the global cap.
        this._releaseConnection(ip)
        socket.close(1013, 'DHT_RELAY_AT_CAPACITY')
        return
      }

      // External-safe info payload: salted-hash prefix instead of raw IP.
      // Raw IP stays in the in-process _ipBuckets Map for rate-limiting.
      // See threat model in the file header.
      const info = this._safeInfo(ip, req.socket.remotePort)

      // Per-connection supervision record. Everything in here is
      // content-neutral: lengths, sizes, and timestamps only.
      const now = Date.now()
      const conn = {
        ip,
        info,
        connectedAt: now,
        firstFrameAt: null, // set on the first inbound frame of any kind
        wsAlive: true, // WS ping/pong liveness flag (supervisor pattern)
        overBuffered: false, // egress backpressure strike (two-tick rule)
        rxWindowStart: now,
        rxWindowBytes: 0,
        bytesIn: 0,
        bytesOut: 0
      }
      this.connections.set(socket, conn)
      this._totalConnectionsServed++

      // Ingress accounting + optional rate ceiling. `ws` fans 'message'
      // out to every listener, so this observes alongside the dht-relay
      // Stream's own handler without consuming anything. Frame LENGTH
      // only — payload bytes are Noise ciphertext and stay untouched.
      socket.on('message', (data) => {
        const len = byteLength(data)
        conn.bytesIn += len
        this._totalBytesIn += len
        if (conn.firstFrameAt === null) conn.firstFrameAt = Date.now()
        if (this.flow.maxRxBytesPerSec > 0) {
          const t = Date.now()
          if (t - conn.rxWindowStart >= 1000) {
            conn.rxWindowStart = t
            conn.rxWindowBytes = 0
          }
          conn.rxWindowBytes += len
          if (conn.rxWindowBytes > this.flow.maxRxBytesPerSec) {
            this._reap(socket, conn, 'rx-rate', 1008, 'DHT_RELAY_RX_RATE')
          }
        }
      })

      // Egress accounting: wrap send() so every byte the relay pipes back
      // out is counted. Length only, same neutrality rule.
      const rawSend = socket.send.bind(socket)
      socket.send = (data, ...args) => {
        const len = byteLength(data)
        conn.bytesOut += len
        this._totalBytesOut += len
        return rawSend(data, ...args)
      }

      // WS-level pong → alive. Browsers answer WS pings automatically
      // (RFC 6455), so this works even for a protocol-idle client.
      socket.on('pong', () => { conn.wsAlive = true })

      // Attach error/close handlers BEFORE the relay() handoff so nothing
      // the upstream does in between can emit into the void.
      socket.on('close', () => {
        this.connections.delete(socket)
        this._releaseConnection(ip)
        this.emit('client-disconnected', info)
      })

      socket.on('error', (err) => {
        this.emit('client-error', { error: scrubError(err), info })
      })

      // Hand the socket off to dht-relay. It speaks its own framed
      // protocol over the WebSocket and proxies DHT operations to our
      // local HyperDHT instance.
      try {
        // relay() returns a Promise that settles on the client handshake.
        // Upstream currently never rejects it, but this transport must not
        // depend on an experimental library's rejection discipline: any
        // async failure is contained to THIS connection (scrubbed event +
        // close), never an unhandledRejection that could crash the pipe.
        Promise.resolve(relay(this.dht, new Stream(false, socket))).catch((err) => {
          this.emit('relay-error', { error: scrubError(err), info })
          this._reap(socket, conn, 'relay-error', 1011, 'DHT_RELAY_FAILED')
        })
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

      this.emit('client-connected', info)
    })

    this._cleanupTimer = setInterval(
      () => this._cleanupStaleBuckets(),
      this.rateLimit.cleanupIntervalMs
    )
    if (this._cleanupTimer.unref) this._cleanupTimer.unref()

    // Connection supervisor: one shared timer sweeps every connection for
    // liveness + bounds (no per-connection timers). Runs at the keepalive
    // cadence; all checks are content-neutral.
    if (this.keepalive.intervalMs > 0) {
      this._supervisorTimer = setInterval(() => this._superviseConnections(), this.keepalive.intervalMs)
      if (this._supervisorTimer.unref) this._supervisorTimer.unref()
    }

    this.running = true
    this.emit('started', { port: this.port, host: this.host })
  }

  // One sweep of every live connection, at the keepalive cadence. Four
  // content-neutral rules (timings + sizes only, never payload):
  //   1. WS ping/pong: no pong since the last sweep → dead TCP → terminate.
  //   2. First-frame deadline: connected but NEVER sent a frame → slot
  //      squatter that upstream will never reap → close.
  //   3. Egress backpressure: socket.bufferedAmount over the ceiling for
  //      two consecutive sweeps → slow/half-open reader → terminate
  //      (upstream's Stream._write never checks bufferedAmount, so this is
  //      the only bound on relay-side egress buffering).
  //   4. Optional absolute session ceiling.
  _superviseConnections () {
    const now = Date.now()
    for (const [socket, conn] of this.connections) {
      // (1) Missed pong since last sweep → the TCP path is gone.
      if (!conn.wsAlive) {
        this._reap(socket, conn, 'dead-socket', null, null)
        continue
      }

      // (2) Never produced a single inbound frame.
      if (
        this.keepalive.firstFrameTimeoutMs > 0 &&
        conn.firstFrameAt === null &&
        (now - conn.connectedAt) > this.keepalive.firstFrameTimeoutMs
      ) {
        this._reap(socket, conn, 'no-first-frame', 1008, 'DHT_RELAY_NO_HANDSHAKE')
        continue
      }

      // (3) Sustained egress backpressure (two-sweep rule so a transient
      // burst against a healthy reader isn't punished).
      if (socket.bufferedAmount > this.flow.maxBufferedBytes) {
        if (conn.overBuffered) {
          this._reap(socket, conn, 'backpressure', null, null)
          continue
        }
        conn.overBuffered = true
      } else {
        conn.overBuffered = false
      }

      // (4) Optional session ceiling.
      if (this.keepalive.maxSessionMs > 0 && (now - conn.connectedAt) > this.keepalive.maxSessionMs) {
        this._reap(socket, conn, 'session-limit', 1000, 'DHT_RELAY_SESSION_LIMIT')
        continue
      }

      // Arm the next liveness probe. Browsers answer at the protocol
      // level automatically; no client cooperation needed.
      conn.wsAlive = false
      try { socket.ping() } catch (_) {}
    }
  }

  // Close a supervised connection. `code`/`reason` use a graceful close
  // when the peer might still be reading; a null code means the TCP path
  // is presumed dead and we terminate() (no close handshake to wait on).
  // The socket's 'close' handler does the accounting (connections map,
  // per-IP release, client-disconnected event) exactly as for any other
  // close — reaping adds only the counter and the reaped event.
  _reap (socket, conn, reason, code, reasonText) {
    this._totalReaped++
    this.emit('connection-reaped', { reason, info: conn.info })
    try {
      if (code) socket.close(code, reasonText)
      else socket.terminate()
    } catch (_) {
      try { socket.terminate() } catch (_) {}
    }
  }

  stop () {
    this._cancelStartThrough = ++this._lifecycleSequence
    return this._enqueueLifecycle(() => this._stop())
  }

  async _stop () {
    if (!this.running) return
    this.running = false

    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer)
      this._cleanupTimer = null
    }
    if (this._supervisorTimer) {
      clearInterval(this._supervisorTimer)
      this._supervisorTimer = null
    }

    for (const socket of this.connections.keys()) {
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
      // Aggregate-only, like everything else here: totals across all
      // connections since start. Byte counts are frame-length sums —
      // the metering signal a pure-pipe operator bills/budgets on —
      // never broken out per client, never tied to an address.
      totalReaped: this._totalReaped,
      totalBytesIn: this._totalBytesIn,
      totalBytesOut: this._totalBytesOut,
      maxConnections: this.maxConnections,
      rateLimit: {
        connectionsPerMinutePerIp: this.rateLimit.connectionsPerMinutePerIp,
        maxConcurrentPerIp: this.rateLimit.maxConcurrentPerIp
      },
      keepalive: { ...this.keepalive },
      flow: { ...this.flow }
    }
  }
}

// Length of a ws 'message'/send payload without touching its contents.
// ws delivers Buffer | ArrayBuffer | Buffer[] depending on options.
function byteLength (data) {
  if (data == null) return 0
  if (typeof data === 'string') return Buffer.byteLength(data)
  if (Array.isArray(data)) {
    let total = 0
    for (const chunk of data) total += byteLength(chunk)
    return total
  }
  return data.byteLength || data.length || 0
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
