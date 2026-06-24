/**
 * Gateway Server — data-plane HTTP server for Hyperdrive content serving.
 *
 * Separated from the control-plane RelayAPI so heavy file traffic cannot
 * starve management endpoints. Serves:
 *   - GET /v1/hyper/:key/*  — HTTP gateway for Hyperdrive content
 *   - GET /catalog.json     — public content catalog (typed)
 *   - GET /health           — simple liveness check for load balancers
 *
 * No auth required — all routes are public, read-only. Privacy tiers are
 * still enforced by the HyperGateway itself.
 *
 * Defaults to 0.0.0.0:9200 (the control plane defaults to 127.0.0.1:9100).
 * When `gatewayPort === apiPort` the server is NOT started — the RelayAPI
 * handles the gateway routes inline (backward compatibility).
 */

import { createServer } from 'http'
import { EventEmitter } from 'events'
import { HyperGateway } from '../../gateway/hyper-gateway.js'
import { buildGatewayCatalogPayload } from './api-catalog-read.js'
import { writeJson } from './api-response.js'

const DEFAULT_GATEWAY_PORT = 9200

// Gateway rate limit — higher than the control plane (file serving is bursty).
const RATE_LIMIT_WINDOW_MS = 60_000
const RATE_LIMIT_MAX = 600 // 10 req/sec sustained per IP

export class GatewayServer extends EventEmitter {
  constructor (relayNode, opts = {}) {
    super()
    this.node = relayNode
    this.port = opts.gatewayPort ?? DEFAULT_GATEWAY_PORT
    this.host = opts.gatewayHost || '0.0.0.0'
    this.corsOrigins = opts.corsOrigins || []
    this.trustProxy = opts.trustProxy || false
    this.server = null
    this._gateway = opts.gateway || new HyperGateway(relayNode, { store: relayNode.store })
    this._ownsGateway = !opts.gateway
    this._rateLimits = new Map()
    this._rateLimitCleanup = null
    this._activeSockets = new Set()
  }

  get gateway () {
    return this._gateway
  }

  async start () {
    this.server = createServer((req, res) => this._handle(req, res))
    this.server.on('connection', (socket) => {
      this._activeSockets.add(socket)
      socket.on('close', () => this._activeSockets.delete(socket))
    })

    this._rateLimitCleanup = setInterval(() => {
      const now = Date.now()
      for (const [ip, entry] of this._rateLimits) {
        if (now > entry.resetAt) this._rateLimits.delete(ip)
      }
    }, 120_000)
    if (this._rateLimitCleanup.unref) this._rateLimitCleanup.unref()

    return new Promise((resolve, reject) => {
      this.server.on('error', reject)
      this.server.listen(this.port, this.host, () => {
        this.emit('started', { port: this.port })
        resolve()
      })
    })
  }

  async stop () {
    if (this._ownsGateway && this._gateway && typeof this._gateway.close === 'function') {
      try { await this._gateway.close() } catch (err) {
        this.emit('gateway-close-error', { error: err && err.message ? err.message : String(err) })
      }
    }

    if (this._rateLimitCleanup) {
      clearInterval(this._rateLimitCleanup)
      this._rateLimitCleanup = null
    }
    this._rateLimits.clear()

    if (this.server) {
      await new Promise(resolve => {
        if (typeof this.server.closeIdleConnections === 'function') {
          try { this.server.closeIdleConnections() } catch (_) {}
        }
        if (typeof this.server.closeAllConnections === 'function') {
          try { this.server.closeAllConnections() } catch (_) {}
          setImmediate(() => {
            try { this.server?.closeAllConnections() } catch (_) {}
          })
        }
        for (const socket of this._activeSockets) {
          try { socket.destroy() } catch (_) {}
        }
        this.server.close(() => resolve())
      })
      this.server = null
    }
    this._activeSockets.clear()
  }

  _getClientIP (req) {
    if (this.trustProxy) {
      const xff = req.headers['x-forwarded-for']
      if (xff) {
        const first = xff.split(',')[0].trim()
        if (first) return first
      }
      const realIP = req.headers['x-real-ip']
      if (realIP) return realIP.trim()
    }
    return req.socket.remoteAddress || ''
  }

  _checkRateLimit (ip) {
    const now = Date.now()
    let entry = this._rateLimits.get(ip)
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS }
      this._rateLimits.set(ip, entry)
    }
    entry.count++
    return entry.count <= RATE_LIMIT_MAX
  }

  _getAllowedOrigin (origin) {
    if (!origin) return null
    if (this.corsOrigins.includes('*')) return '*'
    if (this.corsOrigins.includes(origin)) return origin
    return null
  }

  async _handle (req, res) {
    const ip = this._getClientIP(req) || '127.0.0.1'
    const requestOrigin = req.headers.origin

    const allowedOrigin = this._getAllowedOrigin(requestOrigin)
    if (allowedOrigin) res.setHeader('Access-Control-Allow-Origin', allowedOrigin)
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
      res.writeHead(204)
      res.end()
      return
    }

    if (!this._checkRateLimit(ip)) {
      writeJson(res, { error: 'Too many requests' }, 429, { 'Retry-After': '60' })
      return
    }

    let path = ''
    try {
      path = new URL(req.url, `http://0.0.0.0:${this.port}`).pathname
    } catch {
      writeJson(res, { error: 'Invalid URL' }, 400)
      return
    }

    try {
      // Hyperdrive gateway — the primary data-plane route
      if (path.startsWith('/v1/hyper/')) {
        return this._gateway.handle(req, res)
      }

      // Public catalog — safe to serve on the data plane
      if (req.method === 'GET' && path === '/catalog.json') {
        return this._serveCatalog(req, res)
      }

      // Simple liveness check for load balancers
      if (req.method === 'GET' && (path === '/health' || path === '/')) {
        writeJson(res, { ok: true, service: 'gateway' })
        return
      }

      writeJson(res, { error: 'Not found' }, 404)
    } catch (err) {
      this.emit('error', err)
      writeJson(res, { error: 'Internal error' }, 500)
    }
  }

  _serveCatalog (req, res) {
    const url = new URL(req.url, `http://0.0.0.0:${this.port}`)
    const result = buildGatewayCatalogPayload({ node: this.node, url })
    if (!result.ok) {
      writeJson(res, result.payload, result.status || 400)
      return
    }

    writeJson(res, result.payload, 200, { 'Cache-Control': 'public, max-age=30' })
  }
}
