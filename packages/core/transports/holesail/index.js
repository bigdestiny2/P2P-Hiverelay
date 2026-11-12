/**
 * Holesail API Tunnel Transport
 *
 * Exposes the relay's HTTP API through the Hyperswarm DHT via Holesail,
 * making the API reachable without port forwarding. Designed for
 * home-network relay operators behind NAT.
 *
 * The transport creates a HolesailServer that tunnels the local API port
 * (default 9100) through the DHT. Remote nodes connect using the
 * holesail connection key via HolesailClient.
 *
 * Key persistence: The holesail seed is derived deterministically from
 * the relay's Hyperswarm keypair, so the connection key survives restarts.
 */

import { EventEmitter } from 'events'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)

export class HolesailTransport extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.apiPort = opts.apiPort || 9100
    this.apiHost = opts.host || '127.0.0.1'
    this.seed = opts.seed || null // 32-byte hex string for deterministic keys
    this.connectionKey = null
    this.running = false
    this._server = null
    this._starting = null
    this._serverStart = null
    this._stopping = null
    this._startAttempt = null
  }

  start () {
    if (this._stopping) return this._stopping.then(() => this.start())
    if (this.running) return Promise.resolve()
    if (this._starting) return this._starting
    if (this._server) return Promise.reject(new Error('Holesail server cleanup is required before restart'))

    const starting = this._start().finally(() => {
      if (this._starting === starting) this._starting = null
    })
    this._starting = starting
    return starting
  }

  async _start () {
    const HolesailServer = require('holesail-server')
    const server = new HolesailServer()
    this._server = server

    // Generate deterministic keypair from seed
    if (this.seed) {
      server.generateKeyPair(this.seed)
    }

    const attempt = { cancelled: false, cancel: null, ready: false, completed: false }
    this._startAttempt = attempt
    let timer = null
    try {
      await new Promise((resolve, reject) => {
        attempt.cancel = () => {
          const err = new Error('Holesail server start aborted')
          err.name = 'AbortError'
          err.code = 'ABORT_ERR'
          reject(err)
        }
        timer = setTimeout(() => {
          reject(new Error('Holesail server start timed out after 30s'))
        }, 30000)

        this._serverStart = Promise.resolve(server.start(
          {
            port: this.apiPort,
            host: this.apiHost,
            seed: this.seed
          },
          () => {
            attempt.ready = true
            if (!attempt.cancelled && attempt.completed) resolve()
          }
        ))
        this._serverStart.then(() => {
          attempt.completed = true
          if (!attempt.cancelled && attempt.ready) resolve()
        }, reject)
      })
      if (attempt.cancelled) {
        const err = new Error('Holesail server start aborted')
        err.name = 'AbortError'
        err.code = 'ABORT_ERR'
        throw err
      }
    } finally {
      clearTimeout(timer)
      if (this._startAttempt === attempt) this._startAttempt = null
    }

    this.connectionKey = server.key
    this.running = true

    this.emit('started', { connectionKey: this.connectionKey })
  }

  stop () {
    if (this._stopping) return this._stopping
    if (!this._server && !this._starting) return Promise.resolve()
    this.running = false
    const attempt = this._startAttempt
    if (attempt) {
      attempt.cancelled = true
      attempt.cancel()
    }

    const stopping = this._stop(this._server, this._starting).finally(() => {
      if (this._stopping === stopping) this._stopping = null
    })
    this._stopping = stopping
    return stopping
  }

  async _stop (server, starting) {
    // Cancellation settles startup readiness; only the real destruction
    // operation releases the owner. A failure leaves it available for retry.
    const startSettled = starting ? starting.catch(() => {}) : Promise.resolve()
    // Upstream start can allocate its refresh timer after the listen callback.
    // Preserve and settle that exact operation before the single destruction.
    if (this._serverStart) await this._serverStart.catch(() => {})
    if (server) await server.destroy()
    await startSettled
    if (this._server === server) {
      this._server = null
      this._serverStart = null
    }

    this.connectionKey = null
    this.emit('stopped')
  }

  getInfo () {
    return {
      running: this.running,
      connectionKey: this.connectionKey,
      apiPort: this.apiPort
    }
  }
}
