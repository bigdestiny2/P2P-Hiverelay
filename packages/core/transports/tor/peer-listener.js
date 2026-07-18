/**
 * Onion peer-vport listener (`hiverelay.onion/1` — peer protocol plane).
 *
 * Accepts raw TCP connections forwarded from the tor daemon's peer vport
 * (19737) and upgrades each to a Noise XK stream (@hyperswarm/secret-stream —
 * the same primitive Hyperswarm connections are built on), so the relay's
 * peer protocol — Protomux channels for custody, replication, RPC — runs
 * over the onion service unchanged. Clients dial the onion peer vport as
 * Noise XK initiators with the relay's stable pubkey (from the signed
 * capability doc) as remotePublicKey; the responder side learns the client
 * identity from the handshake, and the relay's normal connection handler
 * re-validates authorization on it (ONION-INV-006: an auth key grants
 * reachability, never service authorization).
 *
 * Loopback-only by default: the endpoint must never be clearnet-exposed —
 * the onion service is the sole ingress (location hiding).
 */

import { EventEmitter } from 'events'
import net from 'net'
import NoiseSecretStream from '@hyperswarm/secret-stream'

export const DEFAULT_PEER_VPORT = 19737

export function isLoopbackHost (host) {
  if (host === '::1') return true
  if (net.isIPv4(host)) return host.startsWith('127.')
  return false
}

export class OnionPeerListener extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (!opts.keyPair || !opts.keyPair.secretKey) {
      throw new Error('OnionPeerListener requires the relay keyPair — it is the Noise XK responder identity')
    }
    this.keyPair = opts.keyPair
    this.host = opts.host || '127.0.0.1'
    if (!isLoopbackHost(this.host)) {
      throw new Error('OnionPeerListener host must be a numeric loopback address')
    }
    this.port = opts.port === undefined ? DEFAULT_PEER_VPORT : opts.port // 0 → ephemeral (tests)
    this.maxConnections = opts.maxConnections || null
    this.running = false
    this._server = null
    this._streams = new Set()
  }

  start () {
    if (this.running) return Promise.resolve()
    return new Promise((resolve, reject) => {
      const server = net.createServer((socket) => this._onSocket(socket))
      server.on('error', (err) => {
        if (this.running) this.emit('listener-error', err)
        else reject(new Error(`onion peer listener bind failed at ${this.host}:${this.port}: ${err.message}`))
      })
      server.listen(this.port, this.host, () => {
        this._server = server
        this.port = server.address().port // materialize ephemeral binds
        this.running = true
        this.emit('listening', { host: this.host, port: this.port })
        resolve()
      })
    })
  }

  _onSocket (socket) {
    if (this.maxConnections && this._streams.size >= this.maxConnections) {
      socket.destroy()
      return
    }
    socket.on('error', () => {})
    const stream = new NoiseSecretStream(false, socket, { keyPair: this.keyPair, pattern: 'XK' })
    stream.on('error', () => {}) // handshake failures and circuit drops are transport noise
    this._streams.add(stream)
    stream.on('close', () => this._streams.delete(stream))
    stream.on('handshake', () => {
      this.emit('connection', stream, { type: 'tor', isOnion: true })
    })
  }

  async stop () {
    if (!this.running) return
    this.running = false
    for (const stream of this._streams) { try { stream.destroy() } catch {} }
    this._streams.clear()
    const server = this._server
    this._server = null
    if (server) await new Promise((resolve) => server.close(() => resolve()))
  }

  getInfo () {
    return {
      running: this.running,
      host: this.host,
      port: this.port,
      activeConnections: this._streams.size
    }
  }
}
