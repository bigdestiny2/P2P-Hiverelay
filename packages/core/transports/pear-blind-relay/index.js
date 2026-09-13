/**
 * Pear 3.4-compatible blind relay transport.
 *
 * This is the native Holepunch blind-relay wire primitive, not HiveRelay's
 * storage/custody service. It forwards framed UDX streams in memory and is
 * deliberately disabled until an operator opts in.
 */

import { EventEmitter } from 'events'
import blindRelay from 'blind-relay'
import b4a from 'b4a'
import hypercoreId from 'hypercore-id-encoding'

const { Server: BlindRelayServer } = blindRelay

export const PEAR_BLIND_RELAY_DEFAULTS = Object.freeze({
  maxSessions: 1024,
  keepAliveMs: 5000
})

function positiveInteger (value, name, max) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new TypeError(`${name} must be an integer in [1, ${max}]`)
  }
  return value
}

function copyStats (stats, refused) {
  return {
    sessions: {
      accepted: stats?.sessions?.accepted || 0,
      opened: stats?.sessions?.opened || 0,
      closed: stats?.sessions?.closed || 0,
      active: stats?.sessions?.active || 0,
      refused
    },
    pairings: {
      requested: stats?.pairings?.requested || 0,
      matched: stats?.pairings?.matched || 0,
      cancelled: stats?.pairings?.cancelled || 0,
      pending: stats?.pairings?.pending || 0,
      active: stats?.pairings?.active || 0
    },
    streams: {
      opened: stats?.streams?.opened || 0,
      closed: stats?.streams?.closed || 0,
      errors: stats?.streams?.errors || 0,
      active: stats?.streams?.active || 0
    }
  }
}

export class PearBlindRelayTransport extends EventEmitter {
  constructor (opts = {}) {
    super()
    if (!opts.dht) throw new TypeError('PearBlindRelayTransport: dht is required')
    if (!opts.keyPair?.publicKey || !opts.keyPair?.secretKey) {
      throw new TypeError('PearBlindRelayTransport: keyPair is required')
    }

    this.dht = opts.dht
    this.keyPair = opts.keyPair
    this.maxSessions = positiveInteger(
      opts.maxSessions ?? PEAR_BLIND_RELAY_DEFAULTS.maxSessions,
      'maxSessions',
      1_000_000
    )
    this.keepAliveMs = positiveInteger(
      opts.keepAliveMs ?? PEAR_BLIND_RELAY_DEFAULTS.keepAliveMs,
      'keepAliveMs',
      86_400_000
    )
    this._RelayServer = opts.RelayServer || BlindRelayServer
    this.relay = null
    this.server = null
    this.publicKey = null
    this.running = false
    this._sessions = new Set()
    this._refused = 0
  }

  async start () {
    if (this.running) return this

    this.relay = new this._RelayServer({
      // Pear v3.4.0 sets framed=true for the raw UDX streams created after a
      // pairing. Keeping this exact is the interoperability boundary.
      createStream: (opts) => this.dht.createRawStream({ ...opts, framed: true })
    })
    this.server = this.dht.createServer((socket) => this._accept(socket))

    try {
      await this.server.listen(this.keyPair)
      this.publicKey = b4a.from(this.server.publicKey || this.keyPair.publicKey)
      this.running = true
      this.emit('started', { publicKey: hypercoreId.encode(this.publicKey) })
      return this
    } catch (error) {
      try { await this.server?.close() } catch (_) {}
      try { await this.relay?.close() } catch (_) {}
      this.server = null
      this.relay = null
      throw error
    }
  }

  _accept (socket) {
    socket.on('error', () => {})
    if (!this.running || this._sessions.size >= this.maxSessions) {
      this._refused++
      socket.destroy()
      this.emit('refused', { reason: this.running ? 'session-limit' : 'not-running' })
      return
    }

    if (typeof socket.setKeepAlive === 'function') socket.setKeepAlive(this.keepAliveMs)
    const session = this.relay.accept(socket, { id: socket.remotePublicKey })
    session.on('error', () => {})
    this._sessions.add(session)
    const forget = () => this._sessions.delete(session)
    session.once('close', forget)
    session.once('destroy', forget)
    this.emit('session', { active: this._sessions.size })
  }

  getStats () {
    return {
      running: this.running,
      publicKey: this.publicKey ? hypercoreId.encode(this.publicKey) : null,
      maxSessions: this.maxSessions,
      keepAliveMs: this.keepAliveMs,
      ...copyStats(this.relay?.stats, this._refused)
    }
  }

  async stop () {
    if (!this.server && !this.relay) return
    this.running = false
    const server = this.server
    const relay = this.relay
    this.server = null
    this.relay = null
    this.publicKey = null
    this._sessions.clear()
    try { await server?.close() } finally { await relay?.close() }
    this.emit('stopped')
  }
}
