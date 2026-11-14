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
  keepAliveMs: 5000,
  maxPendingPairings: 1024,
  maxPendingPerSession: 16,
  maxActiveLinks: 2048,
  maxActiveLinksPerSession: 16,
  pairingTimeoutMs: 30_000,
  idleTimeoutMs: 60_000,
  maxLinkLifetimeMs: 3_600_000,
  stopTimeoutMs: 5000
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
    for (const name of ['maxPendingPairings', 'maxPendingPerSession', 'maxActiveLinks', 'maxActiveLinksPerSession']) {
      this[name] = positiveInteger(opts[name] ?? PEAR_BLIND_RELAY_DEFAULTS[name], name, 1_000_000)
    }
    for (const name of ['pairingTimeoutMs', 'idleTimeoutMs', 'maxLinkLifetimeMs', 'stopTimeoutMs']) {
      this[name] = positiveInteger(opts[name] ?? PEAR_BLIND_RELAY_DEFAULTS[name], name, 86_400_000)
    }
    this._RelayServer = opts.RelayServer || BlindRelayServer
    this.relay = null
    this.server = null
    this.publicKey = null
    this.running = false
    this._sessions = new Set()
    this._sockets = new Set()
    this._streams = new Set()
    this._linksByStream = new Map()
    this._streamsBySession = new Map()
    this._timers = new Map()
    this._pendingTimers = new Map()
    this._refused = 0
    this._pairingsRefused = 0
    this._expired = { pending: 0, links: 0, idle: 0 }
    this._previousStats = copyStats(null, 0)
    this._startPromise = null
    this._stopPromise = null
    this._stopping = false
    this._creating = null
  }

  start () {
    if (this._stopPromise) return this._stopPromise.then(() => this.start())
    if (this._startPromise) return this._startPromise
    if (this.running) return Promise.resolve(this)
    if (this.server || this.relay) return Promise.reject(new Error('Previous Pear blind relay cleanup incomplete'))
    this._startPromise = this._start().finally(() => { this._startPromise = null })
    return this._startPromise
  }

  async _start () {
    this.relay = new this._RelayServer({ createStream: (opts) => this._createStream(opts) })
    // blind-relay 1.6.1 does not expose a pair-admission hook. This adapter
    // guards its Protomux message callback before any upstream allocation.
    // The exact package/source contract is checked by the real-library tests.
    if (!(this.relay._pairing instanceof Map) || !(this.relay._activePairingRefs instanceof Map)) {
      this.relay = null
      throw new Error('Unsupported blind-relay admission contract')
    }
    this.server = this.dht.createServer((socket) => this._accept(socket))
    try {
      await this.server.listen(this.keyPair)
      this.publicKey = b4a.from(this.server.publicKey || this.keyPair.publicKey)
      if (!this._stopping) {
        this.running = true
        this.emit('started', { publicKey: hypercoreId.encode(this.publicKey) })
      }
      return this
    } catch (error) {
      if (!this._stopping) await this._closeOwners()
      throw error
    }
  }

  _createStream (opts) {
    const stream = this.dht.createRawStream({ ...opts, framed: true })
    this._streams.add(stream)
    this._creating?.push(stream)
    stream.on('error', () => {})
    stream.once('close', () => {
      const link = this._linksByStream.get(stream)
      this._linksByStream.delete(stream)
      if (link) {
        const owned = this._streamsBySession.get(link.session)
        owned?.delete(stream)
        if (!owned?.size) this._streamsBySession.delete(link.session)
        link.destroyPair()
      }
      this._streams.delete(stream)
      this._clearTimer(stream)
    })
    this._timer(stream, this.maxLinkLifetimeMs, () => {
      this._expired.links++
      stream.destroy()
    })
    return stream
  }

  _timer (owner, ms, callback) {
    this._clearTimer(owner)
    const timer = setTimeout(() => {
      this._timers.delete(owner)
      callback()
    }, ms)
    timer.unref?.()
    this._timers.set(owner, timer)
  }

  _clearTimer (owner) {
    clearTimeout(this._timers.get(owner))
    this._timers.delete(owner)
  }

  _forgetPending (key) {
    const owner = this._pendingTimers.get(key)
    if (!owner) return
    this._clearTimer(owner)
    this._pendingTimers.delete(key)
  }

  _closeSession (session, socket) {
    session?.destroy()
    socket.destroy()
  }

  _refusePair (session, socket, reason) {
    this._pairingsRefused++
    this._closeSession(session, socket)
    this.emit('refused', { reason })
  }

  _pair (session, socket, receive, message) {
    if (!this.running || session.closed || socket.destroyed) return
    const key = message.token.toString('hex')
    const pending = this.relay._pairing.get(key)
    if (this.relay._activePairingRefs.has(key)) {
      return this._refusePair(session, socket, 'active-token-reuse')
    }
    // Repeated same-side messages do not create work in the pinned library.
    if (pending?.links[+message.isInitiator]) return
    const peer = pending?.links[+!message.isInitiator]?.session
    if (peer === session) return this._refusePair(session, socket, 'self-pair')
    if (!pending && (this.relay._pairing.size >= this.maxPendingPairings || session._pairing.size >= this.maxPendingPerSession)) {
      return this._refusePair(session, socket, 'pending-limit')
    }
    if (peer && (this._streams.size + 2 > this.maxActiveLinks ||
      (this._streamsBySession.get(session)?.size || 0) >= this.maxActiveLinksPerSession ||
      (this._streamsBySession.get(peer)?.size || 0) >= this.maxActiveLinksPerSession)) {
      return this._refusePair(session, socket, 'active-link-limit')
    }
    const creating = []
    this._creating = creating
    try {
      receive(message)
    } catch (error) {
      // An upstream raw-stream creation/activation error must not strand the
      // first half of a pair or either control connection.
      for (const stream of creating) stream.destroy()
      if (peer) this._closeSession(peer, peer.stream)
      this._refusePair(session, socket, 'pairing-error')
      return
    } finally {
      this._creating = null
    }
    if (peer) this._forgetPending(key)
    else if (this.relay._pairing.has(key)) {
      const owner = { session, key }
      this._pendingTimers.set(key, owner)
      this._timer(owner, this.pairingTimeoutMs, () => {
        this._pendingTimers.delete(key)
        this._expired.pending++
        // The native protocol has no negative reply. Closing the timed-out
        // owner's channel makes failure observable to the unmodified client.
        this._closeSession(session, socket)
      })
    }
  }

  _accept (socket) {
    socket.on('error', () => {})
    // The ceiling belongs to live sockets, including closing channels.
    if (!this.running || this._sockets.size >= this.maxSessions) {
      this._refused++
      socket.destroy()
      this.emit('refused', { reason: this.running ? 'session-limit' : 'not-running' })
      return
    }
    this._sockets.add(socket)
    let session
    socket.once('close', () => {
      this._sockets.delete(socket)
      session?.destroy()
    })
    try {
      if (typeof socket.setKeepAlive === 'function') socket.setKeepAlive(this.keepAliveMs)
      session = this.relay.accept(socket, { id: socket.remotePublicKey })
      session.on('error', () => {})
      this._sessions.add(session)
      const forget = () => {
        this._sessions.delete(session)
        this._clearTimer(session)
        for (const [key, owner] of this._pendingTimers) {
          if (owner.session === session) this._forgetPending(key)
        }
        socket.destroy()
      }
      session.once('close', forget)
      session.once('destroy', forget)
      if (!(session._pairing instanceof Set) || !(session._links instanceof Map) ||
          typeof session._pair?.onmessage !== 'function' || typeof session._unpair?.onmessage !== 'function' ||
          typeof session._channel?.onclose !== 'function') {
        throw new Error('Unsupported blind-relay session admission contract')
      }
      const closeChannel = session._channel.onclose
      session._channel.onclose = (...args) => {
        for (const link of session._links.values()) link.destroyPair()
        return closeChannel(...args)
      }
      session.on('pair', (isInitiator, token, stream) => {
        this._linksByStream.set(stream, session._links.get(token.toString('hex')))
        let owned = this._streamsBySession.get(session)
        if (!owned) this._streamsBySession.set(session, (owned = new Set()))
        owned.add(stream)
      })
      const receivePair = session._pair.onmessage
      const receiveUnpair = session._unpair.onmessage
      session._pair.onmessage = (message) => this._pair(session, socket, receivePair, message)
      session._unpair.onmessage = (message) => {
        if (session.closed || socket.destroyed) return
        const key = message.token.toString('hex')
        if (!session._pairing.has(key) && !session._links.has(key)) return
        receiveUnpair(message)
        this._forgetPending(key)
      }
      const expireIdle = () => {
        if (session.closed || socket.destroyed) return
        if (!session._pairing.size && !session._links.size) {
          this._expired.idle++
          this._closeSession(session, socket)
        } else this._timer(session, this.idleTimeoutMs, expireIdle)
      }
      this._timer(session, this.idleTimeoutMs, expireIdle)
      this.emit('session', { active: this._sessions.size })
    } catch (error) {
      this._refused++
      this._closeSession(session, socket)
      this.emit('refused', { reason: 'session-contract' })
    }
  }

  getStats () {
    const stats = copyStats(this.relay?.stats, this._refused)
    for (const [group, keys] of Object.entries({ sessions: ['accepted', 'opened', 'closed'], pairings: ['requested', 'matched', 'cancelled'], streams: ['opened', 'closed', 'errors'] })) {
      for (const key of keys) stats[group][key] += this._previousStats[group][key]
    }
    stats.sessions.active = this._sessions.size
    stats.streams.active = this._streams.size
    stats.pairings.refused = this._pairingsRefused
    return {
      running: this.running,
      stopping: this._stopping,
      publicKey: this.publicKey ? hypercoreId.encode(this.publicKey) : null,
      ...Object.fromEntries(Object.keys(PEAR_BLIND_RELAY_DEFAULTS).map(key => [key, this[key]])),
      ...stats,
      sockets: { active: this._sockets.size },
      expired: { ...this._expired }
    }
  }

  stop () {
    if (this._stopPromise) return this._stopPromise
    if (!this.server && !this.relay && !this._startPromise) return Promise.resolve()
    this._stopping = true
    this.running = false
    const starting = this._startPromise?.catch(() => {})
    this._stopPromise = this._closeOwners(starting).then(() => {
      this._stopping = false
      this.emit('stopped')
    }).finally(() => {
      this._stopPromise = null
    })
    return this._stopPromise
  }

  async _closeOwners (starting) {
    for (const timer of this._timers.values()) clearTimeout(timer)
    this._timers.clear()
    this._pendingTimers.clear()
    const closeEvents = []
    for (const owner of [...this._sockets, ...this._streams]) {
      if (!owner.closed) closeEvents.push(new Promise(resolve => owner.once('close', resolve)))
    }
    for (const session of this._sessions) session.destroy()
    for (const socket of this._sockets) socket.destroy()
    for (const stream of this._streams) stream.destroy()
    let timeout
    try {
      await Promise.race([
        Promise.all([...closeEvents, starting, this.server?.close(), this.relay?.close()]),
        new Promise((resolve, reject) => {
          timeout = setTimeout(() => reject(new Error('Pear blind relay shutdown deadline exceeded')), this.stopTimeoutMs)
        })
      ])
      // Retain owners and truthful telemetry on timeout so a retry can finish
      // cleanup; clearing these references early used to hide leaked work.
      this._previousStats = this.getStats()
      this.server = null
      this.relay = null
      this.publicKey = null
    } finally {
      clearTimeout(timeout)
    }
  }
}
