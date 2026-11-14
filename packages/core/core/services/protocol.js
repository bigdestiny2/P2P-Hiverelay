/**
 * Service Protocol
 *
 * Protomux-based RPC protocol for service communication between peers.
 * Each connection gets a service channel where peers can:
 *   - Exchange service catalogs (what services each relay offers)
 *   - Make RPC calls to remote services
 *   - Receive responses and errors
 *
 * Message types:
 *   0: CATALOG   - Advertise available services
 *   1: REQUEST   - RPC call: { id, service, method, params }
 *   2: RESPONSE  - RPC reply: { id, result }
 *   3: ERROR     - RPC error: { id, error }
 *   7: APP_CATALOG - One controller-scheduled legacy fallback (receive-compatible)
 *   8: APP_CATALOG_DELTA - Legacy receive compatibility only
 *
 * Wire format: JSON over Protomux binary channel.
 * Future: switch to compact-encoding for performance.
 */

import b4a from 'b4a'
import Protomux from 'protomux'
import { EventEmitter } from 'events'
import { SERVICES_PROTOCOL_NAME } from '../constants.js'
import { createLengthPrefixedJsonEncoding } from '../protocol/json-message-encoding.js'
import { sanitizeServiceCatalogEntries } from './service-catalog.js'

const MSG_CATALOG = 0
const MSG_REQUEST = 1
const MSG_RESPONSE = 2
const MSG_ERROR = 3

const RESTRICTED_METHODS = new Set([
  'identity.sign',
  'identity.verify',
  'ai.register-model',
  'ai.remove-model'
])

const PUBLIC_SERVICE_ERROR_CODES = new Set([
  'ACCESS_DENIED',
  'METHOD_NOT_FOUND',
  'MIDDLEWARE_REJECTED',
  'RATE_LIMITED',
  'ROUTE_NOT_FOUND',
  'SERVICE_LIMIT',
  'SERVICE_NOT_FOUND',
  'SERVICE_UNAVAILABLE'
])

const MSG_SUBSCRIBE = 4
const MSG_UNSUBSCRIBE = 5
const MSG_EVENT = 6
const MSG_APP_CATALOG = 7
const MSG_APP_CATALOG_DELTA = 8
export const MAX_SERVICE_MESSAGE_BYTES = 1024 * 1024
const MAX_LEGACY_APP_CATALOG_ENTRIES = 128
const MAX_LEGACY_APP_CATALOG_BYTES = 65_536
const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/

const MAX_REMOTE_SUBSCRIBE_TOPICS_PER_MESSAGE = 64
const MAX_REMOTE_SUBSCRIPTIONS_PER_PEER = 128

// Glob metacharacters that PubSub interprets as wildcard patterns. Remote peers
// must only ever subscribe to EXACT topics — a remotely-supplied glob like
// `poker/*` would match every per-table publish (`poker/<tableKey>`) and
// re-create the cross-table firehose. Server-local code that legitimately needs
// glob subscriptions calls router.pubsub.subscribe(...) directly and never
// passes through _handleSubscribe, so it is unaffected by this guard.
const GLOB_METACHARS = /[*?[\]]/

export const serviceMessageEncoding = createLengthPrefixedJsonEncoding({
  maxBytes: MAX_SERVICE_MESSAGE_BYTES,
  malformedError: 'malformed JSON'
})

export class ServiceProtocol extends EventEmitter {
  constructor (registry, opts = {}) {
    super()
    this.registry = registry
    this.router = null // Set by RelayNode after Router creation
    this.channels = new Map() // remotePubkey -> channel
    this._pendingRequests = new Map() // requestId -> { resolve, reject, timer }
    this._peerSubscriptions = new Map() // remotePubkey -> [subId]
    this._scheduleLegacyAppCatalogHook = typeof opts.scheduleLegacyAppCatalog === 'function'
      ? opts.scheduleLegacyAppCatalog
      : null
    this._legacyAppCatalogSchedules = new Map() // remotePubkey -> { active, sent, cancel }
    this._nextId = 1
    this.requestTimeout = 30_000

    // Role-based authorization
    this._peerRoles = new Map() // pubkey hex -> role string
    this._defaultPeerRole = opts.defaultPeerRole || 'anonymous'

    // Per-peer rate limiting
    this._rateLimitMax = opts.rateLimitMax || 100 // requests per window
    this._rateLimitWindow = opts.rateLimitWindow || 60_000 // 1 minute
    this._peerRateState = new Map() // pubkey -> { tokens, lastRefill }
  }

  /**
   * Assign a role to a peer by pubkey.
   */
  setPeerRole (pubkey, role) {
    this._peerRoles.set(pubkey, role)
  }

  /**
   * Check and consume a rate-limit token for a peer.
   * Returns true if the request is allowed, false if rate-limited.
   */
  _checkRateLimit (pubkey) {
    const now = Date.now()
    let state = this._peerRateState.get(pubkey)

    if (!state) {
      state = { tokens: this._rateLimitMax, lastRefill: now }
      this._peerRateState.set(pubkey, state)
    }

    // Refill tokens based on elapsed time
    const elapsed = now - state.lastRefill
    if (elapsed > 0) {
      const refill = Math.floor((elapsed / this._rateLimitWindow) * this._rateLimitMax)
      if (refill > 0) {
        state.tokens = Math.min(this._rateLimitMax, state.tokens + refill)
        state.lastRefill = now
      }
    }

    if (state.tokens <= 0) return false
    state.tokens--
    return true
  }

  /**
   * Set up the service protocol on a Protomux instance.
   */
  attach (mux, remotePubkey) {
    // One authenticated peer owns at most one services channel. A second
    // connection must not replace the exact channel token captured by an
    // already-scheduled legacy fallback.
    if (this.channels.has(remotePubkey)) return null
    mux = Protomux.from(mux)
    const channel = mux.createChannel({
      protocol: SERVICES_PROTOCOL_NAME,
      id: b4a.from('services-v1'),
      onopen: () => this._onOpen(remotePubkey, channel),
      onclose: () => this._onClose(remotePubkey, channel)
    })

    if (!channel) return null

    const msgHandler = channel.addMessage({
      encoding: serviceMessageEncoding,
      onmessage: (msg) => this._onMessage(remotePubkey, msg)
    })

    this.channels.set(remotePubkey, { channel, msgHandler })
    channel.open()

    return channel
  }

  /**
   * Detach and close a channel.
   */
  detach (remotePubkey) {
    const entry = this.channels.get(remotePubkey)
    if (entry) {
      entry.channel.close()
      this._cleanupPeer(remotePubkey, { emitClose: false, channel: entry.channel })
    }
  }

  /**
   * Call a remote service method.
   */
  async request (remotePubkey, service, method, params = {}) {
    const entry = this.channels.get(remotePubkey)
    if (!entry) throw new Error('NO_CHANNEL: not connected to ' + remotePubkey)

    const id = this._nextId++

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pendingRequests.delete(id)
        reject(new Error('REQUEST_TIMEOUT'))
      }, this.requestTimeout)

      this._pendingRequests.set(id, { resolve, reject, timer, remotePubkey })

      entry.msgHandler.send({
        type: MSG_REQUEST,
        id,
        service,
        method,
        params
      })
    })
  }

  /**
   * Broadcast our service catalog to a peer.
   *
   * Uses Protomux cork/uncork so the catalog message + any concurrent
   * sends on this channel coalesce into a single network frame. Cheap
   * throughput win on chatty connections (catalog + app-catalog often
   * fire back-to-back at connection setup).
   */
  sendCatalog (remotePubkey) {
    const entry = this.channels.get(remotePubkey)
    if (!entry) return

    const channel = entry.channel
    if (channel && typeof channel.cork === 'function') channel.cork()
    try {
      entry.msgHandler.send({
        type: MSG_CATALOG,
        services: this.registry.catalog()
      })
    } finally {
      if (channel && typeof channel.uncork === 'function') channel.uncork()
    }
  }

  _sendScheduledAppCatalog (state, prepared) {
    const entry = this.channels.get(state.remotePubkey)
    if (!entry || entry.channel !== state.channel ||
        this._legacyAppCatalogSchedules.get(state.remotePubkey) !== state) return false
    const envelope = prepared && typeof prepared === 'object' && prepared.envelope
      ? prepared.envelope
      : prepared
    let encodedBytes = Number.POSITIVE_INFINITY
    try { encodedBytes = b4a.byteLength(JSON.stringify(envelope), 'utf8') } catch {}
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
        Object.keys(envelope).sort().join(',') !== 'apps,catalogTimestamp,relayPubkey,signature,type' ||
        envelope.type !== MSG_APP_CATALOG || !Array.isArray(envelope.apps) ||
        envelope.apps.length > MAX_LEGACY_APP_CATALOG_ENTRIES ||
        !HEX_64.test(envelope.relayPubkey) ||
        !Number.isSafeInteger(envelope.catalogTimestamp) || envelope.catalogTimestamp < 0 ||
        !HEX_128.test(envelope.signature) ||
        encodedBytes > MAX_LEGACY_APP_CATALOG_BYTES) {
      throw new Error('LEGACY_APP_CATALOG_ENVELOPE_REQUIRED')
    }
    const channel = entry.channel
    if (channel && typeof channel.cork === 'function') channel.cork()
    try {
      entry.msgHandler.send(envelope)
    } finally {
      if (channel && typeof channel.uncork === 'function') channel.uncork()
    }
    return prepared
  }

  /**
   * Sender compatibility shim. RC9 never broadcasts a legacy full catalog or
   * delta on registry churn; capable peers use the dedicated paged channel and
   * incapable peers receive at most the one controller-owned fallback.
   */
  broadcastAppCatalog () {
    return false
  }

  _scheduleLegacyAppCatalog (remotePubkey, channel) {
    if (!this._scheduleLegacyAppCatalogHook) return false
    const entry = this.channels.get(remotePubkey)
    if (!entry || entry.channel !== channel) return false
    const existing = this._legacyAppCatalogSchedules.get(remotePubkey)
    if (existing?.channel === channel) return false
    if (existing) this._cancelLegacyAppCatalog(remotePubkey, existing.channel)

    const state = { remotePubkey, channel, active: true, sent: false, cancel: null }
    this._legacyAppCatalogSchedules.set(remotePubkey, state)
    const send = (prepared) => {
      if (!state.active || state.sent || this._legacyAppCatalogSchedules.get(remotePubkey) !== state) return false
      // The fallback is terminal. Consume its one attempt before handing bytes
      // to Protomux so a send error cannot be retried into a second catalog.
      state.sent = true
      return this._sendScheduledAppCatalog(state, prepared)
    }

    try {
      const scheduled = this._scheduleLegacyAppCatalogHook({ remotePubkey, send })
      const cancel = typeof scheduled === 'function'
        ? scheduled
        : (scheduled && typeof scheduled.cancel === 'function' ? () => scheduled.cancel() : null)
      if (state.active && this._legacyAppCatalogSchedules.get(remotePubkey) === state) {
        state.cancel = cancel
      } else if (cancel) {
        cancel()
      }
      return true
    } catch (error) {
      state.active = false
      if (this._legacyAppCatalogSchedules.get(remotePubkey) === state) {
        this._legacyAppCatalogSchedules.delete(remotePubkey)
      }
      this.emit('legacy-app-catalog-schedule-error', { remotePubkey, error })
      return false
    }
  }

  _cancelLegacyAppCatalog (remotePubkey, channel = null) {
    const state = this._legacyAppCatalogSchedules.get(remotePubkey)
    if (!state || (channel !== null && state.channel !== channel)) return false
    this._legacyAppCatalogSchedules.delete(remotePubkey)
    state.active = false
    if (state.cancel) {
      try {
        state.cancel()
      } catch (error) {
        this.emit('legacy-app-catalog-cancel-error', { remotePubkey, error })
      }
    }
    return true
  }

  _onOpen (remotePubkey, channel) {
    const entry = this.channels.get(remotePubkey)
    if (!entry || entry.channel !== channel) return false
    this.emit('channel-open', { remotePubkey })
    // The service catalog remains eager and bounded by its own sanitizer. App
    // catalogs are scheduled independently by the paged-catalog controller.
    this.sendCatalog(remotePubkey)
    this._scheduleLegacyAppCatalog(remotePubkey, channel)
    return true
  }

  _onClose (remotePubkey, channel) {
    return this._cleanupPeer(remotePubkey, { emitClose: true, channel })
  }

  _cleanupPeer (remotePubkey, opts = {}) {
    const emitClose = opts.emitClose !== false
    const entry = this.channels.get(remotePubkey)
    if (opts.channel && (!entry || entry.channel !== opts.channel)) return false
    this._cancelLegacyAppCatalog(remotePubkey, entry?.channel || null)
    this.channels.delete(remotePubkey)

    // Clean up pub/sub subscriptions for this peer
    const subs = this._peerSubscriptions.get(remotePubkey)
    if (subs && this.router) {
      for (const entry of subs) this.router.pubsub.unsubscribe(entry.subId)
    }
    this._peerSubscriptions.delete(remotePubkey)
    // Clean up rate limiter state for this peer
    this._peerRateState.delete(remotePubkey)
    this._peerRoles.delete(remotePubkey)

    // Reject any pending requests for this peer
    for (const [id, pending] of this._pendingRequests) {
      if (pending.remotePubkey === remotePubkey) {
        clearTimeout(pending.timer)
        this._pendingRequests.delete(id)
        pending.reject(new Error('PEER_DISCONNECTED'))
      }
    }

    if (emitClose) this.emit('channel-close', { remotePubkey })
    return true
  }

  async _onMessage (remotePubkey, msg) {
    switch (msg.type) {
      case MSG_CATALOG:
        {
          const services = sanitizeServiceCatalogEntries(msg.services)
          this.registry.addRemoteServices(remotePubkey, services)
          this.emit('catalog-received', { remotePubkey, services })
        }
        break

      case MSG_REQUEST:
        await this._handleRequest(remotePubkey, msg)
        break

      case MSG_RESPONSE: {
        const pending = this._pendingRequests.get(msg.id)
        if (pending) {
          clearTimeout(pending.timer)
          this._pendingRequests.delete(msg.id)
          pending.resolve(msg.result)
        }
        break
      }

      case MSG_ERROR: {
        const pending2 = this._pendingRequests.get(msg.id)
        if (pending2) {
          clearTimeout(pending2.timer)
          this._pendingRequests.delete(msg.id)
          pending2.reject(new Error(msg.error))
        }
        break
      }

      case MSG_SUBSCRIBE:
        this._handleSubscribe(remotePubkey, msg)
        break

      case MSG_UNSUBSCRIBE:
        this._handleUnsubscribe(remotePubkey, msg)
        break

      case MSG_EVENT:
        this.emit('event', { remotePubkey, topic: msg.topic, data: msg.data })
        break

      case MSG_APP_CATALOG:
        this.emit('app-catalog', {
          remotePubkey,
          apps: Array.isArray(msg.apps) ? msg.apps : [],
          relayPubkey: msg.relayPubkey || null,
          catalogTimestamp: msg.catalogTimestamp || null,
          signature: msg.signature || null
        })
        break

      case MSG_APP_CATALOG_DELTA: {
        const added = Array.isArray(msg.added) ? msg.added : (Array.isArray(msg.apps) ? msg.apps : [])
        const removed = Array.isArray(msg.removed) ? msg.removed : []
        this.emit('app-catalog-delta', {
          remotePubkey,
          added,
          removed,
          relayPubkey: msg.relayPubkey || null,
          catalogTimestamp: msg.catalogTimestamp || null,
          signature: msg.signature || null
        })
        // Relay-to-relay auto-seeding only acts on additions. Removals are
        // client-cache hints and must not remotely unseed operator content.
        this.emit('app-catalog', {
          remotePubkey,
          apps: added,
          relayPubkey: msg.relayPubkey || null,
          catalogTimestamp: msg.catalogTimestamp || null,
          signature: msg.signature || null,
          delta: true,
          removed
        })
        break
      }
    }
  }

  async _handleRequest (remotePubkey, msg) {
    const entry = this.channels.get(remotePubkey)
    if (!entry) return

    // Per-peer rate limiting
    if (!this._checkRateLimit(remotePubkey)) {
      entry.msgHandler.send({
        type: MSG_ERROR,
        id: msg.id,
        error: 'RATE_LIMITED'
      })
      return
    }

    const qualifiedMethod = msg.service + '.' + msg.method
    if (RESTRICTED_METHODS.has(qualifiedMethod)) {
      entry.msgHandler.send({
        type: MSG_ERROR,
        id: msg.id,
        error: 'ACCESS_DENIED: method requires local access'
      })
      return
    }

    // Role-based authorization
    const role = this._peerRoles.get(remotePubkey) || this._defaultPeerRole
    const authenticated = this._peerRoles.has(remotePubkey)

    try {
      let result
      if (this.router) {
        const route = `${msg.service}.${msg.method}`
        result = await this.router.dispatch(route, msg.params, {
          transport: 'p2p',
          remotePubkey,
          caller: 'remote',
          role,
          authenticated
        })
      } else {
        result = await this.registry.handleRequest(
          msg.service,
          msg.method,
          msg.params,
          { remotePubkey, role, authenticated }
        )
      }
      entry.msgHandler.send({
        type: MSG_RESPONSE,
        id: msg.id,
        result
      })
    } catch (err) {
      const error = publicServiceError(err)
      this.emit('request-error', {
        remotePubkey,
        service: typeof msg.service === 'string' ? msg.service : null,
        method: typeof msg.method === 'string' ? msg.method : null,
        error: err && err.message ? err.message : String(err || 'unknown error'),
        publicError: error
      })
      entry.msgHandler.send({
        type: MSG_ERROR,
        id: msg.id,
        error
      })
    }
  }

  /**
   * Handle P2P pub/sub subscription request from a peer.
   */
  _handleSubscribe (remotePubkey, msg) {
    if (!this.router || !msg.topics || !Array.isArray(msg.topics)) return
    const entry = this.channels.get(remotePubkey)
    if (!entry) return

    const subs = this._peerSubscriptions.get(remotePubkey) || []
    const topics = msg.topics.slice(0, MAX_REMOTE_SUBSCRIBE_TOPICS_PER_MESSAGE)
    const seenTopics = new Set(subs.map((entry) => entry.topic))

    for (const topic of topics) {
      if (subs.length >= MAX_REMOTE_SUBSCRIPTIONS_PER_PEER) break
      if (typeof topic !== 'string' || topic.length === 0 || topic.length > 256) continue
      // Remote peers may only subscribe to exact topics. Reject any glob
      // pattern so a peer cannot use `poker/*` (or `*`) to re-create a
      // cross-table firehose over per-key topics.
      if (GLOB_METACHARS.test(topic)) continue
      if (seenTopics.has(topic)) continue
      let subId
      try {
        subId = this.router.pubsub.subscribe(topic, (t, data) => {
          if (entry.channel.opened) {
            entry.msgHandler.send({ type: MSG_EVENT, topic: t, data })
          }
        }, { remotePubkey, ttl: 60 * 60 * 1000 })
      } catch (err) {
        this.emit('subscription-error', {
          remotePubkey,
          topic,
          error: err && err.message ? err.message : String(err)
        })
        continue
      }
      subs.push({ subId, topic })
      seenTopics.add(topic)
    }

    this._peerSubscriptions.set(remotePubkey, subs)
  }

  /**
   * Handle P2P pub/sub unsubscription request from a peer.
   */
  _handleUnsubscribe (remotePubkey, msg) {
    if (!this.router || !msg.topics) return
    const subs = this._peerSubscriptions.get(remotePubkey) || []
    const topicsToRemove = new Set(msg.topics)

    // Only unsubscribe from requested topics, retain the rest
    const remaining = []
    for (const entry of subs) {
      if (topicsToRemove.has(entry.topic)) {
        this.router.pubsub.unsubscribe(entry.subId)
      } else {
        remaining.push(entry)
      }
    }

    if (remaining.length > 0) {
      this._peerSubscriptions.set(remotePubkey, remaining)
    } else {
      this._peerSubscriptions.delete(remotePubkey)
    }
  }

  /**
   * Cleanup all channels and pending requests.
   */
  destroy () {
    for (const [, pending] of this._pendingRequests) {
      clearTimeout(pending.timer)
      pending.reject(new Error('PROTOCOL_DESTROYED'))
    }
    this._pendingRequests.clear()

    for (const [pubkey] of Array.from(this.channels)) {
      this.detach(pubkey)
    }

    for (const pubkey of Array.from(this._legacyAppCatalogSchedules.keys())) {
      this._cancelLegacyAppCatalog(pubkey)
    }

    // detach() closes known channels. These clears handle any defensive state
    // left by tests/fakes or peers that disappeared before a close callback.
    if (this._peerSubscriptions.size && this.router) {
      for (const subs of this._peerSubscriptions.values()) {
        for (const entry of subs) this.router.pubsub.unsubscribe(entry.subId)
      }
    }
    this._peerSubscriptions.clear()
    this._peerRateState.clear()
    this._peerRoles.clear()
  }
}

function publicServiceError (err) {
  const message = err && err.message ? err.message : ''
  const code = message.split(':', 1)[0]
  if (PUBLIC_SERVICE_ERROR_CODES.has(code)) return message
  return 'SERVICE_ERROR'
}
