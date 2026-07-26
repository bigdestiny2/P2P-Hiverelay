/**
 * Network Discovery Service
 *
 * Joins the Hyperswarm DHT on the well-known relay discovery topic as a client,
 * discovers all live relay nodes, polls their APIs for stats, and maintains
 * a live registry of the network.
 *
 * No central registry — fully DHT-driven. Any relay that announces on the
 * discovery topic is automatically found and tracked.
 */

import Hyperswarm from 'hyperswarm'
import b4a from 'b4a'
import { EventEmitter } from 'events'
import http from 'http'
import Protomux from 'protomux'
import c from 'compact-encoding'
import { createRequire } from 'module'
import { RELAY_DISCOVERY_TOPIC } from './constants.js'

const POLL_INTERVAL = 30_000 // poll each relay every 30s
const STALE_THRESHOLD = 5 * 60_000 // remove relays not seen for 5 min
const API_TIMEOUT = 8000
const MAX_API_OVERVIEW_BYTES = 256 * 1024
const MAX_META_BYTES = 2048
const HOLESAIL_CLIENT_MAX = 20
const HOLESAIL_CLIENT_TTL = 5 * 60_000 // destroy clients unused for 5 min
const META_PROTOCOL = 'hiverelay-meta'
const START_FLUSH_TIMEOUT = 5000
const HOLESAIL_Z32_KEY = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/

function normalizeHolesailKey (key) {
  if (typeof key !== 'string') return null
  let value = key.trim()
  if (value.startsWith('hs://0000')) value = value.slice('hs://0000'.length)
  if (!HOLESAIL_Z32_KEY.test(value)) return null
  return value
}

export class NetworkDiscovery extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.swarm = opts.swarm || null // can share the relay node's swarm
    this._ownSwarm = false
    this._bootstrap = opts.bootstrap || undefined
    this._relays = new Map() // pubkey hex -> { host, port, apiPort, holesailKey, holesailConnected, lastSeen, data }
    this._connections = new Map() // pubkey hex -> conn
    this._retiringConnections = new Set()
    this._pollInterval = null
    this._cleanupInterval = null
    this._localHolesailKey = null
    this._holesailClients = new Map() // holesailKey -> { client, localPort, lastUsed }
    this._holesailAllocationTail = Promise.resolve()
    this._holesailCleanupInterval = null
    this._discoveryHandle = null
    this._onSwarmConnection = null
    this._starting = null
    this._startAbort = null
    this._teardownPromise = null
    this._stopping = null
    this._acceptingWork = false
    this._lifecycleEpoch = 0
    this._holesailClientFactory = typeof opts.holesailClientFactory === 'function'
      ? opts.holesailClientFactory
      : null
    this._holesailConnectTimeout = Number.isSafeInteger(opts.holesailConnectTimeout) && opts.holesailConnectTimeout > 0
      ? opts.holesailConnectTimeout
      : 15_000
    this._startFlushTimeout = Number.isSafeInteger(opts.startFlushTimeout) && opts.startFlushTimeout > 0
      ? opts.startFlushTimeout
      : START_FLUSH_TIMEOUT
    this._stopTimeout = Number.isSafeInteger(opts.stopTimeout) && opts.stopTimeout > 0
      ? opts.stopTimeout
      : START_FLUSH_TIMEOUT
    this._discoveryDestroying = null
    this._swarmDestroying = null
    this.running = false
  }

  setLocalHolesailKey (key) {
    this._localHolesailKey = normalizeHolesailKey(key)
  }

  start () {
    if (this.running) return Promise.resolve()
    if (this._starting) return this._starting
    const abort = new AbortController()
    const operation = this._startLifecycle(abort)
    const starting = operation.finally(() => {
      if (this._starting === starting) this._starting = null
      if (this._startAbort === abort) this._startAbort = null
    })
    this._starting = starting
    return starting
  }

  async _startLifecycle (abort) {
    if (this._stopping) await this._stopping
    if (this._teardownPromise) await this._teardownPromise
    if (this.running) return
    if (this._hasTeardownOwnedResources()) await this._teardown()
    this._startAbort = abort
    this._acceptingWork = true
    this._lifecycleEpoch++
    try {
      return await this._start(abort.signal)
    } catch (startCause) {
      try {
        await this._teardown()
      } catch (teardownCause) {
        const failure = new Error('network discovery startup teardown did not settle')
        failure.code = 'NETWORK_DISCOVERY_START_TEARDOWN_FAILED'
        failure.startCause = startCause
        failure.teardownCause = teardownCause
        throw failure
      }
      throw startCause
    }
  }

  _hasTeardownOwnedResources () {
    return !!(
      this._discoveryHandle ||
      this._onSwarmConnection ||
      this._holesailClients.size > 0 ||
      this._connections.size > 0 ||
      this._retiringConnections.size > 0 ||
      (this._ownSwarm && this.swarm)
    )
  }

  _assertWorkEpoch (epoch) {
    if (this._acceptingWork && this._lifecycleEpoch === epoch) return
    const err = new Error('network discovery is not accepting work')
    err.code = 'NETWORK_DISCOVERY_STOPPING'
    throw err
  }

  async _start (signal) {
    // If no swarm provided, create our own as a client
    if (!this.swarm) {
      this.swarm = new Hyperswarm({ bootstrap: this._bootstrap })
      this._ownSwarm = true
    }

    // Join discovery topic as client to find relay nodes
    this._discoveryHandle = this.swarm.join(RELAY_DISCOVERY_TOPIC, { server: false, client: true })

    this._onSwarmConnection = (conn, info) => this._onConnection(conn, info)
    this.swarm.on('connection', this._onSwarmConnection)

    await this._flushForStart(signal)
    if (signal.aborted) throw abortError()

    // Poll known relays for stats
    this._pollInterval = setInterval(() => {
      this._pollAll().catch(() => {})
    }, POLL_INTERVAL)
    if (this._pollInterval.unref) this._pollInterval.unref()

    // Clean up stale relays
    this._cleanupInterval = setInterval(() => {
      this._cleanup()
    }, STALE_THRESHOLD)
    if (this._cleanupInterval.unref) this._cleanupInterval.unref()

    // Clean up idle holesail clients
    this._holesailCleanupInterval = setInterval(() => {
      this._cleanupHolesailClients().catch((err) => this.emit('holesail-cleanup-error', err))
    }, HOLESAIL_CLIENT_TTL)
    if (this._holesailCleanupInterval.unref) this._holesailCleanupInterval.unref()

    this.running = true
    this.emit('started')
  }

  async _flushForStart (signal) {
    let timer = null
    let onAbort = null
    try {
      await Promise.race([
        Promise.resolve().then(() => this.swarm.flush()),
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            const err = new Error('network discovery startup flush timed out')
            err.code = 'NETWORK_DISCOVERY_START_TIMEOUT'
            reject(err)
          }, this._startFlushTimeout)
        }),
        new Promise((_resolve, reject) => {
          onAbort = () => reject(abortError())
          if (signal.aborted) onAbort()
          else signal.addEventListener('abort', onAbort, { once: true })
        })
      ])
    } finally {
      if (timer) clearTimeout(timer)
      if (onAbort) signal.removeEventListener('abort', onAbort)
    }
  }

  _onConnection (conn, info) {
    if (!this._acceptingWork) {
      try { conn.destroy() } catch (_) {}
      return
    }
    const epoch = this._lifecycleEpoch
    const pubkey = info.publicKey
      ? b4a.toString(info.publicKey, 'hex')
      : (conn.remotePublicKey ? b4a.toString(conn.remotePublicKey, 'hex') : null)

    if (!pubkey) return

    // Extract remote address from the raw stream
    const remoteHost = conn.rawStream
      ? conn.rawStream.remoteHost || conn.rawStream.remoteAddress
      : null
    const remotePort = conn.rawStream
      ? conn.rawStream.remotePort
      : null

    // Track this relay
    if (!this._relays.has(pubkey)) {
      this._relays.set(pubkey, {
        publicKey: pubkey,
        host: remoteHost,
        port: remotePort,
        apiPort: null,
        lastSeen: Date.now(),
        data: null,
        online: true
      })
      this.emit('relay-discovered', { publicKey: pubkey, host: remoteHost })
    } else {
      const relay = this._relays.get(pubkey)
      relay.lastSeen = Date.now()
      relay.online = true
      if (remoteHost) relay.host = remoteHost
    }

    const previous = this._connections.get(pubkey)
    if (previous && previous !== conn) this._retireConnection(previous)
    this._connections.set(pubkey, conn)

    // Exchange holesail metadata via Protomux channel
    this._exchangeMetadata(conn, pubkey, epoch)

    // Try to discover the API port by probing common ports
    if (remoteHost) {
      this._probeApiPort(pubkey, remoteHost, conn, epoch).catch(() => {})
    }

    conn.on('close', () => {
      if (this._connections.get(pubkey) === conn) this._connections.delete(pubkey)
    })

    conn.on('error', () => {
      if (this._connections.get(pubkey) === conn) this._connections.delete(pubkey)
    })
  }

  _retireConnection (conn) {
    const owner = { conn, promise: null }
    this._retiringConnections.add(owner)
    this._startRetiringConnectionDestroy(owner)
    return owner
  }

  _startRetiringConnectionDestroy (owner) {
    if (owner.promise) return owner.promise
    const operation = Promise.resolve().then(() => owner.conn.destroy())
    owner.promise = operation
    operation.then(
      () => {
        this._retiringConnections.delete(owner)
        if (owner.promise === operation) owner.promise = null
      },
      () => { if (owner.promise === operation) owner.promise = null }
    )
    return operation
  }

  async _destroyRetiringConnection (owner) {
    await withTimeout(
      this._startRetiringConnectionDestroy(owner),
      this._stopTimeout,
      'network discovery connection destroy'
    )
  }

  /**
   * Exchange holesail keys (and future metadata) over a Protomux channel
   */
  _exchangeMetadata (conn, pubkey, epoch) {
    try {
      const mux = Protomux.from(conn)

      const channel = mux.createChannel({
        protocol: META_PROTOCOL,
        id: null,
        handshake: c.raw,
        onopen: () => {
          // Send our holesail key if we have one
          if (this._localHolesailKey) {
            metaMsg.send(b4a.from(JSON.stringify({ holesailKey: this._localHolesailKey })))
          }
        },
        onclose: () => {}
      })

      const metaMsg = channel.addMessage({
        encoding: c.raw,
        onmessage: (buf) => this._handleMetadataFrame(pubkey, buf, conn, epoch)
      })

      channel.open(b4a.alloc(0))
    } catch {}
  }

  _handleMetadataFrame (pubkey, buf, conn = null, epoch = this._lifecycleEpoch) {
    if (conn && (!this._acceptingWork || this._lifecycleEpoch !== epoch ||
        this._connections.get(pubkey) !== conn)) return
    if (!buf || buf.byteLength > MAX_META_BYTES) return

    let meta
    try {
      meta = JSON.parse(b4a.toString(buf))
    } catch {
      return
    }
    if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return

    const holesailKey = normalizeHolesailKey(meta.holesailKey)
    if (!holesailKey) return

    const relay = this._relays.get(pubkey)
    if (!relay) return

    relay.holesailKey = holesailKey
    this.emit('relay-holesail-key', { publicKey: pubkey, holesailKey })
  }

  /**
   * Probe common API ports on a discovered relay to find its HTTP API
   */
  async _probeApiPort (pubkey, host, conn = null, epoch = this._lifecycleEpoch) {
    const relay = this._relays.get(pubkey)
    if (!relay) return
    const active = () => this._acceptingWork && this._lifecycleEpoch === epoch &&
      (!conn || this._connections.get(pubkey) === conn) && this._relays.get(pubkey) === relay

    const ports = [9100, 9101, 9102, 9103, 9104, 9105]

    for (const port of ports) {
      if (!active()) return
      try {
        const data = await this._fetchApi(host, port)
        if (!active()) return
        if (data && data.publicKey) {
          if (data.publicKey === pubkey) {
            // Exact match — this is the relay we're probing
            relay.apiPort = port
            relay.data = data
            relay.lastSeen = Date.now()
            this.emit('relay-api-found', { publicKey: pubkey, host, port })
          } else if (!this._relays.has(data.publicKey) || !this._relays.get(data.publicKey).apiPort) {
            // Different relay on the same host (multi-instance) — register it too
            const otherPubkey = data.publicKey
            if (!this._relays.has(otherPubkey)) {
              this._relays.set(otherPubkey, {
                publicKey: otherPubkey,
                host,
                port: null,
                apiPort: port,
                lastSeen: Date.now(),
                data,
                online: true
              })
              this.emit('relay-discovered', { publicKey: otherPubkey, host })
              this.emit('relay-api-found', { publicKey: otherPubkey, host, port })
            } else {
              const other = this._relays.get(otherPubkey)
              other.apiPort = port
              other.data = data
              other.host = host
              other.lastSeen = Date.now()
              other.online = true
            }
          }
          // Keep probing other ports on this host to find all instances
          continue
        }
      } catch {
        continue
      }
    }

    // If direct probe failed, try holesail tunnel as fallback
    if (!active()) return
    if (!relay.apiPort && relay.holesailKey) {
      try {
        const data = await this._fetchViaHolesail(relay.holesailKey)
        if (!active()) return
        if (data && data.publicKey) {
          relay.data = data
          relay.apiPort = 'holesail'
          relay.holesailConnected = true
          relay.lastSeen = Date.now()
          // Capture holesail key from overview if not already set
          const holesailKey = normalizeHolesailKey(data.holesailKey)
          if (holesailKey && !relay.holesailKey) {
            relay.holesailKey = holesailKey
          }
          this.emit('relay-api-found', { publicKey: pubkey, holesailKey: relay.holesailKey })
        }
      } catch {}
    }
  }

  /**
   * Fetch /api/overview from a relay's HTTP API
   */
  _fetchApi (host, port) {
    return new Promise((resolve, reject) => {
      let settled = false
      const finish = (fn, value) => {
        if (settled) return
        settled = true
        fn(value)
      }
      const req = http.get(
        `http://${host}:${port}/api/overview`,
        { timeout: API_TIMEOUT },
        (res) => {
          if (res.statusCode !== 200) {
            res.resume()
            return finish(reject, new Error('Unexpected status: ' + res.statusCode))
          }
          const contentLength = Number(res.headers['content-length'])
          if (Number.isFinite(contentLength) && contentLength > MAX_API_OVERVIEW_BYTES) {
            res.resume()
            return finish(reject, new Error('Response too large'))
          }
          let data = ''
          let bytes = 0
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            bytes += Buffer.byteLength(chunk, 'utf8')
            if (bytes > MAX_API_OVERVIEW_BYTES) {
              res.destroy()
              req.destroy()
              finish(reject, new Error('Response too large'))
              return
            }
            data += chunk
          })
          res.on('end', () => {
            if (settled) return
            let parsed
            try {
              parsed = JSON.parse(data)
            } catch {
              finish(reject, new Error('Invalid JSON'))
              return
            }
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              finish(reject, new Error('Invalid JSON'))
              return
            }
            finish(resolve, parsed)
          })
        }
      )

      req.on('timeout', () => {
        req.destroy()
        finish(reject, new Error('Timeout'))
      })

      req.on('error', err => finish(reject, err))
    })
  }

  /**
   * Fetch /api/overview via holesail tunnel
   * Creates a local proxy client if one doesn't exist for this key
   */
  async _fetchViaHolesail (holesailKey) {
    holesailKey = normalizeHolesailKey(holesailKey)
    if (!holesailKey) throw new Error('Invalid holesail key')
    const epoch = this._lifecycleEpoch
    this._assertWorkEpoch(epoch)

    const entry = await this._queueHolesailAllocation(async () => {
      this._assertWorkEpoch(epoch)
      let current = this._holesailClients.get(holesailKey)
      if (current?.destroying) {
        await withTimeout(current.destroying, this._stopTimeout, `holesail client ${holesailKey} destroy`)
        this._assertWorkEpoch(epoch)
        current = this._holesailClients.get(holesailKey)
      }
      if (current && current.client && current.client.state !== 'destroyed') return current

      // Evict oldest client if at capacity
      if (this._holesailClients.size >= HOLESAIL_CLIENT_MAX) {
        let oldestKey = null
        let oldestTime = Infinity
        for (const [k, v] of this._holesailClients) {
          if (v.lastUsed < oldestTime) {
            oldestTime = v.lastUsed
            oldestKey = k
          }
        }
        if (oldestKey) {
          await this._destroyHolesailEntry(oldestKey, this._holesailClients.get(oldestKey))
          this._assertWorkEpoch(epoch)
        }
      }

      const localPort = 30000 + Math.floor(Math.random() * 30000)
      let client = null
      if (this._holesailClientFactory) {
        client = this._holesailClientFactory({ key: holesailKey })
      } else {
        const require = createRequire(import.meta.url)
        const HolesailClient = require('holesail-client')
        client = new HolesailClient({ key: holesailKey })
      }
      this._assertWorkEpoch(epoch)
      current = {
        client,
        localPort,
        lastUsed: Date.now(),
        connecting: null,
        connectTimer: null,
        rejectConnect: null,
        destroying: null,
        destroyed: false
      }
      this._holesailClients.set(holesailKey, current)
      const connecting = new Promise((resolve, reject) => {
        current.rejectConnect = reject
        current.connectTimer = setTimeout(() => reject(new Error('holesail connect timeout')), this._holesailConnectTimeout)
        client.connect({ port: localPort, host: '127.0.0.1' }, () => {
          if (current.connectTimer) clearTimeout(current.connectTimer)
          current.connectTimer = null
          current.rejectConnect = null
          resolve()
        })
      })
      current.connecting = connecting
      return current
    })

    if (entry.connecting) {
      try {
        await entry.connecting
        entry.connecting = null
        this._assertWorkEpoch(epoch)
      } catch (startCause) {
        entry.connecting = null
        try {
          await this._destroyHolesailEntry(holesailKey, entry)
        } catch (teardownCause) {
          const failure = new Error('holesail client startup teardown did not settle')
          failure.code = 'HOLESAIL_START_TEARDOWN_FAILED'
          failure.startCause = startCause
          failure.teardownCause = teardownCause
          throw failure
        }
        throw startCause
      }
    }

    this._assertWorkEpoch(epoch)
    entry.lastUsed = Date.now()
    return this._fetchApi('127.0.0.1', entry.localPort)
  }

  _queueHolesailAllocation (run) {
    const operation = this._holesailAllocationTail.catch(() => {}).then(run)
    this._holesailAllocationTail = operation.catch(() => {})
    return operation
  }

  /**
   * Destroy holesail clients that haven't been used recently
   */
  async _cleanupHolesailClients () {
    const now = Date.now()
    for (const [key, entry] of this._holesailClients) {
      if (now - entry.lastUsed > HOLESAIL_CLIENT_TTL) {
        await this._destroyHolesailEntry(key, entry)
      }
    }
  }

  async _destroyHolesailEntry (key, entry) {
    if (!entry) return
    if (entry.destroyed) return
    if (entry.connectTimer) {
      clearTimeout(entry.connectTimer)
      entry.connectTimer = null
    }
    if (entry.rejectConnect) {
      entry.rejectConnect(new Error('holesail client destroyed during connect'))
      entry.rejectConnect = null
    }
    if (!entry.destroying) {
      const operation = Promise.resolve().then(() => entry.client.destroy())
      entry.destroying = operation
      operation.then(
        () => {
          if (this._holesailClients.get(key) === entry) this._holesailClients.delete(key)
          entry.destroyed = true
          if (entry.destroying === operation) entry.destroying = null
        },
        () => { if (entry.destroying === operation) entry.destroying = null }
      )
    }
    await withTimeout(entry.destroying, this._stopTimeout, `holesail client ${key} destroy`)
  }

  /**
   * Poll all known relays for fresh stats
   */
  async _pollAll () {
    const epoch = this._lifecycleEpoch
    if (!this._acceptingWork) return
    const active = (relay, pubkey) => this._acceptingWork && this._lifecycleEpoch === epoch &&
      this._relays.get(pubkey) === relay
    const polls = []

    for (const [pubkey, relay] of this._relays) {
      let pollPromise

      if (relay.holesailConnected && relay.holesailKey) {
        // Use holesail tunnel for relays without direct access
        pollPromise = this._fetchViaHolesail(relay.holesailKey)
      } else if (relay.host && relay.apiPort && relay.apiPort !== 'holesail') {
        pollPromise = this._fetchApi(relay.host, relay.apiPort)
      } else if (relay.holesailKey) {
        // No direct apiPort yet, try holesail
        pollPromise = this._fetchViaHolesail(relay.holesailKey)
      } else {
        continue
      }

      const poll = pollPromise
        .then((data) => {
          if (!active(relay, pubkey)) return
          relay.data = data
          relay.lastSeen = Date.now()
          relay.online = true
          // Pick up holesail key from overview response
          const holesailKey = normalizeHolesailKey(data.holesailKey)
          if (holesailKey && !relay.holesailKey) {
            relay.holesailKey = holesailKey
          }
        })
        .catch(() => {
          if (!active(relay, pubkey)) return
          const age = Date.now() - relay.lastSeen
          if (age > STALE_THRESHOLD) {
            relay.online = false
          }
        })

      polls.push(poll)
    }

    await Promise.allSettled(polls)
    if (!this._acceptingWork || this._lifecycleEpoch !== epoch) return
    this.emit('poll-complete', { relayCount: this._relays.size })
  }

  /**
   * Remove relays that haven't been seen in a long time
   */
  _cleanup () {
    const now = Date.now()
    for (const [pubkey, relay] of this._relays) {
      if (now - relay.lastSeen > STALE_THRESHOLD * 3) {
        this._relays.delete(pubkey)
        this.emit('relay-removed', { publicKey: pubkey })
      }
    }
  }

  /**
   * Get the full network state — used by /api/network endpoint
   */
  getNetworkState () {
    const relays = []
    let totalConnections = 0
    let totalStorage = 0
    let totalStorageMax = 0
    let onlineCount = 0

    for (const [pubkey, relay] of this._relays) {
      const d = relay.data || {}
      const entry = {
        publicKey: pubkey,
        name: 'Relay ' + pubkey.slice(0, 8),
        host: relay.host,
        apiPort: relay.apiPort,
        region: d.region || null,
        online: relay.online,
        lastSeen: relay.lastSeen,
        uptime: d.uptime || null,
        connections: d.connections || 0,
        seededApps: d.seededApps || 0,
        storage: d.storage || null,
        relay: d.relay || null,
        seeder: d.seeder || null,
        memory: d.memory || null,
        tor: d.tor || null,
        holesailKey: relay.holesailKey || null,
        holesailConnected: relay.holesailConnected || false,
        errors: d.errors || 0
      }

      if (relay.online) onlineCount++
      totalConnections += entry.connections
      if (d.storage) {
        totalStorage += d.storage.used || 0
        totalStorageMax += d.storage.max || 0
      }

      relays.push(entry)
    }

    // Sort: online first, then by uptime
    relays.sort((a, b) => {
      if (a.online && !b.online) return -1
      if (!a.online && b.online) return 1
      const aUp = a.uptime ? a.uptime.ms : 0
      const bUp = b.uptime ? b.uptime.ms : 0
      return bUp - aUp
    })

    return {
      timestamp: Date.now(),
      summary: {
        totalRelays: relays.length,
        onlineRelays: onlineCount,
        totalConnections,
        totalStorage,
        totalStorageMax
      },
      relays
    }
  }

  stop () {
    if (this._stopping) return this._stopping
    const operation = this._stop()
    const stopping = operation.finally(() => {
      if (this._stopping === stopping) this._stopping = null
    })
    this._stopping = stopping
    return stopping
  }

  async _stop () {
    this._acceptingWork = false
    this._lifecycleEpoch++
    // Cancel first. Awaiting a stalled startup flush before signalling stop
    // made teardown unbounded and allowed a late start to install timers.
    if (this._startAbort) this._startAbort.abort()
    const starting = this._starting
    if (starting) try { await starting } catch (_) {}
    await this._teardown()
  }

  async _teardown () {
    if (this._teardownPromise) return this._teardownPromise
    const operation = this._teardownResources()
    this._teardownPromise = operation
    try {
      return await operation
    } finally {
      if (this._teardownPromise === operation) this._teardownPromise = null
    }
  }

  async _teardownResources () {
    this._acceptingWork = false
    this.running = false

    if (this._pollInterval) {
      clearInterval(this._pollInterval)
      this._pollInterval = null
    }
    if (this._cleanupInterval) {
      clearInterval(this._cleanupInterval)
      this._cleanupInterval = null
    }
    if (this._holesailCleanupInterval) {
      clearInterval(this._holesailCleanupInterval)
      this._holesailCleanupInterval = null
    }

    let firstError = null
    try { await this._holesailAllocationTail } catch (err) { firstError = err }
    for (const [key, entry] of [...this._holesailClients]) {
      try { await this._destroyHolesailEntry(key, entry) } catch (err) {
        if (!firstError) firstError = err
      }
    }

    if (this._onSwarmConnection && this.swarm) {
      this.swarm.removeListener('connection', this._onSwarmConnection)
      this._onSwarmConnection = null
    }

    for (const owner of [...this._retiringConnections]) {
      try {
        await this._destroyRetiringConnection(owner)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }

    // Move current-map connections into explicit retirement ownership before
    // destroy, so a synchronous close event cannot erase retry authority.
    for (const [key, conn] of [...this._connections]) {
      try {
        if (this._connections.get(key) === conn) this._connections.delete(key)
        const owner = this._retireConnection(conn)
        await this._destroyRetiringConnection(owner)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }

    if (firstError) throw firstError

    await this._destroyDiscoverySession()

    await this._destroyOwnedSwarm()

    this.emit('stopped')
  }

  async _destroyDiscoverySession () {
    const handle = this._discoveryHandle
    if (!handle) return
    if (!this._discoveryDestroying) {
      const operation = Promise.resolve().then(() => handle.destroy())
      this._discoveryDestroying = operation
      operation.then(
        () => {
          if (this._discoveryHandle === handle) this._discoveryHandle = null
          if (this._discoveryDestroying === operation) this._discoveryDestroying = null
        },
        () => {
          if (this._discoveryDestroying === operation) this._discoveryDestroying = null
        }
      )
    }
    await withTimeout(this._discoveryDestroying, this._stopTimeout, 'network discovery handle destroy')
  }

  async _destroyOwnedSwarm () {
    if (!this._ownSwarm || !this.swarm) return
    const swarm = this.swarm
    if (!this._swarmDestroying) {
      const operation = Promise.resolve().then(() => swarm.destroy())
      this._swarmDestroying = operation
      operation.then(
        () => {
          if (this.swarm === swarm) this.swarm = null
          if (this._swarmDestroying === operation) this._swarmDestroying = null
        },
        () => {
          if (this._swarmDestroying === operation) this._swarmDestroying = null
        }
      )
    }
    await withTimeout(this._swarmDestroying, this._stopTimeout, 'network discovery swarm destroy')
  }
}

function abortError () {
  const err = new Error('network discovery startup aborted')
  err.name = 'AbortError'
  err.code = 'ABORT_ERR'
  return err
}

async function withTimeout (operation, timeoutMs, label) {
  let timer = null
  try {
    return await Promise.race([
      operation,
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => {
          const err = new Error(label + ' timed out')
          err.code = 'NETWORK_DISCOVERY_STOP_TIMEOUT'
          reject(err)
        }, timeoutMs)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}
