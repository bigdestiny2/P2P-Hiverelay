/**
 * Tor Hidden Service Transport v2 (`hiverelay.onion/1` — RA-01b)
 *
 * Provides relay-side location anonymity via a Tor v3 onion service:
 *
 * 1. **Hidden service (inbound):** persistent ED25519-V3 onion service with
 *    multi-vport forwarding, optional restricted discovery (v3 client
 *    authorization), and health-gated readiness. Peers connect without
 *    knowing the relay's real IP. When a `peerListener` (OnionPeerListener)
 *    is attached, the peer vport (19737) is forwarded to it alongside the
 *    read plane, so the Noise/Protomux peer protocol runs over the onion.
 *
 * 2. **SOCKS5 proxy (outbound):** routes outbound connections through Tor
 *    so the relay's IP is hidden from peers it connects to.
 *
 * Backward compatible with v1: when `keyFile` is not set the service is
 * ephemeral (`NEW:BEST`), exactly as before.
 *
 * Verified control-port semantics (M0 spike, 2026-07-17, tor 0.4.9.6):
 * - Persistent keys: `ADD_ONION ED25519-V3:<blob>` restores the same address.
 * - Client auth is declared AT CREATION via repeated
 *   `ClientAuthV3=<base32-x25519-pubkey>`; there is no runtime service-side
 *   roster add — roster changes rebuild the service (DEL_ONION + ADD_ONION,
 *   same key blob, same address).
 * - PoW defense is daemon-wide via SETCONF
 *   (`HiddenServicePoWDefensesEnabled/QueueRate/QueueBurst`); there are no
 *   per-service ADD_ONION PoW kwargs.
 *
 * Requirements: tor >= 0.4.9.5 (floor enforced when minDaemonVersion set),
 * ControlPort + CookieAuthentication (or HashedControlPassword).
 */

import { EventEmitter } from 'events'
import net from 'net'
import { readFile, writeFile, rename, mkdir } from 'fs/promises'
import { dirname } from 'path'
import { SocksClient } from 'socks'
import { Duplex } from 'stream'
import {
  OnionRosterStore,
  generateClientAuthGuardKey,
  isValidClientPub
} from './auth-keys.js'
import { DEFAULT_PEER_VPORT } from './peer-listener.js'

const DEFAULT_SOCKS_HOST = '127.0.0.1'
const DEFAULT_SOCKS_PORT = 9050
const DEFAULT_CONTROL_HOST = '127.0.0.1'
const DEFAULT_CONTROL_PORT = 9051
const TOR_CHECK_TIMEOUT = 5000
const KEY_BLOB_RE = /^ED25519-V3:[A-Za-z0-9+/=]+$/

export const TorHealth = Object.freeze({
  DISABLED: 'disabled',
  STARTING: 'tor-starting',
  KEY_LOADED: 'key-loaded',
  DESCRIPTOR_UPLOADED: 'descriptor-uploaded',
  READY: 'ready',
  DEGRADED: 'degraded'
})

/** Parse and compare tor version strings like "0.4.9.6", "0.4.9.5-alpha-dev". */
export function parseTorVersion (str) {
  const m = String(str).match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/)
  return m ? [+m[1], +m[2], +m[3], +m[4]] : null
}

export function versionAtLeast (version, floor) {
  const v = parseTorVersion(version)
  const f = parseTorVersion(floor)
  if (!v || !f) return false
  for (let i = 0; i < 4; i++) {
    if (v[i] !== f[i]) return v[i] > f[i]
  }
  return true
}

/**
 * Minimal Tor control-port client: serializes commands, routes complete
 * replies to their waiter, and dispatches asynchronous 650 events
 * IMMEDIATELY through a persistent parser — events must never wait for the
 * next command to be readable (the health machine depends on live HS_DESC
 * events arriving between commands; M0 spike finding).
 */
export class TorControl extends EventEmitter {
  constructor ({ host, port }) {
    super()
    this.host = host
    this.port = port
    this.sock = null
    this._queue = Promise.resolve()
    this._pending = null // { resolve, reject, timer, lines: [] }
    this._buf = ''
  }

  connect () {
    return new Promise((resolve, reject) => {
      this.sock = net.createConnection(this.port, this.host)
      const timer = setTimeout(() => {
        this.sock.destroy()
        reject(new Error(`Tor control port not reachable at ${this.host}:${this.port}. Enable it in /etc/tor/torrc: ControlPort ${this.port}`))
      }, TOR_CHECK_TIMEOUT)
      this.sock.on('connect', () => { clearTimeout(timer); resolve() })
      this.sock.on('error', (err) => { clearTimeout(timer); reject(new Error(`Tor control port error: ${err.message}. Enable it in /etc/tor/torrc: ControlPort ${this.port}`)) })
      this.sock.on('data', (chunk) => this._onData(chunk))
      this.sock.on('close', () => {
        if (this._pending) {
          const p = this._pending
          this._pending = null
          clearTimeout(p.timer)
          p.reject(new Error('Tor control socket closed'))
        }
      })
    })
  }

  _onData (chunk) {
    this._buf += chunk.toString()
    for (;;) {
      const idx = this._buf.indexOf('\r\n')
      if (idx === -1) return
      const line = this._buf.slice(0, idx)
      this._buf = this._buf.slice(idx + 2)
      if (line.startsWith('650 ')) { this.emit('event', line.slice(4)); continue }
      if (!this._pending) continue
      this._pending.lines.push(line)
      if (/^\d{3} /.test(line)) {
        const p = this._pending
        this._pending = null
        clearTimeout(p.timer)
        const body = p.lines.join('\n').trim()
        if (/^5\d{2}/m.test(body)) p.reject(new Error(body))
        else p.resolve(body)
      }
    }
  }

  /** Send a command and wait for its reply. Commands are serialized. */
  cmd (command, timeoutMs = 15000) {
    const run = this._queue.then(() => this._send(command, timeoutMs))
    this._queue = run.catch(() => {})
    return run
  }

  _send (command, timeoutMs) {
    return new Promise((resolve, reject) => {
      if (!this.sock || this.sock.destroyed) return reject(new Error('Tor control socket closed'))
      const timer = setTimeout(() => {
        this._pending = null
        reject(new Error(`Tor control command timed out: ${command.split(' ')[0]}`))
      }, timeoutMs)
      this._pending = { resolve, reject, timer, lines: [] }
      this.sock.write(command + '\r\n')
    })
  }

  destroy () { try { this.sock && this.sock.destroy() } catch {} this.sock = null }
}

export class TorTransport extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.socksHost = opts.socksHost || DEFAULT_SOCKS_HOST
    this.socksPort = opts.socksPort || DEFAULT_SOCKS_PORT
    this.controlHost = opts.controlHost || DEFAULT_CONTROL_HOST
    this.controlPort = opts.controlPort || DEFAULT_CONTROL_PORT
    this.controlPassword = opts.controlPassword || null
    this.cookieAuthFile = opts.cookieAuthFile || '/var/lib/tor/control_auth_cookie'

    // v2 options — all optional; absence preserves v1 behavior
    this.keyFile = opts.keyFile || null // persistent ED25519-V3 key custody
    this.minDaemonVersion = opts.minDaemonVersion || null // fail-closed floor
    this.vports = Array.isArray(opts.vports) ? opts.vports : null // [{ vport, targetHost?, targetPort }]
    this.clientAuthKeys = Array.isArray(opts.clientAuthKeys) ? [...opts.clientAuthKeys] : [] // base32 x25519 pubkeys
    this.rosterFile = opts.rosterFile || null // persisted roster (survives restarts); operator-private
    this._roster = this.rosterFile ? new OnionRosterStore(this.rosterFile) : null
    // Once restricted discovery is configured or activated, an empty roster
    // must stay closed rather than silently reverting the descriptor to public.
    this.restrictedDiscovery = !!(this.rosterFile || this.clientAuthKeys.length)
    this._clientAuthGuardKey = null
    this.endpointKeyId = opts.endpointKeyId || null // signed-advertisement key id (rotation)
    this.startedAtMs = null
    this.pow = opts.pow || null // { enabled, queueRate?, queueBurst? } — daemon-wide SETCONF
    this.healthOpts = Object.assign({ probeIntervalMs: 900000, probeFailLimit: 3, minDescriptorUploads: 2, probeVport: null }, opts.health || {})
    this.maxStreams = opts.maxStreams || null

    // Peer protocol plane: a bound OnionPeerListener the peer vport forwards
    // to. Inbound peer connections surface through the same 'connection'
    // event as outbound SOCKS streams — the relay's one handler serves both.
    this.peerListener = opts.peerListener || null
    this.peerVport = opts.peerVport || DEFAULT_PEER_VPORT
    if (this.peerListener) {
      this.peerListener.on('connection', (stream, info) => this.emit('connection', stream, info))
    }

    // legacy: single localPort → vport 80
    this.localPort = opts.localPort || null

    this.onionAddress = null
    this.serviceId = null
    this.daemonVersion = null
    this.health = TorHealth.DISABLED
    this.running = false
    this._control = null
    this._connections = new Set()
    this._probeTimer = null
    this._probeFails = 0
    this._descriptorUploads = 0
    this._controlFactory = opts._controlFactory || null // test injection
  }

  _makeControl () {
    if (this._controlFactory) return this._controlFactory()
    return new TorControl({ host: this.controlHost, port: this.controlPort })
  }

  _effectiveVports () {
    const vports = (this.vports && this.vports.length)
      ? [...this.vports]
      : this.localPort
        ? [{ vport: 80, targetHost: '127.0.0.1', targetPort: this.localPort }]
        : []
    // Forward the peer vport to the bound peer listener so the hidden
    // service carries Noise/Protomux next to the read plane. An explicit
    // vports entry for the same vport wins (operator override).
    if (this.peerListener && !vports.some((v) => v.vport === this.peerVport)) {
      vports.push({ vport: this.peerVport, targetHost: this.peerListener.host, targetPort: this.peerListener.port })
    }
    return vports
  }

  async start () {
    if (this.running) return
    this._setHealth(TorHealth.STARTING)

    try {
      await this._checkTorRunning()

      // Bind the peer protocol endpoint before the hidden service is created
      // so the peer vport forwards to the live port (ephemeral binds included).
      if (this.peerListener && !this.peerListener.running) await this.peerListener.start()

      const vports = this._effectiveVports()
      if (vports.length || this.minDaemonVersion || this.pow) {
        this._control = this._makeControl()
        await this._control.connect()
        await this._controlAuth()
        this._control.on('event', (line) => this._onControlEvent(line))

        if (this.minDaemonVersion) {
          await this._checkDaemonVersion()
        }
        if (this.pow && this.pow.enabled) {
          await this._applyPow()
        }
        if (vports.length) {
          await this._createHiddenService(vports)
        }
      } else if (this.localPort) {
        await this._createHiddenService(this.localPort) // unreachable; kept for clarity
      }

      this.running = true
      this.startedAtMs = Date.now()
      this.emit('started', {
        socksPort: this.socksPort,
        onionAddress: this.onionAddress,
        health: this.health,
        daemonVersion: this.daemonVersion
      })
    } catch (err) {
      // start() can fail after the peer listener or control connection has
      // opened but before running flips true. Release partial resources here
      // so lifecycle rollback and a later retry cannot inherit a bound port.
      this.running = false
      this.startedAtMs = null
      if (this._probeTimer) {
        clearInterval(this._probeTimer)
        this._probeTimer = null
      }
      if (this._control) {
        try { this._control.destroy() } catch {}
        this._control = null
      }
      if (this.peerListener && this.peerListener.running) {
        try { await this.peerListener.stop() } catch {}
      }
      this._descriptorUploads = 0
      this._probeFails = 0
      this._setHealth(TorHealth.DISABLED)
      throw err
    }
  }

  async stop () {
    if (!this.running) return
    this.running = false
    this.startedAtMs = null
    this._setHealth(TorHealth.DISABLED)
    if (this._probeTimer) { clearInterval(this._probeTimer); this._probeTimer = null }

    for (const conn of this._connections) conn.destroy()
    this._connections.clear()

    if (this._control) { this._control.destroy(); this._control = null }
    if (this.peerListener) await this.peerListener.stop()
    this._descriptorUploads = 0
    this.emit('stopped')
  }

  /**
   * Create a SOCKS5 connection through Tor to a .onion address or IP.
   * Returns a Duplex stream compatible with Hyperswarm connections.
   */
  async connect (host, port) {
    if (!this.running) throw new Error('Tor transport not running')

    const { socket } = await SocksClient.createConnection({
      proxy: { host: this.socksHost, port: this.socksPort, type: 5 },
      command: 'connect',
      destination: { host, port },
      timeout: 30000
    })

    const stream = new TorStream(socket)
    this._connections.add(stream)
    stream.on('close', () => this._connections.delete(stream))

    this.emit('connection', stream, {
      type: 'tor',
      remoteAddress: host,
      remotePort: port,
      isOnion: host.endsWith('.onion')
    })

    return stream
  }

  // ---------- client-auth roster (restricted discovery) ----------

  /**
   * Rebuild the service with an updated authorized-client set.
   * Tor exposes no runtime service-side roster add; the service keeps its
   * key blob and address, so this is a brief intro-point churn, not an
   * identity change. ONION-INV: address MUST stay identical after rebuild.
   */
  async _rebuildWithRoster (keys) {
    if (!this.keyFile) throw new Error('client-auth roster requires persistent keyFile mode')
    const blob = await this._loadOrThrowKey()
    await this._control.cmd('DEL_ONION ' + this.serviceId)
    const addressBefore = this.onionAddress
    this._descriptorUploads = 0
    await this._addOnion(blob, keys)
    if (this.onionAddress !== addressBefore) {
      throw new Error('onion address changed across roster rebuild — refusing to continue')
    }
  }

  async addAuthClient (pubB32, { name = null, expiresAtMs = null } = {}) {
    if (!isValidClientPub(pubB32)) throw new Error('invalid x25519 client public key (base32, 52 chars)')
    this.restrictedDiscovery = true
    if (this._roster) {
      if (!this._roster.loaded) await this._roster.load()
      this._roster.add(pubB32, { name, expiresAtMs })
      this._roster.purge()
      await this._roster.save()
      this.clientAuthKeys = this._roster.activeKeys()
    } else if (!this.clientAuthKeys.includes(pubB32)) {
      this.clientAuthKeys = [...this.clientAuthKeys, pubB32]
    } else {
      return this.clientAuthKeys
    }
    if (this.onionAddress) await this._rebuildWithRoster(this.clientAuthKeys)
    this.emit('roster-changed', { added: pubB32, size: this.clientAuthKeys.length })
    return this.clientAuthKeys
  }

  async removeAuthClient (pubB32) {
    let changed = true
    if (this._roster) {
      if (!this._roster.loaded) await this._roster.load()
      changed = this._roster.revoke(pubB32)
      this._roster.purge()
      await this._roster.save()
      this.clientAuthKeys = this._roster.activeKeys()
    } else {
      const keys = this.clientAuthKeys.filter((k) => k !== pubB32)
      changed = keys.length !== this.clientAuthKeys.length
      this.clientAuthKeys = keys
    }
    if (changed && this.onionAddress) await this._rebuildWithRoster(this.clientAuthKeys)
    if (changed) this.emit('roster-changed', { removed: pubB32, size: this.clientAuthKeys.length })
    return this.clientAuthKeys
  }

  listAuthClients () { return [...this.clientAuthKeys] }

  isRestrictedDiscoveryActive () { return this.restrictedDiscovery }

  // ---------- health ----------

  _setHealth (state) {
    if (this.health === state) return
    this.health = state
    this.emit('health', state)
  }

  _onControlEvent (line) {
    if (line.startsWith('HS_DESC UPLOADED') && this.serviceId && line.includes(this.serviceId)) {
      this._descriptorUploads++
      if (this.health === TorHealth.KEY_LOADED && this._descriptorUploads >= this.healthOpts.minDescriptorUploads) {
        this._setHealth(TorHealth.DESCRIPTOR_UPLOADED)
        this._probeNow()
      }
    }
  }

  async _startHealthLoop () {
    if (this._probeTimer) clearInterval(this._probeTimer)
    this._probeFails = 0
    this._probeTimer = setInterval(() => this._probeNow(), this.healthOpts.probeIntervalMs)
    this._probeTimer.unref && this._probeTimer.unref()
  }

  /** Self-probe: SOCKS-connect back to our own onion through the network. */
  async _probeNow () {
    const vport = this.healthOpts.probeVport
    if (!vport || !this.onionAddress) {
      // No probe surface configured: descriptor uploads are the readiness signal.
      if (this.health === TorHealth.DESCRIPTOR_UPLOADED) this._setHealth(TorHealth.READY)
      return
    }
    try {
      const { socket } = await SocksClient.createConnection({
        proxy: { host: this.socksHost, port: this.socksPort, type: 5 },
        command: 'connect',
        destination: { host: this.onionAddress, port: vport },
        timeout: 60000
      })
      socket.destroy()
      this._probeFails = 0
      this._setHealth(TorHealth.READY)
    } catch {
      this._probeFails++
      if (this._probeFails >= this.healthOpts.probeFailLimit) this._setHealth(TorHealth.DEGRADED)
    }
  }

  // ---------- daemon setup ----------

  async _checkDaemonVersion () {
    const resp = await this._control.cmd('GETINFO version')
    this.daemonVersion = (resp.split('=')[1] || '').trim()
    if (!versionAtLeast(this.daemonVersion, this.minDaemonVersion)) {
      throw new Error(`tor daemon ${this.daemonVersion} below floor ${this.minDaemonVersion} — refusing to start (fail closed)`)
    }
  }

  async _applyPow () {
    const parts = ['HiddenServicePoWDefensesEnabled=1']
    if (this.pow.queueRate) parts.push(`HiddenServicePoWQueueRate=${this.pow.queueRate}`)
    if (this.pow.queueBurst) parts.push(`HiddenServicePoWQueueBurst=${this.pow.queueBurst}`)
    // PoW is daemon-wide via SETCONF (no per-service ADD_ONION kwargs exist),
    // and C-tor REJECTS it with "no preceding HiddenServiceDir directive" when
    // no filesystem hidden service is configured (M0 finding, tor 0.4.9.6):
    // PoW on a control-port-only deployment requires at least one
    // HiddenServiceDir in torrc/SETCONF. Surface that failure loudly.
    try {
      await this._control.cmd('SETCONF ' + parts.join(' '))
    } catch (err) {
      throw new Error(`tor PoW SETCONF failed (${err.message.slice(0, 120)}) — PoW defense requires a HiddenServiceDir-configured service; control-port-only services cannot use it`)
    }
  }

  async _createHiddenService (vportsOrLegacy) {
    const vports = Array.isArray(vportsOrLegacy)
      ? vportsOrLegacy
      : [{ vport: 80, targetHost: '127.0.0.1', targetPort: vportsOrLegacy }]

    // Ensure we have a control connection even in legacy mode
    if (!this._control) {
      this._control = this._makeControl()
      await this._control.connect()
      await this._controlAuth()
      this._control.on('event', (line) => this._onControlEvent(line))
    }

    if (this.keyFile) {
      const blob = await this._loadOrCreateKey()
      if (this._roster) {
        await this._roster.load()
        this._roster.purge()
        const union = new Set([...this.clientAuthKeys, ...this._roster.activeKeys()])
        this.clientAuthKeys = [...union]
      }
      await this._addOnion(blob, this.clientAuthKeys, vports)
    } else {
      await this._addOnion(null, this.clientAuthKeys, vports)
    }

    this._setHealth(TorHealth.KEY_LOADED)
    await this._startHealthLoop()

    // Subscribe to descriptor events (needed for descriptor-uploaded health)
    try { await this._control.cmd('SETEVENTS HS_DESC') } catch {}

    this.emit('hidden-service', { onionAddress: this.onionAddress, vports, health: this.health })
  }

  async _addOnion (keyBlob, clientKeys = [], vports = null) {
    const effective = vports || this._effectiveVports()
    const portArgs = effective.map((v) => `Port=${v.vport},${v.targetHost || '127.0.0.1'}:${v.targetPort}`).join(' ')
    let effectiveClientKeys = clientKeys
    if (this.restrictedDiscovery && effectiveClientKeys.length === 0) {
      // Tor treats an ADD_ONION without ClientAuthV3 entries as public. Keep
      // an intentionally unreachable guard credential in the daemon command
      // until a real client is enrolled. The private half is destroyed at
      // generation and the guard is never persisted or advertised.
      if (!this._clientAuthGuardKey) this._clientAuthGuardKey = generateClientAuthGuardKey()
      effectiveClientKeys = [this._clientAuthGuardKey]
    }
    // v3 client authorization requires BOTH the V3Auth flag (auth type) and
    // per-client ClientAuthV3 keys — keys without the flag fail with
    // "512 No auth type specified" (M0 finding, tor 0.4.9.6).
    const flags = effectiveClientKeys.length ? ' Flags=V3Auth' : ''
    const authArgs = effectiveClientKeys.map((k) => `ClientAuthV3=${k}`).join(' ')
    const keyArg = keyBlob || (this.keyFile ? 'NEW:ED25519-V3' : 'NEW:BEST')
    const maxStreams = this.maxStreams ? ` MaxStreams=${this.maxStreams}` : ''
    const cmd = [`ADD_ONION ${keyArg}${flags}`, portArgs, authArgs].filter(Boolean).join(' ') + maxStreams

    const response = await this._control.cmd(cmd)
    for (const line of response.split('\n')) {
      if (line.startsWith('250-ServiceID=')) {
        this.serviceId = line.split('=')[1].trim()
        this.onionAddress = this.serviceId + '.onion'
      }
      if (!keyBlob && line.startsWith('250-PrivateKey=')) {
        await this._storeKey(line.slice('250-PrivateKey='.length).trim())
      }
    }
    if (!this.onionAddress) throw new Error('Failed to create hidden service — no ServiceID in response')
  }

  async _loadOrThrowKey () {
    const blob = (await readFile(this.keyFile, 'utf8')).trim()
    if (!KEY_BLOB_RE.test(blob)) {
      throw new Error(`corrupt tor key file at ${this.keyFile} — refusing silent re-identity; restore from backup or delete to mint a new endpoint`)
    }
    return blob
  }

  async _loadOrCreateKey () {
    try {
      return await this._loadOrThrowKey()
    } catch (err) {
      if (err.code === 'ENOENT') return null // first boot: mint below
      throw err
    }
  }

  async _storeKey (blob) {
    if (!this.keyFile || !KEY_BLOB_RE.test(blob)) return
    await mkdir(dirname(this.keyFile), { recursive: true })
    const tmp = this.keyFile + '.tmp'
    await writeFile(tmp, blob + '\n', { mode: 0o600 })
    await rename(tmp, this.keyFile)
  }

  // ---------- shared v1 helpers ----------

  async _checkTorRunning () {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection(this.socksPort, this.socksHost)
      const timer = setTimeout(() => {
        sock.destroy()
        reject(new Error(`Tor SOCKS proxy not reachable at ${this.socksHost}:${this.socksPort}. Make sure Tor is running: sudo systemctl start tor`))
      }, TOR_CHECK_TIMEOUT)
      sock.on('connect', () => { clearTimeout(timer); sock.destroy(); resolve() })
      sock.on('error', (err) => {
        clearTimeout(timer)
        reject(new Error(`Tor SOCKS proxy not reachable at ${this.socksHost}:${this.socksPort}: ${err.message}. Make sure Tor is running: sudo systemctl start tor`))
      })
    })
  }

  async _controlAuth () {
    try {
      const cookie = await readFile(this.cookieAuthFile)
      const response = await this._control.cmd(`AUTHENTICATE ${cookie.toString('hex')}`)
      if (response.startsWith('250')) return
    } catch {}
    if (this.controlPassword) {
      const escapedPassword = this.controlPassword.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
      const response = await this._control.cmd(`AUTHENTICATE "${escapedPassword}"`)
      if (response.startsWith('250')) return
      throw new Error('Tor control authentication failed with password')
    }
    const response = await this._control.cmd('AUTHENTICATE')
    if (response.startsWith('250')) return
    throw new Error('Tor control authentication failed. Configure in /etc/tor/torrc: CookieAuthentication 1 or HashedControlPassword')
  }

  getInfo () {
    return {
      running: this.running,
      health: this.health,
      daemonVersion: this.daemonVersion,
      socksProxy: `${this.socksHost}:${this.socksPort}`,
      onionAddress: this.onionAddress,
      vports: this._effectiveVports().map((v) => v.vport),
      authClients: this.clientAuthKeys.length,
      restrictedDiscovery: this.restrictedDiscovery,
      pow: this.pow ? !!this.pow.enabled : false,
      persistent: !!this.keyFile,
      descriptorUploads: this._descriptorUploads,
      activeConnections: this._connections.size
    }
  }
}

/**
 * Wraps a SOCKS5-established TCP socket into a Duplex stream
 * compatible with the Hyperswarm connection interface.
 */
class TorStream extends Duplex {
  constructor (socket, opts = {}) {
    super({ ...opts, allowHalfOpen: false })
    this.socket = socket
    socket.on('data', (data) => { if (!this.push(data)) socket.pause() })
    socket.on('end', () => this.push(null))
    socket.on('close', () => this.destroy())
    socket.on('error', (err) => this.destroy(err))
  }

  _write (chunk, encoding, cb) {
    if (this.socket.destroyed) { cb(new Error('Socket is destroyed')); return }
    this.socket.write(chunk, encoding, cb)
  }

  _read () {
    if (this.socket && !this.socket.destroyed) this.socket.resume()
  }

  _destroy (err, cb) {
    if (!this.socket.destroyed) this.socket.destroy()
    cb(err)
  }

  get remoteHost () { return this.socket.remoteAddress }
  get remotePort () { return this.socket.remotePort }
}
