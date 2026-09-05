import b4a from 'b4a'
import punycode from 'punycode/punycode.js'
import { constants } from 'fs'
import { open, rename, unlink, mkdir } from 'fs/promises'
import { join, dirname } from 'path'

const CACHE_FILENAME = 'bootstrap-cache.json'
const SAVE_INTERVAL = 15 * 60 * 1000 // 15 minutes

export const DEFAULT_BOOTSTRAP_CACHE_PEERS = 50
export const MAX_BOOTSTRAP_CACHE_PEERS = 256
export const MAX_BOOTSTRAP_CACHE_FILE_BYTES = 131_072
export const MAX_BOOTSTRAP_HOST_BYTES = 1_024
export const MAX_BOOTSTRAP_ROWS = 256
export const MAX_MERGED_BOOTSTRAP_ROWS = 256

// bare-fs does not currently expose O_NOFOLLOW even though its Unix binding
// accepts the platform flag. Keep symlink refusal atomic on supported Unix
// runtimes and retain the identity checks below as a second fence.
const O_NOFOLLOW = constants.O_NOFOLLOW ?? platformNoFollowFlag()

function platformNoFollowFlag () {
  const platform = globalThis.Bare ? globalThis.Bare.platform : process.platform
  if (platform === 'linux') return 0x20000
  if (platform === 'darwin') return 0x100
  return 0
}

function strictPositiveInteger (value, fallback, maximum, name) {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer`)
  }
  return Math.min(value, maximum)
}

export function parseBootstrapCachePeers (value) {
  return strictPositiveInteger(
    value,
    DEFAULT_BOOTSTRAP_CACHE_PEERS,
    MAX_BOOTSTRAP_CACHE_PEERS,
    'bootstrapCachePeers'
  )
}

function safeUtf8 (value) {
  if (typeof value !== 'string' || value.length === 0) return null
  // Reject lone surrogates before an encoder can silently replace them.
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(++i)
      if (!(low >= 0xdc00 && low <= 0xdfff)) return null
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return null
    }
  }
  const encoded = b4a.from(value, 'utf8')
  if (encoded.byteLength < 1 || encoded.byteLength > MAX_BOOTSTRAP_HOST_BYTES) return null
  if (b4a.toString(encoded, 'utf8') !== value) return null
  return value
}

function parseIPv4 (raw) {
  const parts = raw.split('.')
  if (parts.length !== 4) return null
  const bytes = new Uint8Array(4)
  for (let i = 0; i < 4; i++) {
    const part = parts[i]
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null
    const value = Number(part)
    if (value > 255) return null
    bytes[i] = value
  }
  return { family: 4, bytes, host: Array.from(bytes).join('.') }
}

function ipv6Words (raw) {
  if (!raw.includes(':') || raw.includes('%')) return null
  if (raw.startsWith(':') && !raw.startsWith('::')) return null
  if (raw.endsWith(':') && !raw.endsWith('::')) return null
  if ((raw.match(/::/g) || []).length > 1) return null

  const hasCompression = raw.includes('::')
  const halves = hasCompression ? raw.split('::') : [raw]
  const left = halves[0] ? halves[0].split(':') : []
  const right = hasCompression && halves[1] ? halves[1].split(':') : []
  const tokens = [...left, ...right]
  const words = []

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    if (!token) return null
    if (token.includes('.')) {
      if (i !== tokens.length - 1 || !raw.endsWith(token)) return null
      const ipv4 = parseIPv4(token)
      if (!ipv4) return null
      words.push((ipv4.bytes[0] << 8) | ipv4.bytes[1])
      words.push((ipv4.bytes[2] << 8) | ipv4.bytes[3])
      continue
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null
    words.push(Number.parseInt(token, 16))
  }

  if (hasCompression) {
    const omitted = 8 - words.length
    if (omitted < 1) return null
    const split = left.length
    words.splice(split, 0, ...new Array(omitted).fill(0))
  }
  if (words.length !== 8) return null
  return words
}

function canonicalIPv6 (words) {
  let bestStart = -1
  let bestLength = 0
  for (let i = 0; i < words.length;) {
    if (words[i] !== 0) {
      i++
      continue
    }
    let end = i + 1
    while (end < words.length && words[end] === 0) end++
    const length = end - i
    if (length >= 2 && length > bestLength) {
      bestStart = i
      bestLength = length
    }
    i = end
  }

  const rendered = words.map(word => word.toString(16))
  if (bestStart < 0) return rendered.join(':')
  const head = rendered.slice(0, bestStart).join(':')
  const tail = rendered.slice(bestStart + bestLength).join(':')
  return `${head}::${tail}`
}

function parseIPv6 (raw) {
  const words = ipv6Words(raw)
  if (!words) return null
  const bytes = new Uint8Array(16)
  for (let i = 0; i < words.length; i++) {
    bytes[i * 2] = words[i] >>> 8
    bytes[i * 2 + 1] = words[i] & 0xff
  }
  return { family: 6, bytes, host: canonicalIPv6(words) }
}

function domainToASCII (candidate) {
  try {
    return punycode.toASCII(candidate.toLowerCase())
  } catch {
    return null
  }
}

export function normalizeBootstrapHost (value) {
  const raw = safeUtf8(value)
  if (raw === null) return null
  // Endpoint syntax is never accepted in a host field. Brackets are added
  // only after a raw IPv6 literal has been parsed into bytes.
  if (/[[\]@/?#\\\s]/.test(raw)) return null
  for (let i = 0; i < raw.length; i++) {
    const unit = raw.charCodeAt(i)
    if (unit <= 0x1f || unit === 0x7f) return null
  }

  const ipv4 = parseIPv4(raw)
  if (ipv4) return ipv4
  if (/^[0-9.]+$/.test(raw)) return null
  const ipv6 = parseIPv6(raw)
  if (ipv6) return ipv6
  if (raw.includes(':') || raw.includes('%')) return null

  const candidate = raw.endsWith('.') ? raw.slice(0, -1) : raw
  if (!candidate || candidate.endsWith('.')) return null
  const ascii = domainToASCII(candidate)
  if (typeof ascii !== 'string' || ascii.length < 1 || b4a.byteLength(ascii) > 253) return null
  const host = ascii.toLowerCase()
  const labels = host.split('.')
  if (labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null
  return { family: 0, bytes: b4a.from(host), host }
}

function normalizedPort (value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= 65_535
    ? value
    : null
}

function normalizedLastSeen (value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : null
}

export function normalizeBootstrapPeer (peer) {
  if (!peer || typeof peer !== 'object' || Array.isArray(peer)) return null
  const normalized = normalizeBootstrapHost(peer.host)
  const port = normalizedPort(peer.port)
  const lastSeen = normalizedLastSeen(peer.lastSeen)
  if (!normalized || port === null || lastSeen === null) return null
  const key = normalized.family === 6
    ? `[${normalized.host}]:${port}`
    : `${normalized.host}:${port}`
  return { key, host: normalized.host, port, lastSeen }
}

function sameIdentity (before, after) {
  return before && after && before.dev === after.dev && before.ino === after.ino &&
    before.isFile() && after.isFile()
}

async function readBoundedRegularFile (path) {
  let handle = null
  try {
    handle = await open(path, constants.O_RDONLY | O_NOFOLLOW)
    const before = await handle.stat()
    if (!before.isFile() || !Number.isSafeInteger(before.size) ||
        before.size < 1 || before.size > MAX_BOOTSTRAP_CACHE_FILE_BYTES) {
      throw new Error('bootstrap cache file is not a bounded regular file')
    }
    const raw = b4a.alloc(before.size)
    let offset = 0
    while (offset < raw.byteLength) {
      const result = await handle.read(raw, offset, raw.byteLength - offset, offset)
      if (!result || result.bytesRead < 1) throw new Error('bootstrap cache short read')
      offset += result.bytesRead
    }
    const after = await handle.stat()
    if (!sameIdentity(before, after) || before.size !== after.size) {
      throw new Error('bootstrap cache changed during read')
    }
    return b4a.toString(raw, 'utf8')
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
}

export class BootstrapCache {
  constructor (storagePath, opts = {}) {
    if (typeof storagePath !== 'string' || storagePath.length === 0) {
      throw new TypeError('BootstrapCache: storagePath is required')
    }
    this._storagePath = storagePath
    this._filePath = join(storagePath, CACHE_FILENAME)
    this._maxPeers = parseBootstrapCachePeers(opts.maxPeers)
    this._enabled = opts.enabled !== false
    this._seenPeers = new Map() // oldest -> newest
    this._peers = [] // compatibility snapshot, also bounded
    this._interval = null
    this._swarm = null
    this._connectionHandler = null
    this._accepting = true
    this._stopping = false
    this._stopped = false
    this._saveRequested = false
    this._savePromise = null
    this._stopPromise = null
    this._tempSequence = 0
    this._mutationVersion = 0
    // A constructor/load attempt must not create a missing operator storage
    // root during failed-start rollback. Persistence becomes owned only after
    // a cache was actually loaded, explicitly saved, or attached to a swarm.
    this._persistenceActive = false
    this._stats = {
      inserts: 0,
      refreshes: 0,
      evictions: 0,
      invalid: 0,
      overflow: 0,
      saveCoalesced: 0,
      saveFailures: 0,
      stops: 0
    }
  }

  async load () {
    if (!this._enabled || this._stopping || this._stopped) return false
    const loaded = new Map()
    try {
      const raw = await readBoundedRegularFile(this._filePath)
      const data = JSON.parse(raw)
      if (!data || typeof data !== 'object' || !Array.isArray(data.peers)) {
        throw new Error('bootstrap cache shape is invalid')
      }
      const rows = Math.min(data.peers.length, MAX_BOOTSTRAP_ROWS)
      if (data.peers.length > MAX_BOOTSTRAP_ROWS) this._stats.overflow += data.peers.length - MAX_BOOTSTRAP_ROWS
      for (let i = 0; i < rows; i++) {
        const peer = normalizeBootstrapPeer(data.peers[i])
        if (!peer || loaded.has(peer.key)) {
          this._stats.invalid++
          continue
        }
        loaded.set(peer.key, peer)
        while (loaded.size > this._maxPeers) {
          loaded.delete(loaded.keys().next().value)
          this._stats.evictions++
        }
      }
      this._seenPeers = loaded
      this._syncCompatibilityPeers()
      this._persistenceActive = true
      return true
    } catch {
      this._seenPeers.clear()
      this._syncCompatibilityPeers()
      return false
    }
  }

  async save () {
    if (!this._enabled || this._stopping || this._stopped) return false
    this._persistenceActive = true
    this._saveRequested = true
    if (this._savePromise) {
      this._stats.saveCoalesced++
      return this._savePromise
    }
    this._savePromise = this._runSaveLoop()
    try {
      return await this._savePromise
    } finally {
      this._savePromise = null
    }
  }

  async _runSaveLoop () {
    let saved = false
    while (this._saveRequested && !this._stopping) {
      this._saveRequested = false
      saved = await this._saveSnapshot()
      if (!saved) break
    }
    return saved
  }

  async _saveSnapshot () {
    const version = this._mutationVersion
    const peers = this._snapshotOldestFirst()
    const raw = JSON.stringify({ version: 1, peers }) + '\n'
    if (b4a.byteLength(raw) > MAX_BOOTSTRAP_CACHE_FILE_BYTES) {
      this._stats.saveFailures++
      return false
    }
    let tempPath = null
    let handle = null
    try {
      await mkdir(dirname(this._filePath), { recursive: true })
      for (let attempt = 0; attempt < 4; attempt++) {
        tempPath = this._ownedTempPath()
        try {
          handle = await open(
            tempPath,
            constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW,
            0o600
          )
          break
        } catch (err) {
          if (err?.code !== 'EEXIST' || attempt === 3) throw err
        }
      }
      const bytes = b4a.from(raw)
      let offset = 0
      while (offset < bytes.byteLength) {
        const result = await handle.write(bytes, offset, bytes.byteLength - offset, offset)
        if (!result || result.bytesWritten < 1) throw new Error('bootstrap cache short write')
        offset += result.bytesWritten
      }
      if (typeof handle.sync === 'function') await handle.sync()
      await handle.close()
      handle = null
      await rename(tempPath, this._filePath)
      tempPath = null
      if (version !== this._mutationVersion && !this._stopping) this._saveRequested = true
      return true
    } catch {
      this._stats.saveFailures++
      return false
    } finally {
      if (handle) await handle.close().catch(() => {})
      if (tempPath) await unlink(tempPath).catch(() => {})
    }
  }

  merge (configuredBootstrap) {
    if (!this._enabled) return configuredBootstrap || undefined
    if (!Array.isArray(configuredBootstrap) || configuredBootstrap.length === 0) return undefined

    const seen = new Set()
    const merged = []
    const configuredRows = Math.min(configuredBootstrap.length, MAX_BOOTSTRAP_ROWS)
    if (configuredBootstrap.length > MAX_BOOTSTRAP_ROWS) {
      this._stats.overflow += configuredBootstrap.length - MAX_BOOTSTRAP_ROWS
    }
    for (let i = 0; i < configuredRows && merged.length < MAX_MERGED_BOOTSTRAP_ROWS; i++) {
      const input = configuredBootstrap[i]
      const peer = normalizeBootstrapPeer({ ...input, lastSeen: input?.lastSeen ?? 0 })
      if (!peer) {
        this._stats.invalid++
        continue
      }
      if (seen.has(peer.key)) continue
      seen.add(peer.key)
      merged.push({ host: peer.host, port: peer.port })
    }

    for (const peer of this._collectPeers()) {
      if (merged.length >= MAX_MERGED_BOOTSTRAP_ROWS) break
      if (seen.has(peer.key)) continue
      seen.add(peer.key)
      merged.push({ host: peer.host, port: peer.port })
    }
    return merged.length ? merged : undefined
  }

  start (swarm) {
    if (!this._enabled || this._stopping || this._stopped) return
    if (!swarm || typeof swarm.on !== 'function') throw new TypeError('BootstrapCache.start: swarm is required')
    if (this._connectionHandler) return
    this._persistenceActive = true
    this._swarm = swarm
    this._connectionHandler = (conn) => {
      if (!this._accepting) return
      const raw = conn?.rawStream
      this._insert({ host: raw?.remoteHost, port: raw?.remotePort, lastSeen: Date.now() })
    }
    swarm.on('connection', this._connectionHandler)
    this._interval = setInterval(() => {
      this.save().catch(() => {})
    }, SAVE_INTERVAL)
    if (this._interval.unref) this._interval.unref()
  }

  stop () {
    if (this._stopPromise) return this._stopPromise
    this._stopPromise = this._stop()
    return this._stopPromise
  }

  async _stop () {
    if (this._stopped) return
    this._stats.stops++
    this._accepting = false
    this._stopping = true
    if (this._swarm && this._connectionHandler) {
      this._swarm.removeListener('connection', this._connectionHandler)
    }
    this._connectionHandler = null
    this._swarm = null
    if (this._interval) clearInterval(this._interval)
    this._interval = null

    // Drain an already-owned save before issuing one final latest snapshot.
    if (this._savePromise) await this._savePromise.catch(() => false)
    if (this._enabled && this._persistenceActive) await this._saveSnapshot()
    this._saveRequested = false
    this._stopped = true
    this._stopping = false
  }

  _insert (input) {
    const peer = normalizeBootstrapPeer(input)
    if (!peer) {
      this._stats.invalid++
      return false
    }
    if (this._seenPeers.has(peer.key)) {
      this._seenPeers.delete(peer.key)
      this._stats.refreshes++
    } else {
      this._stats.inserts++
    }
    this._seenPeers.set(peer.key, peer)
    while (this._seenPeers.size > this._maxPeers) {
      this._seenPeers.delete(this._seenPeers.keys().next().value)
      this._stats.evictions++
    }
    this._mutationVersion++
    this._syncCompatibilityPeers()
    return true
  }

  _ownedTempPath () {
    const nonce = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString(36)
    return `${this._filePath}.${Date.now().toString(36)}-${++this._tempSequence}-${nonce}.tmp`
  }

  _snapshotOldestFirst () {
    const peers = []
    for (const peer of this._seenPeers.values()) {
      if (peers.length >= this._maxPeers) break
      peers.push({ host: peer.host, port: peer.port, lastSeen: peer.lastSeen })
    }
    return peers
  }

  _syncCompatibilityPeers () {
    this._peers = this._snapshotOldestFirst()
  }

  _collectPeers () {
    const peers = []
    for (const [key, peer] of this._seenPeers) {
      if (peers.length >= this._maxPeers) break
      peers.push({ key, host: peer.host, port: peer.port, lastSeen: peer.lastSeen })
    }
    peers.reverse() // newest first for connection preference; still O(cap)
    return peers
  }

  getStats () {
    return {
      size: this._seenPeers.size,
      cap: this._maxPeers,
      ...this._stats,
      saving: this._savePromise !== null,
      stopping: this._stopping,
      stopped: this._stopped
    }
  }
}
