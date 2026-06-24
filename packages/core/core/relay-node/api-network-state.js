const MAX_NETWORK_RELAYS = 1000
const MAX_NETWORK_STRING_BYTES = 128
const HEX_64 = /^[a-f0-9]{64}$/i

export function isDetailedNetworkStateQuery (value) {
  return value === '1' || value === 'true'
}

export function buildNetworkStatePayload ({
  networkDiscovery,
  detailed = false
} = {}) {
  if (!networkDiscovery || typeof networkDiscovery.getNetworkState !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: 'Network discovery not running' }
    }
  }

  const state = networkDiscovery.getNetworkState()
  return {
    ok: true,
    status: 200,
    payload: detailed ? detailedNetworkState(state) : publicNetworkState(state)
  }
}

export function publicNetworkState (state = {}) {
  const relays = Array.isArray(state.relays) ? state.relays : []
  return {
    timestamp: safeTimestamp(state.timestamp),
    summary: sanitizeNetworkSummary(state.summary),
    relays: relays.slice(0, MAX_NETWORK_RELAYS).map(publicNetworkRelay)
  }
}

export function publicNetworkRelay (relay = {}) {
  const source = sanitizeDetailedNetworkRelay(relay)
  return {
    publicKey: source.publicKey,
    name: source.name,
    region: source.region,
    online: source.online,
    lastSeen: source.lastSeen,
    uptime: source.uptime,
    connections: source.connections,
    seededApps: source.seededApps,
    storage: source.storage,
    relay: source.relay,
    seeder: source.seeder,
    apiReachable: source.apiPort !== null && source.apiPort !== undefined,
    torAvailable: source.tor && source.tor.running === true,
    holesailAvailable: !!source.holesailKey || source.holesailConnected === true,
    errors: source.errors
  }
}

export function detailedNetworkState (state = {}) {
  const relays = Array.isArray(state.relays) ? state.relays : []
  return {
    timestamp: safeTimestamp(state.timestamp),
    summary: sanitizeNetworkSummary(state.summary),
    relays: relays.slice(0, MAX_NETWORK_RELAYS).map(sanitizeDetailedNetworkRelay)
  }
}

export function sanitizeDetailedNetworkRelay (relay = {}) {
  const source = relay && typeof relay === 'object' && !Array.isArray(relay) ? relay : {}
  return {
    publicKey: safeHexKey(source.publicKey),
    name: safeNetworkString(source.name),
    host: safeNetworkString(source.host, 253),
    apiPort: safeApiPort(source.apiPort),
    region: safeNetworkString(source.region, 64),
    online: source.online === true,
    lastSeen: safeTimestamp(source.lastSeen),
    uptime: sanitizeUptime(source.uptime),
    connections: safeCounter(source.connections),
    seededApps: safeCounter(source.seededApps),
    storage: sanitizeStorage(source.storage),
    relay: sanitizeRelayStats(source.relay),
    seeder: sanitizeSeederStats(source.seeder),
    memory: sanitizeMemory(source.memory),
    tor: sanitizeTorInfo(source.tor),
    holesailKey: safeNetworkString(source.holesailKey, 128),
    holesailConnected: source.holesailConnected === true,
    errors: safeCounter(source.errors)
  }
}

function sanitizeNetworkSummary (summary = {}) {
  const source = summary && typeof summary === 'object' && !Array.isArray(summary) ? summary : {}
  return {
    totalRelays: safeCounter(source.totalRelays),
    onlineRelays: safeCounter(source.onlineRelays),
    totalConnections: safeCounter(source.totalConnections),
    totalStorage: safeCounter(source.totalStorage),
    totalStorageMax: safeCounter(source.totalStorageMax)
  }
}

function sanitizeUptime (uptime) {
  if (!uptime || typeof uptime !== 'object' || Array.isArray(uptime)) return null
  const out = {}
  if (uptime.ms !== undefined) out.ms = safeCounter(uptime.ms)
  if (uptime.hours !== undefined) out.hours = safeNumber(uptime.hours)
  const human = safeNetworkString(uptime.human, 64)
  if (human) out.human = human
  return Object.keys(out).length > 0 ? out : null
}

function sanitizeStorage (storage) {
  if (!storage || typeof storage !== 'object' || Array.isArray(storage)) return null
  return {
    used: safeCounter(storage.used),
    max: safeCounter(storage.max),
    pct: safeRatioOrPercent(storage.pct)
  }
}

function sanitizeRelayStats (relay) {
  if (!relay || typeof relay !== 'object' || Array.isArray(relay)) return null
  return {
    activeCircuits: safeCounter(relay.activeCircuits),
    totalCircuitsServed: safeCounter(relay.totalCircuitsServed),
    totalBytesRelayed: safeCounter(relay.totalBytesRelayed),
    capacityUsedPct: safePercent(relay.capacityUsedPct),
    peersWithCircuits: safeCounter(relay.peersWithCircuits)
  }
}

function sanitizeSeederStats (seeder) {
  if (!seeder || typeof seeder !== 'object' || Array.isArray(seeder)) return null
  return {
    coresSeeded: safeCounter(seeder.coresSeeded),
    totalBytesStored: safeCounter(seeder.totalBytesStored),
    totalBytesServed: safeCounter(seeder.totalBytesServed),
    capacityUsedPct: safePercent(seeder.capacityUsedPct)
  }
}

function sanitizeMemory (memory) {
  if (!memory || typeof memory !== 'object' || Array.isArray(memory)) return null
  return {
    heapUsed: safeCounter(memory.heapUsed),
    rss: safeCounter(memory.rss)
  }
}

function sanitizeTorInfo (tor) {
  if (!tor || typeof tor !== 'object' || Array.isArray(tor)) return null
  return {
    running: tor.running === true,
    onionAddress: safeNetworkString(tor.onionAddress, 128),
    activeConnections: safeCounter(tor.activeConnections)
  }
}

function safeHexKey (value) {
  return typeof value === 'string' && HEX_64.test(value) ? value.toLowerCase() : null
}

function safeNetworkString (value, maxBytes = MAX_NETWORK_STRING_BYTES) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed || Buffer.byteLength(trimmed, 'utf8') > maxBytes) return null
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i)
    if (code < 32 || code === 127) return null
  }
  return trimmed
}

function safeApiPort (value) {
  if (value === 'holesail') return value
  if (!Number.isSafeInteger(value) || value < 0 || value > 65535) return null
  return value
}

function safeCounter (value) {
  if (!Number.isFinite(value) || value < 0) return 0
  return Math.min(Math.floor(value), Number.MAX_SAFE_INTEGER)
}

function safeNumber (value) {
  if (!Number.isFinite(value) || value < 0) return 0
  return value
}

function safePercent (value) {
  if (!Number.isFinite(value)) return 0
  return Math.min(100, Math.max(0, Math.floor(value)))
}

function safeRatioOrPercent (value) {
  if (!Number.isFinite(value) || value < 0) return 0
  return value <= 1 ? value : safePercent(value)
}

function safeTimestamp (value) {
  if (!Number.isFinite(value) || value < 0) return null
  return Math.min(Math.floor(value), Number.MAX_SAFE_INTEGER)
}
