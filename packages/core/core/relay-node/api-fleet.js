/**
 * Operator fleet multi-node view (data-layer v3).
 *
 * Read-only aggregate of public peer /health + /status scrapes.
 * Never merges private Tor detail (no onion, no RD roster, no client-auth).
 *
 * Peer list comes from operator config (config.fleet.peers) — not request body
 * — to avoid open SSRF. Only http(s) base URLs are allowed.
 */

const FLEET_ROUTES = Object.freeze({
  'GET /api/fleet': Object.freeze({
    kind: 'fleet',
    authMessage: 'Unauthorized — API key required for /api/fleet'
  })
})

export const DEFAULT_FLEET_TIMEOUT_MS = 4000
export const MAX_FLEET_PEERS = 32
export const MAX_FLEET_STRING_BYTES = 128
export const MAX_FLEET_ERROR_BYTES = 160

const HEX_64 = /^[a-f0-9]{64}$/i

export function resolveFleetRoute (method, path) {
  const route = FLEET_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

function objectRecord (value) {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function safeString (value, maxBytes = MAX_FLEET_STRING_BYTES) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  if (!text || Buffer.byteLength(text, 'utf8') > maxBytes) return null
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    if (code < 32 || code === 127) return null
  }
  return text
}

function safeCounter (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return 0
  return Math.floor(n)
}

function safeMetric (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return null
  return Math.min(n, Number.MAX_SAFE_INTEGER)
}

function safeBool (value) {
  if (value === true) return true
  if (value === false) return false
  return null
}

function truncateKey (value) {
  if (typeof value !== 'string') return null
  const hex = value.trim().toLowerCase()
  if (!HEX_64.test(hex)) {
    // Allow already-short display keys (12–64 hex).
    if (/^[a-f0-9]{12,64}$/i.test(hex)) return hex.slice(0, 12)
    return safeString(value, 64)
  }
  return hex.slice(0, 12)
}

/**
 * Only http(s) absolute base URLs. Rejects credentials in the URL.
 */
export function isAllowedFleetBaseUrl (value) {
  if (typeof value !== 'string' || !value.trim()) return false
  let u
  try {
    u = new URL(value.trim())
  } catch {
    return false
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false
  if (u.username || u.password) return false
  if (u.hash) return false
  return true
}

export function normalizeFleetBaseUrl (value) {
  if (!isAllowedFleetBaseUrl(value)) return null
  const u = new URL(value.trim())
  // Drop path noise except intentional path prefix (e.g. reverse-proxy mount).
  let base = u.origin + (u.pathname === '/' ? '' : u.pathname.replace(/\/+$/, ''))
  return base
}

/**
 * Normalize config.fleet.peers entries into a bounded, safe list.
 */
export function normalizeFleetPeers (rawPeers, { maxPeers = MAX_FLEET_PEERS } = {}) {
  if (!Array.isArray(rawPeers)) return []
  const out = []
  const seen = new Set()
  for (const entry of rawPeers) {
    if (out.length >= maxPeers) break
    if (!objectRecord(entry) && typeof entry !== 'string') continue
    const baseUrl = normalizeFleetBaseUrl(
      typeof entry === 'string' ? entry : (entry.baseUrl || entry.url)
    )
    if (!baseUrl) continue
    const key = baseUrl.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    const id = safeString(
      (objectRecord(entry) && (entry.id || entry.label || entry.name)) || baseUrl,
      64
    ) || baseUrl
    const region = objectRecord(entry) ? safeString(entry.region, 32) : null
    const label = objectRecord(entry)
      ? safeString(entry.label || entry.name, 64)
      : null
    const declaredPubkey = objectRecord(entry)
      ? truncateKey(entry.pubkey || entry.publicKey || entry.declaredPubkey)
      : null
    out.push({
      id,
      baseUrl,
      region: region || null,
      label: label || id,
      declaredPubkey: declaredPubkey || null
    })
  }
  return out
}

export function resolveFleetConfig (config = {}) {
  const fleet = objectRecord(config.fleet) ? config.fleet : {}
  const timeoutMs = Number.isFinite(Number(fleet.timeoutMs)) && Number(fleet.timeoutMs) > 0
    ? Math.min(Math.floor(Number(fleet.timeoutMs)), 30_000)
    : DEFAULT_FLEET_TIMEOUT_MS
  const maxPeers = Number.isFinite(Number(fleet.maxPeers)) && Number(fleet.maxPeers) > 0
    ? Math.min(Math.floor(Number(fleet.maxPeers)), MAX_FLEET_PEERS)
    : MAX_FLEET_PEERS
  const peers = normalizeFleetPeers(fleet.peers, { maxPeers })
  // includeSelf defaults true so a node with empty peer list still shows local card.
  const includeSelf = fleet.includeSelf !== false
  return { peers, timeoutMs, maxPeers, includeSelf }
}

/**
 * Coarse privacy lane from public status.transports — health only, never onion.
 */
export function sanitizeFleetPrivacy (transports) {
  if (!objectRecord(transports)) return null
  const tor = objectRecord(transports.tor) ? transports.tor : null
  if (!tor) {
    // Legacy boolean-ish shapes
    if (transports.torAvailable === true || transports.tor === true) {
      return [{ id: 'tor-v3-onion-v1', health: 'unknown', running: true }]
    }
    return null
  }
  const health = typeof tor.health === 'string'
    ? safeString(tor.health, 32)
    : (tor.running === true ? 'ready' : tor.running === false ? 'down' : 'unknown')
  return [{
    id: 'tor-v3-onion-v1',
    running: tor.running === true,
    health: health || 'unknown'
  }]
}

/**
 * Build one fleet card from public health + status JSON (or fetch errors).
 * Strips any accidental onion / secret fields by allow-listing.
 */
export function sanitizeFleetPeerCard ({
  id,
  label = null,
  region = null,
  baseUrl = null,
  declaredPubkey = null,
  health = null,
  status = null,
  error = null,
  self = false,
  fetchedAt = null
} = {}) {
  const card = {
    id: safeString(id, 64) || 'peer',
    label: safeString(label, 64) || safeString(id, 64) || 'peer',
    region: safeString(region, 32),
    baseUrl: baseUrl && isAllowedFleetBaseUrl(baseUrl) ? normalizeFleetBaseUrl(baseUrl) : null,
    self: self === true,
    up: false,
    running: null,
    publicKey: declaredPubkey ? truncateKey(declaredPubkey) : null,
    uptimeMs: null,
    connections: null,
    seededApps: null,
    disk: null,
    storage: null,
    healthy: null,
    privacyTransports: null,
    version: null,
    errors: [],
    fetchedAt: Number.isFinite(Number(fetchedAt)) ? Math.floor(Number(fetchedAt)) : null
  }

  if (error) {
    const msg = safeString(String(error), MAX_FLEET_ERROR_BYTES) || 'fetch failed'
    card.errors.push({ endpoint: 'poll', error: msg })
  }

  if (objectRecord(health)) {
    const ok = safeBool(health.ok)
    const running = safeBool(health.running)
    if (ok === true || running === true) card.up = true
    if (running !== null) card.running = running
    if (objectRecord(health.uptime) && health.uptime.ms != null) {
      card.uptimeMs = safeMetric(health.uptime.ms)
    } else if (health.uptimeMs != null) {
      card.uptimeMs = safeMetric(health.uptimeMs)
    }
  }

  if (objectRecord(status)) {
    if (status.running === true) {
      card.up = true
      card.running = true
    } else if (status.running === false && card.running == null) {
      card.running = false
    }
    if (status.publicKey) card.publicKey = truncateKey(status.publicKey) || card.publicKey
    if (status.region) card.region = safeString(status.region, 32) || card.region
    if (status.uptimeMs != null) card.uptimeMs = safeMetric(status.uptimeMs)
    if (status.connections != null) card.connections = safeCounter(status.connections)
    if (status.seededApps != null) card.seededApps = safeCounter(status.seededApps)

    if (objectRecord(status.health)) {
      const h = safeBool(status.health.healthy)
      if (h !== null) card.healthy = h
    }

    if (objectRecord(status.disk)) {
      const disk = {}
      const usedPct = safeMetric(status.disk.usedPct)
      if (usedPct != null) disk.usedPct = usedPct
      if (typeof status.disk.status === 'string') {
        const s = safeString(status.disk.status, 32)
        if (s) disk.status = s
      }
      const freeGB = safeMetric(status.disk.freeGB)
      if (freeGB != null) disk.freeGB = freeGB
      if (Object.keys(disk).length) card.disk = disk
    }

    if (objectRecord(status.storage)) {
      const storage = {}
      if (status.storage.totalBytes != null || status.storage.used != null) {
        const used = safeMetric(status.storage.totalBytes != null ? status.storage.totalBytes : status.storage.used)
        if (used != null) storage.used = used
      }
      if (status.storage.max != null || status.storage.maxBytes != null) {
        const max = safeMetric(status.storage.max != null ? status.storage.max : status.storage.maxBytes)
        if (max != null) storage.max = max
      }
      if (Object.keys(storage).length) card.storage = storage
    }

    card.privacyTransports = sanitizeFleetPrivacy(status.transports)
    // Explicitly never copy onion-bearing fields even if present on raw status.
  }

  // up if health ok OR status running, and no total poll failure without data
  if (!card.up && card.errors.length && !objectRecord(health) && !objectRecord(status)) {
    card.up = false
  }

  return card
}

/**
 * Aggregate fleet cards into operator summary (counts only).
 */
export function aggregateFleet (cards = [], { now = Date.now() } = {}) {
  const list = Array.isArray(cards) ? cards : []
  let up = 0
  let down = 0
  let diskWarn = 0
  let diskCritical = 0
  let unhealthy = 0
  let privacyDegraded = 0
  const regions = new Set()

  for (const c of list) {
    if (!objectRecord(c)) continue
    if (c.up) up++
    else down++
    if (c.region) regions.add(c.region)
    if (c.healthy === false) unhealthy++
    if (objectRecord(c.disk)) {
      if (c.disk.status === 'critical' || (c.disk.usedPct != null && c.disk.usedPct >= 90)) diskCritical++
      else if (c.disk.status === 'warn' || (c.disk.usedPct != null && c.disk.usedPct >= 75)) diskWarn++
    }
    const pt = Array.isArray(c.privacyTransports) ? c.privacyTransports[0] : null
    if (pt && pt.health && pt.health !== 'ready' && pt.health !== 'ok' && pt.health !== 'unknown') {
      privacyDegraded++
    }
  }

  return {
    peerCount: list.length,
    up,
    down,
    regions: regions.size,
    diskWarn,
    diskCritical,
    unhealthy,
    privacyDegraded,
    updatedAt: Math.floor(now)
  }
}

/**
 * Poll configured peers (and optional self card) into a fleet payload.
 * fetchJson(url) must return parsed JSON or throw.
 */
export async function buildFleetPayload ({
  config = {},
  selfStatus = null,
  selfHealth = null,
  selfPublicKey = null,
  selfRegion = null,
  fetchJson = null,
  now = Date.now()
} = {}) {
  const fleetCfg = resolveFleetConfig(config)
  const cards = []

  if (fleetCfg.includeSelf) {
    cards.push(sanitizeFleetPeerCard({
      id: 'self',
      label: 'this node',
      region: selfRegion,
      declaredPubkey: selfPublicKey,
      health: selfHealth,
      status: selfStatus,
      self: true,
      fetchedAt: now
    }))
  }

  if (typeof fetchJson === 'function' && fleetCfg.peers.length) {
    const settled = await Promise.all(fleetCfg.peers.map(async (peer) => {
      const base = peer.baseUrl
      let health = null
      let status = null
      const errors = []
      try {
        health = await fetchJson(`${base}/health`)
      } catch (err) {
        errors.push(err && err.message ? err.message : 'health failed')
      }
      try {
        status = await fetchJson(`${base}/status`)
      } catch (err) {
        errors.push(err && err.message ? err.message : 'status failed')
      }
      const error = (!health && !status)
        ? (errors[0] || 'unreachable')
        : null
      return sanitizeFleetPeerCard({
        id: peer.id,
        label: peer.label,
        region: peer.region,
        baseUrl: peer.baseUrl,
        declaredPubkey: peer.declaredPubkey,
        health,
        status,
        error,
        self: false,
        fetchedAt: now
      })
    }))
    for (const card of settled) cards.push(card)
  }

  // Drop absolute certainty: re-scan cards for any forbidden onion substrings.
  const scrubbed = cards.map(stripForbiddenFleetFields)

  return {
    summary: aggregateFleet(scrubbed, { now }),
    peers: scrubbed,
    config: {
      peerTargets: fleetCfg.peers.length,
      includeSelf: fleetCfg.includeSelf,
      timeoutMs: fleetCfg.timeoutMs
    }
  }
}

function stripForbiddenFleetFields (card) {
  if (!objectRecord(card)) return card
  const json = JSON.stringify(card)
  // Defense-in-depth: if anything onion-shaped leaked, redact the whole string fields.
  if (!/\.onion\b/i.test(json) && !/ED25519-V3:/i.test(json)) return card
  const clone = { ...card }
  for (const key of Object.keys(clone)) {
    if (typeof clone[key] === 'string' && (/\.onion\b/i.test(clone[key]) || /ED25519-V3:/i.test(clone[key]))) {
      clone[key] = '[redacted]'
    }
  }
  // privacyTransports must stay coarse — rebuild without any free-form strings beyond health.
  if (Array.isArray(clone.privacyTransports)) {
    clone.privacyTransports = clone.privacyTransports.map((p) => ({
      id: 'tor-v3-onion-v1',
      running: !!(p && p.running),
      health: (p && typeof p.health === 'string' && !/\.onion/i.test(p.health))
        ? p.health.slice(0, 32)
        : 'unknown'
    }))
  }
  return clone
}

export async function buildFleetRoutePayload ({
  route,
  node = {},
  fetchJson = null,
  now = Date.now()
} = {}) {
  if (!route || route.kind !== 'fleet') {
    return {
      ok: false,
      status: 404,
      payload: { error: 'unknown fleet route' }
    }
  }

  const config = objectRecord(node.config) ? node.config : {}
  const fleetCfg = resolveFleetConfig(config)

  // Default fetchJson uses global fetch with per-request timeout.
  const doFetch = typeof fetchJson === 'function'
    ? fetchJson
    : createTimedFetchJson(fleetCfg.timeoutMs)

  let selfStatus = null
  let selfHealth = null
  let selfPublicKey = null
  let selfRegion = null

  if (fleetCfg.includeSelf) {
    try {
      if (typeof node.getStats === 'function') {
        const stats = node.getStats({ includeSecrets: false })
        selfPublicKey = stats && stats.publicKey
        // Prefer building from local status builder if available via lazy import pattern —
        // callers may pass prebuilt self; here we assemble a minimal status-like object.
        selfStatus = {
          running: stats && stats.running !== false,
          publicKey: stats && stats.publicKey,
          region: Array.isArray(config.regions) ? config.regions[0] : null,
          uptimeMs: node.metrics && Number.isFinite(node.metrics.startedAt)
            ? Math.max(0, now - node.metrics.startedAt)
            : null,
          connections: stats && stats.connections,
          seededApps: stats && stats.seededApps,
          health: typeof node.getHealthStatus === 'function'
            ? (() => {
              try {
                const h = node.getHealthStatus()
                return h ? { healthy: h.healthy === true } : null
              } catch { return null }
            })()
            : null,
          disk: stats && stats.disk,
          storage: stats && stats.storage,
          transports: stats && stats.transports
        }
      }
      if (typeof node.getHealthStatus === 'function') {
        const h = node.getHealthStatus()
        selfHealth = {
          ok: h && h.healthy !== false,
          running: true,
          uptimeMs: selfStatus && selfStatus.uptimeMs
        }
      } else {
        selfHealth = { ok: true, running: true }
      }
      selfRegion = Array.isArray(config.regions) ? config.regions[0] : null
    } catch {
      selfStatus = { running: true }
      selfHealth = { ok: true, running: true }
    }
  }

  const payload = await buildFleetPayload({
    config,
    selfStatus,
    selfHealth,
    selfPublicKey,
    selfRegion,
    fetchJson: doFetch,
    now
  })

  return { ok: true, status: 200, payload }
}

export function createTimedFetchJson (timeoutMs = DEFAULT_FLEET_TIMEOUT_MS) {
  return async function timedFetchJson (url) {
    if (typeof globalThis.fetch !== 'function') {
      throw new Error('fetch unavailable')
    }
    const ms = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_FLEET_TIMEOUT_MS
    const controller = typeof AbortController === 'function' ? new AbortController() : null
    const timer = controller
      ? setTimeout(() => controller.abort(), ms)
      : null
    try {
      const res = await globalThis.fetch(url, controller ? { signal: controller.signal } : {})
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return await res.json()
    } finally {
      if (timer) clearTimeout(timer)
    }
  }
}
