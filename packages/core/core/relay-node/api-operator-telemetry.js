import { queryInt } from './api-validation.js'

export const MAX_METRICS_HISTORY_SNAPSHOTS = 1440
export const MAX_OPERATOR_HEALTH_ACTIONS = 50
export const MAX_OPERATOR_STORAGE_TOP_ENTRIES = 100
export const MAX_OPERATOR_AUTO_HEAL_DRIVES = 256
export const MAX_OPERATOR_LABEL_BYTES = 128
export const MAX_OPERATOR_MESSAGE_BYTES = 512
export const MAX_OPERATOR_LIST_VALUES = 32
export const DEFAULT_OPERATOR_STORAGE_TOP_ENTRIES = 30
export const DEFAULT_METRICS_HISTORY_MINUTES = 60
export const MAX_METRICS_HISTORY_MINUTES = 24 * 60

const OPERATOR_TELEMETRY_ROUTES = Object.freeze({
  'GET /api/health-detail': Object.freeze({
    kind: 'health-detail',
    authMessage: 'Unauthorized — API key required for /api/health-detail'
  }),
  'GET /api/storage/top': Object.freeze({
    kind: 'storage-top',
    authMessage: 'Unauthorized — storage top requires API key or localhost'
  }),
  'GET /api/auto-heal': Object.freeze({
    kind: 'auto-heal',
    authMessage: 'Unauthorized — API key required for /api/auto-heal'
  }),
  'GET /api/history': Object.freeze({
    kind: 'history',
    authMessage: 'Unauthorized — API key required for /api/history'
  })
})

const HEX_64 = /^[0-9a-f]{64}$/i

const METRIC_GROUPS = {
  relay: [
    'activeCircuits',
    'totalCircuitsServed',
    'totalBytesRelayed',
    'capacityUsedPct',
    'peersWithCircuits'
  ],
  seeder: [
    'coresSeeded',
    'totalBytesStored',
    'totalBytesServed',
    'capacityUsedPct'
  ],
  served: [
    'totalBytesServed',
    'totalBlocksServed',
    'trackedCores'
  ],
  storage: [
    'totalBytes',
    'measuredEntries',
    'fullSweeps',
    'lastFullSweepAt'
  ],
  appRegistry: [
    'entries',
    'anchored',
    'unanchored',
    'cores'
  ],
  replication: [
    'trackedApps',
    'underReplicated',
    'lastCheckedAt'
  ],
  reputation: [
    'trackedRelays'
  ],
  dhtRelayWs: [
    'activeConnections',
    'totalConnectionsServed',
    'totalRateLimited',
    'totalReaped',
    'totalBytesIn',
    'totalBytesOut',
    'maxConnections'
  ]
}

const DISK_METRICS = [
  'totalBytes',
  'usedBytes',
  'availableBytes',
  'usedPct',
  'checkedAt'
]
const DISK_STATUSES = new Set(['ok', 'warn', 'critical'])
const RELAY_MODES = new Set(['public', 'private'])
const HEALTH_CHECKS = ['memory', 'connections', 'swarm', 'errors', 'disk']
const HEALTH_CHECK_FIELDS = {
  memory: ['heapPct', 'rssMB'],
  connections: ['zeroFor', 'staleCount', 'totalConns', 'stalePct'],
  swarm: [],
  errors: ['errorRate'],
  disk: ['usedPct', 'freeGB', 'totalGB']
}
const SELF_HEAL_NUMERIC_FIELDS = ['destroyed']
const AUTO_HEAL_NUMERIC_FIELDS = [
  'tickMs',
  'maxRecruitsPerTick',
  'storageMargin',
  'proofFreshnessMs',
  'maxProofsPerTick',
  'tracked',
  'below',
  'backoffs',
  'proofCacheSize'
]
const AUTO_HEAL_THRESHOLD_FIELDS = [
  'minReplicas',
  'minRegions',
  'minOperators',
  'replicaBuffer',
  'maxPerOperator'
]
const AUTO_HEAL_DRIVE_NUMERIC_FIELDS = ['replicas']
const AUTO_HEAL_DRIVE_LIST_FIELDS = ['regions', 'operators']

export function resolveOperatorTelemetryRoute (method, path) {
  const route = OPERATOR_TELEMETRY_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildHealthDetailPayload ({ node } = {}) {
  const health = node && typeof node.getHealthStatus === 'function'
    ? node.getHealthStatus()
    : {}
  const actions = node && node.selfHeal && typeof node.selfHeal.getActions === 'function'
    ? node.selfHeal.getActions()
    : []

  return {
    payload: buildOperatorHealthPayload(health, actions),
    status: 200
  }
}

export function buildStorageTopPayload ({ storageAccounting, n = 30 } = {}) {
  if (!storageAccounting) {
    return {
      payload: { entries: [] },
      status: 200
    }
  }

  const summary = typeof storageAccounting.getSummary === 'function'
    ? storageAccounting.getSummary()
    : {}
  const entries = typeof storageAccounting.getTop === 'function'
    ? storageAccounting.getTop(n)
    : []

  return {
    payload: buildOperatorStorageTopPayload(summary, entries),
    status: 200
  }
}

export function buildAutoHealPayload ({ autoHeal } = {}) {
  if (!autoHeal) {
    return {
      payload: { enabled: false, reason: 'AutoHeal not enabled in config' },
      status: 200
    }
  }

  return {
    payload: buildOperatorAutoHealPayload(
      typeof autoHeal.snapshot === 'function' ? autoHeal.snapshot() : {}
    ),
    status: 200
  }
}

export function buildMetricsHistoryPayload ({ metrics, minutes = 60, now = Date.now() } = {}) {
  if (!metrics) {
    return {
      payload: { error: 'Metrics not enabled' },
      status: 503
    }
  }

  const cutoff = now - (minutes * 60_000)
  const snapshots = Array.isArray(metrics.snapshots) ? metrics.snapshots : []
  const payload = []
  const start = Math.max(0, snapshots.length - (MAX_METRICS_HISTORY_SNAPSHOTS * 4))

  for (let i = snapshots.length - 1; i >= start && payload.length < MAX_METRICS_HISTORY_SNAPSHOTS; i--) {
    const snapshot = snapshots[i]
    if (!snapshot ||
      typeof snapshot !== 'object' ||
      Array.isArray(snapshot) ||
      !Number.isFinite(snapshot.timestamp) ||
      snapshot.timestamp < cutoff) {
      continue
    }

    const clean = sanitizeMetricsSnapshot(snapshot)
    if (clean) payload.push(clean)
  }

  payload.reverse()

  return { payload, status: 200 }
}

export function buildOperatorTelemetryRoutePayload ({
  route,
  node,
  url
} = {}) {
  const kind = route && route.kind
  if (kind === 'health-detail') return buildHealthDetailPayload({ node })
  if (kind === 'storage-top') {
    const n = queryRouteInt(url, 'n', DEFAULT_OPERATOR_STORAGE_TOP_ENTRIES, 1, MAX_OPERATOR_STORAGE_TOP_ENTRIES)
    return buildStorageTopPayload({
      storageAccounting: node && node.storageAccounting,
      n
    })
  }
  if (kind === 'auto-heal') return buildAutoHealPayload({ autoHeal: node && node.autoHeal })
  if (kind === 'history') {
    const minutes = queryRouteInt(url, 'minutes', DEFAULT_METRICS_HISTORY_MINUTES, 1, MAX_METRICS_HISTORY_MINUTES)
    return buildMetricsHistoryPayload({
      metrics: node && node.metrics,
      minutes
    })
  }
  return {
    payload: { error: 'unknown operator telemetry route' },
    status: 404
  }
}

function queryRouteInt (url, name, defaultValue, min, max) {
  if (!url || !url.searchParams) return defaultValue
  return queryInt(url, name, defaultValue, min, max)
}

function sanitizeMetricsSnapshot (snapshot) {
  const timestamp = safeTimestamp(snapshot.timestamp)
  if (timestamp === null) return null

  const out = { timestamp }
  const running = safeBoolean(snapshot.running)
  const mode = safeMode(snapshot.mode)

  if (running !== null) out.running = running
  if (mode !== null) out.mode = mode
  assignMetric(out, 'seededApps', snapshot.seededApps)
  assignMetric(out, 'connections', snapshot.connections)

  for (const [key, fields] of Object.entries(METRIC_GROUPS)) {
    const group = sanitizeMetricGroup(snapshot[key], fields)
    if (group) out[key] = group
  }

  const disk = sanitizeDiskMetrics(snapshot.disk)
  if (disk) out.disk = disk

  return out
}

function buildOperatorHealthPayload (health, actions) {
  const payload = {}

  if (health && typeof health === 'object' && !Array.isArray(health)) {
    const healthy = safeBoolean(health.healthy)
    const lastCheck = safeTimestamp(health.lastCheck)
    const consecutiveFailures = safeMetric(health.consecutiveFailures)
    const checks = sanitizeHealthChecks(health.checks)

    if (healthy !== null) payload.healthy = healthy
    if (lastCheck !== null) payload.lastCheck = lastCheck
    if (consecutiveFailures !== null) payload.consecutiveFailures = consecutiveFailures
    if (checks) payload.checks = checks
  }

  payload.actions = sanitizeSelfHealActions(actions)
  return payload
}

function sanitizeHealthChecks (checks) {
  if (!checks || typeof checks !== 'object' || Array.isArray(checks)) return null

  const out = {}
  for (const check of HEALTH_CHECKS) {
    const entry = sanitizeHealthCheck(checks[check], HEALTH_CHECK_FIELDS[check] || [])
    if (entry) out[check] = entry
  }

  return Object.keys(out).length > 0 ? out : null
}

function sanitizeHealthCheck (entry, numericFields) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null

  const out = {}
  const ok = safeBoolean(entry.ok)
  const critical = safeBoolean(entry.critical)
  const reason = safeString(entry.reason, MAX_OPERATOR_MESSAGE_BYTES)
  const suggestion = safeString(entry.suggestion, MAX_OPERATOR_MESSAGE_BYTES)
  const error = safeString(entry.error, MAX_OPERATOR_MESSAGE_BYTES)

  if (ok !== null) out.ok = ok
  if (critical !== null) out.critical = critical
  for (const field of numericFields) assignMetric(out, field, entry[field])
  if (reason !== null) out.reason = reason
  if (suggestion !== null) out.suggestion = suggestion
  if (error !== null) out.error = error

  return Object.keys(out).length > 0 ? out : null
}

function sanitizeSelfHealActions (actions) {
  if (!Array.isArray(actions)) return []

  return actions
    .slice(-MAX_OPERATOR_HEALTH_ACTIONS)
    .map(sanitizeSelfHealAction)
    .filter(Boolean)
}

function sanitizeSelfHealAction (action) {
  if (!action || typeof action !== 'object' || Array.isArray(action)) return null

  const out = {}
  const type = safeString(action.type, MAX_OPERATOR_LABEL_BYTES)
  const check = safeString(action.check, MAX_OPERATOR_LABEL_BYTES)
  const timestamp = safeTimestamp(action.timestamp)
  const reason = safeString(action.reason, MAX_OPERATOR_MESSAGE_BYTES)
  const error = safeString(action.error, MAX_OPERATOR_MESSAGE_BYTES)
  const appKey = safeHexKey(action.appKey)
  const details = sanitizeHealthCheck(action.details, [
    'heapPct',
    'rssMB',
    'zeroFor',
    'staleCount',
    'totalConns',
    'stalePct',
    'errorRate'
  ])

  if (type !== null) out.type = type
  if (check !== null) out.check = check
  if (timestamp !== null) out.timestamp = timestamp
  if (reason !== null) out.reason = reason
  if (error !== null) out.error = error
  if (appKey !== null) out.appKey = appKey
  for (const field of SELF_HEAL_NUMERIC_FIELDS) assignMetric(out, field, action[field])
  if (details) out.details = details

  return Object.keys(out).length > 0 ? out : null
}

function buildOperatorStorageTopPayload (summary, entries) {
  const payload = sanitizeMetricGroup(summary, [
    'totalBytes',
    'measuredEntries',
    'fullSweeps',
    'lastFullSweepAt'
  ]) || {}

  payload.entries = sanitizeStorageTopEntries(entries)
  return payload
}

function sanitizeStorageTopEntries (entries) {
  if (!Array.isArray(entries)) return []

  const out = []
  for (const entry of entries) {
    if (out.length >= MAX_OPERATOR_STORAGE_TOP_ENTRIES) break
    const clean = sanitizeStorageTopEntry(entry)
    if (clean) out.push(clean)
  }
  return out
}

function sanitizeStorageTopEntry (entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null

  const appKey = safeHexKey(entry.appKey)
  if (appKey === null) return null
  const bytes = safeMetric(entry.bytes)
  if (bytes === null) return null

  const out = { appKey, bytes }
  assignMetric(out, 'measuredAt', entry.measuredAt)

  return out
}

export function buildOperatorAutoHealPayload (snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
    return { enabled: true, running: false, drives: [] }
  }

  const payload = {}
  const enabled = safeBoolean(snapshot.enabled)
  const running = safeBoolean(snapshot.running)
  const verifyProofs = safeBoolean(snapshot.verifyProofs)
  const thresholds = sanitizeMetricGroup(snapshot.thresholds, AUTO_HEAL_THRESHOLD_FIELDS)

  if (enabled !== null) payload.enabled = enabled
  if (running !== null) payload.running = running
  if (verifyProofs !== null) payload.verifyProofs = verifyProofs
  for (const field of AUTO_HEAL_NUMERIC_FIELDS) assignMetric(payload, field, snapshot[field])
  if (thresholds) payload.thresholds = thresholds
  payload.drives = sanitizeAutoHealDrives(snapshot.drives)

  return payload
}

function sanitizeAutoHealDrives (drives) {
  if (!Array.isArray(drives)) return []

  const out = []
  for (const drive of drives) {
    if (out.length >= MAX_OPERATOR_AUTO_HEAL_DRIVES) break
    const clean = sanitizeAutoHealDrive(drive)
    if (clean) out.push(clean)
  }
  return out
}

function sanitizeAutoHealDrive (drive) {
  if (!drive || typeof drive !== 'object' || Array.isArray(drive)) return null

  const appKey = safeHexKey(drive.appKey)
  if (appKey === null) return null

  const out = { appKey }
  const meetsThreshold = safeBoolean(drive.meetsThreshold)
  const haveLocally = safeBoolean(drive.haveLocally)

  for (const field of AUTO_HEAL_DRIVE_NUMERIC_FIELDS) assignMetric(out, field, drive[field])
  for (const field of AUTO_HEAL_DRIVE_LIST_FIELDS) {
    const list = sanitizeStringList(drive[field], MAX_OPERATOR_LIST_VALUES, MAX_OPERATOR_LABEL_BYTES)
    if (list) out[field] = list
  }
  if (meetsThreshold !== null) out.meetsThreshold = meetsThreshold
  if (haveLocally !== null) out.haveLocally = haveLocally
  if (drive.backoff && typeof drive.backoff === 'object' && !Array.isArray(drive.backoff)) {
    const backoff = sanitizeMetricGroup(drive.backoff, ['failures', 'retryInMs'])
    if (backoff) out.backoff = backoff
  }

  return out
}

function sanitizeMetricGroup (source, fields) {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return null

  const out = {}
  for (const field of fields) assignMetric(out, field, source[field])

  return Object.keys(out).length > 0 ? out : null
}

function sanitizeDiskMetrics (disk) {
  if (!disk || typeof disk !== 'object' || Array.isArray(disk)) return null

  const out = sanitizeMetricGroup(disk, DISK_METRICS) || {}
  const status = safeStatus(disk.status, DISK_STATUSES)

  if (status !== null) out.status = status

  return Object.keys(out).length > 0 ? out : null
}

function assignMetric (target, key, value) {
  const clean = safeMetric(value)
  if (clean !== null) target[key] = clean
}

function safeMetric (value) {
  if (!Number.isFinite(value) || value < 0) return null
  return Math.min(value, Number.MAX_SAFE_INTEGER)
}

function safeTimestamp (value) {
  const clean = safeMetric(value)
  return clean === null ? null : Math.floor(clean)
}

function safeBoolean (value) {
  if (value === true) return true
  if (value === false) return false
  return null
}

function safeMode (value) {
  return safeStatus(value, RELAY_MODES)
}

function safeStatus (value, allowed) {
  if (typeof value !== 'string') return null
  const clean = value.trim()
  if (!allowed.has(clean)) return null
  return clean
}

function safeString (value, maxLength) {
  if (typeof value !== 'string') return null
  const clean = value.trim()
  if (!clean || clean.length > maxLength) return null
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return null
  }
  return clean
}

function safeHexKey (value) {
  const clean = safeString(value, 64)
  return clean && HEX_64.test(clean) ? clean.toLowerCase() : null
}

function sanitizeStringList (values, maxItems, maxLength) {
  if (!Array.isArray(values)) return null

  const out = []
  for (const value of values) {
    if (out.length >= maxItems) break
    const clean = safeString(value, maxLength)
    if (clean !== null) out.push(clean)
  }

  return out.length > 0 ? out : null
}
