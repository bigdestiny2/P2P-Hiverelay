import { formatErr } from '../error-prefixes.js'

const RATE_REQUIRED = 'satsPerGiBDay (number) required'
const RATE_NON_NEGATIVE = 'satsPerGiBDay must be a non-negative number'
const PERSIST_FAILED = 'failed to persist lease config; check storage permissions and disk space'
const MAX_PAY_TO_LENGTH = 512
const MAX_PROVIDER_LENGTH = 128
const RATE_MAX_PREFIX = 'satsPerGiBDay exceeds maximum'

export function countActiveLeaseManagedApps ({ appRegistry, now = Date.now() } = {}) {
  let activeLeases = 0
  const apps = appRegistry && appRegistry.apps
  if (!apps || typeof apps[Symbol.iterator] !== 'function') return activeLeases

  for (const [, entry] of apps) {
    if (
      entry &&
      entry.leaseManaged === true &&
      Number.isFinite(entry.retainUntil) &&
      entry.retainUntil > now
    ) {
      activeLeases++
    }
  }
  return activeLeases
}

export function buildLeaseStatusPayload ({ leaseManager, appRegistry, now = Date.now() } = {}) {
  if (!leaseManager) {
    return {
      payload: { enabled: false },
      status: 200
    }
  }

  const summary = typeof leaseManager.getSummary === 'function'
    ? leaseManager.getSummary()
    : {}

  return {
    payload: {
      ...sanitizeLeaseSummary(summary),
      activeLeases: countActiveLeaseManagedApps({ appRegistry, now })
    },
    status: 200
  }
}

export function parseLeaseRateUpdate (body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || !Number.isFinite(body.satsPerGiBDay)) {
    return { ok: false, kind: 'bad-request', message: RATE_REQUIRED }
  }
  if (body.satsPerGiBDay < 0) {
    return { ok: false, kind: 'bad-request', message: RATE_NON_NEGATIVE }
  }

  return { ok: true, satsPerGiBDay: body.satsPerGiBDay }
}

export async function runLeaseConfigAction ({ body, leaseManager } = {}) {
  if (!leaseManager) {
    return {
      ok: false,
      kind: 'not-enabled',
      payload: { error: formatErr('NOT_ENABLED', 'paid seeding is off - set lease.enabled in config and restart') },
      status: 409
    }
  }

  const parsed = parseLeaseRateUpdate(body)
  if (!parsed.ok) {
    return {
      ...parsed,
      payload: { error: formatErr('BAD_REQUEST', parsed.message) },
      status: 400
    }
  }

  const setRate = typeof leaseManager.setRateDurable === 'function'
    ? leaseManager.setRateDurable.bind(leaseManager)
    : typeof leaseManager.setRate === 'function'
      ? leaseManager.setRate.bind(leaseManager)
      : null

  if (!setRate) {
    return {
      ok: false,
      kind: 'unsupported',
      payload: { error: formatErr('UNSUPPORTED', 'paid seeding rate updates are unavailable') },
      status: 503
    }
  }

  try {
    const rate = await setRate(parsed.satsPerGiBDay)
    return {
      ok: true,
      payload: { ok: true, satsPerGiBDay: rate },
      status: 200
    }
  } catch (err) {
    if (err && err.code === 'LEASE_RATE_PERSIST_FAILED') {
      return {
        ok: false,
        kind: 'persist',
        payload: { error: formatErr('PERSIST_FAILED', PERSIST_FAILED) },
        status: 503
      }
    }

    return {
      ok: false,
      kind: 'bad-request',
      payload: { error: formatErr('BAD_REQUEST', publicErrorMessage(err)) },
      status: 400
    }
  }
}

export function sanitizeLeaseSummary (summary = {}) {
  return {
    enabled: true,
    satsPerGiBDay: nonNegativeInteger(summary.satsPerGiBDay),
    minDays: nonNegativeInteger(summary.minDays),
    maxDays: nonNegativeInteger(summary.maxDays),
    payTo: safeStringOrNull(summary.payTo, MAX_PAY_TO_LENGTH),
    totalLeasedSats: nonNegativeInteger(summary.totalLeasedSats),
    leaseCount: nonNegativeInteger(summary.leaseCount),
    provider: safeStringOrNull(summary.provider, MAX_PROVIDER_LENGTH),
    providerConnected: summary.providerConnected === true
  }
}

function nonNegativeInteger (value) {
  if (!Number.isFinite(value) || value < 0) return 0
  return Math.floor(value)
}

function safeStringOrNull (value, maxLength) {
  if (value === null || value === undefined) return null
  if (typeof value !== 'string') return null
  if (hasControlChars(value)) return null
  return value.length > maxLength ? value.slice(0, maxLength) : value
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if ((code >= 0 && code < 32) || code === 127) return true
  }
  return false
}

function publicErrorMessage (err) {
  const message = err && typeof err.message === 'string'
    ? err.message.trim()
    : ''
  if (!message || hasControlChars(message)) return 'invalid lease config'
  if (message === RATE_NON_NEGATIVE || message.startsWith(RATE_MAX_PREFIX)) return message
  return 'invalid lease config'
}
