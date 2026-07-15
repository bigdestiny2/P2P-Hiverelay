import sodium from 'sodium-universal'
import b4a from 'b4a'

export const SIGNED_LOG_CONTROL_DOMAIN = 'hiverelay.signed-log-control.v1'
export const SIGNED_LOG_CONTROL_VERSION = 1
export const SIGNED_LOG_CONTROL_ACTIONS = Object.freeze(['create', 'grant', 'revoke', 'close'])
export const MAX_CONTROL_VALIDITY_MS = 7 * 24 * 60 * 60 * 1000
export const CONTROL_CLOCK_SKEW_MS = 5 * 60 * 1000

const HEX_KEY = /^[0-9a-f]{64}$/i
const HEX_SIG = /^[0-9a-f]{128}$/i
const ACTIONS = new Set(SIGNED_LOG_CONTROL_ACTIONS)

export function canonicalSignedLogControl (control) {
  const normalized = normalizeControl(control, { signature: false })
  return b4a.from(stable(normalized), 'utf8')
}

export function hashControlOptions (options) {
  const digest = b4a.alloc(32)
  sodium.crypto_generichash(digest, b4a.from(stable(options == null ? {} : options), 'utf8'))
  return b4a.toString(digest, 'hex')
}

export function verifySignedLogControl (control, opts = {}) {
  let normalized
  try {
    normalized = normalizeControl(control, { signature: true })
  } catch (err) {
    return { ok: false, reason: 'bad-control', detail: err.message }
  }

  const now = Number.isFinite(opts.now) ? opts.now : Date.now()
  if (normalized.issuedAt > now + CONTROL_CLOCK_SKEW_MS) return { ok: false, reason: 'control-not-yet-valid' }
  if (normalized.expiresAt < now - CONTROL_CLOCK_SKEW_MS) return { ok: false, reason: 'control-expired' }
  if (normalized.expiresAt - normalized.issuedAt > MAX_CONTROL_VALIDITY_MS) return { ok: false, reason: 'control-validity-too-long' }
  if (opts.action && normalized.action !== opts.action) return { ok: false, reason: 'wrong-control-action' }
  if (opts.tableKey && normalized.tableKey !== String(opts.tableKey).toLowerCase()) return { ok: false, reason: 'wrong-control-table' }
  if (opts.authority && normalized.authority !== String(opts.authority).toLowerCase()) return { ok: false, reason: 'wrong-control-authority' }
  if (Number.isInteger(opts.revision) && normalized.revision !== opts.revision) {
    return { ok: false, reason: 'bad-control-revision', detail: { expected: opts.revision, got: normalized.revision } }
  }

  const signature = b4a.from(normalized.signature, 'hex')
  const publicKey = b4a.from(normalized.authority, 'hex')
  if (!sodium.crypto_sign_verify_detached(signature, canonicalSignedLogControl(normalized), publicKey)) {
    return { ok: false, reason: 'bad-control-signature' }
  }
  return { ok: true, control: Object.freeze(normalized) }
}

function normalizeControl (control, opts) {
  if (!control || typeof control !== 'object' || Array.isArray(control)) throw new Error('control must be an object')
  const domain = String(control.domain || '')
  const version = control.version
  const action = String(control.action || '')
  const tableKey = String(control.tableKey || '').toLowerCase()
  const authority = String(control.authority || '').toLowerCase()
  const revision = control.revision
  const issuedAt = control.issuedAt
  const expiresAt = control.expiresAt
  if (domain !== SIGNED_LOG_CONTROL_DOMAIN) throw new Error('bad domain')
  if (version !== SIGNED_LOG_CONTROL_VERSION) throw new Error('bad version')
  if (!ACTIONS.has(action)) throw new Error('bad action')
  if (!HEX_KEY.test(tableKey)) throw new Error('bad tableKey')
  if (!HEX_KEY.test(authority)) throw new Error('bad authority')
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('bad revision')
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) throw new Error('bad issuedAt')
  if (!Number.isSafeInteger(expiresAt) || expiresAt < issuedAt) throw new Error('bad expiresAt')

  const out = { domain, version, action, tableKey, authority, revision, issuedAt, expiresAt }
  if (action === 'create') {
    if (authority !== tableKey) throw new Error('create authority must equal tableKey')
    if (!Array.isArray(control.writers) || control.writers.length === 0) throw new Error('create writers required')
    out.writers = normalizeWriters(control.writers)
    if (!HEX_KEY.test(String(control.optionsHash || ''))) throw new Error('bad optionsHash')
    out.optionsHash = String(control.optionsHash).toLowerCase()
  } else if (action === 'grant' || action === 'revoke') {
    if (!HEX_KEY.test(String(control.writer || ''))) throw new Error('bad writer')
    out.writer = String(control.writer).toLowerCase()
  }
  if (opts.signature) {
    if (!HEX_SIG.test(String(control.signature || ''))) throw new Error('bad signature')
    out.signature = String(control.signature).toLowerCase()
  }
  return out
}

function normalizeWriters (writers) {
  const unique = new Set()
  for (const writer of writers) {
    if (!HEX_KEY.test(String(writer || ''))) throw new Error('bad writer')
    unique.add(String(writer).toLowerCase())
  }
  return [...unique].sort()
}

function stable (value) {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).filter(key => value[key] !== undefined).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
  }
  return JSON.stringify(value)
}
