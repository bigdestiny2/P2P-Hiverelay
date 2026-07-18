/**
 * Tor-specific observability redaction (`hiverelay.onion/1` §12, RA-07).
 *
 * Two tools:
 *
 * 1. redactTorInfo() — shape transport info for public vs operator surfaces.
 *    Public surfaces get coarse health only: no onion address, no roster size,
 *    no descriptor counters (fine-grained timing), no vports detail.
 *
 * 2. auditPayload() — the forbidden-field privacy gate. Deep-walks a payload
 *    and reports material that must never appear in default/public logs,
 *    metrics, or status: onion addresses, client auth pubkeys, hidden-service
 *    key blobs, roster file contents. Intentionally advertised endpoints (the
 *    capability doc's own onion address) are whitelisted explicitly by the
 *    caller — everything else is a violation.
 */

export const FORBIDDEN_PATTERNS = Object.freeze([
  { name: 'onion-address', re: /\b[a-z2-7]{56}\.onion\b/ },
  { name: 'client-auth-pubkey', re: /\b[a-z2-7]{52}\b/ },
  { name: 'hs-key-blob', re: /ED25519-V3:[A-Za-z0-9+/=]{20,}/ },
  { name: 'auth-private-line', re: /:descriptor:x25519:[A-Za-z2-7]{52}\b/ },
  { name: 'roster-file', re: /"keys"\s*:\s*\[\s*\{\s*"pub"\s*:/ }
])

/**
 * @param {object|null} info  TorTransport.getInfo() payload
 * @param {object} [opts]
 * @param {boolean} [opts.operator]  true = full operator diagnostics
 * @returns {object} surface-appropriate info
 */
export function redactTorInfo (info, { operator = false } = {}) {
  if (!info || typeof info !== 'object') return null
  if (operator) return { ...info }
  return {
    running: !!info.running,
    health: typeof info.health === 'string' ? info.health : 'unknown',
    activeConnections: typeof info.activeConnections === 'number' ? info.activeConnections : 0
  }
}

/**
 * Deep-walk a payload and report forbidden fields.
 *
 * @param {*} payload
 * @param {object} [opts]
 * @param {string[]} [opts.allowOnionAddresses]  intentionally advertised endpoints
 * @param {number} [opts.maxViolations]
 * @returns {{ ok: boolean, violations: Array<{ name: string, path: string, sample: string }> }}
 */
export function auditPayload (payload, { allowOnionAddresses = [], maxViolations = 50 } = {}) {
  const violations = []
  const allowed = new Set(allowOnionAddresses)

  const check = (value, path) => {
    if (violations.length >= maxViolations) return
    if (typeof value !== 'string') return
    for (const { name, re } of FORBIDDEN_PATTERNS) {
      const m = value.match(re)
      if (!m) continue
      if (name === 'onion-address' && allowed.has(m[0])) continue
      violations.push({ name, path, sample: m[0].slice(0, 24) + (m[0].length > 24 ? '…' : '') })
      break // one violation per string is enough
    }
  }

  const walk = (value, path) => {
    if (violations.length >= maxViolations) return
    if (typeof value === 'string') return check(value, path)
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) walk(value[i], `${path}[${i}]`)
      return
    }
    if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) walk(v, path ? `${path}.${k}` : k)
    }
  }
  walk(payload, '')

  return { ok: violations.length === 0, violations }
}
