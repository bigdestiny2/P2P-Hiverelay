const OVERBROAD_RELEASE_PROMISE_PATTERNS = Object.freeze([
  Object.freeze({
    name: 'AI/QVAC/Ollama product claim',
    pattern: /\b(?:AI|QVAC|Ollama)\b/i
  }),
  Object.freeze({
    name: 'poker product claim',
    pattern: /\bpoker\b/i
  }),
  Object.freeze({
    name: 'custody product claim',
    pattern: /\bcustody\b/i
  }),
  Object.freeze({
    name: 'service marketplace claim',
    pattern: /\bservice\s+marketplace\b/i
  }),
  Object.freeze({
    name: 'payment marketplace/settlement claim',
    pattern: /\bpayment\s+(?:marketplace|settlement|provider|network)\b/i
  }),
  Object.freeze({
    name: 'ZK product claim',
    pattern: /\b(?:ZK|zero[- ]knowledge)\b/i
  }),
  Object.freeze({
    name: 'arbitration product claim',
    pattern: /\barbitration\b/i
  }),
  Object.freeze({
    name: 'Lightning/Cashu release claim',
    pattern: /\b(?:Lightning|Cashu)\b/i
  })
])

export const NARROW_RELEASE_PROMISE_LABEL = 'Core Availability / Blindspark'

export function findOverbroadReleasePromises (value, opts = {}) {
  const text = typeof value === 'string' ? value : String(value || '')
  const allow = new Set(Array.isArray(opts.allow) ? opts.allow : [])
  const findings = []

  for (const rule of OVERBROAD_RELEASE_PROMISE_PATTERNS) {
    if (allow.has(rule.name)) continue
    const match = text.match(rule.pattern)
    if (!match) continue
    findings.push({
      name: rule.name,
      match: match[0],
      index: match.index || 0
    })
  }

  return findings
}

export function assertNarrowReleasePromise (value, opts = {}) {
  const findings = findOverbroadReleasePromises(value, opts)
  if (findings.length === 0) return
  const label = opts.label || 'release promise'
  const names = findings.map(finding => `${finding.name} (${JSON.stringify(finding.match)})`).join(', ')
  throw new Error(`${label} must stay scoped to ${NARROW_RELEASE_PROMISE_LABEL}; remove overbroad claims: ${names}`)
}
