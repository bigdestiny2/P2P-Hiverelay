import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  roleDomainSignable,
  validateRoleDomainMessage
} from './role-domain-signature.js'

export const HIVEMESH_PROVE_HELD_PROFILE_KIND = 'hivemesh-prove-held-profile'
export const HIVEMESH_PROVE_HELD_PROFILE_VERSION = 1
export const HIVEMESH_PROVE_HELD_COMMIT_DOMAIN = 'hivemesh-prove-held-commit-root-v1'
export const HIVEMESH_PROVE_HELD_DEFAULT_HOT_WINDOW_SECONDS = 5
export const HIVEMESH_PROVE_HELD_DEFAULT_COLD_WINDOW_SECONDS = 60

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_16 = /^[0-9a-f]{32}$/i

export function hiveMeshProveHeldCommitRoot (blockIndices, nonce) {
  const indices = normalizeBlockIndices(blockIndices)
  const nonceHex = lowerHex(nonce, HEX_16)
  if (!indices.ok) throw new Error(indices.reason)
  if (!nonceHex) throw new Error('nonce must be 16 bytes hex')
  return hashJson([
    HIVEMESH_PROVE_HELD_COMMIT_DOMAIN,
    indices.values,
    nonceHex
  ])
}

export function evaluateHiveMeshProveHeldProfile (input = {}) {
  const policy = normalizePolicy(input.policy)
  const sessions = []

  for (const session of Array.isArray(input.sessions) ? input.sessions : []) {
    sessions.push(evaluateSession(session, policy))
  }

  return {
    kind: HIVEMESH_PROVE_HELD_PROFILE_KIND,
    version: HIVEMESH_PROVE_HELD_PROFILE_VERSION,
    claim: 't2-commit-reveal-proof-of-held-ciphertext',
    limitation: 'fast cross-vault fetch can still pass if completed inside the reveal window',
    policy,
    sessions
  }
}

function evaluateSession (session, policy) {
  const id = typeof session?.id === 'string' ? session.id : null
  const commit = normalizeCommit(session?.commit)
  const reveal = normalizeReveal(session?.reveal)
  const response = normalizeResponse(session?.response)
  const base = { id, valid: false, commit: commit.value, reveal: reveal.value, response: response.value }

  if (!commit.ok) return reject(base, 'E_MALFORMED', commit.reason)
  if (!reveal.ok) return reject(base, 'E_MALFORMED', reveal.reason)
  if (!response.ok) return reject(base, 'E_MALFORMED', response.reason)

  if (commit.value.windowSeconds < policy.minWindowSeconds || commit.value.windowSeconds > policy.maxWindowSeconds) {
    return reject(base, 'E_WINDOW', 'window outside policy bounds', 'windowSeconds')
  }
  if (commit.value.deadline < commit.value.committedAt) {
    return reject(base, 'E_DEADLINE', 'deadline precedes commit', 'deadline')
  }
  if (reveal.value.revealedAt < commit.value.committedAt || reveal.value.revealedAt > commit.value.deadline) {
    return reject(base, 'E_DEADLINE', 'reveal outside commit deadline', 'revealedAt')
  }

  const expectedCommitRoot = hiveMeshProveHeldCommitRoot(reveal.value.blockIndices, reveal.value.nonce)
  if (reveal.value.commitRoot !== commit.value.commitRoot || expectedCommitRoot !== commit.value.commitRoot) {
    return reject(base, 'E_COMMIT_MISMATCH', 'reveal does not match committed challenge set', 'commitRoot', {
      expectedCommitRoot
    })
  }

  const responseDeadline = Math.min(commit.value.deadline, reveal.value.revealedAt + commit.value.windowSeconds)
  if (response.value.receivedAt > responseDeadline) {
    return reject(base, 'E_RESPONSE_DEADLINE', 'response arrived after reveal window', 'receivedAt', {
      responseDeadline
    })
  }
  if (!sameIntegerArray(response.value.blockIndices, reveal.value.blockIndices)) {
    return reject(base, 'E_RESPONSE_MISMATCH', 'response block indices do not match reveal', 'blockIndices')
  }
  if (response.value.blocks.length !== reveal.value.blockIndices.length) {
    return reject(base, 'E_RESPONSE_MISMATCH', 'response block count does not match reveal', 'blocks')
  }
  for (const block of response.value.blocks) {
    if (!reveal.value.blockIndices.includes(block.index)) {
      return reject(base, 'E_RESPONSE_MISMATCH', 'response block is outside reveal set', 'blocks')
    }
  }

  const domains = buildDomains(commit.value, reveal.value, response.value)
  const invalidDomain = domains.find(domain => domain.verdict.valid !== true)
  if (invalidDomain) {
    return reject(base, invalidDomain.verdict.code, invalidDomain.verdict.reason, invalidDomain.name)
  }

  return {
    ...base,
    valid: true,
    result: {
      expectedCommitRoot,
      responseDeadline,
      evidenceWeight: {
        numerator: 1,
        denominator: commit.value.windowSeconds
      },
      strength: commit.value.windowSeconds <= HIVEMESH_PROVE_HELD_DEFAULT_HOT_WINDOW_SECONDS
        ? 'hot'
        : 'cold'
    },
    domains: domains.map(publicDomain)
  }
}

function buildDomains (commit, reveal, response) {
  return [
    roleDomain('commit', 'rkv', 'commit', commit),
    roleDomain('reveal', 'rkv', 'reveal', reveal),
    roleDomain('response', 'rk2', 'proof-response', response)
  ]
}

function roleDomain (name, rolePrefix, messageType, payload) {
  const message = {
    protocol: 'hivemesh',
    rolePrefix,
    channel: 't2-prove-held',
    messageType,
    messageVersion: 1,
    payloadHash: hashJson(payload)
  }
  return {
    name,
    message,
    signableHex: b4a.toString(roleDomainSignable(message), 'hex'),
    verdict: validateRoleDomainMessage(message)
  }
}

function publicDomain (domain) {
  return {
    name: domain.name,
    message: domain.message,
    signableHex: domain.signableHex,
    verdict: {
      valid: domain.verdict.valid,
      code: domain.verdict.code,
      reason: domain.verdict.reason
    }
  }
}

function reject (base, code, reason, field = null, extra = {}) {
  return {
    ...base,
    error: { code, reason, field },
    ...extra
  }
}

function normalizePolicy (policy) {
  const p = policy && typeof policy === 'object' ? policy : {}
  const minWindowSeconds = safePositiveInteger(p.minWindowSeconds, 1)
  return {
    minWindowSeconds,
    hotWindowSeconds: safePositiveInteger(p.hotWindowSeconds, HIVEMESH_PROVE_HELD_DEFAULT_HOT_WINDOW_SECONDS),
    coldWindowSeconds: safePositiveInteger(p.coldWindowSeconds, HIVEMESH_PROVE_HELD_DEFAULT_COLD_WINDOW_SECONDS),
    maxWindowSeconds: Math.max(
      minWindowSeconds,
      safePositiveInteger(p.maxWindowSeconds, HIVEMESH_PROVE_HELD_DEFAULT_COLD_WINDOW_SECONDS)
    )
  }
}

function normalizeCommit (commit) {
  const value = {
    discoveryKey: lowerHex(commit?.discoveryKey, HEX_32),
    verifierPubkey: lowerHex(commit?.verifierPubkey, HEX_32),
    commitRoot: lowerHex(commit?.commitRoot, HEX_32),
    windowSeconds: safePositiveInteger(commit?.windowSeconds, null),
    deadline: safeNonNegativeInteger(commit?.deadline, null),
    committedAt: safeNonNegativeInteger(commit?.committedAt, null)
  }
  if (!value.discoveryKey) return { ok: false, reason: 'commit.discoveryKey required', value }
  if (!value.verifierPubkey) return { ok: false, reason: 'commit.verifierPubkey required', value }
  if (!value.commitRoot) return { ok: false, reason: 'commit.commitRoot must be 32 bytes hex', value }
  if (!Number.isSafeInteger(value.windowSeconds)) return { ok: false, reason: 'commit.windowSeconds must be positive integer', value }
  if (!Number.isSafeInteger(value.deadline)) return { ok: false, reason: 'commit.deadline must be non-negative integer', value }
  if (!Number.isSafeInteger(value.committedAt)) return { ok: false, reason: 'commit.committedAt must be non-negative integer', value }
  return { ok: true, value }
}

function normalizeReveal (reveal) {
  const indices = normalizeBlockIndices(reveal?.blockIndices)
  const value = {
    commitRoot: lowerHex(reveal?.commitRoot, HEX_32),
    blockIndices: indices.ok ? indices.values : [],
    nonce: lowerHex(reveal?.nonce, HEX_16),
    verifierPubkey: lowerHex(reveal?.verifierPubkey, HEX_32),
    revealedAt: safeNonNegativeInteger(reveal?.revealedAt, null)
  }
  if (!value.commitRoot) return { ok: false, reason: 'reveal.commitRoot must be 32 bytes hex', value }
  if (!indices.ok) return { ok: false, reason: indices.reason, value }
  if (!value.nonce) return { ok: false, reason: 'reveal.nonce must be 16 bytes hex', value }
  if (!value.verifierPubkey) return { ok: false, reason: 'reveal.verifierPubkey required', value }
  if (!Number.isSafeInteger(value.revealedAt)) return { ok: false, reason: 'reveal.revealedAt must be non-negative integer', value }
  return { ok: true, value }
}

function normalizeResponse (response) {
  const indices = normalizeBlockIndices(response?.blockIndices)
  const blocks = normalizeBlocks(response?.blocks)
  const value = {
    vaultPubkey: lowerHex(response?.vaultPubkey, HEX_32),
    blockIndices: indices.ok ? indices.values : [],
    blocks: blocks.ok ? blocks.values : [],
    receivedAt: safeNonNegativeInteger(response?.receivedAt, null)
  }
  if (!value.vaultPubkey) return { ok: false, reason: 'response.vaultPubkey required', value }
  if (!indices.ok) return { ok: false, reason: indices.reason, value }
  if (!blocks.ok) return { ok: false, reason: blocks.reason, value }
  if (!Number.isSafeInteger(value.receivedAt)) return { ok: false, reason: 'response.receivedAt must be non-negative integer', value }
  return { ok: true, value }
}

function normalizeBlocks (blocks) {
  if (!Array.isArray(blocks) || blocks.length === 0) return { ok: false, reason: 'response.blocks must be non-empty array' }
  const values = []
  for (const block of blocks) {
    const value = {
      index: safeNonNegativeInteger(block?.index, null),
      blockHash: lowerHex(block?.blockHash, HEX_32),
      merklePathHash: lowerHex(block?.merklePathHash, HEX_32),
      sigRoot: lowerHex(block?.sigRoot, HEX_32)
    }
    if (!Number.isSafeInteger(value.index)) return { ok: false, reason: 'response block index must be non-negative integer' }
    if (!value.blockHash) return { ok: false, reason: 'response blockHash must be 32 bytes hex' }
    if (!value.merklePathHash) return { ok: false, reason: 'response merklePathHash must be 32 bytes hex' }
    if (!value.sigRoot) return { ok: false, reason: 'response sigRoot must be 32 bytes hex' }
    values.push(value)
  }
  values.sort((a, b) => a.index - b.index)
  return { ok: true, values }
}

function normalizeBlockIndices (blockIndices) {
  if (!Array.isArray(blockIndices) || blockIndices.length === 0) {
    return { ok: false, reason: 'blockIndices must be non-empty array' }
  }
  const out = []
  const seen = new Set()
  for (const index of blockIndices) {
    if (!Number.isSafeInteger(index) || index < 0) return { ok: false, reason: 'blockIndices must be non-negative integers' }
    if (seen.has(index)) return { ok: false, reason: 'blockIndices must be unique' }
    seen.add(index)
    out.push(index)
  }
  out.sort((a, b) => a - b)
  return { ok: true, values: out }
}

function sameIntegerArray (a, b) {
  return a.length === b.length && a.every((value, index) => value === b[index])
}

function safePositiveInteger (value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback
}

function safeNonNegativeInteger (value, fallback) {
  return Number.isSafeInteger(value) && value >= 0 ? value : fallback
}

function lowerHex (value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) return null
  return value.toLowerCase()
}

function hashJson (value) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(stableStringify(value)))
  return b4a.toString(out, 'hex')
}

function stableStringify (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']'
  const keys = Object.keys(value).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stableStringify(value[key])).join(',') + '}'
}
