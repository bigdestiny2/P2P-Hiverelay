import b4a from 'b4a'
import sodium from 'sodium-universal'

export const ROLE_DOMAIN_SIGNATURE_PROFILE_KIND = 'role-domain-signature-profile'
export const ROLE_DOMAIN_SIGNATURE_PROFILE_VERSION = 1
export const ROLE_DOMAIN_SIGNATURE_DOMAIN = 'hiverelay-role-domain-signature-v1'

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_SIG = /^[0-9a-f]{128}$/i

const RELAYKERNEL_ROLE_RULES = Object.freeze({
  rk1: {
    'rk-seed': ['seed-ack', 'lease-expired', 'reject'],
    'rk-proof': ['proof-response', 'reject'],
    'rk-circuit': ['circuit-ack', 'circuit-close', 'reject'],
    'rk-meta': ['hello', 'directory-record', 'capability-doc', 'reject'],
    'rk-accounting': ['accounting-receipt']
  },
  rkp: {
    'rk-seed': ['seed', 'unseed', 'heartbeat'],
    'rk-meta': ['hello', 'query']
  },
  rkv: {
    'rk-proof': ['proof-challenge'],
    'rk-meta': ['hello', 'query']
  },
  rkc: {
    'rk-circuit': ['circuit-open', 'circuit-data', 'circuit-close'],
    'rk-meta': ['hello', 'query']
  }
})

const HIVEMESH_ROLE_RULES = Object.freeze({
  rk1: {
    't1-seed': ['seed-ack', 'lease-expired', 'reject'],
    't1-circuit': ['circuit-ack', 'circuit-close', 'reject'],
    't1-gateway': ['gateway-response', 'reject'],
    't1-dir': ['directory-record'],
    't1-accounting': ['accounting-receipt'],
    't1-anchor': ['anchor-proof']
  },
  rk2: {
    't2-custody': ['custody-receipt', 'custody-proof', 'non-serving-proof', 'reject'],
    't2-prove-held': ['proof-response', 'reject']
  },
  rk3: {
    't3-witness': ['tombstone', 'non-serving-observation'],
    't3-cosig': ['bandwidth-cosig']
  },
  rkp: {
    't1-seed': ['seed', 'unseed', 'heartbeat'],
    't2-custody': ['custody-intent', 'custody-commit', 'source-retired'],
    't1-dir': ['query']
  },
  rkv: {
    't1-proof': ['proof-challenge'],
    't2-prove-held': ['commit', 'reveal']
  }
})

const PROTOCOL_RULES = Object.freeze({
  relaykernel: RELAYKERNEL_ROLE_RULES,
  hivemesh: HIVEMESH_ROLE_RULES
})

export function roleDomainSignable (message) {
  const normalized = normalizeRoleDomainMessage(message)
  if (!normalized.ok) throw new Error(normalized.reason)
  return signableBytes(normalized.message)
}

export function validateRoleDomainMessage (message) {
  const normalized = normalizeRoleDomainMessage(message)
  if (!normalized.ok) {
    return {
      valid: false,
      code: 'E_MALFORMED',
      reason: normalized.reason,
      message: normalized.message
    }
  }

  const verdict = roleRuleVerdict(normalized.message)
  return {
    ...verdict,
    message: normalized.message
  }
}

export function signRoleDomainMessage (message, keyPair) {
  const verdict = validateRoleDomainMessage(message)
  if (!verdict.valid) throw new Error(verdict.code + ': ' + verdict.reason)
  if (!keyPair || !keyPair.secretKey || keyPair.secretKey.byteLength !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new Error('secretKey required')
  }

  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, signableBytes(verdict.message), keyPair.secretKey)
  return signature
}

export function verifyRoleDomainSignature (message, signature, publicKey) {
  const verdict = validateRoleDomainMessage(message)
  if (!verdict.valid) return verdict

  const sig = bufferFromSignature(signature)
  if (!sig) {
    return { valid: false, code: 'E_MALFORMED', reason: 'signature must be 64 bytes', message: verdict.message }
  }
  const pub = bufferFromPublicKey(publicKey)
  if (!pub) {
    return { valid: false, code: 'E_MALFORMED', reason: 'publicKey must be 32 bytes', message: verdict.message }
  }

  const ok = sodium.crypto_sign_verify_detached(sig, signableBytes(verdict.message), pub)
  return ok
    ? { valid: true, code: null, reason: null, message: verdict.message }
    : { valid: false, code: 'E_BAD_SIGNATURE', reason: 'signature does not verify for role domain', message: verdict.message }
}

export function evaluateRoleDomainSignatureProfile (input = {}) {
  const keyPair = keyPairFromSeed(input.seedHex)
  const publicKey = keyPair ? b4a.toString(keyPair.publicKey, 'hex') : null
  const messages = []
  const byId = new Map()

  for (const item of Array.isArray(input.messages) ? input.messages : []) {
    const row = evaluateMessage(item, keyPair, publicKey)
    messages.push(row)
    if (row.id) byId.set(row.id, row)
  }

  return {
    kind: ROLE_DOMAIN_SIGNATURE_PROFILE_KIND,
    version: ROLE_DOMAIN_SIGNATURE_PROFILE_VERSION,
    domain: ROLE_DOMAIN_SIGNATURE_DOMAIN,
    publicKey,
    messages,
    replayChecks: evaluateReplayChecks(input.replayChecks, byId, publicKey)
  }
}

function evaluateMessage (item, keyPair, publicKey) {
  const normalized = normalizeRoleDomainMessage(item)
  const id = typeof item?.id === 'string' ? item.id : null
  if (!normalized.ok) {
    return {
      id,
      validShape: false,
      allowed: false,
      message: normalized.message,
      error: {
        code: 'E_MALFORMED',
        reason: normalized.reason
      }
    }
  }

  const verdict = roleRuleVerdict(normalized.message)
  const signableHex = b4a.toString(signableBytes(normalized.message), 'hex')
  const row = {
    id,
    validShape: true,
    allowed: verdict.valid,
    message: normalized.message,
    signableHex
  }

  if (!verdict.valid) {
    row.error = {
      code: verdict.code,
      reason: verdict.reason
    }
    return row
  }

  if (keyPair) {
    const signature = signRoleDomainMessage(normalized.message, keyPair)
    row.signature = b4a.toString(signature, 'hex')
    row.verify = publicVerdict(verifyRoleDomainSignature(normalized.message, signature, keyPair.publicKey))
    row.publicKey = publicKey
  }

  return row
}

function publicVerdict (verdict) {
  return {
    valid: verdict.valid,
    code: verdict.code,
    reason: verdict.reason
  }
}

function evaluateReplayChecks (checks, byId, publicKey) {
  const rows = []
  for (const check of Array.isArray(checks) ? checks : []) {
    const from = byId.get(check?.signatureFrom)
    const targetRow = check?.targetId ? byId.get(check.targetId) : null
    const target = targetRow ? targetRow.message : check?.target
    const signature = from?.signature || check?.signature
    const verdict = verifyRoleDomainSignature(target, signature, publicKey)
    rows.push({
      name: typeof check?.name === 'string' ? check.name : null,
      signatureFrom: typeof check?.signatureFrom === 'string' ? check.signatureFrom : null,
      targetId: typeof check?.targetId === 'string' ? check.targetId : null,
      valid: verdict.valid,
      code: verdict.code,
      reason: verdict.reason
    })
  }
  return rows
}

function roleRuleVerdict (message) {
  const protocol = PROTOCOL_RULES[message.protocol]
  if (!protocol) {
    return { valid: false, code: 'E_PROTOCOL', reason: 'unsupported protocol: ' + message.protocol }
  }

  const role = protocol[message.rolePrefix]
  if (!role) {
    return { valid: false, code: 'E_KEY_ROLE', reason: 'role not allowed for protocol: ' + message.rolePrefix }
  }

  const channel = role[message.channel]
  if (!channel) {
    return {
      valid: false,
      code: message.protocol === 'hivemesh' ? 'E_KEY_TIER' : 'E_KEY_ROLE',
      reason: message.rolePrefix + ' cannot sign channel ' + message.channel
    }
  }
  if (!channel.includes(message.messageType)) {
    return {
      valid: false,
      code: message.protocol === 'hivemesh' ? 'E_KEY_TIER' : 'E_KEY_ROLE',
      reason: message.rolePrefix + ' cannot sign ' + message.channel + '/' + message.messageType
    }
  }

  return { valid: true, code: null, reason: null }
}

function normalizeRoleDomainMessage (message) {
  const normalized = {
    protocol: lowerToken(message?.protocol),
    rolePrefix: lowerToken(message?.rolePrefix),
    channel: lowerToken(message?.channel),
    messageType: lowerToken(message?.messageType),
    messageVersion: Number.isSafeInteger(message?.messageVersion) ? message.messageVersion : null,
    payloadHash: lowerHex(message?.payloadHash, HEX_32)
  }

  if (!normalized.protocol) return { ok: false, reason: 'protocol required', message: normalized }
  if (!normalized.rolePrefix) return { ok: false, reason: 'rolePrefix required', message: normalized }
  if (!normalized.channel) return { ok: false, reason: 'channel required', message: normalized }
  if (!normalized.messageType) return { ok: false, reason: 'messageType required', message: normalized }
  if (!Number.isSafeInteger(normalized.messageVersion) || normalized.messageVersion < 0 || normalized.messageVersion > 255) {
    return { ok: false, reason: 'messageVersion must be a u8 integer', message: normalized }
  }
  if (!normalized.payloadHash) return { ok: false, reason: 'payloadHash must be 32 bytes hex', message: normalized }
  return { ok: true, message: normalized }
}

function signableBytes (message) {
  return b4a.from(JSON.stringify([
    ROLE_DOMAIN_SIGNATURE_DOMAIN,
    message.protocol,
    message.rolePrefix,
    message.channel,
    message.messageType,
    message.messageVersion,
    message.payloadHash
  ]))
}

function keyPairFromSeed (seedHex) {
  if (typeof seedHex !== 'string' || !HEX_32.test(seedHex)) return null
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.from(seedHex, 'hex'))
  return { publicKey, secretKey }
}

function bufferFromSignature (value) {
  if (b4a.isBuffer(value)) return value.byteLength === sodium.crypto_sign_BYTES ? value : null
  if (typeof value !== 'string' || !HEX_SIG.test(value)) return null
  return b4a.from(value, 'hex')
}

function bufferFromPublicKey (value) {
  if (b4a.isBuffer(value)) return value.byteLength === sodium.crypto_sign_PUBLICKEYBYTES ? value : null
  if (typeof value !== 'string' || !HEX_32.test(value)) return null
  return b4a.from(value, 'hex')
}

function lowerToken (value) {
  return typeof value === 'string' && value.length > 0 ? value.toLowerCase() : null
}

function lowerHex (value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) return null
  return value.toLowerCase()
}
