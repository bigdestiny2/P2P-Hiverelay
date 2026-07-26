/**
 * Signed, fail-closed durability acknowledgements between independently run
 * OutboxLog relays. This is deliberately a small HTTP control protocol rather
 * than an inference from swarm membership: a browser is only told that a
 * commit is published after the configured remote relays have committed the
 * exact signed transition and returned receipts for that transition.
 */
import b4a from 'b4a'
import sodium from 'sodium-universal'

export const OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL = 'hiverelay-outboxlog-federation-v1'
export const OUTBOXLOG_FEDERATION_QUORUM_VERSION = 1
export const OUTBOXLOG_FEDERATION_QUORUM_PATH = '/api/sync/federation/commit'

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_64 = /^[0-9a-f]{128}$/i
const MAX_PEERS = 32
const MAX_TIMEOUT_MS = 60_000
const DEFAULT_TIMEOUT_MS = 8_000
const MAX_CLOCK_SKEW_MS = 2 * 60_000

export function createOutboxFederationQuorum ({ config, keyPair, fetch: request = globalThis.fetch, now = () => Date.now() } = {}) {
  const normalized = normalizeOutboxFederationQuorumConfig(config)
  if (!normalized.enabled) return disabledQuorum()
  assertKeyPair(keyPair)
  if (typeof request !== 'function') throw new Error('OutboxLog: federation quorum requires fetch')

  const relayPubkey = hex(keyPair.publicKey, 'relay key')
  return {
    enabled: true,
    descriptor: () => publicDescriptor(normalized),

    // The caller has already made the local atomic commit durable. A response
    // is only successful when enough distinct configured remote operators
    // return signed receipts for this exact resulting head.
    async confirm ({ appId, commit, localReceipt }) {
      const expected = receiptExpectation(appId, commit, localReceipt)
      const envelope = signFederationRequest({
        appId: expected.appId,
        commit,
        senderPubkey: relayPubkey,
        issuedAt: now()
      }, keyPair)
      const attempts = await Promise.all(normalized.peers.map(async peer => {
        try {
          const receipt = await postFederationCommit(peer.url, envelope, request, normalized.timeoutMs)
          const verified = verifyFederationReceipt(receipt, {
            appId: expected.appId,
            commitId: expected.commitId,
            head: expected.head,
            relayPubkey: peer.publicKey
          })
          if (!verified.valid) return { peer, receipt: null, reason: verified.reason }
          return { peer, receipt: verified.receipt, reason: null }
        } catch (err) {
          return { peer, receipt: null, reason: err && err.message ? err.message : 'request failed' }
        }
      }))
      const receipts = attempts.filter(result => result.receipt).map(result => result.receipt)
      if (receipts.length < normalized.quorum) {
        const err = new Error('network durability quorum not reached')
        err.status = 503
        err.code = 'OUTBOXLOG_FEDERATION_QUORUM_UNAVAILABLE'
        // Keep diagnostics content-free; a caller can safely log which relay
        // ids timed out without leaking post bodies or bearer credentials.
        err.detail = attempts.map(({ peer, reason }) => ({ peerId: peer.id, acknowledged: !reason, reason: reason || null }))
        throw err
      }
      return {
        protocol: OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL,
        version: OUTBOXLOG_FEDERATION_QUORUM_VERSION,
        requiredRemoteAcks: normalized.quorum,
        receipts
      }
    },

    // Called only by the private federation route. Configured peer public keys
    // are the authentication boundary; browser bearer tokens are never valid
    // for this path.
    async accept (envelope, sync) {
      const verified = verifyFederationRequest(envelope, {
        allowedSenders: normalized.peers.map(peer => peer.publicKey),
        now
      })
      if (!verified.valid) {
        const err = new Error('invalid federation commit: ' + verified.reason)
        err.status = 401
        throw err
      }
      if (!sync || typeof sync.commit !== 'function') {
        const err = new Error('atomic commit unavailable')
        err.status = 503
        throw err
      }
      const localReceipt = await sync.commit(verified.envelope.appId, verified.envelope.commit)
      const expected = receiptExpectation(verified.envelope.appId, verified.envelope.commit, localReceipt)
      return createFederationReceipt({
        appId: expected.appId,
        commitId: expected.commitId,
        head: expected.head,
        relayPubkey,
        committedAt: now()
      }, keyPair)
    }
  }
}

export function normalizeOutboxFederationQuorumConfig (value) {
  if (value === undefined || value === false || value == null) return { enabled: false }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('outboxlog.federationQuorum must be an object or false')
  }
  const allowed = new Set(['enabled', 'quorum', 'peers', 'timeoutMs'])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new TypeError('outboxlog.federationQuorum has unknown field: ' + key)
  }
  if (value.enabled !== true) return { enabled: false }
  if (!Array.isArray(value.peers) || value.peers.length === 0 || value.peers.length > MAX_PEERS) {
    throw new TypeError('outboxlog.federationQuorum.peers must contain 1 to ' + MAX_PEERS + ' peers')
  }
  const seen = new Set()
  const peers = value.peers.map((peer, index) => normalizePeer(peer, index, seen))
  const quorum = positiveInteger(value.quorum, 'outboxlog.federationQuorum.quorum', peers.length)
  const timeoutMs = value.timeoutMs === undefined
    ? DEFAULT_TIMEOUT_MS
    : positiveInteger(value.timeoutMs, 'outboxlog.federationQuorum.timeoutMs', MAX_TIMEOUT_MS)
  return { enabled: true, quorum, timeoutMs, peers }
}

export function signFederationRequest (input, keyPair) {
  assertKeyPair(keyPair)
  const unsigned = normalizeFederationRequest({
    protocol: OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL,
    version: OUTBOXLOG_FEDERATION_QUORUM_VERSION,
    ...input
  }, { signatureRequired: false })
  const signature = signBytes(federationSignable('request', unsigned), keyPair)
  return { ...unsigned, signature }
}

export function verifyFederationRequest (input, { allowedSenders = [], now = () => Date.now() } = {}) {
  try {
    const envelope = normalizeFederationRequest(input, { signatureRequired: true })
    const allowed = new Set(allowedSenders.map(value => hex(value, 'allowed sender')))
    if (!allowed.has(envelope.senderPubkey)) return { valid: false, reason: 'sender is not configured' }
    if (Math.abs(now() - envelope.issuedAt) > MAX_CLOCK_SKEW_MS) return { valid: false, reason: 'request timestamp outside replay window' }
    if (!verifyBytes(federationSignable('request', withoutSignature(envelope)), envelope.signature, envelope.senderPubkey)) {
      return { valid: false, reason: 'bad signature' }
    }
    return { valid: true, envelope }
  } catch (err) {
    return { valid: false, reason: err.message || 'malformed request' }
  }
}

export function createFederationReceipt (input, keyPair) {
  assertKeyPair(keyPair)
  const relayPubkey = hex(keyPair.publicKey, 'relay key')
  const unsigned = normalizeFederationReceipt({
    protocol: OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL,
    version: OUTBOXLOG_FEDERATION_QUORUM_VERSION,
    ...input,
    relayPubkey
  }, { signatureRequired: false })
  return { ...unsigned, signature: signBytes(federationSignable('receipt', unsigned), keyPair) }
}

export function verifyFederationReceipt (input, expected = {}) {
  try {
    const receipt = normalizeFederationReceipt(input, { signatureRequired: true })
    if (expected.appId && receipt.appId !== hex(expected.appId, 'expected appId')) return { valid: false, reason: 'appId mismatch' }
    if (expected.commitId && receipt.commitId !== hex(expected.commitId, 'expected commitId')) return { valid: false, reason: 'commitId mismatch' }
    if (expected.relayPubkey && receipt.relayPubkey !== hex(expected.relayPubkey, 'expected relay key')) return { valid: false, reason: 'relay key mismatch' }
    if (expected.head && !sameHead(receipt.head, expected.head)) return { valid: false, reason: 'head mismatch' }
    if (!verifyBytes(federationSignable('receipt', withoutSignature(receipt)), receipt.signature, receipt.relayPubkey)) {
      return { valid: false, reason: 'bad signature' }
    }
    return { valid: true, receipt }
  } catch (err) {
    return { valid: false, reason: err.message || 'malformed receipt' }
  }
}

function disabledQuorum () {
  return {
    enabled: false,
    descriptor: () => ({ enabled: false }),
    async confirm () { return null },
    async accept () {
      const err = new Error('federation quorum unavailable')
      err.status = 404
      throw err
    }
  }
}

function normalizePeer (peer, index, seen) {
  if (!peer || typeof peer !== 'object' || Array.isArray(peer)) throw new TypeError('outboxlog.federationQuorum.peers[' + index + '] must be an object')
  for (const key of Object.keys(peer)) {
    if (key !== 'id' && key !== 'url' && key !== 'publicKey') throw new TypeError('outboxlog.federationQuorum.peers[' + index + '] has unknown field: ' + key)
  }
  const id = typeof peer.id === 'string' && peer.id.trim() ? peer.id.trim() : 'relay-' + (index + 1)
  if (id.length > 128) throw new TypeError('outboxlog.federationQuorum peer id too long')
  let url
  try {
    url = new URL(String(peer.url))
  } catch {
    throw new TypeError('outboxlog.federationQuorum peer url invalid')
  }
  if (url.protocol !== 'https:' && url.hostname !== '127.0.0.1' && url.hostname !== 'localhost') {
    throw new TypeError('outboxlog.federationQuorum peer url must use https')
  }
  if (url.username || url.password || url.search || url.hash) throw new TypeError('outboxlog.federationQuorum peer url cannot include credentials, query, or fragment')
  const publicKey = hex(peer.publicKey, 'outboxlog.federationQuorum peer publicKey')
  if (seen.has(publicKey)) throw new TypeError('outboxlog.federationQuorum peer public keys must be unique')
  seen.add(publicKey)
  return { id, url: url.href.replace(/\/$/, ''), publicKey }
}

function normalizeFederationRequest (input, { signatureRequired }) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('request object required')
  assertExactKeys(input, ['protocol', 'version', 'appId', 'commit', 'senderPubkey', 'issuedAt', 'signature'], signatureRequired, 'request')
  if (input.protocol !== OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL || input.version !== OUTBOXLOG_FEDERATION_QUORUM_VERSION) throw new TypeError('unsupported federation protocol')
  if (!input.commit || typeof input.commit !== 'object' || Array.isArray(input.commit)) throw new TypeError('request commit required')
  return {
    protocol: input.protocol,
    version: input.version,
    appId: hex(input.appId, 'request appId'),
    commit: input.commit,
    senderPubkey: hex(input.senderPubkey, 'request senderPubkey'),
    issuedAt: timestamp(input.issuedAt, 'request issuedAt'),
    ...(signatureRequired ? { signature: signature(input.signature) } : {})
  }
}

function normalizeFederationReceipt (input, { signatureRequired }) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('receipt object required')
  assertExactKeys(input, ['protocol', 'version', 'appId', 'commitId', 'head', 'relayPubkey', 'committedAt', 'signature'], signatureRequired, 'receipt')
  if (input.protocol !== OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL || input.version !== OUTBOXLOG_FEDERATION_QUORUM_VERSION) throw new TypeError('unsupported federation protocol')
  return {
    protocol: input.protocol,
    version: input.version,
    appId: hex(input.appId, 'receipt appId'),
    commitId: hex(input.commitId, 'receipt commitId'),
    head: normalizeHead(input.head),
    relayPubkey: hex(input.relayPubkey, 'receipt relayPubkey'),
    committedAt: timestamp(input.committedAt, 'receipt committedAt'),
    ...(signatureRequired ? { signature: signature(input.signature) } : {})
  }
}

function publicDescriptor (config) {
  return {
    enabled: true,
    protocol: OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL,
    version: OUTBOXLOG_FEDERATION_QUORUM_VERSION,
    requiredRemoteAcks: config.quorum,
    relays: config.peers.map(peer => ({ id: peer.id, publicKey: peer.publicKey }))
  }
}

function receiptExpectation (appId, commit, localReceipt) {
  if (!localReceipt || localReceipt.durable !== true) throw new Error('local atomic commit is not durable')
  return {
    appId: hex(appId, 'appId'),
    commitId: hex(commit && commit.commitId, 'commitId'),
    head: normalizeHead(localReceipt.head)
  }
}

async function postFederationCommit (url, envelope, request, timeoutMs) {
  const controller = typeof AbortController === 'function' ? new AbortController() : null
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null
  try {
    const res = await request(url + OUTBOXLOG_FEDERATION_QUORUM_PATH, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
      ...(controller ? { signal: controller.signal } : {})
    })
    let body = null
    try { body = await res.json() } catch {}
    if (!res || res.ok !== true || !body || typeof body !== 'object') throw new Error((body && body.error) || 'relay did not acknowledge')
    return body.receipt || body
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function federationSignable (kind, value) {
  return b4a.from(OUTBOXLOG_FEDERATION_QUORUM_PROTOCOL + '|' + kind + '|' + stable(value), 'utf8')
}

function signBytes (bytes, keyPair) {
  const out = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(out, bytes, keyPair.secretKey)
  return b4a.toString(out, 'hex')
}

function verifyBytes (bytes, sig, publicKey) {
  const signature = b4a.from(sig, 'hex')
  const key = b4a.from(publicKey, 'hex')
  return signature.byteLength === sodium.crypto_sign_BYTES && key.byteLength === sodium.crypto_sign_PUBLICKEYBYTES && sodium.crypto_sign_verify_detached(signature, bytes, key)
}

function stable (value) {
  if (value === null) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('federation value must be JSON')
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}

function normalizeHead (head) {
  if (!head || typeof head !== 'object' || Array.isArray(head)) throw new TypeError('head required')
  assertExactKeys(head, ['version', 'count', 'root'], true, 'head')
  if (!Number.isSafeInteger(head.version) || head.version < 1) throw new TypeError('head version invalid')
  if (!Number.isSafeInteger(head.count) || head.count < 0) throw new TypeError('head count invalid')
  return { version: head.version, count: head.count, root: hex(head.root, 'head root') }
}

function sameHead (left, right) {
  const expected = normalizeHead(right)
  return left.version === expected.version && left.count === expected.count && left.root === expected.root
}

function assertKeyPair (keyPair) {
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) throw new Error('OutboxLog: federation quorum requires relay Ed25519 keypair')
  if (b4a.from(keyPair.publicKey).byteLength !== sodium.crypto_sign_PUBLICKEYBYTES || b4a.from(keyPair.secretKey).byteLength !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new Error('OutboxLog: federation quorum relay keypair invalid')
  }
}

function assertExactKeys (value, allowed, signatureRequired, label) {
  const expected = signatureRequired ? allowed : allowed.filter(key => key !== 'signature')
  const actual = Object.keys(value).sort()
  const sorted = [...expected].sort()
  if (actual.length !== sorted.length || actual.some((key, index) => key !== sorted[index])) throw new TypeError(label + ' fields invalid')
}

function withoutSignature (value) {
  const { signature, ...unsigned } = value
  return unsigned
}

function hex (value, name) {
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) value = b4a.toString(value, 'hex')
  const out = typeof value === 'string' ? value.toLowerCase() : ''
  if (!HEX_32.test(out)) throw new TypeError(name + ' must be 32-byte hex')
  return out
}

function signature (value) {
  const out = typeof value === 'string' ? value.toLowerCase() : ''
  if (!HEX_64.test(out)) throw new TypeError('signature must be 64-byte hex')
  return out
}

function timestamp (value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(name + ' must be a timestamp')
  return value
}

function positiveInteger (value, name, max) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new TypeError(name + ' must be an integer from 1 to ' + max)
  return value
}
