// pow-issuance-v1 issuer — small public HTTP(S) service, operator-run per fleet.
// GET  /challenge → fresh HMAC-signed challenge (random 32B id, short TTL)
// POST /redeem    → verify hashcash over challenge‖recordCommitment‖nonce, issue token
// No accounts, no database. recordCommitment is held only in request-scope memory and
// is never logged (owner decision D2 disclosure: issuer and relay share one operator;
// issuance↔redemption unlinkability is operator-trust at v1).
import http from 'node:http'
import https from 'node:https'
import b4a from 'b4a'
import {
  POW_ISSUANCE_V1_DEFAULT_CHALLENGE_TTL_SECONDS,
  POW_ISSUANCE_V1_DEFAULT_DIFFICULTY_BITS,
  POW_ISSUANCE_V1_DEFAULT_TOKEN_TTL_EPOCHS,
  POW_ISSUANCE_V1_MAX_ALLOWANCE,
  POW_ISSUANCE_V1_MAX_DIFFICULTY_BITS,
  POW_ISSUANCE_V1_MAX_TOKEN_TTL_EPOCHS,
  POW_ISSUANCE_V1_SCHEME_ID,
  derivePowIssuanceV1Keys,
  mintPowIssuanceV1Challenge,
  mintPowIssuanceV1Token,
  parsePowIssuanceV1Challenge,
  verifyPowIssuanceV1Work,
  wipePowIssuanceV1Key
} from './token-codec.js'

const SIX_HOURS_MILLIS = 21_600_000
const MAX_BODY_BYTES = 8 * 1024
const MAX_REDEEMED_CHALLENGES = 65536
const PUBLIC_BROWSER_HEADERS = Object.freeze({
  'access-control-allow-origin': '*',
  'cross-origin-resource-policy': 'cross-origin'
})
const PREFLIGHT_MAX_AGE_SECONDS = '600'

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function defaultEpochNow () {
  return Math.floor(Date.now() / SIX_HOURS_MILLIS)
}

function base64url (bytes) {
  return b4a.toString(bytes, 'base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromBase64url (text) {
  if (typeof text !== 'string' || !/^[0-9A-Za-z_-]+$/.test(text)) {
    fail('POW_CHALLENGE_INVALID', 'challenge is not base64url')
  }
  return b4a.from(text.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
}

function hexBytes (value, length, field) {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]+$/.test(value)) fail('POW_ISSUANCE_INVALID', `${field} must be hex`)
  const bytes = b4a.from(value, 'hex')
  if (bytes.byteLength !== length) fail('POW_ISSUANCE_INVALID', `${field} must be exactly ${length} bytes`)
  return bytes
}

function readBody (request) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    request.on('data', chunk => {
      total += chunk.byteLength
      if (total > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('redeem body exceeds 8KiB'), { code: 'POW_BODY_TOO_LARGE' }))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.once('error', reject)
    request.once('end', () => resolve(b4a.concat(chunks, total)))
  })
}

function sendJson (response, status, value) {
  const body = b4a.from(JSON.stringify(value), 'utf8')
  response.writeHead(status, {
    ...PUBLIC_BROWSER_HEADERS,
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(body.byteLength),
    'cache-control': 'no-store'
  })
  response.end(body)
}

function sendPreflight (response, methods, allowHeaders = null) {
  const headers = {
    ...PUBLIC_BROWSER_HEADERS,
    'access-control-allow-methods': methods,
    'access-control-max-age': PREFLIGHT_MAX_AGE_SECONDS,
    'cache-control': 'no-store',
    'content-length': '0'
  }
  if (allowHeaders !== null) headers['access-control-allow-headers'] = allowHeaders
  response.writeHead(204, headers)
  response.end()
}

export function createPowIssuanceV1Issuer (options = {}) {
  if (!options.issuerKey || typeof options.issuerKey.byteLength !== 'number' ||
      options.issuerKey.byteLength !== 32) {
    throw new TypeError('the 32-byte fleet issuer key is required')
  }
  const keys = derivePowIssuanceV1Keys(options.issuerKey)
  const difficultyBits = options.difficultyBits == null
    ? POW_ISSUANCE_V1_DEFAULT_DIFFICULTY_BITS
    : options.difficultyBits
  if (!Number.isInteger(difficultyBits) || difficultyBits < 1 ||
      difficultyBits > POW_ISSUANCE_V1_MAX_DIFFICULTY_BITS) {
    throw new TypeError('difficultyBits must be within 1..32')
  }
  const challengeTtlSeconds = options.challengeTtlSeconds == null
    ? POW_ISSUANCE_V1_DEFAULT_CHALLENGE_TTL_SECONDS
    : options.challengeTtlSeconds
  if (!Number.isInteger(challengeTtlSeconds) || challengeTtlSeconds < 5 || challengeTtlSeconds > 3600) {
    throw new TypeError('challengeTtlSeconds must be within 5..3600')
  }
  const tokenTtlEpochs = options.tokenTtlEpochs == null
    ? POW_ISSUANCE_V1_DEFAULT_TOKEN_TTL_EPOCHS
    : options.tokenTtlEpochs
  if (!Number.isInteger(tokenTtlEpochs) || tokenTtlEpochs < 1 || tokenTtlEpochs > POW_ISSUANCE_V1_MAX_TOKEN_TTL_EPOCHS) {
    throw new TypeError('tokenTtlEpochs must be within 1..4')
  }
  const maxAllowance = options.maxAllowance == null ? 2 : options.maxAllowance
  if (!Number.isInteger(maxAllowance) || maxAllowance < 1 || maxAllowance > POW_ISSUANCE_V1_MAX_ALLOWANCE) {
    throw new TypeError('maxAllowance must be within 1..8')
  }
  const epochNow = typeof options.epochNow === 'function' ? options.epochNow : defaultEpochNow
  const nowUnix = typeof options.nowUnix === 'function' ? options.nowUnix : () => Math.floor(Date.now() / 1000)

  // One token per challenge: redeemed challengeIds live only until their TTL has
  // certainly passed, in memory, bounded.
  const redeemed = new Map() // challengeId hex -> evict-at unix time
  const sweepRedeemed = now => {
    if (redeemed.size < MAX_REDEEMED_CHALLENGES) return
    for (const [id, evictAt] of redeemed) {
      if (now >= evictAt) redeemed.delete(id)
    }
    if (redeemed.size >= MAX_REDEEMED_CHALLENGES) {
      fail('BUSY', 'pow-issuance-v1 issuer redeemed-challenge memory is full')
    }
  }

  async function handleChallenge (response) {
    const challenge = mintPowIssuanceV1Challenge(keys.challengeKey, {
      ttlSeconds: challengeTtlSeconds,
      difficultyBits,
      issuedAtUnix: nowUnix()
    })
    sendJson(response, 200, {
      scheme: 'pow-issuance-v1',
      challenge: base64url(challenge),
      difficultyBits,
      expiresAtUnix: nowUnix() + challengeTtlSeconds
    })
  }

  async function handleRedeem (request, response) {
    const raw = await readBody(request)
    let body
    try {
      body = JSON.parse(b4a.toString(raw, 'utf8'))
    } catch {
      fail('POW_ISSUANCE_INVALID', 'redeem body must be JSON')
    }
    if (!body || typeof body !== 'object') fail('POW_ISSUANCE_INVALID', 'redeem body must be a JSON object')
    const challenge = fromBase64url(body.challenge)
    const parsed = parsePowIssuanceV1Challenge(keys.challengeKey, challenge, { nowUnix: nowUnix() })
    const recordCommitment = hexBytes(body.recordCommitment, 32, 'recordCommitment')
    const nonce = hexBytes(body.nonce, 8, 'nonce')
    const allowance = body.allowance == null ? maxAllowance : body.allowance
    if (!Number.isInteger(allowance) || allowance < 1 || allowance > maxAllowance) {
      fail('POW_ALLOWANCE_INVALID', `allowance must be within 1..${maxAllowance}`)
    }
    const challengeKey = b4a.toString(parsed.challengeId, 'hex')
    sweepRedeemed(nowUnix())
    if (redeemed.has(challengeKey)) {
      fail('POW_CHALLENGE_REPLAYED', 'pow-issuance-v1 challenge was already redeemed')
    }
    if (!verifyPowIssuanceV1Work({
      difficultyBits: parsed.difficultyBits,
      challengePayload: parsed.payload,
      recordCommitment,
      nonce: BigInt('0x' + b4a.toString(nonce, 'hex'))
    })) {
      fail('POW_INSUFFICIENT_WORK', 'proof-of-work does not meet the required difficulty')
    }
    redeemed.set(challengeKey, parsed.issuedAtUnix + parsed.ttlSeconds)
    const expiryEpoch = epochNow() + tokenTtlEpochs
    const token = mintPowIssuanceV1Token(keys.tokenKey, {
      challengeId: parsed.challengeId,
      recordCommitment,
      allowance,
      expiryEpoch
    })
    sendJson(response, 200, {
      scheme: 'pow-issuance-v1',
      token: b4a.toString(token, 'hex'),
      allowance,
      expiryEpoch
    })
  }

  const server = options.tls && options.tls.key && options.tls.cert
    ? https.createServer({ key: options.tls.key, cert: options.tls.cert }, handle)
    : http.createServer(handle)

  function handle (request, response) {
    const path = (request.url || '').split('?')[0]
    if (request.method === 'OPTIONS') {
      if (path === '/challenge' || path === '/health') {
        sendPreflight(response, 'GET, OPTIONS')
        return
      }
      if (path === '/redeem') {
        sendPreflight(response, 'POST, OPTIONS', 'content-type')
        return
      }
    }
    const route = `${request.method} ${path}`
    const work = route === 'GET /challenge'
      ? handleChallenge(response)
      : route === 'POST /redeem'
        ? handleRedeem(request, response)
        : route === 'GET /health'
          ? Promise.resolve(sendJson(response, 200, {
            ok: true,
            scheme: 'pow-issuance-v1',
            schemeId: POW_ISSUANCE_V1_SCHEME_ID,
            difficultyBits
          }))
          : Promise.reject(Object.assign(new Error('not found'), { code: 'NOT_FOUND' }))
    work.catch(error => {
      const status = error && error.code === 'NOT_FOUND' ? 404 : error && error.code === 'BUSY' ? 503 : 400
      sendJson(response, status, { error: typeof error?.code === 'string' ? error.code : 'POW_ISSUANCE_INVALID' })
    })
  }

  let closed = false
  return Object.freeze({
    difficultyBits,
    challengeTtlSeconds,
    tokenTtlEpochs,
    maxAllowance,
    server,
    start () {
      return new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen(options.port == null ? 0 : options.port, options.host || '127.0.0.1', () => {
          server.off('error', reject)
          resolve(server.address())
        })
      })
    },
    address () {
      return server.address()
    },
    close () {
      if (closed) return Promise.resolve()
      closed = true
      return new Promise(resolve => server.close(() => {
        wipePowIssuanceV1Key(keys.challengeKey)
        wipePowIssuanceV1Key(keys.tokenKey)
        resolve()
      }))
    }
  })
}
