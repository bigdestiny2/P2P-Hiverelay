/**
 * FCM (Firebase Cloud Messaging) HTTP v1 egress adapter.
 *
 * Two hops: an RS256 service-account assertion is exchanged at Google's OAuth2
 * endpoint for a short-lived access token, which then authorizes the send. The
 * two hops get separate transport seams so a test can drive them independently
 * and prove the access token is actually cached rather than re-minted per send.
 */

import { rs256Jwt, loadServiceAccountKey, TokenCache } from './jwt.js'

export const FCM_TOKEN_URL = 'https://oauth2.googleapis.com/token'
export const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging'
const ASSERTION_TTL_SECONDS = 3600
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'

const URGENCY_PRIORITY = { silent: 'normal', normal: 'high', high: 'high' }

export function createFcmProvider (opts = {}) {
  const credentials = opts.credentials || {}
  const key = loadServiceAccountKey(credentials.privateKey)
  const clientEmail = requireString(credentials.clientEmail, 'fcm.credentials.clientEmail')
  const projectId = requireString(credentials.projectId, 'fcm.credentials.projectId')
  const tokenUrl = credentials.tokenUrl || FCM_TOKEN_URL
  const sendUrl = credentials.sendUrl ||
    ('https://fcm.googleapis.com/v1/projects/' + encodeURIComponent(projectId) + '/messages:send')
  const transport = opts.transport || defaultTransport
  const tokenTransport = opts.tokenTransport || opts.transport || defaultTransport
  const openToken = requireFunction(opts.openToken, 'openToken')
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now()
  const cache = new TokenCache({ now })

  async function accessToken () {
    const cached = cache.get()
    if (cached) return cached
    const issuedAt = Math.floor(now() / 1000)
    const assertion = rs256Jwt({
      header: {},
      payload: {
        iss: clientEmail,
        scope: FCM_SCOPE,
        aud: tokenUrl,
        iat: issuedAt,
        exp: issuedAt + ASSERTION_TTL_SECONDS
      },
      key
    })
    const response = await tokenTransport({
      method: 'POST',
      url: tokenUrl,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      form: { grant_type: GRANT_TYPE, assertion }
    })
    const body = response && response.body ? response.body : null
    if (!body || typeof body.access_token !== 'string' || !body.access_token) {
      throw new Error('fcm_token_exchange_failed')
    }
    const expiresIn = Number.isFinite(body.expires_in) ? body.expires_in : ASSERTION_TTL_SECONDS
    // Expire a minute early so a token never goes stale mid-flight.
    return cache.set(body.access_token, Math.max(1, expiresIn - 60) * 1000)
  }

  return {
    kind: 'fcm',
    live: true,

    async send (delivery) {
      // The watch-wake delivery has no `intent` key — do not dereference it.
      const token = openToken(delivery.providerTokenCiphertext)
      if (!token) return { status: 'token_invalid', providerStatus: 'token_unreadable' }

      let bearer
      try {
        bearer = await accessToken()
      } catch (err) {
        // A failed token exchange is an operator/credential problem, not a dead
        // device. Never let it stale the binding.
        return { status: 'provider_attempted', reason: 'fcm_auth_failed', providerStatus: message(err), billable: false }
      }

      let response
      try {
        response = await transport({
          method: 'POST',
          url: sendUrl,
          headers: {
            Authorization: 'Bearer ' + bearer,
            'content-type': 'application/json'
          },
          body: { message: buildMessage(delivery, token) }
        })
      } catch (err) {
        return { status: 'provider_attempted', reason: 'transport_error', providerStatus: message(err), billable: false }
      }
      return classify(response)
    }
  }
}

function buildMessage (delivery, token) {
  const data = {}
  if (delivery.payloadCiphertext) data.c = delivery.payloadCiphertext
  if (delivery.channel) data.ch = delivery.channel

  const android = { priority: URGENCY_PRIORITY[delivery.urgency] || 'high' }
  if (Number.isSafeInteger(delivery.ttlSeconds) && delivery.ttlSeconds > 0) {
    android.ttl = delivery.ttlSeconds + 's'
  }
  if (delivery.collapseKey) android.collapse_key = truncate(delivery.collapseKey, 64)

  // Data-only: an FCM `notification` block would be rendered by the OS from
  // relay-visible text, which v1 does not have and must not invent.
  return { token, data, android }
}

function classify (response) {
  const status = response && Number.isInteger(response.status) ? response.status : 0
  const error = response && response.body && response.body.error ? response.body.error : null
  const detail = error && Array.isArray(error.details) ? error.details : []
  const errorCode = detail.map(d => d && d.errorCode).find(c => typeof c === 'string') || null
  const reason = errorCode || (error && typeof error.status === 'string' ? error.status : null)

  if (status >= 200 && status < 300) {
    return { status: 'accepted_by_provider', providerStatus: 'fcm_' + status, billable: true }
  }
  // UNREGISTERED means the app was uninstalled or the token rotated; 404 on the
  // send endpoint is the same condition. Both are permanent.
  if (errorCode === 'UNREGISTERED' || status === 404) {
    return { status: 'token_invalid', providerStatus: reason || 'fcm_unregistered' }
  }
  if (status === 429 || status >= 500) {
    return { status: 'provider_attempted', reason: 'fcm_retryable', providerStatus: reason || ('fcm_' + status), billable: false }
  }
  return { status: 'provider_rejected', reason: reason || 'fcm_rejected', providerStatus: 'fcm_' + status }
}

async function defaultTransport (req) {
  const init = { method: req.method, headers: req.headers }
  if (req.form) init.body = new URLSearchParams(req.form).toString()
  else if (req.body !== undefined) init.body = JSON.stringify(req.body)
  const res = await globalThis.fetch(req.url, init)
  let body = null
  try {
    body = await res.json()
  } catch {
    body = null
  }
  return { status: res.status, body }
}

function requireString (value, name) {
  if (typeof value !== 'string' || !value) throw new Error('NOTIFY_PUSH_BAD_CONFIG: ' + name + ' required')
  return value
}

function requireFunction (value, name) {
  if (typeof value !== 'function') throw new Error('NOTIFY_PUSH_BAD_CONFIG: ' + name + ' required')
  return value
}

function truncate (value, max) {
  const str = String(value)
  return str.length > max ? str.slice(0, max) : str
}

function message (err) {
  return err && typeof err.message === 'string' ? err.message.slice(0, 200) : 'error'
}
