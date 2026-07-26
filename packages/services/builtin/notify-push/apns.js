/**
 * APNS (Apple Push Notification service) HTTP/2 egress adapter.
 *
 * Speaks NotifyService's four-status provider vocabulary. `token_invalid` is
 * load-bearing: it permanently marks the binding stale, so it is returned only
 * for the two responses Apple defines as "this token is dead", never for a
 * transport error or a throttle.
 */

import { es256Jwt, loadP8, TokenCache } from './jwt.js'

export const APNS_HOST_PRODUCTION = 'https://api.push.apple.com'
export const APNS_HOST_SANDBOX = 'https://api.sandbox.push.apple.com'

// Apple rejects tokens older than 1h and rate-limits reissue; 55 min leaves
// margin without churn.
const JWT_TTL_MS = 55 * 60 * 1000

const URGENCY_PRIORITY = { silent: '5', normal: '10', high: '10' }

export function createApnsProvider (opts = {}) {
  const credentials = opts.credentials || {}
  const key = loadP8(credentials.privateKey)
  const keyId = requireString(credentials.keyId, 'apns.credentials.keyId')
  const teamId = requireString(credentials.teamId, 'apns.credentials.teamId')
  const defaultTopic = typeof credentials.bundleId === 'string' ? credentials.bundleId : null
  // Sandbox vs production is a host swap, and shipping a hardcoded production
  // host makes every development build silently undeliverable.
  const host = stripSlash(credentials.host || APNS_HOST_PRODUCTION)
  const transport = opts.transport || defaultTransport
  const openToken = requireFunction(opts.openToken, 'openToken')
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now()
  const cache = new TokenCache({ now })

  function authToken () {
    const cached = cache.get()
    if (cached) return cached
    const issuedAt = Math.floor(now() / 1000)
    return cache.set(es256Jwt({
      header: { kid: keyId },
      payload: { iss: teamId, iat: issuedAt },
      key
    }), JWT_TTL_MS)
  }

  return {
    kind: 'apns',
    live: true,

    async send (delivery) {
      // NOTE: the watch-wake delivery has no `intent` key at all (it carries
      // `watch` instead). Never dereference `delivery.intent` here.
      const token = openToken(delivery.providerTokenCiphertext)
      if (!token) return { status: 'token_invalid', providerStatus: 'token_unreadable' }

      const topic = pickTopic(delivery, defaultTopic)
      if (!topic) return { status: 'provider_rejected', reason: 'apns_topic_missing', providerStatus: 'no_topic' }

      const headers = {
        authorization: 'bearer ' + authToken(),
        'apns-topic': topic,
        'apns-push-type': delivery.payloadCiphertext ? 'alert' : 'background',
        'apns-priority': URGENCY_PRIORITY[delivery.urgency] || '10',
        'content-type': 'application/json'
      }
      if (Number.isSafeInteger(delivery.ttlSeconds) && delivery.ttlSeconds > 0) {
        headers['apns-expiration'] = String(Math.floor(now() / 1000) + delivery.ttlSeconds)
      } else {
        headers['apns-expiration'] = '0'
      }
      if (delivery.collapseKey) headers['apns-collapse-id'] = truncate(delivery.collapseKey, 64)

      let response
      try {
        response = await transport({
          method: 'POST',
          url: host + '/3/device/' + encodeURIComponent(token),
          headers,
          body: buildPayload(delivery)
        })
      } catch (err) {
        return { status: 'provider_attempted', reason: 'transport_error', providerStatus: message(err), billable: false }
      }
      return classify(response)
    }
  }
}

function buildPayload (delivery) {
  // `genericDisplay` is always true in v1: the relay never learns enough to
  // render a real alert, and the payload it does carry is ciphertext.
  const aps = delivery.payloadCiphertext
    ? { 'mutable-content': 1, alert: { 'loc-key': 'NOTIFY_GENERIC' } }
    : { 'content-available': 1 }
  const payload = { aps }
  if (delivery.payloadCiphertext) payload.c = delivery.payloadCiphertext
  if (delivery.channel) payload.ch = delivery.channel
  return payload
}

function classify (response) {
  const status = response && Number.isInteger(response.status) ? response.status : 0
  const reason = response && response.body && typeof response.body.reason === 'string' ? response.body.reason : null

  if (status >= 200 && status < 300) {
    return { status: 'accepted_by_provider', providerStatus: 'apns_' + status, billable: true }
  }
  // The only two responses Apple defines as "this token will never work again".
  // Everything else — 429, 5xx, malformed request — must not stale the binding.
  if (status === 410 || (status === 400 && reason === 'BadDeviceToken')) {
    return { status: 'token_invalid', providerStatus: reason || 'apns_410' }
  }
  if (status === 429 || status >= 500) {
    return { status: 'provider_attempted', reason: 'apns_retryable', providerStatus: reason || ('apns_' + status), billable: false }
  }
  return { status: 'provider_rejected', reason: reason || 'apns_rejected', providerStatus: 'apns_' + status }
}

function pickTopic (delivery, fallback) {
  // Direct sends carry the signed intent, whose binding scope names the bundle.
  const scoped = delivery.intent && delivery.intent.scope && typeof delivery.intent.scope.bundle === 'string'
    ? delivery.intent.scope.bundle
    : null
  return scoped || fallback
}

async function defaultTransport (req) {
  const res = await globalThis.fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: JSON.stringify(req.body)
  })
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

function stripSlash (value) {
  return String(value).replace(/\/+$/, '')
}

function truncate (value, max) {
  const str = String(value)
  return str.length > max ? str.slice(0, max) : str
}

function message (err) {
  return err && typeof err.message === 'string' ? err.message.slice(0, 200) : 'error'
}
