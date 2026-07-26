/**
 * Web Push (RFC 8030) egress adapter with VAPID (RFC 8292) authorization.
 *
 * Unlike APNS and FCM there is no central host: the subscription endpoint is
 * the destination, and the VAPID JWT is audience-bound to that endpoint's
 * origin. So the token cache is keyed per origin, not global.
 *
 * Payload encryption (RFC 8291 aes128gcm) is deliberately out of scope. v1
 * sends a bodiless wake — the relay holds only ciphertext it cannot re-encrypt
 * to the subscription's keys anyway, and the woken app fetches truth over p2p.
 */

import { es256Jwt, loadVapidKey, TokenCache } from './jwt.js'

const JWT_TTL_MS = 12 * 60 * 60 * 1000
const JWT_EXP_SECONDS = 12 * 60 * 60
const URGENCY_HEADER = { silent: 'low', normal: 'normal', high: 'high' }

export function createWebPushProvider (opts = {}) {
  const credentials = opts.credentials || {}
  const keys = loadVapidKey(credentials.privateKey, credentials.publicKey || null)
  const subject = requireSubject(credentials.subject)
  const transport = opts.transport || defaultTransport
  const openToken = requireFunction(opts.openToken, 'openToken')
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now()
  const caches = new Map()

  function authHeader (origin) {
    let cache = caches.get(origin)
    if (!cache) {
      cache = new TokenCache({ now })
      caches.set(origin, cache)
    }
    const cached = cache.get()
    if (cached) return cached
    const jwt = es256Jwt({
      header: {},
      payload: { aud: origin, exp: Math.floor(now() / 1000) + JWT_EXP_SECONDS, sub: subject },
      key: keys.privateKey
    })
    return cache.set('vapid t=' + jwt + ',k=' + keys.publicKeyB64, JWT_TTL_MS)
  }

  return {
    kind: 'webpush',
    live: true,

    async send (delivery) {
      // The watch-wake delivery has no `intent` key — do not dereference it.
      const endpoint = openToken(delivery.providerTokenCiphertext)
      if (!endpoint) return { status: 'token_invalid', providerStatus: 'endpoint_unreadable' }

      let origin
      try {
        const url = new URL(endpoint)
        if (url.protocol !== 'https:') return { status: 'token_invalid', providerStatus: 'endpoint_not_https' }
        origin = url.origin
      } catch {
        return { status: 'token_invalid', providerStatus: 'endpoint_malformed' }
      }

      const headers = {
        Authorization: authHeader(origin),
        TTL: String(Number.isSafeInteger(delivery.ttlSeconds) && delivery.ttlSeconds > 0 ? delivery.ttlSeconds : 0),
        Urgency: URGENCY_HEADER[delivery.urgency] || 'normal'
      }
      if (delivery.collapseKey) headers.Topic = webSafeTopic(delivery.collapseKey)

      let response
      try {
        response = await transport({ method: 'POST', url: endpoint, headers, body: null })
      } catch (err) {
        return { status: 'provider_attempted', reason: 'transport_error', providerStatus: message(err), billable: false }
      }
      return classify(response)
    }
  }
}

function classify (response) {
  const status = response && Number.isInteger(response.status) ? response.status : 0
  if (status >= 200 && status < 300) {
    return { status: 'accepted_by_provider', providerStatus: 'webpush_' + status, billable: true }
  }
  // RFC 8030: 404 means the subscription never existed, 410 means it was
  // removed. Both are permanent; 429/5xx are not.
  if (status === 404 || status === 410) {
    return { status: 'token_invalid', providerStatus: 'webpush_' + status }
  }
  if (status === 429 || status >= 500) {
    return { status: 'provider_attempted', reason: 'webpush_retryable', providerStatus: 'webpush_' + status, billable: false }
  }
  return { status: 'provider_rejected', reason: 'webpush_rejected', providerStatus: 'webpush_' + status }
}

// RFC 8030 restricts Topic to a short base64url token; collapse keys like
// `watch:<64 hex>` are neither short enough nor in-alphabet.
function webSafeTopic (value) {
  return String(value).replace(/[^A-Za-z0-9\-_]/g, '_').slice(0, 32)
}

function requireSubject (subject) {
  if (typeof subject !== 'string' || !subject) {
    throw new Error('NOTIFY_PUSH_BAD_CONFIG: webpush.credentials.subject required (mailto: or https: contact)')
  }
  if (!subject.startsWith('mailto:') && !subject.startsWith('https://')) {
    throw new Error('NOTIFY_PUSH_BAD_CONFIG: webpush.credentials.subject must be a mailto: or https:// URI')
  }
  return subject
}

async function defaultTransport (req) {
  const res = await globalThis.fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body === null ? undefined : JSON.stringify(req.body)
  })
  return { status: res.status, body: null }
}

function requireFunction (value, name) {
  if (typeof value !== 'function') throw new Error('NOTIFY_PUSH_BAD_CONFIG: ' + name + ' required')
  return value
}

function message (err) {
  return err && typeof err.message === 'string' ? err.message.slice(0, 200) : 'error'
}
