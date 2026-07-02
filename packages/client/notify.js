import b4a from 'b4a'
import sodium from 'sodium-universal'

export const NOTIFY_DOMAINS = Object.freeze({
  providerBinding: 'hiverelay.notify.v1.provider-binding',
  deviceRegistration: 'hiverelay.notify.v1.device-registration',
  receiveCap: 'hiverelay.notify.v1.receive-cap',
  sendCap: 'hiverelay.notify.v1.send-cap',
  intent: 'hiverelay.notify.v1.intent',
  watch: 'hiverelay.notify.v1.watch',
  status: 'hiverelay.notify.v1.status',
  revoke: 'hiverelay.notify.v1.revoke',
  deliveryEvent: 'hiverelay.notify.v1.delivery-event'
})

export const NOTIFY_HTTP_PATHS = Object.freeze({
  capabilities: '/api/v1/notify/capabilities',
  provider: '/api/v1/notify/provider',
  device: '/api/v1/notify/device',
  receiveCap: '/api/v1/notify/receive-cap',
  sendCap: '/api/v1/notify/send-cap',
  revoke: '/api/v1/notify/revoke',
  send: '/api/v1/notify/send',
  watch: '/api/v1/notify/watch',
  unwatch: '/api/v1/notify/unwatch',
  status: '/api/v1/notify/status',
  managementStatus: '/api/manage/notify',
  productionGates: '/api/manage/notify/production-gates'
})

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_SIG = /^[0-9a-f]{128}$/i

export function notifySignaturePayload (domain, obj) {
  return b4a.from(domain + '\0' + stableObjectString(obj, new Set(['signature'])), 'utf8')
}

export function signNotifyObject (keyPair, domain, object) {
  if (!keyPair || !keyPair.secretKey) throw new Error('signNotifyObject: keyPair.secretKey required')
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, notifySignaturePayload(domain, object), keyPair.secretKey)
  return { ...object, signature: b4a.toString(signature, 'hex') }
}

export function verifyNotifySignature (obj, domain, publicKeyHex) {
  if (!isHex32(publicKeyHex)) return false
  if (!obj || typeof obj.signature !== 'string' || !HEX_SIG.test(obj.signature)) return false
  return sodium.crypto_sign_verify_detached(
    b4a.from(obj.signature, 'hex'),
    notifySignaturePayload(domain, obj),
    b4a.from(publicKeyHex, 'hex')
  )
}

export function createNotifyProviderBinding (fields, deviceKeyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.provider-binding.v1',
    ...fields,
    device: fields && fields.device ? fields.device : publicKeyHex(deviceKeyPair),
    createdAt: timeOr(fields && fields.createdAt, now),
    nonce: fields && fields.nonce ? fields.nonce : randomHex(16)
  }
  return signNotifyObject(deviceKeyPair, NOTIFY_DOMAINS.providerBinding, body)
}

export function createNotifyDeviceRegistration (fields, deviceKeyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.device-registration.v1',
    ...fields,
    device: fields && fields.device ? fields.device : publicKeyHex(deviceKeyPair),
    createdAt: timeOr(fields && fields.createdAt, now),
    nonce: fields && fields.nonce ? fields.nonce : randomHex(16)
  }
  return signNotifyObject(deviceKeyPair, NOTIFY_DOMAINS.deviceRegistration, body)
}

export function createNotifyReceiveCap (fields, keyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.receive-cap.v1',
    ...fields,
    createdAt: timeOr(fields && fields.createdAt, now),
    nonce: fields && fields.nonce ? fields.nonce : randomHex(16)
  }
  return signNotifyObject(keyPair, NOTIFY_DOMAINS.receiveCap, body)
}

export function createNotifySendCap (fields, keyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.send-cap.v1',
    ...fields,
    createdAt: timeOr(fields && fields.createdAt, now),
    nonce: fields && fields.nonce ? fields.nonce : randomHex(16)
  }
  return signNotifyObject(keyPair, NOTIFY_DOMAINS.sendCap, body)
}

export function createNotifyRevocation (fields, keyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.revocation.v1',
    ...fields,
    createdAt: timeOr(fields && fields.createdAt, now),
    nonce: fields && fields.nonce ? fields.nonce : randomHex(16)
  }
  return signNotifyObject(keyPair, NOTIFY_DOMAINS.revoke, body)
}

export function createNotifyIntent (fields, senderKeyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.intent.v1',
    ...fields,
    sender: fields && fields.sender ? fields.sender : publicKeyHex(senderKeyPair),
    createdAt: timeOr(fields && fields.createdAt, now)
  }
  return signNotifyObject(senderKeyPair, NOTIFY_DOMAINS.intent, body)
}

export function createNotifyWatch (fields, keyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.watch.v1',
    ...fields,
    createdAt: timeOr(fields && fields.createdAt, now)
  }
  return signNotifyObject(keyPair, NOTIFY_DOMAINS.watch, body)
}

export function createNotifyUnwatch (fields, keyPair) {
  return signNotifyObject(keyPair, NOTIFY_DOMAINS.watch, {
    type: 'hiverelay.notify.unwatch.v1',
    ...fields
  })
}

export function createNotifyStatusRequest (fields, keyPair, opts = {}) {
  const now = timeOr(opts.now, Date.now())
  const body = {
    type: 'hiverelay.notify.status.v1',
    ...fields,
    createdAt: timeOr(fields && fields.createdAt, now),
    nonce: fields && fields.nonce ? fields.nonce : randomHex(16)
  }
  return signNotifyObject(keyPair, NOTIFY_DOMAINS.status, body)
}

export function createNotifyServiceClient (client, opts = {}) {
  if (!client || typeof client.callService !== 'function') throw new Error('createNotifyServiceClient: client.callService required')
  const callOpts = { ...(opts.call || opts) }
  const call = (method, params, next = {}) => client.callService('notify', method, params, { ...callOpts, ...next })
  return {
    bindProvider: (params, next) => call('bind-provider', params, next),
    registerDevice: (params, next) => call('register-device', params, next),
    installReceiveCap: (params, next) => call('install-receive-cap', params, next),
    installSendCap: (params, next) => call('install-send-cap', params, next),
    revoke: (params, next) => call('revoke', params, next),
    send: (params, next) => call('send', params, next),
    watch: (params, next) => call('watch', params, next),
    unwatch: (params, next) => call('unwatch', params, next),
    status: (params, next) => call('status', params, next),
    deliveryEvent: (params, next) => call('delivery-event', params, next),
    productionGates: (params, next) => call('production-gates', params, next)
  }
}

export function createNotifyHttpClient (baseUrl, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch
  if (typeof fetchImpl !== 'function') throw new Error('createNotifyHttpClient: fetch required')
  const base = normalizeBaseUrl(baseUrl)
  const request = (method, path, body = null, next = {}) => notifyHttpRequest(base, method, path, body, {
    ...opts,
    ...next,
    fetch: fetchImpl
  })
  return {
    capabilities: (next) => request('GET', NOTIFY_HTTP_PATHS.capabilities, null, next),
    bindProvider: (body, next) => request('POST', NOTIFY_HTTP_PATHS.provider, body, next),
    registerDevice: (body, next) => request('POST', NOTIFY_HTTP_PATHS.device, body, next),
    installReceiveCap: (body, next) => request('POST', NOTIFY_HTTP_PATHS.receiveCap, body, next),
    installSendCap: (body, next) => request('POST', NOTIFY_HTTP_PATHS.sendCap, body, next),
    revoke: (body, next) => request('POST', NOTIFY_HTTP_PATHS.revoke, body, next),
    send: (body, next) => request('POST', NOTIFY_HTTP_PATHS.send, body, next),
    watch: (body, next) => request('POST', NOTIFY_HTTP_PATHS.watch, body, next),
    unwatch: (body, next) => request('POST', NOTIFY_HTTP_PATHS.unwatch, body, next),
    status: (body, next) => request('POST', NOTIFY_HTTP_PATHS.status, body, next),
    managementStatus: (query, next) => request('GET', pathWithQuery(NOTIFY_HTTP_PATHS.managementStatus, query), null, next),
    productionGates: (query, next) => request('GET', pathWithQuery(NOTIFY_HTTP_PATHS.productionGates, query), null, next)
  }
}

export async function notifyHttpRequest (baseUrl, method, path, body = null, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch
  if (typeof fetchImpl !== 'function') throw new Error('notifyHttpRequest: fetch required')
  const headers = { ...(opts.headers || {}) }
  if (body !== null && body !== undefined) headers['Content-Type'] = headers['Content-Type'] || 'application/json'
  if (opts.apiKey && !headers.Authorization) headers.Authorization = 'Bearer ' + opts.apiKey

  const response = await fetchImpl(normalizeBaseUrl(baseUrl) + path, {
    method,
    headers,
    body: body === null || body === undefined ? undefined : JSON.stringify(body),
    signal: opts.signal
  })
  const parsed = await parseResponseBody(response)
  if (!response.ok) {
    const err = new Error((parsed && parsed.error) || 'notify request failed')
    err.status = response.status
    err.body = parsed
    throw err
  }
  return parsed
}

export function publicKeyHex (keyPair) {
  if (!keyPair || !keyPair.publicKey) throw new Error('publicKeyHex: keyPair.publicKey required')
  return b4a.toString(keyPair.publicKey, 'hex')
}

export function randomHex (bytes = 16) {
  const out = b4a.alloc(bytes)
  sodium.randombytes_buf(out)
  return b4a.toString(out, 'hex')
}

function stableObjectString (value, exclude = new Set()) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value === undefined ? null : value)
  if (Array.isArray(value)) return '[' + value.map(v => stableObjectString(v, exclude)).join(',') + ']'
  const keys = Object.keys(value).filter(key => !exclude.has(key)).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stableObjectString(value[key], exclude)).join(',') + '}'
}

function timeOr (value, fallback) {
  return Number.isSafeInteger(value) || typeof value === 'string' ? value : fallback
}

function isHex32 (value) {
  return typeof value === 'string' && HEX_32.test(value)
}

function normalizeBaseUrl (baseUrl) {
  if (typeof baseUrl !== 'string' || !baseUrl) throw new Error('notify baseUrl required')
  return baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl
}

function pathWithQuery (path, query) {
  if (!query || typeof query !== 'object') return path
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null) params.set(key, String(value))
  }
  const suffix = params.toString()
  return suffix ? path + '?' + suffix : path
}

async function parseResponseBody (response) {
  if (!response || typeof response.json !== 'function') return null
  try {
    return await response.json()
  } catch (_) {
    return null
  }
}
