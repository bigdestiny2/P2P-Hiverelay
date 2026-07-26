/**
 * JWT and key-loading primitives shared by the APNS, FCM and WebPush adapters.
 *
 * No new dependency: `node:crypto` covers everything the three providers need.
 * The one non-obvious knob is `dsaEncoding: 'ieee-p1363'` — ES256 JWTs carry a
 * raw 64-byte `r||s` signature, but Node emits ASN.1 DER by default, and a DER
 * signature is silently rejected by every push endpoint. Setting the encoding
 * gets the JOSE form directly, so there is no DER parser here.
 *
 * Bare has no `node:crypto` ES256, so this module is Node-only by construction;
 * `assertNodeCrypto()` fails loudly rather than letting a Bare relay boot with a
 * push adapter that can never sign.
 */

import { createPrivateKey, createPublicKey, createECDH, sign as cryptoSign } from 'node:crypto'

export const ES256_SIGNATURE_BYTES = 64
const P256_CURVE = 'prime256v1'
const P256_POINT_BYTES = 65

export function canUseNodeCrypto () {
  return typeof process !== 'undefined' &&
    process &&
    process.versions &&
    process.versions.node &&
    typeof globalThis.Bare === 'undefined'
}

export function assertNodeCrypto () {
  if (!canUseNodeCrypto()) {
    throw new Error('NOTIFY_PUSH_UNSUPPORTED_RUNTIME: push adapters require Node.js crypto (ES256 is unavailable under Bare)')
  }
}

export function b64url (input) {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input)
  return buf.toString('base64url')
}

function encodeSegment (obj) {
  return b64url(JSON.stringify(obj))
}

/**
 * ES256 (ECDSA P-256 + SHA-256) JWT, signed into the JOSE `r||s` form.
 */
export function es256Jwt ({ header, payload, key }) {
  assertNodeCrypto()
  const fullHeader = { alg: 'ES256', typ: 'JWT', ...header }
  const signingInput = encodeSegment(fullHeader) + '.' + encodeSegment(payload)
  const signature = cryptoSign('sha256', Buffer.from(signingInput, 'utf8'), {
    key,
    dsaEncoding: 'ieee-p1363'
  })
  return signingInput + '.' + signature.toString('base64url')
}

/**
 * RS256 (RSASSA-PKCS1-v1_5 + SHA-256) JWT — the service-account assertion FCM
 * exchanges for an OAuth2 access token.
 */
export function rs256Jwt ({ header, payload, key }) {
  assertNodeCrypto()
  const fullHeader = { alg: 'RS256', typ: 'JWT', ...header }
  const signingInput = encodeSegment(fullHeader) + '.' + encodeSegment(payload)
  const signature = cryptoSign('sha256', Buffer.from(signingInput, 'utf8'), key)
  return signingInput + '.' + signature.toString('base64url')
}

/**
 * Load an Apple `.p8` auth key. Apple ships PKCS#8 PEM, which `createPrivateKey`
 * reads directly — but it will just as happily read an RSA key, and the failure
 * would then surface as an opaque provider rejection at send time. Assert the
 * curve here instead, at configuration time.
 */
export function loadP8 (pem) {
  assertNodeCrypto()
  if (typeof pem !== 'string' || !pem.trim()) throw new Error('NOTIFY_PUSH_BAD_KEY: APNS key PEM required')
  let key
  try {
    key = createPrivateKey(pem)
  } catch (err) {
    throw new Error('NOTIFY_PUSH_BAD_KEY: APNS key is not a readable PKCS#8 private key: ' + err.message)
  }
  if (key.asymmetricKeyType !== 'ec') {
    throw new Error('NOTIFY_PUSH_BAD_KEY: APNS key must be EC, got ' + key.asymmetricKeyType)
  }
  const curve = key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve
  if (curve !== P256_CURVE) {
    throw new Error('NOTIFY_PUSH_BAD_KEY: APNS key must be P-256, got ' + curve)
  }
  return key
}

export function loadServiceAccountKey (pem) {
  assertNodeCrypto()
  if (typeof pem !== 'string' || !pem.trim()) throw new Error('NOTIFY_PUSH_BAD_KEY: service account private_key required')
  let key
  try {
    key = createPrivateKey(pem)
  } catch (err) {
    throw new Error('NOTIFY_PUSH_BAD_KEY: service account key is not a readable private key: ' + err.message)
  }
  if (key.asymmetricKeyType !== 'rsa') {
    throw new Error('NOTIFY_PUSH_BAD_KEY: service account key must be RSA, got ' + key.asymmetricKeyType)
  }
  return key
}

/**
 * Load a VAPID key pair from the base64url form the WebPush ecosystem publishes.
 *
 * Node rejects a JWK carrying only `d`, so the public point is required to build
 * a usable private key. When the operator configured only the private key we
 * recover the point with ECDH scalar multiplication rather than making them
 * paste a second value they may not have kept.
 */
export function loadVapidKey (privateKeyB64, publicKeyB64 = null) {
  assertNodeCrypto()
  if (typeof privateKeyB64 !== 'string' || !privateKeyB64) {
    throw new Error('NOTIFY_PUSH_BAD_KEY: VAPID privateKey required')
  }
  const d = Buffer.from(privateKeyB64, 'base64url')
  if (d.length !== 32) throw new Error('NOTIFY_PUSH_BAD_KEY: VAPID privateKey must be 32 bytes, got ' + d.length)

  const ecdh = createECDH(P256_CURVE)
  try {
    ecdh.setPrivateKey(d)
  } catch (err) {
    throw new Error('NOTIFY_PUSH_BAD_KEY: VAPID privateKey is not a valid P-256 scalar: ' + err.message)
  }
  const point = ecdh.getPublicKey()

  if (publicKeyB64) {
    const supplied = Buffer.from(publicKeyB64, 'base64url')
    if (supplied.length !== P256_POINT_BYTES || supplied[0] !== 0x04) {
      throw new Error('NOTIFY_PUSH_BAD_KEY: VAPID publicKey must be a 65-byte uncompressed P-256 point')
    }
    // Node imports a JWK without checking that `d` actually corresponds to
    // `x`/`y` (verified), so a mismatched pair would load fine and then fail as
    // an opaque 401 on every single push. Compare against the derived point.
    if (!supplied.equals(point)) {
      throw new Error('NOTIFY_PUSH_BAD_KEY: VAPID key pair is inconsistent — publicKey does not match privateKey')
    }
  }

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    d: d.toString('base64url'),
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33).toString('base64url')
  }
  let privateKey
  try {
    privateKey = createPrivateKey({ key: jwk, format: 'jwk' })
  } catch (err) {
    throw new Error('NOTIFY_PUSH_BAD_KEY: VAPID key pair is inconsistent: ' + err.message)
  }
  return {
    privateKey,
    publicKey: createPublicKey(privateKey),
    publicKeyB64: point.toString('base64url')
  }
}

/**
 * Single-slot TTL cache for a signed credential.
 *
 * `now` is injectable because both consumers (the 55-minute APNS JWT and the
 * FCM access token) need their expiry proven in tests without fake timers.
 */
export class TokenCache {
  constructor (opts = {}) {
    this.now = typeof opts.now === 'function' ? opts.now : () => Date.now()
    this.value = null
    this.expiresAt = 0
  }

  get () {
    if (this.value === null) return null
    return this.now() < this.expiresAt ? this.value : null
  }

  set (value, ttlMs) {
    this.value = value
    this.expiresAt = this.now() + ttlMs
    return value
  }

  clear () {
    this.value = null
    this.expiresAt = 0
  }
}
