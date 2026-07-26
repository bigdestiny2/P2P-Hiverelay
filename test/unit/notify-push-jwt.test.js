import test from 'brittle'
import { generateKeyPairSync, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import {
  b64url,
  es256Jwt,
  rs256Jwt,
  loadP8,
  loadServiceAccountKey,
  loadVapidKey,
  TokenCache,
  ES256_SIGNATURE_BYTES
} from '../../packages/services/builtin/notify-push/jwt.js'

// All keys are generated in-process. No credentials, no network, no fixtures.
function ecKeyPem () {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  return privateKey.export({ type: 'pkcs8', format: 'pem' })
}

function rsaKeyPem () {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return privateKey.export({ type: 'pkcs8', format: 'pem' })
}

function decodeSegment (segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'))
}

test('notify push jwt: es256 signs into the 64-byte JOSE form, not DER', async (t) => {
  const pem = ecKeyPem()
  const key = loadP8(pem)
  const jwt = es256Jwt({ header: { kid: 'KEYID123' }, payload: { iss: 'TEAMID', iat: 1782864000 }, key })

  const parts = jwt.split('.')
  t.is(parts.length, 3, 'header.payload.signature')

  const header = decodeSegment(parts[0])
  t.is(header.alg, 'ES256')
  t.is(header.typ, 'JWT')
  t.is(header.kid, 'KEYID123')
  t.is(decodeSegment(parts[1]).iss, 'TEAMID')

  const signature = Buffer.from(parts[2], 'base64url')
  // A DER signature is variable-length ~70 bytes and every push endpoint
  // rejects it. Exactly 64 bytes is the proof that r||s came out.
  t.is(signature.length, ES256_SIGNATURE_BYTES, 'raw r||s, not DER')

  const verified = cryptoVerify(
    'sha256',
    Buffer.from(parts[0] + '.' + parts[1], 'utf8'),
    { key: createPublicKey(key), dsaEncoding: 'ieee-p1363' },
    signature
  )
  t.ok(verified, 'signature verifies against the public key')
})

test('notify push jwt: rs256 signs a verifiable service-account assertion', async (t) => {
  const key = loadServiceAccountKey(rsaKeyPem())
  const jwt = rs256Jwt({ header: {}, payload: { iss: 'svc@example.iam.gserviceaccount.com' }, key })
  const parts = jwt.split('.')
  t.is(decodeSegment(parts[0]).alg, 'RS256')
  t.ok(cryptoVerify(
    'sha256',
    Buffer.from(parts[0] + '.' + parts[1], 'utf8'),
    createPublicKey(key),
    Buffer.from(parts[2], 'base64url')
  ), 'assertion verifies')
})

test('notify push jwt: key loaders reject the wrong key type at config time', async (t) => {
  t.exception(() => loadP8(rsaKeyPem()), /must be EC/, 'APNS key must be EC')
  t.exception(() => loadP8('not a pem'), /not a readable/, 'garbage rejected')
  t.exception(() => loadP8(''), /required/, 'empty rejected')
  t.exception(() => loadServiceAccountKey(ecKeyPem()), /must be RSA/, 'FCM key must be RSA')

  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
  t.exception(
    () => loadP8(privateKey.export({ type: 'pkcs8', format: 'pem' })),
    /must be P-256/,
    'wrong curve rejected'
  )
})

test('notify push jwt: vapid key recovers the public point from the private scalar', async (t) => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const jwk = privateKey.export({ format: 'jwk' })

  // Private key alone — the point must be derived, since Node rejects a d-only JWK.
  const derived = loadVapidKey(jwk.d)
  t.is(derived.publicKeyB64.length, 87, '65-byte uncompressed point, base64url')
  const point = Buffer.from(derived.publicKeyB64, 'base64url')
  t.is(point[0], 0x04, 'uncompressed prefix')
  t.is(point.subarray(1, 33).toString('base64url'), jwk.x, 'derived x matches')
  t.is(point.subarray(33).toString('base64url'), jwk.y, 'derived y matches')

  // Explicit public key — same result.
  const explicit = loadVapidKey(jwk.d, derived.publicKeyB64)
  t.is(explicit.publicKeyB64, derived.publicKeyB64)

  // And the derived key actually signs.
  const jwt = es256Jwt({ header: {}, payload: { aud: 'https://push.example' }, key: derived.privateKey })
  t.is(Buffer.from(jwt.split('.')[2], 'base64url').length, ES256_SIGNATURE_BYTES)
})

test('notify push jwt: vapid key rejects malformed input', async (t) => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const jwk = privateKey.export({ format: 'jwk' })

  t.exception(() => loadVapidKey(''), /required/)
  t.exception(() => loadVapidKey(Buffer.alloc(16).toString('base64url')), /must be 32 bytes/)
  // Truncated point.
  t.exception(() => loadVapidKey(jwk.d, Buffer.alloc(64, 4).toString('base64url')), /65-byte uncompressed/)
  // Right length, wrong prefix.
  t.exception(() => loadVapidKey(jwk.d, Buffer.alloc(65, 2).toString('base64url')), /65-byte uncompressed/)

  // A well-formed point that is not this private key's point must be caught,
  // otherwise every signature would verify against the wrong advertised key.
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const otherJwk = other.privateKey.export({ format: 'jwk' })
  const otherPoint = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(otherJwk.x, 'base64url'),
    Buffer.from(otherJwk.y, 'base64url')
  ])
  t.exception(() => loadVapidKey(jwk.d, otherPoint.toString('base64url')), /inconsistent/)
})

test('notify push jwt: TokenCache expires on the injected clock', async (t) => {
  let clock = 1782864000000
  const cache = new TokenCache({ now: () => clock })

  t.is(cache.get(), null, 'empty cache misses')
  cache.set('token-1', 55 * 60 * 1000)
  t.is(cache.get(), 'token-1', 'fresh hit')

  clock += 54 * 60 * 1000
  t.is(cache.get(), 'token-1', 'still cached at t+54m')

  clock += 2 * 60 * 1000
  t.is(cache.get(), null, 'expired at t+56m')

  cache.set('token-2', 1000)
  t.is(cache.get(), 'token-2')
  cache.clear()
  t.is(cache.get(), null, 'cleared')
})

test('notify push jwt: b64url produces unpadded url-safe output', async (t) => {
  t.is(b64url('hello world!!'), 'aGVsbG8gd29ybGQhIQ')
  const encoded = b64url(Buffer.from([0xfb, 0xff, 0xbf, 0xfa, 0xfe, 0xbe]))
  t.absent(encoded.includes('+'), 'no + in output')
  t.absent(encoded.includes('/'), 'no / in output')
  t.absent(encoded.includes('='), 'no padding')
})
