import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  X402_PRICE_MANIFEST_PATH,
  X402_PROTOCOL_VERSION,
  normalizeX402Config
} from './config.js'

export const X402_PRICE_MANIFEST_SCHEMA = 'hiverelay.x402-prices'
export const X402_PRICE_MANIFEST_VERSION = 1
export const X402_PRICE_MANIFEST_SIGNATURE_DOMAIN = 'hiverelay.x402-prices.v1'

export function buildX402PriceManifest (opts = {}) {
  const relay = opts.relay || null
  const config = normalizeX402Config(opts.config || relay?.config?.x402 || {})
  const attestedAt = Number.isSafeInteger(opts.attestedAt) ? opts.attestedAt : Date.now()
  const pubkey = publicKeyHex(opts.publicKey || identityPublicKey(relay))
  const services = {}

  if (config.enabled) {
    for (const route of Object.values(config.routes)) {
      services[route.serviceRoute] = {
        method: route.method,
        path: route.path,
        unit: route.unit,
        proofType: route.proofType,
        sideEffects: route.sideEffects,
        accepts: route.accepts.map(accept => ({
          scheme: accept.scheme,
          network: accept.network,
          asset: accept.price.asset,
          amount: accept.price.amount,
          payTo: accept.payTo,
          ...(accept.maxTimeoutSeconds == null
            ? {}
            : { maxTimeoutSeconds: accept.maxTimeoutSeconds })
        }))
      }
    }
  }

  const manifest = {
    schema: X402_PRICE_MANIFEST_SCHEMA,
    schemaVersion: X402_PRICE_MANIFEST_VERSION,
    x402Version: X402_PROTOCOL_VERSION,
    enabled: config.enabled,
    manifestPath: X402_PRICE_MANIFEST_PATH,
    servicePrefix: '/svc/',
    pubkey,
    services,
    attestedAt
  }

  const secretKey = opts.secretKey || identitySecretKey(relay)
  if (secretKey && pubkey) {
    const signature = b4a.alloc(64)
    sodium.crypto_sign_detached(signature, x402PriceManifestSignablePayload(manifest), secretKey)
    manifest.signature = {
      v: 1,
      domain: X402_PRICE_MANIFEST_SIGNATURE_DOMAIN,
      sig: b4a.toString(signature, 'hex')
    }
  }

  return manifest
}

export function verifyX402PriceManifest (manifest) {
  if (!manifest || typeof manifest !== 'object') return { valid: false, reason: 'not an object' }
  if (manifest.schema !== X402_PRICE_MANIFEST_SCHEMA) return { valid: false, reason: 'unsupported schema' }
  if (manifest.schemaVersion !== X402_PRICE_MANIFEST_VERSION) {
    return { valid: false, reason: 'unsupported schema version' }
  }
  if (!manifest.signature) return { valid: false, reason: 'manifest is unsigned' }
  if (manifest.signature.v !== 1 || manifest.signature.domain !== X402_PRICE_MANIFEST_SIGNATURE_DOMAIN) {
    return { valid: false, reason: 'unsupported signature profile' }
  }
  if (!/^[0-9a-f]{64}$/i.test(manifest.pubkey || '')) {
    return { valid: false, reason: 'invalid relay pubkey' }
  }
  if (!/^[0-9a-f]{128}$/i.test(manifest.signature.sig || '')) {
    return { valid: false, reason: 'invalid signature' }
  }

  try {
    const valid = sodium.crypto_sign_verify_detached(
      b4a.from(manifest.signature.sig, 'hex'),
      x402PriceManifestSignablePayload(manifest),
      b4a.from(manifest.pubkey, 'hex')
    )
    return valid ? { valid: true } : { valid: false, reason: 'signature verification failed' }
  } catch (err) {
    return { valid: false, reason: 'verification failed: ' + err.message }
  }
}

export function x402PriceManifestSignablePayload (manifest) {
  const canonical = canonicalJson(manifest)
  return b4a.concat([
    b4a.from(X402_PRICE_MANIFEST_SIGNATURE_DOMAIN + '\0', 'utf8'),
    b4a.from(canonical, 'utf8')
  ])
}

function canonicalJson (manifest) {
  const unsigned = {}
  for (const key of Object.keys(manifest).sort()) {
    if (key === 'signature') continue
    unsigned[key] = sortKeysDeep(manifest[key])
  }
  return JSON.stringify(unsigned)
}

function sortKeysDeep (value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep)
  if (!value || typeof value !== 'object') return value
  const out = {}
  for (const key of Object.keys(value).sort()) out[key] = sortKeysDeep(value[key])
  return out
}

function publicKeyHex (value) {
  if (!value) return null
  if (typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)) return value.toLowerCase()
  try {
    const hex = b4a.toString(value, 'hex')
    return /^[0-9a-f]{64}$/i.test(hex) ? hex : null
  } catch {
    return null
  }
}

function identityPublicKey (relay) {
  if (!relay) return null
  if (typeof relay.getIdentityPublicKey === 'function') {
    try {
      const key = relay.getIdentityPublicKey()
      if (key) return key
    } catch {}
  }
  return relay.identityKeyPair?.publicKey || relay.swarm?.keyPair?.publicKey || relay.publicKey || null
}

function identitySecretKey (relay) {
  return relay?.identityKeyPair?.secretKey || relay?.swarm?.keyPair?.secretKey || null
}
