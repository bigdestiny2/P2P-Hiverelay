import b4a from 'b4a'
import sodium from './crypto.js'
import { asBytes, randomBytes, wipe } from './bytes.js'
import { fail } from './errors.js'

const PUBLIC_KEY_BYTES = 32
const PRIVATE_SEED_BYTES = 32
const SECRET_KEY_BYTES = 64
const SIGNATURE_BYTES = 64

export function publicKeyFromPrivateSeed (privateSeed) {
  privateSeed = asBytes(privateSeed, 'private seed', PRIVATE_SEED_BYTES)
  const publicKey = b4a.alloc(PUBLIC_KEY_BYTES)
  const secretKey = b4a.alloc(SECRET_KEY_BYTES)
  try {
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, privateSeed)
    return publicKey
  } finally {
    wipe(secretKey)
  }
}

export function generateCapabilityKeyPair (runtime) {
  const privateSeed = randomBytes(runtime, PRIVATE_SEED_BYTES, 'capability private seed')
  const publicKey = publicKeyFromPrivateSeed(privateSeed)
  return { publicKey, privateSeed }
}

export function signCapability (privateSeed, message) {
  privateSeed = asBytes(privateSeed, 'private seed', PRIVATE_SEED_BYTES)
  message = asBytes(message, 'signature message')
  const publicKey = b4a.alloc(PUBLIC_KEY_BYTES)
  const secretKey = b4a.alloc(SECRET_KEY_BYTES)
  const signature = b4a.alloc(SIGNATURE_BYTES)
  try {
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, privateSeed)
    sodium.crypto_sign_detached(signature, message, secretKey)
    return signature
  } finally {
    wipe(secretKey)
  }
}

export function verifyCapabilitySignature (publicKey, message, signature) {
  publicKey = asBytes(publicKey, 'public key', PUBLIC_KEY_BYTES)
  message = asBytes(message, 'signature message')
  signature = asBytes(signature, 'signature', SIGNATURE_BYTES)
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

export function generateDistinctCapabilityKeys (runtime, names, forbiddenPublicKeys = []) {
  if (!Array.isArray(names) || names.length === 0 || new Set(names).size !== names.length) {
    fail('BAD_CLIENT_INPUT', 'capability names must be a nonempty distinct array')
  }
  const result = {}
  const publicKeys = forbiddenPublicKeys.map((publicKey, index) => asBytes(publicKey, `forbiddenPublicKeys[${index}]`, 32))
  try {
    for (const name of names) {
      if (typeof name !== 'string' || name.length === 0) fail('BAD_CLIENT_INPUT', 'capability name must be nonempty')
      let pair
      for (let attempt = 0; attempt < 8; attempt++) {
        pair = generateCapabilityKeyPair(runtime)
        if (!publicKeys.some(publicKey => b4a.equals(publicKey, pair.publicKey))) break
        wipe(pair.privateSeed)
        pair = null
      }
      if (!pair) fail('RNG_COLLISION', 'could not generate distinct capability keys')
      publicKeys.push(pair.publicKey)
      result[name] = pair
    }
  } catch (error) {
    for (const value of Object.values(result)) wipe(value.privateSeed)
    throw error
  }
  return result
}

export function destroyCellWriteCapability (writeCap) {
  if (!writeCap || typeof writeCap !== 'object') return
  wipe(writeCap.createPrivateKey)
  wipe(writeCap.renewPrivateKey)
  wipe(writeCap.dropPrivateKey)
}

export function destroyCellReadCapability (readCap) {
  if (!readCap || typeof readCap !== 'object') return
  wipe(readCap.cellKey)
}

export function destroyCellCapabilities (writeCap) {
  if (!writeCap || typeof writeCap !== 'object') return
  destroyCellWriteCapability(writeCap)
  destroyCellReadCapability(writeCap.readCap)
}
