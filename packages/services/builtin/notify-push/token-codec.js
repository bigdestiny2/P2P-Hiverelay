/**
 * Device-token codec for push egress.
 *
 * `PUSH-NOTIFICATION-SERVICE-SPEC.md` says `tokenCiphertext` "is decrypted only
 * by local provider egress code" but never specified the scheme, and no client
 * in this ecosystem registers a real binding yet — so this module defines it
 * rather than matching an existing wire format. The scheme chosen is the one
 * already used elsewhere in the ecosystem for wrapping keys to a peer identity:
 * libsodium `crypto_box_seal` to the relay's Ed25519 identity converted to
 * X25519. Sealed is the default; a device can seal to a relay it has never
 * talked to, and the relay is the only party that can open it.
 *
 * `plaintext` mode exists because an operator running a first-party app may
 * legitimately not want a sealing step. It has to be selected deliberately in
 * config — a token sitting in the clear inside the relay's state snapshot is a
 * real exposure, and it should never be what someone gets by accident.
 */

import b4a from 'b4a'
import sodium from 'sodium-universal'

export const TOKEN_ENCODINGS = Object.freeze(['sealed', 'plaintext'])

const MAX_TOKEN_BYTES = 4096

function relayBoxKeyPair (keyPair) {
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
    throw new Error('NOTIFY_PUSH_NO_RELAY_KEY: sealed token encoding requires the relay key pair')
  }
  const publicKey = b4a.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)
  const secretKey = b4a.allocUnsafe(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey, b4a.from(keyPair.publicKey))
  sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey, b4a.from(keyPair.secretKey))
  return { publicKey, secretKey }
}

/**
 * Client-side helper: seal a provider device token to a relay's Ed25519 public
 * key. Exported so a device (and the adapter tests) can produce the exact bytes
 * `createTokenOpener('sealed', …)` accepts.
 */
export function sealDeviceToken (token, relayPublicKey) {
  if (typeof token !== 'string' || !token) throw new Error('NOTIFY_PUSH_BAD_TOKEN: token required')
  const ed = typeof relayPublicKey === 'string' ? b4a.from(relayPublicKey, 'hex') : b4a.from(relayPublicKey)
  const boxPublicKey = b4a.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)
  sodium.crypto_sign_ed25519_pk_to_curve25519(boxPublicKey, ed)
  const message = b4a.from(token, 'utf8')
  const sealed = b4a.allocUnsafe(message.length + sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal(sealed, message, boxPublicKey)
  return b4a.toString(sealed, 'base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Build the opener the adapters call on every delivery.
 *
 * Returns `null` for anything it cannot open. Callers map that to
 * `token_invalid`, which permanently stales the binding — the correct outcome
 * for a token this relay can never read, and much better than throwing, which
 * would be recorded as an ambiguous `provider_attempted`.
 */
export function createTokenOpener (encoding = 'sealed', relayKeyPair = null) {
  if (!TOKEN_ENCODINGS.includes(encoding)) {
    throw new Error('NOTIFY_PUSH_BAD_TOKEN_ENCODING: expected one of ' + TOKEN_ENCODINGS.join(', ') + ', got ' + encoding)
  }

  if (encoding === 'plaintext') {
    return (ciphertext) => {
      if (typeof ciphertext !== 'string' || !ciphertext) return null
      if (b4a.byteLength(ciphertext) > MAX_TOKEN_BYTES) return null
      return ciphertext
    }
  }

  // Convert once at construction so a missing/short relay key fails at wiring
  // time rather than on the first wake.
  const box = relayBoxKeyPair(relayKeyPair)
  return (ciphertext) => {
    if (typeof ciphertext !== 'string' || !ciphertext) return null
    let sealed
    try {
      // b4a's base64 decoder accepts the base64url alphabet and missing padding
      // transparently (verified), so both spellings round-trip without a
      // normalization step.
      sealed = b4a.from(ciphertext, 'base64')
    } catch {
      return null
    }
    if (sealed.length <= sodium.crypto_box_SEALBYTES) return null
    if (sealed.length - sodium.crypto_box_SEALBYTES > MAX_TOKEN_BYTES) return null
    const opened = b4a.allocUnsafe(sealed.length - sodium.crypto_box_SEALBYTES)
    if (!sodium.crypto_box_seal_open(opened, sealed, box.publicKey, box.secretKey)) return null
    const token = b4a.toString(opened, 'utf8')
    return token || null
  }
}
