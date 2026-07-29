import b4a from 'b4a'
import { asBytes } from '../bytes.js'
import { fail } from '../errors.js'

function webCrypto (provided) {
  const value = provided || globalThis.crypto
  if (!value || !value.subtle || typeof value.getRandomValues !== 'function') {
    fail('CRYPTO_UNAVAILABLE', 'Web Crypto with AES-GCM is required')
  }
  return value
}

export function createBrowserCryptoRuntime (provided) {
  const crypto = webCrypto(provided)
  return Object.freeze({
    randomBytes (length) {
      const output = new Uint8Array(length)
      for (let offset = 0; offset < output.byteLength; offset += 65536) {
        crypto.getRandomValues(output.subarray(offset, Math.min(output.byteLength, offset + 65536)))
      }
      return b4a.from(output.buffer, output.byteOffset, output.byteLength)
    },
    async aes256GcmEncrypt ({ key, nonce, aad, plaintext }) {
      key = asBytes(key, 'key', 32)
      nonce = asBytes(nonce, 'nonce', 12)
      aad = asBytes(aad, 'aad')
      plaintext = asBytes(plaintext, 'plaintext')
      const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt'])
      const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, cryptoKey, plaintext)
      return b4a.from(sealed)
    },
    async aes256GcmDecrypt ({ key, nonce, aad, sealed }) {
      key = asBytes(key, 'key', 32)
      nonce = asBytes(nonce, 'nonce', 12)
      aad = asBytes(aad, 'aad')
      sealed = asBytes(sealed, 'sealed')
      const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt'])
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, cryptoKey, sealed)
      return b4a.from(plaintext)
    }
  })
}
