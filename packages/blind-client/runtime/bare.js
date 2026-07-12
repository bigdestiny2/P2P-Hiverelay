import crypto from 'bare-crypto'
import b4a from 'b4a'
import { asBytes } from '../bytes.js'

export function createBareCryptoRuntime () {
  return Object.freeze({
    randomBytes (length) {
      return crypto.randomBytes(length)
    },
    async aes256GcmEncrypt ({ key, nonce, aad, plaintext }) {
      key = asBytes(key, 'key', 32)
      nonce = asBytes(nonce, 'nonce', 12)
      aad = asBytes(aad, 'aad')
      plaintext = asBytes(plaintext, 'plaintext')
      const cipher = crypto.createCipheriv(crypto.constants.cipher.AES256GCM, key, nonce, { authTagLength: 16 })
      cipher.setAAD(aad)
      const ciphertext = b4a.concat([cipher.update(plaintext), cipher.final()])
      return b4a.concat([ciphertext, cipher.getAuthTag()])
    },
    async aes256GcmDecrypt ({ key, nonce, aad, sealed }) {
      key = asBytes(key, 'key', 32)
      nonce = asBytes(nonce, 'nonce', 12)
      aad = asBytes(aad, 'aad')
      sealed = asBytes(sealed, 'sealed')
      if (sealed.byteLength < 16) throw new Error('sealed AES-GCM value is truncated')
      const ciphertext = sealed.subarray(0, sealed.byteLength - 16)
      const tag = sealed.subarray(sealed.byteLength - 16)
      const decipher = crypto.createDecipheriv(crypto.constants.cipher.AES256GCM, key, nonce, { authTagLength: 16 })
      decipher.setAAD(aad)
      decipher.setAuthTag(tag)
      return b4a.concat([decipher.update(ciphertext), decipher.final()])
    }
  })
}
