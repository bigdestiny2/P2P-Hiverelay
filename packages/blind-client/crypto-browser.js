import generichash from 'sodium-javascript/crypto_generichash.js'
import randombytes from 'sodium-javascript/randombytes.js'
import sign from 'sodium-javascript/crypto_sign.js'

// sodium-universal's browser mapping exposes all of sodium-javascript through a
// CommonJS namespace, which prevents browser bundlers from discarding unrelated
// primitives. Keep this facade closed over the exact primitives used by the
// blind wire/client implementation. The functions themselves are the same
// sodium-javascript implementations selected by sodium-universal in browsers.
export default Object.freeze({
  crypto_generichash: generichash.crypto_generichash,
  crypto_sign_detached: sign.crypto_sign_detached,
  crypto_sign_seed_keypair: sign.crypto_sign_seed_keypair,
  crypto_sign_verify_detached: sign.crypto_sign_verify_detached,
  randombytes_buf: randombytes.randombytes_buf
})
