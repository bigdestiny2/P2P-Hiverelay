'use strict'

function disabledSha512Wasm () {
  throw new Error('SHA-512 acceleration is disabled by the browser artifact CSP contract')
}

disabledSha512Wasm.SUPPORTED = false
disabledSha512Wasm.WASM_SUPPORTED = false
disabledSha512Wasm.ready = function ready (callback) {
  callback(new Error('SHA-512 acceleration is disabled by the browser artifact CSP contract'))
}

module.exports = disabledSha512Wasm
