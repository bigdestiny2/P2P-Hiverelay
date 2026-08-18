'use strict'

function disabledBlake2bWasm () {
  throw new Error('BLAKE2b acceleration is disabled by the browser artifact CSP contract')
}

disabledBlake2bWasm.SUPPORTED = false
disabledBlake2bWasm.WASM_SUPPORTED = false
disabledBlake2bWasm.ready = function ready (callback) {
  callback(new Error('BLAKE2b acceleration is disabled by the browser artifact CSP contract'))
}

module.exports = disabledBlake2bWasm
