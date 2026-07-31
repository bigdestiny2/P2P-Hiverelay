// CSP-safe stand-in for blake2b-wasm in locked-down browser artifacts.
//
// blake2b-wasm probes WebAssembly.compile() at require time; under a
// script-src 'self' Content-Security-Policy (no 'wasm-unsafe-eval') that
// probe rejects and surfaces as an unhandledrejection / securitypolicyviolation,
// so these artifacts must not attempt WebAssembly at all. This module
// presents the exact surface blake2b consumes from blake2b-wasm (ready(cb)
// and SUPPORTED), answering "unavailable" so blake2b keeps its pure-JS
// implementation — byte-identical output, zero WebAssembly.

function Blake2bUnavailable () {
  throw new Error('WASM not available in the CSP-safe browser build. Wait for Blake2b.ready(cb)')
}

Blake2bUnavailable.SUPPORTED = false
Blake2bUnavailable.WASM_SUPPORTED = false
Blake2bUnavailable.WASM_LOADED = false
Blake2bUnavailable.WASM = null
Blake2bUnavailable.ready = function ready (cb) {
  cb(new Error('WebAssembly not supported in the CSP-safe browser build'))
}
Blake2bUnavailable.prototype.ready = Blake2bUnavailable.ready

module.exports = Blake2bUnavailable
