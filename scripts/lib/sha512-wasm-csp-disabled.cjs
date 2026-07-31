// CSP-safe stand-in for sha512-wasm in locked-down browser artifacts.
//
// sha512-wasm eagerly compiles its inline WebAssembly module synchronously at
// require time. Under a script-src 'self' Content-Security-Policy (no
// 'wasm-unsafe-eval') that compile throws CompileError and — caught or not —
// the attempt is still reported as a securitypolicyviolation, so these
// artifacts must not attempt WebAssembly at all. This module presents the
// exact surface sha512-universal consumes from sha512-wasm (ready(cb) and
// SUPPORTED), answering "unavailable" so sha512-universal keeps its pure-JS
// implementation — byte-identical output, zero WebAssembly.

function Sha512Unavailable () {
  throw new Error('WASM not available in the CSP-safe browser build. Wait for Sha512.ready(cb)')
}

Sha512Unavailable.SUPPORTED = false
Sha512Unavailable.WASM_SUPPORTED = false
Sha512Unavailable.WASM_LOADED = false
Sha512Unavailable.ready = function ready (cb) {
  cb(new Error('WebAssembly not supported in the CSP-safe browser build'))
}
Sha512Unavailable.prototype.ready = Sha512Unavailable.ready

module.exports = Sha512Unavailable
