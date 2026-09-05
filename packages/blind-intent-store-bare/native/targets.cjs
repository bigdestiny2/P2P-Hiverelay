const darwinArm64 = require('./flags-darwin-arm64.cjs')
const linuxX64 = require('./flags-linux-x64.cjs')

// Compiling a flag artifact does not add a supported runtime target. Keep this
// list explicit so package bundlers retain exactly the qualified artifacts.
module.exports = function selectNativeFlags (platform, arch, version) {
  if (version === 'v1.31.0' && platform === 'darwin' && arch === 'arm64') return darwinArm64
  if (version === 'v1.31.0' && platform === 'linux' && arch === 'x64') return linuxX64
  throw Object.assign(new Error('intent backend requires a qualified Bare v1.31.0 native flag target'), {
    code: 'INTENT_STORE_PLATFORM'
  })
}
