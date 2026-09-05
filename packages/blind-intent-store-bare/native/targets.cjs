const darwinArm64 = require('./flags-darwin-arm64.cjs')
const linuxX64 = require('./flags-linux-x64.cjs')

const qualify = (flags, runtime) => Object.freeze({ ...flags, runtime })
const darwinArm64Bare131 = qualify(darwinArm64, 'v1.31.0')
const linuxX64Bare131 = qualify(linuxX64, 'v1.31.0')
const darwinArm64PearWorker = qualify(darwinArm64, 'v1.29.4')
const linuxX64PearWorker = qualify(linuxX64, 'v1.29.4')

// Compiling a flag artifact does not add a supported runtime target. Keep this
// list explicit so package bundlers retain exactly the qualified artifacts.
// Pear runtime 1.3.1 / sidecar 0.5.2 embeds Bare 1.29.4 on these two targets.
// Both versions use the same unchanged target-system flag artifacts.
module.exports = function selectNativeFlags (platform, arch, version) {
  if (version === 'v1.31.0' && platform === 'darwin' && arch === 'arm64') return darwinArm64Bare131
  if (version === 'v1.31.0' && platform === 'linux' && arch === 'x64') return linuxX64Bare131
  if (version === 'v1.29.4' && platform === 'darwin' && arch === 'arm64') return darwinArm64PearWorker
  if (version === 'v1.29.4' && platform === 'linux' && arch === 'x64') return linuxX64PearWorker
  throw Object.assign(new Error('intent backend requires an explicitly qualified Bare runtime and native flag target'), {
    code: 'INTENT_STORE_PLATFORM'
  })
}
