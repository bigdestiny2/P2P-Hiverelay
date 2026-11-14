import { execFile } from 'node:child_process'
import { readFile, realpath } from 'node:fs/promises'
import { createRequire } from 'node:module'
import path from 'node:path'
import { promisify } from 'node:util'
import { assertIntentTestTarget, intentTestRuntimeDirectory } from '../integration-test-profiles.mjs'

const execute = promisify(execFile)
export const PRIVATE_VECTOR_BARE_VERSION = 'v1.31.0'

// The frozen sodium-v4 wire profile is independent of the public Bare cohort.
// Never retry an incompatible executable against another runtime silently.
export async function privateVectorRuntime (root, configured = process.env.HIVERELAY_PRIVATE_BARE_EXECUTABLE) {
  assertIntentTestTarget()
  let executable = configured
  try {
    if (executable == null || executable === '') {
      const tool = path.join(root, intentTestRuntimeDirectory)
      for (const name of ['bare', 'bare-runtime']) {
        const manifest = JSON.parse(await readFile(path.join(tool, 'node_modules', name, 'package.json'), 'utf8'))
        if (manifest.name !== name || manifest.version !== '1.31.0') {
          throw new Error(`${name} must be 1.31.0 in the private tool install`)
        }
      }
      const require = createRequire(path.join(tool, 'package.json'))
      executable = require(path.join(tool, 'node_modules/bare-runtime'))()
    }
    if (typeof executable !== 'string' || !path.isAbsolute(executable)) {
      throw new Error('configured private Bare executable must be an absolute path')
    }
    const canonical = await realpath(executable)
    const result = await execute(canonical, ['-e', 'console.log(JSON.stringify({ version: Bare.version, executable: Bare.argv[0] }))'], {
      encoding: 'utf8', timeout: 10000, maxBuffer: 64 * 1024
    })
    const receipt = JSON.parse(result.stdout)
    if (receipt.version !== PRIVATE_VECTOR_BARE_VERSION ||
        typeof receipt.executable !== 'string' || !path.isAbsolute(receipt.executable) ||
        await realpath(receipt.executable) !== canonical) {
      throw new Error(`private vector runtime must identify its exact ${PRIVATE_VECTOR_BARE_VERSION} executable`)
    }
    return Object.freeze({ executable: canonical, version: receipt.version })
  } catch (error) {
    throw new Error(`private vector runtime failed: ${error.message}; run npm run test:integration:prepare or configure HIVERELAY_PRIVATE_BARE_EXECUTABLE with the qualified ${PRIVATE_VECTOR_BARE_VERSION} native executable`, { cause: error })
  }
}
