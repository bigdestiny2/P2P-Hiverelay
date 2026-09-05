import './prepare-baseline.mjs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
const result = spawnSync(process.execPath, [
  fileURLToPath(new URL('../node_modules/brittle/brittle-node.js', import.meta.url)),
  '--timeout', '120000', 'test/integration/blind-intent-store-bare.test.js'
], { cwd: fileURLToPath(new URL('../../..', import.meta.url)), stdio: 'inherit' })
if (result.error) throw result.error
process.exitCode = result.status ?? 1
