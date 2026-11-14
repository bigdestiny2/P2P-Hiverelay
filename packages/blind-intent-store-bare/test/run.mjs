import './prepare-baseline.mjs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
const packaging = spawnSync(process.execPath, [
  '--test', fileURLToPath(new URL('./native-targets.test.mjs', import.meta.url))
], { stdio: 'inherit' })
if (packaging.error) throw packaging.error
if (packaging.status !== 0) process.exit(packaging.status ?? 1)
const result = spawnSync(process.execPath, [
  fileURLToPath(new URL('../node_modules/brittle/brittle-node.js', import.meta.url)),
  '--timeout', '120000', 'test/integration/blind-intent-store-bare.test.js'
], { cwd: fileURLToPath(new URL('../../..', import.meta.url)), stdio: 'inherit' })
if (result.error) throw result.error
process.exitCode = result.status ?? 1
