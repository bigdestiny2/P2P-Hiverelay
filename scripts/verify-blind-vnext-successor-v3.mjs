#!/usr/bin/env node
import path from 'node:path'
import process from 'node:process'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const node = process.execPath
const executableSuffix = process.platform === 'win32' ? '.cmd' : ''
const brittleNode = path.join(root, `node_modules/.bin/brittle-node${executableSuffix}`)
const brittleBare = path.join(root, `node_modules/.bin/brittle-bare${executableSuffix}`)
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const skipChromium = process.argv.includes('--skip-chromium')

const successorTests = [
  'test/unit/blind-protocol-wire-v3.test.js',
  'packages/blind-ipc/test/private-ipc-v4-contract.test.js',
  'test/unit/blind-client-composition-v3.test.js'
]

const commands = [
  ['accepted predecessor successor-contract gate', node, ['packages/blind-protocol/verify-vnext-contracts.mjs']],
  ['WIRE v3 deterministic generator', node, ['packages/blind-protocol/generate-wire-v3.mjs', '--check']],
  ['private IPC v4 deterministic generator', node, ['packages/blind-ipc/generate-private-ipc-v4.mjs', '--check']],
  ['client composition v3 deterministic generator', node, ['packages/blind-protocol/generate-client-composition-v3.mjs', '--check']],
  ['browser v3 deterministic generator and source closure', node, ['packages/blind-client/generate-browser-artifact-v3.mjs', '--check']],
  ['successor Node contracts', brittleNode, ['--timeout', '120000', ...successorTests]],
  ['successor Bare contracts', brittleBare, ['--timeout', '120000', ...successorTests]],
  ['successor Node package-root exports', brittleNode, ['test/unit/blind-vnext-successor-package-exports.test.js']],
  ['accepted blind specifications', npm, ['run', 'verify:blind-specs']],
  ['accepted WIRE cross-runtime', npm, ['run', 'test:blind-wire:cross-runtime']],
  ['accepted composition cross-runtime', npm, ['run', 'test:blind-client-composition:cross-runtime']]
]
if (!skipChromium) {
  commands.push([
    'real Chromium v3 IndexedDB crash/retry gate',
    node,
    ['scripts/test-blind-client-browser-artifact-v3-chromium.mjs']
  ])
}

const completed = []
for (const [label, command, args] of commands) {
  process.stdout.write(`\n[successor-v3] ${label}\n`)
  const started = Date.now()
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: 'inherit',
    env: {
      ...process.env,
      PATH: `${path.join(root, 'node_modules/bare/bin')}${path.delimiter}${process.env.PATH || ''}`
    }
  })
  const durationMillis = Date.now() - started
  if (result.error) throw result.error
  if (result.status !== 0) {
    process.stderr.write(`${JSON.stringify({ label, exitCode: result.status, durationMillis, ok: false })}\n`)
    process.exit(result.status == null ? 1 : result.status)
  }
  completed.push({ label, durationMillis })
}

process.stdout.write(`${JSON.stringify({
  schema: 'hiverelay-blind-vnext-successor-v3-verification-v1',
  node: process.version,
  chromiumIncluded: !skipChromium,
  gates: completed,
  readiness: 0,
  runtimeReady: false,
  authorizesRelease: false,
  ok: true
}, null, 2)}\n`)
