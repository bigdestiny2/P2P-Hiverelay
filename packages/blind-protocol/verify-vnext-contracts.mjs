#!/usr/bin/env node
import path from 'node:path'
import process from 'node:process'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const node = process.execPath
const brittle = path.join(root, 'node_modules/.bin/brittle-node')

const commands = [
  [node, ['packages/blind-protocol/generate-wire-v2.mjs', '--check']],
  [node, ['packages/blind-ipc/generate-private-ipc-v3.mjs', '--check']],
  [node, ['packages/blind-protocol/generate-client-composition-v2.mjs', '--check']],
  [node, ['packages/blind-client/generate-browser-artifact-v2.mjs', '--check']],
  [brittle, [
    'test/unit/blind-protocol-v1-compatibility-floor.test.js',
    'test/unit/blind-protocol-wire-v2.test.js',
    'test/unit/blind-client-composition-v2.test.js',
    'packages/blind-ipc/test/private-ipc-v3-contract.test.js'
  ]]
]

for (const [command, args] of commands) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) process.exit(result.status == null ? 1 : result.status)
}

console.log('vNext WIRE v2 / private IPC v3 / composition v2 / browser v2 contracts verified')
