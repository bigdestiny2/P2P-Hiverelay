#!/usr/bin/env node
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertIntentTestTarget, intentTestRuntimeDirectory, npmCommand, privateIntegrationProfiles, privateIntegrationRuntime, runTestChild } from './integration-test-profiles.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
assertIntentTestTarget()
for (const directory of [intentTestRuntimeDirectory, ...privateIntegrationProfiles.map(profile => profile.directory)]) {
  const command = npmCommand(['ci', '--prefix', path.join(root, directory), '--workspaces=false', '--ignore-scripts', '--no-audit', '--no-fund'])
  const code = await runTestChild(command.executable, command.args, { cwd: root })
  if (code !== 0) process.exit(code)
}
const executable = privateIntegrationRuntime(root)
process.stdout.write(`private integration prerequisites ready: ${executable}\n`)
