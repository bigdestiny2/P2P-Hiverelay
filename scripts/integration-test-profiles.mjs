import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readFileSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'

export const intentTestRuntimeDirectory = 'scripts/test-tools/private-intent-runtime'
export const privateIntegrationProfiles = Object.freeze([
  { file: 'test/integration/blind-intent-store-bare.test.js', directory: 'packages/blind-intent-store-bare' },
  { file: 'test/integration/blind-intent-store-pear.test.js', directory: 'packages/blind-intent-pear-consumer' }
])

export function assertIntentTestTarget (platform = process.platform, arch = process.arch) {
  if ((platform === 'darwin' && arch === 'arm64') || (platform === 'linux' && arch === 'x64')) return
  throw new Error(`private intent integration target ${platform}-${arch} is unqualified; use darwin-arm64 or linux-x64 (no tests skipped)`)
}

export function partitionIntegrationTests (files) {
  const privateProfiles = privateIntegrationProfiles.filter(profile => files.includes(profile.file))
  const ordinary = files.filter(file => !privateProfiles.some(profile => profile.file === file))
  return { privateProfiles, ordinary }
}

export function privateIntegrationRuntime (root) {
  assertIntentTestTarget()
  const instruction = 'run npm run test:integration:prepare before the integration suite'
  try {
    const tool = path.join(root, intentTestRuntimeDirectory)
    const require = createRequire(path.join(tool, 'package.json'))
    for (const [directory, name, version] of [
      [tool, 'bare', '1.31.0'], [tool, 'bare-runtime', '1.31.0'],
      [path.join(root, privateIntegrationProfiles[0].directory), 'brittle', '4.1.0'],
      [path.join(root, privateIntegrationProfiles[1].directory), 'pear-runtime', '1.3.1'],
      [path.join(root, privateIntegrationProfiles[1].directory), 'bare-sidecar', '0.5.2']
    ]) {
      const manifest = JSON.parse(readFileSync(path.join(directory, 'node_modules', name, 'package.json'), 'utf8'))
      if (manifest.name !== name || manifest.version !== version) throw new Error(`${name} must be ${version} in its own test profile`)
    }
    for (const profile of privateIntegrationProfiles) {
      if (!existsSync(path.join(root, profile.directory, 'package-lock.json'))) throw new Error(`missing own lock for ${profile.directory}`)
    }
    // Resolve only from the dedicated tool install, never an ambient/global Bare.
    const executable = require(path.join(tool, 'node_modules/bare-runtime'))()
    // The locked launcher sets executable mode on its downloaded native payload.
    const launcher = path.join(tool, 'node_modules/bare/bin/bare')
    const probe = spawnSync(process.execPath, [launcher, '-e', 'console.log(JSON.stringify({ executable: Bare.argv[0], version: Bare.version }))'], {
      encoding: 'utf8', timeout: 10000
    })
    if (probe.error || probe.signal || probe.status !== 0) throw new Error(`standalone Bare probe failed: ${probe.error?.message || probe.signal || probe.stderr || probe.status}`)
    let receipt
    try { receipt = JSON.parse(probe.stdout) } catch { throw new Error('standalone Bare probe did not return a JSON receipt') }
    if (receipt.version !== 'v1.31.0' || typeof receipt.executable !== 'string' || !path.isAbsolute(receipt.executable) || realpathSync(receipt.executable) !== realpathSync(executable)) {
      throw new Error('standalone Bare receipt does not identify the locked v1.31.0 executable')
    }
    return executable
  } catch (error) {
    throw new Error(`private integration prerequisites failed: ${error.message}; ${instruction}`, { cause: error })
  }
}

export function npmCommand (args) {
  return process.env.npm_execpath
    ? { executable: process.execPath, args: [process.env.npm_execpath, ...args] }
    : { executable: 'npm', args }
}

export async function runTestChild (executable, args, options = {}) {
  const child = spawn(executable, args, { stdio: 'inherit', windowsHide: true, ...options })
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('exit', (code, signal) => resolve({ code, signal }))
  })
  if (result.signal) process.stderr.write(`test child terminated by ${result.signal}\n`)
  return result.signal ? 1 : (result.code ?? 1)
}
