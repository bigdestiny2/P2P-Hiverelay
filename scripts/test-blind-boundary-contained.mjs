import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { blindBoundaryScratchRoot } from '../test/blind-boundary-scratch.js'

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const boundaryTestDirectories = [
  'packages/blind-ipc/test',
  'packages/blind-peercred/test',
  'packages/blind-edge/test',
  'packages/blind-daemon/test'
]
const scratchRoot = await blindBoundaryScratchRoot()
const environment = {
  ...process.env,
  HIVERELAY_BLIND_BOUNDARY_TEST_ROOT: scratchRoot,
  TMPDIR: scratchRoot,
  TMP: scratchRoot,
  TEMP: scratchRoot
}

async function testFiles () {
  const files = []
  for (const directory of boundaryTestDirectories) {
    const names = (await fs.readdir(path.join(root, directory)))
      .filter(name => name.endsWith('.test.js'))
      .sort()
    files.push(...names.map(name => path.join(directory, name)))
  }
  return files
}

function run (file, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [file, ...args], {
      cwd: root,
      env: environment,
      stdio: 'inherit'
    })
    child.once('error', reject)
    child.once('exit', (code, signal) => {
      if (code === 0) return resolve()
      reject(new Error(`${path.basename(file)} failed with ${signal || `exit ${code}`}`))
    })
  })
}

await run(path.join(root, 'scripts/audit-blind-boundary-scratch.mjs'), [])
await run(path.join(root, 'node_modules/brittle/bin/node.js'), [
  '--timeout', '120000',
  ...await testFiles()
])
