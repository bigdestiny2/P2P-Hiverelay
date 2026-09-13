import fs from 'node:fs/promises'
import path from 'node:path'
import { createRequire } from 'node:module'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'
import { initializeCorestoreGenerationEnvelope, corestoreGenerationOpenOptions } from '../../core/core/persistence/corestore-generation-envelope.js'
import { PROFILE_DIGEST } from '../../blind-core-upstream-hc11-v1/format.js'
import { Hc11InstallationParticipantV1 } from '../index.js'
export const requireNative = createRequire(new URL('../../blind-core-upstream-hc11-v1/package.json', import.meta.url))
export const Corestore = requireNative('corestore')
export const Hypercore = requireNative('hypercore')
export const sha = bytes => createHash('sha256').update(bytes).digest('hex')
export const tick = () => new Promise(resolve => setImmediate(resolve))
export const deferred = () => { let done; const promise = new Promise(resolve => { done = resolve }); return { promise, resolve: done } }
export async function fixture (t) {
  const base = fileURLToPath(new URL('../.scratch/', import.meta.url))
  await fs.mkdir(base, { recursive: true, mode: 0o700 })
  const root = await fs.realpath(await fs.mkdtemp(path.join(base, 'participant-')))
  const ceremony = initializeCorestoreGenerationEnvelope(root, { participants: ['private-shared-v1'] })
  const options = { root, rootId: Buffer.alloc(32, 17), profileDigest: Buffer.from(PROFILE_DIGEST), envelope: corestoreGenerationOpenOptions(ceremony, { participant: 'private-shared-v1' }) }
  const owners = []
  const create = () => { const owner = new Hc11InstallationParticipantV1(options); owners.push(owner); return owner }
  t.after(async () => { for (const owner of owners) await owner.close(); await fs.rm(root, { recursive: true, force: true }) })
  return { root, ceremony, options, create, trigger: path.join(root, '.hiverelay-generation/hc11-trigger.v1.json'), database: path.join(root, 'generations/hc11-v1/db/IDENTITY'), generation: path.join(root, 'generations/hc11-v1') }
}
export async function inventory (root) {
  const out = []
  async function walk (dir, prefix = '') {
    for (const name of (await fs.readdir(dir)).sort()) {
      const file = path.join(dir, name); const relative = prefix + name; const stat = await fs.lstat(file)
      if (stat.isDirectory()) { out.push({ path: relative + '/', mode: stat.mode }); await walk(file, relative + '/') } else if (stat.isSymbolicLink()) out.push({ path: relative, target: await fs.readlink(file) })
      else out.push({ path: relative, sha256: sha(await fs.readFile(file)), bytes: stat.size, mode: stat.mode })
    }
  }
  await walk(root); return out
}
export async function child (mode, root) {
  const process = spawn(globalThis.process.execPath, [fileURLToPath(new URL('native-child.mjs', import.meta.url)), mode, root], { stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = ''; let stderr = ''
  process.stdout.on('data', b => { stdout += b }); process.stderr.on('data', b => { stderr += b })
  const code = await new Promise((resolve, reject) => { process.on('error', reject); process.on('exit', resolve) })
  if (code !== 0) throw new Error('Child failed: ' + stderr + stdout)
  return JSON.parse(stdout)
}
