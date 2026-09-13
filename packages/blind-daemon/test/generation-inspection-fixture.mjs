import { createHash, createHmac } from 'node:crypto'
import { lstat, readFile, readdir, readlink } from 'node:fs/promises'
import path from 'node:path'
import { openBlindStoreGenerationFloor } from '../storage-generation-v12.js'

export const KEY = Buffer.alloc(32, 0xa1)
export const IDENTITY = Buffer.from('generation-inspection-installation')
export const first = { walSequence: 1n, walHash: Buffer.alloc(32, 1) }
export const second = { walSequence: 2n, walHash: Buffer.alloc(32, 2) }

export function floorOptions (overrides = {}) {
  return { manifestKey: KEY, storeIdentity: IDENTITY, storeEvidence: first, ...overrides }
}

export function recordFile (root, sequence) {
  return path.join(root, `blind-store-generation-record-${String(sequence).padStart(16, '0')}-v2.json`)
}

function stable (value) {
  if (Array.isArray(value)) return value.map(stable)
  if (value == null || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]))
}

export function canonicalBytes (value) { return Buffer.from(JSON.stringify(stable(value)) + '\n') }
export function digest (bytes) { return createHash('sha256').update(bytes).digest('hex') }

export function signedBytes (body) {
  const mac = createHmac('sha256', KEY).update(canonicalBytes(body)).digest('hex')
  return canonicalBytes({ ...body, mac })
}

export async function signedBody (file) {
  const body = JSON.parse(await readFile(file))
  delete body.mac
  return body
}

function state (stat) {
  return Object.fromEntries(['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeMs', 'ctimeMs'].map(key => [key, stat[key]]))
}

// Fixtures own a small flat private directory. Access time is deliberately
// excluded: reading bytes may update it, but must change no content/namespace.
export async function inventory (root) {
  const entries = []
  for (const name of (await readdir(root)).sort()) {
    const file = path.join(root, name)
    const stat = await lstat(file)
    entries.push({
      name,
      ...state(stat),
      sha256: stat.isFile() ? digest(await readFile(file)) : null,
      link: stat.isSymbolicLink() ? await readlink(file) : null
    })
  }
  return { root: state(await lstat(root)), entries }
}

if (process.argv[2] === 'kill-at-phase') {
  const root = process.argv[3]
  const phase = process.argv[4]
  const keepAlive = setInterval(() => {}, 1000)
  const floor = await openBlindStoreGenerationFloor(root, floorOptions({
    async faultInjector (point) {
      if (point !== phase) return
      process.send({ point })
      await new Promise(() => {})
    }
  }))
  await floor.acknowledgeBlindOnlyWrite(second)
  clearInterval(keepAlive)
  throw new Error('inspection fixture did not reach the requested phase')
}
