#!/usr/bin/env node
// publish-code-drive.mjs — package the Blindspark JS app code (packages/) into a
// signed Hyperdrive for drive-boot self-updating appliances (docs/DRIVE-BOOT-APPLIANCE.md,
// milestone M1). This is the publisher half; the loader (M2) is the consumer.
//
// v1 boundary (D2): only the PURE-JS app tree ships on the drive. Native addons
// (sodium-native, udx-native, …) and the rest of node_modules stay baked in the thin
// Docker image, so the drive is arch-agnostic and a dependency-graph change still rides
// a (rare) image bump. `.node` / `.bare` prebuilds and test trees are excluded here.
//
// Output: a Hyperdrive in a corestore, carrying every app file plus a signed
// /release-manifest.json + /release-manifest.sig (see release-manifest.mjs). The
// release key is an OFFLINE Ed25519 seed supplied out-of-band:
//
//   DRIVE_BOOT_RELEASE_SEED=<64hex> node scripts/drive-boot/publish-code-drive.mjs \
//     --root . --store /var/lib/blindspark-code-drive --version 0.24.2 [--key <hex>]
//
// Seeding the resulting drive durably onto the fleet is the next step (client.seed /
// POST /seed-core); this script produces + signs the drive and prints its key.

import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import { readdir, readFile, stat, mkdir } from 'node:fs/promises'
import { join, sep } from 'node:path'
import { sha256Hex, signDriveManifest } from './release-manifest.mjs'

// App code that ships on the drive. Kept explicit (not "everything") so the drive
// never accidentally carries node_modules, secrets, or build junk.
export const DEFAULT_INCLUDE = [
  'packages/core',
  'packages/services',
  'packages/client',
  'packages/verifier',
  'dashboard'
]
const EXCLUDE_DIRS = new Set(['node_modules', 'test', '__tests__', 'tests', '.git', 'prebuilds', 'coverage', '.nyc_output'])
const EXCLUDE_EXT = new Set(['.node', '.bare', '.map', '.log', '.tsbuildinfo'])
const MANIFEST_PATH = '/release-manifest.json'
const MANIFEST_SIG_PATH = '/release-manifest.sig'

// Walk `include` dirs under root and return sorted { path (posix drive path), abs,
// content } for every pure-JS app file. Deterministic order → reproducible manifest.
export async function collectCodeFiles (root, { include = DEFAULT_INCLUDE } = {}) {
  const files = []
  async function walk (absDir, driveDir) {
    let entries
    try { entries = await readdir(absDir, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (EXCLUDE_DIRS.has(e.name)) continue
        await walk(join(absDir, e.name), driveDir + '/' + e.name)
      } else if (e.isFile()) {
        const dot = e.name.lastIndexOf('.')
        const ext = dot >= 0 ? e.name.slice(dot) : ''
        if (EXCLUDE_EXT.has(ext)) continue
        const abs = join(absDir, e.name)
        files.push({ path: driveDir + '/' + e.name, abs, content: await readFile(abs) })
      }
    }
  }
  for (const inc of include) {
    const absInc = join(root, inc)
    try { if ((await stat(absInc)).isDirectory()) await walk(absInc, '/' + inc.split(sep).join('/')) } catch { /* skip missing */ }
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  return files
}

// Map the collected files to their sha256 for the manifest `files` field.
export function fileHashMap (files) {
  const map = {}
  for (const f of files) map[f.path] = sha256Hex(f.content)
  return map
}

// Write the app files + the signed manifest into `drive`. Returns { manifest, signature }.
// The manifest+sig are written AFTER the app files and are NOT part of the signed
// `files` map (they'd be self-referential) — exactly like peerit's asset-manifest.json.
export async function writeCodeDrive (drive, { files, version, seedHex, runtime }) {
  for (const f of files) await drive.put(f.path, f.content)
  const driveKey = drive.key.toString('hex')
  const manifest = { files: fileHashMap(files), driveKey: driveKey.toLowerCase(), version, runtime }
  const signature = signDriveManifest(manifest, seedHex)
  await drive.put(MANIFEST_PATH, Buffer.from(JSON.stringify(manifest, null, 2)))
  await drive.put(MANIFEST_SIG_PATH, Buffer.from(JSON.stringify(signature, null, 2)))
  // Puts are durable once resolved; no flush() needed (and hyperdrive@11's flush()
  // routes through a Hyperbee method not present in this version).
  return { manifest, signature, driveKey }
}

function arg (name, dflt) {
  const i = process.argv.indexOf(name)
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt
}

async function main () {
  const root = arg('--root', process.cwd())
  const storeDir = arg('--store', join(root, '.drive-boot-store'))
  const version = arg('--version') || JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version
  const seedHex = (process.env.DRIVE_BOOT_RELEASE_SEED || '').trim()
  if (!seedHex) { console.error('publish-code-drive: set DRIVE_BOOT_RELEASE_SEED (64 hex) — the OFFLINE release key'); process.exit(1) }
  const runtime = { nodeMajor: String(process.versions.node.split('.')[0]), packagesOnly: true }

  const files = await collectCodeFiles(root)
  if (!files.length) { console.error('publish-code-drive: no app files found under ' + root); process.exit(1) }
  const total = files.reduce((n, f) => n + f.content.length, 0)

  await mkdir(storeDir, { recursive: true })
  const store = new Corestore(storeDir)
  const existingKey = arg('--key')
  const drive = existingKey ? new Hyperdrive(store, Buffer.from(existingKey, 'hex')) : new Hyperdrive(store)
  await drive.ready()

  const { manifest, signature, driveKey } = await writeCodeDrive(drive, { files, version, seedHex, runtime })

  console.log('publish-code-drive: signed code drive built')
  console.log('  version:    ' + version)
  console.log('  files:      ' + files.length + ' (' + (total / 1024).toFixed(1) + ' KB pure-JS)')
  console.log('  driveKey:   ' + driveKey)
  console.log('  releaseKey: ' + signature.key + '  (pin this in the loader / store manifest)')
  console.log('  version@:   ' + drive.version)
  console.log('  store:      ' + storeDir)
  console.log('\nNext: seed this drive durably onto the fleet (client.seed / POST /seed-core), then')
  console.log('advance the drive-boot channel pointer to driveKey@' + drive.version + '.')

  await drive.close()
  await store.close()
}

// Only run the CLI when invoked directly, not when imported by the test/loader.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => { console.error('publish-code-drive: ' + (err && err.stack || err)); process.exit(1) })
}
