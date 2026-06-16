/**
 * Spike C — core-density: open N hypercores on corestore 6 (flat-file) vs
 * corestore 7 (RocksDB single-store) and measure open file descriptors + RSS.
 *
 * Hypothesis (the migration thesis): corestore 6 opens ~k files per core, so
 * fd count grows linearly with cores and a 1000+ app relay (~2N cores) hits
 * the OS fd ceiling; corestore 7's single RocksDB store keeps fds ~flat. If
 * true, the fd/inode relief is the real justification for the migration.
 *
 * argv: <corestoreModulePath> <storageDir> <N> <label>
 * Prints one JSON line: { label, N, coresOpened, fds, rssMB, openMs, error? }
 */
import fs from 'node:fs'
import { createRequire } from 'node:module'

const corestorePath = process.argv[2]
const storageDir = process.argv[3]
const N = parseInt(process.argv[4], 10)
const label = process.argv[5] || 'unknown'

function openFds () { try { return fs.readdirSync('/dev/fd').length } catch { return -1 } }

// corestore is CJS; createRequire resolves the package main/exports and the
// module.exports class for both the v6 and v7 installs.
const require = createRequire(import.meta.url)
const mod = require(corestorePath)
const Corestore = mod.default || mod

const fdsBefore = openFds()
const t0 = performance.now()
const store = new Corestore(storageDir)
await store.ready()

let opened = 0
let error = null
try {
  for (let i = 0; i < N; i++) {
    const core = store.get({ name: 'c' + i })
    await core.ready()
    await core.append(Buffer.from('x')) // materialize the core on disk
    opened++
  }
} catch (err) {
  error = (err && err.code) || (err && err.message) || String(err)
}

const openMs = performance.now() - t0
const out = {
  label,
  N,
  coresOpened: opened,
  fds: openFds(),
  fdsBefore,
  rssMB: +(process.memoryUsage().rss / 1048576).toFixed(1),
  openMs: +openMs.toFixed(0)
}
if (error) out.error = error
console.log(JSON.stringify(out))
process.exit(0)
