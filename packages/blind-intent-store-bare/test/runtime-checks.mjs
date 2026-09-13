/* global Bare */
import fs from 'bare-fs'
import { join } from 'bare-path'
import { BareIntentBackend, BARE_INTENT_BACKEND_LIMITS, BARE_INTENT_BACKEND_RUNTIME } from '../index.js'
import { constants, exactStat, open, writeAll } from '../runtime.js'

const base = Bare.argv[2]
const checks = []
function check (value, name) {
  if (!value) throw new Error(name)
  checks.push(name)
}
async function rejects (operation, code) {
  try { await operation() } catch (error) {
    check(error.code === code, `${code}: ${error.code}`)
    return
  }
  throw new Error('expected rejection: ' + code)
}
const key = n => 'intent:' + BigInt(n).toString(16).padStart(64, '0')
const eio = () => Object.assign(new Error('injected IO failure'), { code: 'EIO' })

try {
  check(BARE_INTENT_BACKEND_RUNTIME.runtime === Bare.version, 'selected runtime matches actual Bare worker')
  check(BARE_INTENT_BACKEND_RUNTIME.platform === Bare.platform && BARE_INTENT_BACKEND_RUNTIME.arch === Bare.arch, 'selected flags match actual worker target')
  const path = join(base, 'native-file')
  let handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)
  let writes = 0
  const nativeWrite = handle.write.bind(handle)
  handle.write = (bytes, offset, length, position) => { writes++; return nativeWrite(bytes, offset, Math.min(3, length), position) }
  await writeAll(handle, Buffer.from('complete-native-write'))
  await handle.sync()
  check(writes === 7, 'native partial writes loop to completion before file fsync')
  const stat = await handle.stat()
  check(Number.isSafeInteger(stat.ino), 'native stat exact inode')
  await handle.close()
  check((await fs.promises.readFile(path)).toString() === 'complete-native-write', 'partial writes retain exact bytes')
  await rejects(() => open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600), 'EEXIST')
  await fs.promises.symlink(path, join(base, 'link'))
  await rejects(() => open(join(base, 'link'), constants.O_RDONLY | constants.O_NOFOLLOW), 'ELOOP')
  await rejects(() => open(path, constants.O_RDONLY | constants.O_DIRECTORY), 'ENOTDIR')
  handle = await open(base, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  await handle.sync()
  await handle.close()
  check(true, 'actual directory fsync succeeds')
  // Parent created a FIFO. O_NONBLOCK must let this open complete without a writer.
  handle = await open(join(base, 'fifo'), constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW)
  check((await handle.stat()).isFIFO(), 'native nonblocking FIFO open completes')
  await handle.close()
  for (const bytesWritten of [0, -1, 100, 1.5, NaN]) {
    await rejects(() => writeAll({ write: async () => ({ bytesWritten }) }, Buffer.from('x')), 'EIO')
  }
  await rejects(() => writeAll({ write: async () => { throw eio() } }, Buffer.from('x')), 'EIO')
  for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size']) {
    await rejects(() => exactStat({ ...stat, [field]: Number.MAX_SAFE_INTEGER + 1 }), 'INTENT_STORE_CUSTODY')
  }
  handle = await open(path, constants.O_RDONLY)
  let closes = 0
  const nativeClose = handle._handle.close.bind(handle._handle)
  handle._handle.close = async () => { closes++; await nativeClose(); throw eio() }
  await rejects(() => handle.close(), 'EIO')
  await rejects(() => handle.close(), 'EIO')
  check(closes === 1, 'close error never retries a potentially reused descriptor')

  const store = join(base, 'bounded')
  let release
  let reached
  const gate = new Promise(resolve => { release = resolve })
  const entered = new Promise(resolve => { reached = resolve })
  let paused = false
  const backend = new BareIntentBackend(store, {
    onCommitPhase: async phase => {
      if (!paused && phase === 'before-write') { paused = true; reached(); await gate }
    }
  })
  const first = backend.compareAndSwap(key(1), 0n, Buffer.from('one'))
  await entered
  const bytes = Buffer.from('snapshot')
  const second = backend.compareAndSwap(key(2), 0n, bytes)
  bytes.fill(0)
  const remaining = []
  for (let n = 3; n <= BARE_INTENT_BACKEND_LIMITS.maxPendingOperations; n++) remaining.push(backend.compareAndSwap(key(n), 0n, Buffer.from('x')))
  check(backend._pending === 8, 'admission holds exactly eight operations')
  await rejects(() => backend.read(key(99)), 'INTENT_STORE_BUSY')
  const closing = backend.close()
  await rejects(() => backend.read(key(1)), 'INTENT_STORE_CLOSED')
  release()
  check((await Promise.all([first, second, ...remaining])).every(Boolean), 'close drains all admitted writes')
  await closing
  check(backend._pending === 0 && backend._lock === null, 'close drains pending and relinquishes lease')
  const reopened = new BareIntentBackend(store)
  check((await reopened.read(key(2))).ciphertext.toString() === 'snapshot', 'admission snapshots caller ciphertext')
  for (let n = 9; n <= 90; n++) await reopened.compareAndSwap(key(n), 0n, Buffer.from('x'))
  const found = []
  let cursor = null
  let pages = 0
  do {
    const page = await reopened.keysPage({ cursor, limit: 7 })
    check(page.keys.length <= 7, 'page bounded ' + pages)
    found.push(...page.keys)
    cursor = page.cursor
    pages++
  } while (cursor)
  check(found.length === 90 && new Set(found).size === 90 && pages === 14, 'enumeration has exact coverage and read bounds')
  const cursors = []
  for (let n = 0; n < 4; n++) cursors.push((await reopened.keysPage({ limit: 1 })).cursor)
  await rejects(() => reopened.keysPage({ limit: 1 }), 'INTENT_STORE_BUSY')
  await rejects(() => reopened.compareAndSwap(key(91), 0n, Buffer.from('x')), 'INTENT_STORE_BUSY')
  for (const cursor of cursors) await reopened.closeScan(cursor)
  await rejects(() => reopened.closeScan(cursors[0]), 'INTENT_STORE_CURSOR')
  check(reopened._scans.size === 0, 'explicit scan close releases four cursors')
  const rawScan = (await reopened.keysPage({ limit: 1 })).cursor
  const scan = reopened._scans.get(rawScan)
  const nativeScanClose = scan.close.bind(scan)
  scan.close = async () => { await nativeScanClose(); throw eio() }
  await rejects(() => reopened.close(), 'EIO')
  check(reopened._lock === null && reopened._directory === null && reopened._scans.size === 0, 'failed scan close still releases directory and lease')
  const replacement = new BareIntentBackend(store)
  await replacement.ready()
  await replacement.close()

  const failed = new BareIntentBackend(join(base, 'failed'))
  await failed.ready()
  failed._directory.sync = async () => { throw eio() }
  let successes = 0
  const uncertain = failed.compareAndSwap(key(1), 0n, Buffer.from('unknown')).then(value => { if (value) successes++ })
  const queued = failed.compareAndSwap(key(2), 0n, Buffer.from('must-not-write'))
  await rejects(() => uncertain, 'INTENT_STORE_COMMIT_UNKNOWN')
  await rejects(() => queued, 'INTENT_STORE_FAILED')
  await rejects(() => failed.ready(), 'INTENT_STORE_FAILED')
  await rejects(() => failed.read(key(1)), 'INTENT_STORE_FAILED')
  check(successes === 0, 'uncertain publication grants no success')
  await failed.close()
  const recovered = new BareIntentBackend(join(base, 'failed'))
  check((await recovered.read(key(1))).revision === 1n, 'process reopen sees complete published uncertain record')
  check((await recovered.read(key(2))).revision === 0n, 'queued write never published after failure')
  await recovered.close()

  for (const fault of ['partial-write-error', 'file-sync-error', 'record-close-error']) {
    const directory = join(base, fault)
    const phases = []
    const backend = new BareIntentBackend(directory, { onCommitPhase: phase => { phases.push(phase) } })
    await backend.ready()
    const originalWrite = fs.write
    const originalSync = fs.fsync
    const originalClose = fs.close
    let writes = 0
    let closes = 0
    if (fault === 'partial-write-error') {
      fs.write = async (fd, bytes, offset, length, position) => {
        if (writes++) throw eio()
        return originalWrite(fd, bytes, offset, Math.min(3, length), position)
      }
    }
    if (fault === 'file-sync-error') {
      fs.fsync = async fd => {
        if (fs.fstatSync(fd).isFile()) throw eio()
        return originalSync(fd)
      }
    }
    if (fault === 'record-close-error') {
      fs.close = (...args) => {
        const record = args.length === 1 && fs.fstatSync(args[0]).isFile() && fs.fstatSync(args[0]).size > 0
        const result = originalClose(...args)
        if (record) { closes++; return result.then(() => { throw eio() }) }
        return result
      }
    }
    try {
      const first = backend.compareAndSwap(key(1), 0n, Buffer.from('bounded-complete-record'))
      const next = backend.compareAndSwap(key(2), 0n, Buffer.from('must-not-commit'))
      await rejects(() => first, 'INTENT_STORE_COMMIT_UNKNOWN')
      await rejects(() => next, 'INTENT_STORE_FAILED')
      await rejects(() => backend.ready(), 'INTENT_STORE_FAILED')
    } finally {
      fs.write = originalWrite
      fs.fsync = originalSync
      fs.close = originalClose
      await backend.close()
    }
    if (fault === 'record-close-error') {
      check(closes === 1, 'CAS close failure retains unknown outcome without retry')
      check(phases.join(',') === 'before-write,after-file-sync,after-publication,before-directory-sync,after-directory-sync', 'CAS close occurs after exact durable commit phases')
    } else check(phases.join(',') === 'before-write', fault + ' never reaches publication')
    const after = new BareIntentBackend(directory)
    check((await after.read(key(1))).revision === (fault === 'record-close-error' ? 1n : 0n), fault + ' reopens only committed records')
    check((await after.read(key(2))).revision === 0n, fault + ' queued CAS remains absent')
    await after.close()
  }

  const substitutionPath = join(base, 'pending-substitution')
  let substitute = false
  const substitution = new BareIntentBackend(substitutionPath, {
    onCommitPhase: async phase => {
      if (substitute && phase === 'after-file-sync') {
        await fs.promises.rename(join(substitutionPath, '.pending'), join(substitutionPath, '.saved'))
        await fs.promises.writeFile(join(substitutionPath, '.pending'), 'replacement', { mode: 0o600 })
      }
    }
  })
  await substitution.compareAndSwap(key(1), 0n, Buffer.from('prior'))
  substitute = true
  await rejects(() => substitution.compareAndSwap(key(1), 1n, Buffer.from('next')), 'INTENT_STORE_COMMIT_UNKNOWN')
  await substitution.close()
  await fs.promises.unlink(join(substitutionPath, '.saved'))
  const prior = new BareIntentBackend(substitutionPath)
  check((await prior.read(key(1))).ciphertext.toString() === 'prior', 'pre-rename pending inode substitution preserves prior record')
  await prior.close()

  const inputs = new BareIntentBackend(join(base, 'input'))
  for (const name of ['../escape', 'intent:../escape', 'intent:' + 'AA'.repeat(32)]) await rejects(() => inputs.read(name), 'INTENT_STORE_INPUT')
  await rejects(() => inputs.compareAndSwap(key(1), -1n, Buffer.from('x')), 'INTENT_STORE_INPUT')
  await rejects(() => inputs.compareAndSwap(key(1), 0n, Buffer.alloc(BARE_INTENT_BACKEND_LIMITS.maxCiphertextBytes + 1)), 'INTENT_STORE_INPUT')
  await rejects(() => inputs.keysPage({ limit: 257 }), 'INTENT_STORE_INPUT')
  await inputs.close()
  const loadedAddons = Object.values(Bare.Addon.cache).map(addon => addon.url.href).sort()
  console.log(JSON.stringify({ ok: true, runtime: BARE_INTENT_BACKEND_RUNTIME, versions: Bare.versions, loadedAddons, constants, checks, measurements: { admitted: 8, keys: found.length, pageLimit: 7, pages, scans: 4 } }))
} catch (error) {
  console.error(error.stack)
  console.log(JSON.stringify({ ok: false, error: error.code || 'ERROR', message: error.message, checks }))
  Bare.exitCode = 1
}

// A local Pear worker also owns its IPC pipe; close it after all awaited checks.
if (Bare.IPC) Bare.IPC.end()
