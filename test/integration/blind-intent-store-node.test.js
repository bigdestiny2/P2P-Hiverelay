import test from 'brittle'
import assert from 'node:assert/strict'
import { fork, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { NodeIntentBackend, NODE_INTENT_BACKEND_LIMITS } from '../../packages/blind-intent-store-node/index.js'

const fixture = fileURLToPath(new URL('../../packages/blind-intent-store-node/test/process-fixture.mjs', import.meta.url))
const key = n => 'intent:' + BigInt(n).toString(16).padStart(64, '0')
const filename = n => key(n).slice(7) + '.intent'

async function setup (t) {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'hiverelay-intent-node-'))
  const backends = []
  const children = []
  t.teardown(async () => {
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
    for (const backend of backends) await backend.close()
    await rm(base, { recursive: true, force: true })
  })
  return {
    base,
    directory: join(base, 'store'),
    backend (directory = join(base, 'store'), options) {
      const backend = new NodeIntentBackend(directory, options)
      backends.push(backend)
      return backend
    },
    child (args) {
      const child = fork(fixture, args, { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] })
      children.push(child)
      return child
    }
  }
}

function runChild (args) {
  const result = spawnSync(process.execPath, [fixture, ...args], { encoding: 'utf8', timeout: 30_000 })
  assert.equal(result.error, undefined)
  assert.equal(result.signal, null)
  return { status: result.status, ...JSON.parse(result.stdout) }
}

async function rejectsCode (promise, code) {
  await assert.rejects(promise, error => error.code === code)
}

test('intent backend holds a real exclusive lease and preserves CAS across independent processes', async t => {
  const context = await setup(t)
  const backend = context.backend()
  await backend.ready()
  t.alike(await backend.read(key(1)), { revision: 0n, ciphertext: null })
  t.ok(await backend.compareAndSwap(key(1), 0n, Buffer.from('cipher-one')))
  const rawLock = runChild(['raw-lock', context.directory])
  t.is(rawLock.status, 1, 'an independent raw FDLock cannot acquire the inode')
  t.alike(runChild(['cas', context.directory, key(1), '0', 'aa']).error, 'INTENT_STORE_LOCKED')
  const value = await backend.read(key(1))
  value.ciphertext.fill(0)
  t.is((await backend.read(key(1))).ciphertext.toString(), 'cipher-one')
  await backend.close()
  const conflict = runChild(['cas', context.directory, key(1), '0', 'aa'])
  t.is(conflict.status, 0)
  t.is(conflict.changed, false)
  t.is(conflict.revision, '1')
  t.is(conflict.ciphertext, Buffer.from('cipher-one').toString('hex'))
  const changed = runChild(['cas', context.directory, key(1), '1', 'aabb'])
  t.is(changed.changed, true)
  t.is(changed.revision, '2')
  t.alike(await context.backend().read(key(1)), { revision: 2n, ciphertext: Buffer.from('aabb', 'hex') })
})

test('kill boundaries recover only exact published ciphertext and never promote pending files', async t => {
  const context = await setup(t)
  for (const phase of ['before-write', 'after-file-sync', 'after-publication', 'before-directory-sync']) {
    const directory = join(context.base, phase)
    const initial = context.backend(directory)
    await initial.compareAndSwap(key(1), 0n, Buffer.from('old'))
    await initial.close()
    const child = context.child(['kill-cas', directory, key(1), '1', Buffer.from('new').toString('hex'), phase])
    const exited = once(child, 'exit')
    const [message] = await once(child, 'message')
    t.is(message.phase, phase)
    child.kill('SIGKILL')
    const [, signal] = await exited
    t.is(signal, 'SIGKILL')
    const reopened = context.backend(directory)
    const record = await reopened.read(key(1))
    const published = phase === 'after-publication' || phase === 'before-directory-sync'
    t.is(record.revision, published ? 2n : 1n)
    t.is(record.ciphertext.toString(), published ? 'new' : 'old')
    t.absent((await readdir(directory)).includes('.pending'))
    await reopened.close()
  }
})

test('a failed directory sync never reports CAS success and fences queued operations until reopen', async t => {
  const context = await setup(t)
  const backend = context.backend()
  await backend.ready()
  backend._directory.sync = async () => { throw Object.assign(new Error('injected directory sync failure'), { code: 'EIO' }) }
  let sendLicenses = 0
  const first = backend.compareAndSwap(key(1), 0n, Buffer.from('unknown')).then(value => { if (value) sendLicenses++ })
  const queued = backend.compareAndSwap(key(2), 0n, Buffer.from('must-not-write'))
  await rejectsCode(first, 'INTENT_STORE_COMMIT_UNKNOWN')
  await rejectsCode(queued, 'INTENT_STORE_FAILED')
  await rejectsCode(backend.read(key(1)), 'INTENT_STORE_FAILED')
  await rejectsCode(backend.ready(), 'INTENT_STORE_FAILED')
  t.is(sendLicenses, 0)
  await backend.close()
  const reopened = context.backend()
  t.is((await reopened.read(key(1))).revision, 1n, 'SIGKILL/process recovery observes publication; this does not simulate power loss')
  t.alike(await reopened.read(key(2)), { revision: 0n, ciphertext: null })
})

test('intent custody rejects unsafe directories, symlinks, hardlinks, FIFOs and corrupt committed records', async t => {
  const context = await setup(t)
  const unsafe = join(context.base, 'unsafe')
  await mkdir(unsafe, { mode: 0o755 })
  await rejectsCode(context.backend(unsafe).ready(), 'INTENT_STORE_CUSTODY')
  const directory = context.directory
  const backend = context.backend()
  await backend.compareAndSwap(key(1), 0n, Buffer.from('original'))
  await backend.close()
  const outside = join(context.base, 'outside')
  await writeFile(outside, 'outside-sentinel', { mode: 0o600 })
  const original = await readFile(join(directory, filename(1)))
  for (const type of ['symlink', 'hardlink', 'fifo', 'mode', 'truncated', 'checksum', 'wrong-key']) {
    const path = join(directory, filename(1))
    await rm(path)
    if (type === 'symlink') await symlink(outside, path)
    else if (type === 'hardlink') await link(outside, path)
    else if (type === 'fifo') {
      const mkfifo = spawnSync('mkfifo', ['-m', '600', path])
      assert.equal(mkfifo.status, 0)
    } else {
      const bytes = Buffer.from(original)
      if (type === 'checksum') bytes[bytes.length - 1] ^= 1
      if (type === 'wrong-key') bytes[20] ^= 1
      await writeFile(path, type === 'truncated' ? bytes.subarray(0, 10) : bytes, { mode: type === 'mode' ? 0o644 : 0o600 })
    }
    const reader = context.backend()
    await rejectsCode(reader.read(key(1)), ['truncated', 'checksum', 'wrong-key'].includes(type) ? 'INTENT_CORRUPT' : 'INTENT_STORE_CUSTODY')
    await reader.close()
    t.pass(type + ' rejected')
  }
  t.is(await readFile(outside, 'utf8'), 'outside-sentinel')
  const alias = join(context.base, 'alias')
  await symlink(directory, alias)
  await rejectsCode(context.backend(alias).ready(), 'INTENT_STORE_CUSTODY')
  await rejectsCode(context.backend(join(alias, 'child')).ready(), 'INTENT_STORE_CUSTODY')
  const lock = join(directory, '.writer-lock')
  await rm(lock)
  await symlink(outside, lock)
  await rejectsCode(context.backend().ready(), 'INTENT_STORE_CUSTODY')
  t.pass('root, ancestor and lock symlinks rejected')
})

test('pending substitution cannot overwrite the prior committed record and root custody changes fail closed', async t => {
  const context = await setup(t)
  let replacePending = false
  const backend = context.backend(undefined, {
    onCommitPhase: async phase => {
      if (phase === 'after-file-sync' && replacePending) {
        await rename(join(context.directory, '.pending'), join(context.directory, '.saved-pending'))
        await writeFile(join(context.directory, '.pending'), 'substitute', { mode: 0o600 })
      }
    }
  })
  await backend.compareAndSwap(key(1), 0n, Buffer.from('prior'))
  const committed = await readFile(join(context.directory, filename(1)))
  replacePending = true
  await rejectsCode(backend.compareAndSwap(key(1), 1n, Buffer.from('new')), 'INTENT_STORE_COMMIT_UNKNOWN')
  t.alike(await readFile(join(context.directory, filename(1))), committed)
  await backend.close()
  await rm(join(context.directory, '.saved-pending'))
  const reopened = context.backend()
  t.is((await reopened.read(key(1))).ciphertext.toString(), 'prior')
  await rename(context.directory, context.directory + '-moved')
  await mkdir(context.directory, { mode: 0o700 })
  await rejectsCode(reopened.read(key(1)), 'ENOENT')
  t.pass('substituted root cannot be treated as an empty intent')
})

test('bounded admission snapshots ciphertext, close drains accepted writes, and page scans hold bounded state', async t => {
  const context = await setup(t)
  let release
  let reached
  const gate = new Promise(resolve => { release = resolve })
  const started = new Promise(resolve => { reached = resolve })
  let paused = false
  const backend = context.backend(undefined, {
    onCommitPhase: async phase => {
      if (!paused && phase === 'before-write') { paused = true; reached(); await gate }
    }
  })
  const first = backend.compareAndSwap(key(1), 0n, Buffer.from('one'))
  await started
  const input = Buffer.from('snapshot')
  const second = backend.compareAndSwap(key(2), 0n, input)
  input.fill(0)
  const remaining = []
  for (let n = 3; n <= NODE_INTENT_BACKEND_LIMITS.maxPendingOperations; n++) remaining.push(backend.compareAndSwap(key(n), 0n, Buffer.from('x')))
  const admittedAtBurst = backend._pending
  await rejectsCode(backend.compareAndSwap(key(99), 0n, Buffer.from('overflow')), 'INTENT_STORE_BUSY')
  const drainStarted = performance.now()
  const closing = backend.close()
  await rejectsCode(backend.read(key(1)), 'INTENT_STORE_CLOSED')
  release()
  t.ok((await Promise.all([first, second, ...remaining])).every(Boolean))
  await closing
  t.comment(JSON.stringify({ admittedAtBurst, pendingAfterClose: backend._pending, closeDrainMs: performance.now() - drainStarted }))
  const reopened = context.backend()
  t.is((await reopened.read(key(2))).ciphertext.toString(), 'snapshot')
  for (let n = 9; n <= 90; n++) await reopened.compareAndSwap(key(n), 0n, Buffer.from('x'))
  const found = []
  let cursor = null
  let pages = 0
  do {
    const page = await reopened.keysPage({ cursor, limit: 7 })
    t.ok(page.keys.length <= 7)
    found.push(...page.keys)
    cursor = page.cursor
    pages++
  } while (cursor)
  t.is(found.length, 90)
  t.is(new Set(found).size, 90)
  t.ok(pages <= 14)
  t.comment(JSON.stringify({ enumeratedKeys: found.length, pageLimit: 7, pages }))
  const cursors = []
  for (let n = 0; n < 4; n++) cursors.push((await reopened.keysPage({ limit: 1 })).cursor)
  await rejectsCode(reopened.keysPage({ limit: 1 }), 'INTENT_STORE_BUSY')
  await rejectsCode(reopened.compareAndSwap(key(91), 0n, Buffer.from('scan-mutation')), 'INTENT_STORE_BUSY')
  for (const cursor of cursors) await reopened.closeScan(cursor)
  await rejectsCode(reopened.keysPage({ cursor: cursors[0] }), 'INTENT_STORE_CURSOR')
  t.is(reopened._scans.size, 0)
  t.ok(await reopened.compareAndSwap(key(91), 0n, Buffer.from('after-scan')))
})

test('real encrypted intent restart preserves SENT identity and transitions to PENDING_UNKNOWN without plaintext persistence', async t => {
  const context = await setup(t)
  const sent = runChild(['intent-send', context.directory])
  t.is(sent.status, 0)
  t.is(sent.state, 3)
  t.is(sent.revision, '3')
  const recovered = runChild(['intent-recover', context.directory])
  t.is(recovered.status, 0)
  t.is(recovered.state, 5)
  t.is(recovered.revision, '4')
  for (const field of ['logicalId', 'operation', 'commitment', 'nonce', 'mayHaveCommitted', 'attemptCount']) t.is(recovered[field], sent[field])
  const disk = await readFile(join(context.directory, filename(BigInt('0x' + '01'.repeat(32)))))
  t.absent(disk.includes(Buffer.from('SIGNED_CAPABILITY_SENTINEL_INTENT_RESTART_20260905')))
  t.absent(disk.includes(Buffer.from('HRINT1')))
  t.is((await lstat(context.directory)).mode & 0o777, 0o700)
  t.is((await lstat(join(context.directory, '.writer-lock'))).mode & 0o777, 0o600)
})

test('intent input bounds reject traversal, oversized ciphertext and invalid revisions without publishing', async t => {
  const context = await setup(t)
  const backend = context.backend()
  for (const invalid of ['../escape', 'intent:../escape', 'intent:' + 'AA'.repeat(32)]) await rejectsCode(backend.read(invalid), 'INTENT_STORE_INPUT')
  await rejectsCode(backend.compareAndSwap(key(1), -1n, Buffer.from('x')), 'INTENT_STORE_INPUT')
  await rejectsCode(backend.compareAndSwap(key(1), 0n, Buffer.alloc(NODE_INTENT_BACKEND_LIMITS.maxCiphertextBytes + 1)), 'INTENT_STORE_INPUT')
  await rejectsCode(backend.keysPage({ limit: 257 }), 'INTENT_STORE_INPUT')
  t.alike(await backend.read(key(1)), { revision: 0n, ciphertext: null })
  await backend.close()
  await writeFile(join(context.directory, '.pending'), Buffer.from('partial-unpublished'), { mode: 0o600 })
  const recovered = context.backend()
  t.alike(await recovered.read(key(1)), { revision: 0n, ciphertext: null })
  t.absent((await readdir(context.directory)).includes('.pending'))
})

test('commit phases finish synchronization before success and unpublished symlinks are never recovered', async t => {
  const context = await setup(t)
  const phases = []
  const backend = context.backend(undefined, { onCommitPhase: phase => { phases.push(phase) } })
  t.ok(await backend.compareAndSwap(key(1), 0n, Buffer.from('cipher')))
  t.alike(phases, ['before-write', 'after-file-sync', 'after-publication', 'before-directory-sync', 'after-directory-sync'])
  t.is((await lstat(join(context.directory, filename(1)))).mode & 0o777, 0o600)
  await backend.close()
  const outside = join(context.base, 'outside-pending')
  await writeFile(outside, 'retained', { mode: 0o600 })
  await symlink(outside, join(context.directory, '.pending'))
  await rejectsCode(context.backend().ready(), 'INTENT_STORE_CUSTODY')
  t.is(await readFile(outside, 'utf8'), 'retained')
  t.ok((await lstat(join(context.directory, '.pending'))).isSymbolicLink())
})
