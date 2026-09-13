import test from '../../packages/blind-intent-store-bare/node_modules/brittle/index.js'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { constants } from 'node:fs'
import { link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { NodeIntentBackend } from '../../packages/blind-intent-store-bare/test/.baseline/packages/blind-intent-store-node/index.js'

const fixture = fileURLToPath(new URL('../../packages/blind-intent-store-bare/test/process-fixture.mjs', import.meta.url))
const runtimeChecks = fileURLToPath(new URL('../../packages/blind-intent-store-bare/test/runtime-checks.mjs', import.meta.url))
const nodeFixture = fileURLToPath(new URL('../../packages/blind-intent-store-bare/test/.baseline/packages/blind-intent-store-node/test/process-fixture.mjs', import.meta.url))
const launcher = process.env.BARE_EXECUTABLE || 'bare'
const probe = spawnSync(launcher, ['-e', 'console.log(JSON.stringify({ executable: Bare.argv[0], version: Bare.version }))'], { encoding: 'utf8', timeout: 10000 })
assert.equal(probe.status, 0, probe.stderr)
const bare = JSON.parse(probe.stdout).executable
const key = n => 'intent:' + BigInt(n).toString(16).padStart(64, '0')
const filename = n => key(n).slice(7) + '.intent'

async function setup (t) {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'hiverelay-intent-bare-'))
  const children = []
  const backends = []
  t.teardown(async () => {
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) {
        const ended = once(child, 'exit')
        child.kill('SIGKILL')
        await ended
      }
    }
    for (const backend of backends) await backend.close()
    await rm(base, { recursive: true, force: true })
  })
  return {
    base,
    directory: join(base, 'store'),
    backend (directory = join(base, 'store')) {
      const backend = new NodeIntentBackend(directory)
      backends.push(backend)
      return backend
    },
    child (args) {
      const child = spawn(bare, [fixture, ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
      children.push(child)
      return child
    }
  }
}

function run (args, runtime = bare, script = fixture) {
  const result = spawnSync(runtime, [script, ...args], { encoding: 'utf8', timeout: 60_000 })
  assert.equal(result.error, undefined, result.stderr)
  assert.equal(result.signal, null, result.stderr)
  const lines = result.stdout.trim().split('\n')
  // Bare can exit zero on an uncaught import/async error. Require a parsed receipt.
  const output = JSON.parse(lines.at(-1))
  return { status: result.status, ...output }
}

async function message (child) {
  return new Promise((resolve, reject) => {
    let output = ''
    let errors = ''
    const timer = setTimeout(() => reject(new Error('Bare child did not acknowledge its phase')), 30_000)
    child.stderr.on('data', bytes => { errors += bytes })
    child.stdout.on('data', bytes => {
      output += bytes
      if (output.includes('\n')) {
        clearTimeout(timer)
        resolve(JSON.parse(output.split('\n')[0]))
      }
    })
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('exit', () => { clearTimeout(timer); if (!output.includes('\n')) reject(new Error(errors || 'Bare child exited before receipt')) })
  })
}

function recordBytes (intentKey, revision, ciphertext) {
  const bytes = Buffer.alloc(84 + ciphertext.length)
  bytes.write('HRINDB01')
  bytes.writeBigUInt64BE(revision, 8)
  bytes.writeUInt32BE(ciphertext.length, 16)
  Buffer.from(intentKey.slice(7), 'hex').copy(bytes, 20)
  ciphertext.copy(bytes, 84)
  createHash('sha256').update(bytes.subarray(0, 52)).update(ciphertext).digest().copy(bytes, 52)
  return bytes
}

test('real Bare adapter qualifies native flags, full writes, exact stats, sync, bounded admission and close ownership', async t => {
  const context = await setup(t)
  assert.equal(spawnSync('mkfifo', ['-m', '600', join(context.base, 'fifo')]).status, 0)
  const result = run([context.base], bare, runtimeChecks)
  t.is(result.status, 0)
  t.is(result.ok, true, result.message)
  for (const [name, value] of Object.entries(result.constants || {})) t.is(value, constants[name], name + ' agrees with Node native constants')
  t.ok(result.checks.length >= 60)
  t.comment(JSON.stringify(result))
})

test('Bare and Node produce common exact records, preserve u64 revisions and alternate CAS ownership', async t => {
  const context = await setup(t)
  const node = context.backend(join(context.base, 'node'))
  const data = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
  t.ok(await node.compareAndSwap(key(1), 0n, data))
  await node.close()
  const created = run(['cas', context.directory, key(1), '0', data.toString('hex')])
  t.is(created.status, 0)
  t.is(created.changed, true)
  const expected = recordBytes(key(1), 1n, data)
  t.alike(await readFile(join(context.base, 'node', filename(1))), expected)
  t.alike(await readFile(join(context.directory, filename(1))), expected)
  t.comment('common-vector=' + expected.toString('hex'))
  const reader = context.backend()
  t.alike(await reader.read(key(1)), { revision: 1n, ciphertext: data })
  t.ok(await reader.compareAndSwap(key(1), 1n, Buffer.from('node-next')))
  await reader.close()
  t.is(run(['cas', context.directory, key(1), '1', 'aabb']).changed, false)
  t.is(run(['cas', context.directory, key(1), '2', 'aabb']).revision, '3')
  const high = (1n << 64n) - 2n
  await writeFile(join(context.directory, filename(2)), recordBytes(key(2), high, data), { mode: 0o600 })
  const highResult = run(['cas', context.directory, key(2), String(high), 'cc'])
  t.is(highResult.revision, String(high + 1n))
  t.is(highResult.changed, true)
  t.is(run(['cas', context.directory, key(2), String(high + 1n), 'dd']).error, 'INTENT_STORE_REVISION')
})

test('Bare-Bare and Node-Bare processes share one permanent exclusive writer lease', async t => {
  const context = await setup(t)
  const node = context.backend()
  await node.ready()
  t.is(run(['cas', context.directory, key(1), '0', 'aa']).error, 'INTENT_STORE_LOCKED')
  t.is(run(['raw-lock', context.directory]).status, 1)
  const lockStat = await lstat(join(context.directory, '.writer-lock'))
  await node.close()
  const child = context.child(['hold', context.directory])
  t.is((await message(child)).held, true)
  t.is(run(['cas', context.directory, key(1), '0', 'aa']).error, 'INTENT_STORE_LOCKED')
  t.is(run(['cas', context.directory, key(1), '0', 'aa'], process.execPath, nodeFixture).error, 'INTENT_STORE_LOCKED')
  t.is(run(['raw-lock', context.directory], process.execPath, nodeFixture).status, 1)
  const exited = once(child, 'exit')
  child.kill('SIGKILL')
  await exited
  t.is(run(['cas', context.directory, key(1), '0', 'aa']).changed, true)
  t.is((await lstat(join(context.directory, '.writer-lock'))).ino, lockStat.ino)
})

test('Bare process kill boundaries reopen prior or published complete records without promoting pending', async t => {
  const context = await setup(t)
  for (const phase of ['before-write', 'after-file-sync', 'after-publication', 'before-directory-sync', 'after-directory-sync']) {
    const directory = join(context.base, phase)
    const old = run(['cas', directory, key(1), '0', Buffer.from('old').toString('hex')])
    t.is(old.changed, true)
    const child = context.child(['kill-cas', directory, key(1), '1', Buffer.from('new').toString('hex'), phase])
    t.is((await message(child)).phase, phase)
    const exited = once(child, 'exit')
    child.kill('SIGKILL')
    t.is((await exited)[1], 'SIGKILL')
    const published = ['after-publication', 'before-directory-sync', 'after-directory-sync'].includes(phase)
    const recovered = run(['read', directory, key(1)])
    t.is(recovered.status, 0)
    t.is(recovered.revision, published ? '2' : '1')
    t.is(recovered.ciphertext, Buffer.from(published ? 'new' : 'old').toString('hex'))
    t.absent((await readdir(directory)).includes('.pending'))
    const node = context.backend(directory)
    t.is((await node.read(key(1))).revision, published ? 2n : 1n)
    await node.close()
  }
})

test('Bare custody rejects unsafe modes, aliases, hardlinks, FIFOs and corrupt records without modifying external bytes', async t => {
  const context = await setup(t)
  const outside = join(context.base, 'outside')
  await writeFile(outside, 'external-sentinel', { mode: 0o600 })
  t.is(run(['cas', context.directory, key(1), '0', 'aabb']).changed, true)
  const path = join(context.directory, filename(1))
  const original = await readFile(path)
  for (const type of ['symlink', 'hardlink', 'fifo', 'mode', 'truncated', 'checksum', 'wrong-key']) {
    await rm(path)
    if (type === 'symlink') await symlink(outside, path)
    else if (type === 'hardlink') await link(outside, path)
    else if (type === 'fifo') assert.equal(spawnSync('mkfifo', ['-m', '600', path]).status, 0)
    else {
      const bytes = Buffer.from(original)
      if (type === 'checksum') bytes[bytes.length - 1] ^= 1
      if (type === 'wrong-key') bytes[20] ^= 1
      await writeFile(path, type === 'truncated' ? bytes.subarray(0, 10) : bytes, { mode: type === 'mode' ? 0o644 : 0o600 })
    }
    t.is(run(['read', context.directory, key(1)]).error, ['truncated', 'checksum', 'wrong-key'].includes(type) ? 'INTENT_CORRUPT' : 'INTENT_STORE_CUSTODY', type)
  }
  await mkdir(join(context.base, 'unsafe'), { mode: 0o755 })
  t.is(run(['read', join(context.base, 'unsafe'), key(1)]).error, 'INTENT_STORE_CUSTODY')
  await symlink(context.directory, join(context.base, 'alias'))
  t.is(run(['read', join(context.base, 'alias'), key(1)]).error, 'INTENT_STORE_CUSTODY')
  t.is(run(['read', join(context.base, 'alias', 'child'), key(1)]).error, 'INTENT_STORE_CUSTODY')
  await symlink(outside, join(context.directory, '.pending'))
  t.is(run(['read', context.directory, key(1)]).error, 'INTENT_STORE_CUSTODY')
  t.ok((await lstat(join(context.directory, '.pending'))).isSymbolicLink())
  t.is(await readFile(outside, 'utf8'), 'external-sentinel')
})

test('caller authenticated intent sealer preserves SENT identity across Bare and Node recovery', async t => {
  const context = await setup(t)
  for (const [writer, reader] of [[bare, bare], [bare, process.execPath], [process.execPath, bare]]) {
    const directory = join(context.base, 'intent-' + (writer === bare ? 'bare' : 'node') + '-' + (reader === bare ? 'bare' : 'node'))
    const sent = run(['intent-send', directory], writer, writer === bare ? fixture : nodeFixture)
    t.is(sent.status, 0, sent.message)
    t.is(sent.state, 3)
    t.is(sent.revision, '3')
    const recovered = run(['intent-recover', directory], reader, reader === bare ? fixture : nodeFixture)
    t.is(recovered.status, 0, recovered.message)
    t.is(recovered.state, 5)
    t.is(recovered.revision, '4')
    for (const field of ['logicalId', 'operation', 'commitment', 'nonce', 'mayHaveCommitted', 'attemptCount']) t.is(recovered[field], sent[field])
    const disk = await readFile(join(directory, '01'.repeat(32) + '.intent'))
    t.absent(disk.includes(Buffer.from('SIGNED_CAPABILITY_SENTINEL_INTENT_RESTART_20260905')))
    t.absent(disk.includes(Buffer.from('HRINT1')))
  }
})
