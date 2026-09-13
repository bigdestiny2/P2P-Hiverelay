import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtemp, realpath, rm, readdir, readFile, cp, chmod } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { NodeIntentBackend } from '../../blind-intent-store-node/index.js'
import { BoundedNativeIntentBackend } from '../index.js'

const fixture = fileURLToPath(new URL('./process.mjs', import.meta.url))
const key = n => 'intent:' + n.toString(16).padStart(64, '0')
async function temp (t) {
  const base = await mkdtemp(join(await realpath(tmpdir()), 'intent-journal-v1-'))
  t.after(() => rm(base, { recursive: true, force: true }))
  return base
}
function run (adapter, mode, directory) {
  const command = adapter === 'bare' ? '/opt/homebrew/bin/bare' : process.execPath
  const result = spawnSync(command, [fixture, adapter, mode, directory], { encoding: 'utf8', timeout: 45000 })
  assert.equal(result.error, undefined, result.stderr)
  assert.equal(result.signal, null, result.stderr)
  let output
  try { output = JSON.parse(result.stdout.trim()) } catch { assert.fail(result.stdout + result.stderr) }
  console.log(JSON.stringify({ vector: { adapter, mode }, status: result.status, ...output }))
  return { status: result.status, output }
}
async function files (directory) {
  const entries = await readdir(directory)
  return Promise.all(entries.filter(name => name.endsWith('.intent')).sort().map(async name => [name, (await readFile(join(directory, name))).toString('hex')]))
}
for (const [writer, reader] of [['node', 'bare'], ['bare', 'pear'], ['pear', 'node']]) {
  test(writer + ' to ' + reader + ' same logical encrypted intent recovery in real runtimes', { timeout: 120000 }, async t => {
    const base = await temp(t)
    const directory = join(base, 'journal')
    const created = run(writer, 'create', directory)
    assert.equal(created.status, 0)
    assert.equal(created.output.record.revision, '3')
    assert.equal(created.output.record.state, 3)
    const before = await files(directory)
    for (const [, hex] of before) assert.equal(Buffer.from(hex, 'hex').includes(Buffer.from('PRIVATE_CAPABILITY')), false)
    const wrong = run(reader, 'wrong-key', directory)
    assert.equal(wrong.status, 1)
    assert.equal(wrong.output.error, 'INTENT_CORRUPT')
    assert.deepEqual(await files(directory), before, 'wrong recovery key does not write any committed record')
    const recovered = run(reader, 'recover', directory)
    assert.equal(recovered.status, 0)
    assert.equal(recovered.output.record.revision, '4')
    assert.equal(recovered.output.record.state, 5)
    assert.equal(recovered.output.record.mayHaveCommitted, true)
    assert.equal(recovered.output.recovery.networkSends, 0)
    assert.equal(recovered.output.recovery.uncertain, 1)
    for (const field of ['logicalId', 'nonce', 'commitment', 'operation']) assert.equal(recovered.output.record[field], created.output.record[field])
    const reopened = run(writer, 'recover', directory)
    assert.equal(reopened.status, 0)
    assert.equal(reopened.output.record.revision, '4', 'recovery does not manufacture another logical attempt')
  })
}

test('retained native record and byte quota survives reopen, preserves unresolved work, permits shrinking updates', async t => {
  const base = await temp(t); const directory = join(base, 'quota')
  const policy = { maxRecords: 2, maxTotalBytes: 368, maxCiphertextBytes: 200 }
  let backend = new BoundedNativeIntentBackend(new NodeIntentBackend(directory), policy)
  t.after(() => backend.close())
  assert.equal(await backend.compareAndSwap(key(1), 0n, new Uint8Array(100)), true)
  assert.equal(await backend.compareAndSwap(key(2), 0n, new Uint8Array(100)), true)
  await assert.rejects(backend.compareAndSwap(key(3), 0n, new Uint8Array([3])), { code: 'INTENT_STORE_CAPACITY' })
  await assert.rejects(backend.compareAndSwap(key(1), 1n, new Uint8Array(101)), { code: 'INTENT_STORE_CAPACITY' })
  await backend.close()
  backend = new BoundedNativeIntentBackend(new NodeIntentBackend(directory), policy)
  await backend.ready()
  assert.equal(backend.totalBytes, 368)
  assert.equal(await backend.compareAndSwap(key(1), 1n, new Uint8Array(1)), true)
  assert.equal(backend.totalBytes, 269)
  assert.equal((await backend.read(key(2))).ciphertext.byteLength, 100)
})

test('unknown native publication fences already admitted later work and preserves exact committed revision', async t => {
  const base = await temp(t); const directory = join(base, 'unknown')
  const native = new NodeIntentBackend(directory, { onCommitPhase: phase => { if (phase === 'after-publication') throw Error('injected lost publication acknowledgment') } })
  const backend = new BoundedNativeIntentBackend(native, { maxRecords: 2, maxTotalBytes: 1024 })
  await backend.ready()
  const first = backend.compareAndSwap(key(1), 0n, new Uint8Array([1]))
  const queued = backend.compareAndSwap(key(2), 0n, new Uint8Array([2]))
  await assert.rejects(first, { code: 'INTENT_STORE_COMMIT_UNKNOWN' })
  await assert.rejects(queued, { code: 'INTENT_STORE_FAILED' })
  await backend.close()
  const reopened = new NodeIntentBackend(directory)
  assert.equal((await reopened.read(key(1))).revision, 1n)
  assert.equal((await reopened.read(key(2))).revision, 0n)
  await reopened.close()
})

test('caller-supplied revision floor detects a rolled-back backup before recovery writes', async t => {
  const base = await temp(t); const original = join(base, 'original'); const backup = join(base, 'backup')
  const created = run('node', 'create', original)
  assert.equal(created.status, 0)
  await cp(original, backup, { recursive: true }); await chmod(backup, 0o700)
  const backend = new NodeIntentBackend(backup)
  const id = 'intent:' + '01'.repeat(32)
  const committed = await backend.read(id)
  await backend.close()
  // A whole valid older store is not detectable without the external floor.
  const { DurableIntentJournal } = await import('../index.js')
  const { createAesGcmIntentSealer } = await import('../../blind-client/intent.js')
  const { createNodeCryptoRuntime } = await import('../../blind-client/runtime/node.js')
  const journal = new DurableIntentJournal({ backend: new NodeIntentBackend(backup), sealer: createAesGcmIntentSealer(createNodeCryptoRuntime(), Buffer.alloc(32, 9)), policy: { maxRecords: 2, maxTotalBytes: 2048 }, recoveryFloors: [{ key: id, revision: committed.revision + 1n }] })
  const before = await files(backup)
  await assert.rejects(journal.ready(), { code: 'INTENT_RECOVERY_ROLLBACK' })
  assert.deepEqual(await files(backup), before)
  await journal.close()
})

for (const [writer, reader] of [['node', 'bare'], ['bare', 'pear'], ['pear', 'node']]) {
  test(writer + ' abrupt live runtime loss after SENT recovers in ' + reader, { timeout: 60000 }, async t => {
    const base = await temp(t); const directory = join(base, 'killed-journal')
    const child = spawn(writer === 'bare' ? '/opt/homebrew/bin/bare' : process.execPath, [fixture, writer, 'kill-sent', directory], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] })
    let exited = false; let stdout = ''; let stderr = ''
    const exit = new Promise(resolve => child.once('exit', (code, signal) => { exited = true; resolve({ code, signal }) }))
    const killGroup = () => { if (!exited) { try { process.kill(-child.pid, 'SIGKILL') } catch (error) { if (error.code !== 'ESRCH') throw error } } }
    t.after(killGroup)
    child.stderr.on('data', data => { stderr += data })
    const receipt = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { killGroup(); reject(Error('No bounded live SENT receipt: ' + stderr)) }, 30000)
      child.once('error', error => { clearTimeout(timer); reject(error) })
      child.stdout.on('data', data => {
        stdout += data
        if (!stdout.includes('\n')) return
        try { const value = JSON.parse(stdout.split('\n')[0]); clearTimeout(timer); resolve(value) } catch (error) { clearTimeout(timer); reject(error) }
      })
      exit.then(result => { clearTimeout(timer); reject(Error('Fixture exited before kill: ' + JSON.stringify(result) + stderr)) })
    })
    assert.equal(exited, false)
    assert.equal(receipt.record.revision, '3')
    assert.equal(receipt.record.state, 3)
    const nativePid = writer === 'pear' ? receipt.embeddedPid : receipt.pid
    assert.equal(Number.isSafeInteger(nativePid) && nativePid > 1, true)
    // The live fixture supplied this exact native PID immediately before pausing.
    // Its process group is test-owned and also terminated to reap launchers/hosts.
    process.kill(nativePid, 'SIGKILL')
    killGroup()
    const termination = await exit
    const recovered = run(reader, 'recover', directory)
    assert.equal(recovered.status, 0)
    assert.equal(recovered.output.record.revision, '4')
    assert.equal(recovered.output.record.state, 5)
    assert.equal(recovered.output.recovery.networkSends, 0)
    for (const field of ['logicalId', 'nonce', 'commitment', 'operation']) assert.equal(recovered.output.record[field], receipt.record[field])
    console.log(JSON.stringify({ vector: 'real-live-runtime-SIGKILL-after-SENT', writer, reader, nativePid, runtime: receipt.runtime, embeddedRuntime: receipt.embeddedRuntime, executable: receipt.executable, embeddedExecutable: receipt.embeddedExecutable, embeddedExecutableSha256: receipt.embeddedExecutableSha256, termination, recoveredRevision: recovered.output.record.revision }))
  })
}

for (const adapter of ['node', 'bare', 'pear']) {
  test(adapter + ' actual backend owns admitted Buffer and Uint8Array-subclass bytes across queued writes', async t => {
    const base = await temp(t)
    const result = run(adapter, 'copy-admission', join(base, 'copy-journal'))
    assert.equal(result.status, 0)
    assert.deepEqual(result.output.stored, [7, 11, 13, 17, 19, 23])
    assert.deepEqual(result.output.changed, Array(6).fill(true))
    if (adapter !== 'bare') assert.equal(result.output.inputTypes[0], 'Buffer')
  })
}
