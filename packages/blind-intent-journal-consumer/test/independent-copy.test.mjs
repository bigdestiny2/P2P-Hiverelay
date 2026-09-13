import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { NodeIntentBackend } from '../../blind-intent-store-node/index.js'
import { BoundedNativeIntentBackend } from '../index.js'
for (const [name, make] of [['Uint8Array', () => new Uint8Array([7])], ['Node Buffer', () => Buffer.from([7])]]) {
  test(`independent native admission copies ${name} before yielding`, async t => {
    const root = await mkdtemp(join(await realpath(tmpdir()), 'independent-intent-copy-'))
    const backend = new BoundedNativeIntentBackend(new NodeIntentBackend(join(root, 'journal')), { maxRecords: 2, maxTotalBytes: 1024 })
    t.after(async () => { await backend.close(); await rm(root, { recursive: true, force: true }) })
    await backend.ready()
    const value = make(); const key = 'intent:' + '01'.repeat(32)
    const writing = backend.compareAndSwap(key, 0n, value)
    value[0] = 9
    assert.equal(await writing, true)
    assert.deepEqual([...(await backend.read(key)).ciphertext], [7], 'committed bytes must be the admitted value')
  })
}
