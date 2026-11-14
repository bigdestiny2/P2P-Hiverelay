import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { readPreparedHc11Participant } from '../index.js'
import { fixture, inventory, Corestore, Hypercore, deferred } from './helpers.mjs'

async function substitute (f, kind) {
  const database = path.dirname(f.database); const old = database + '.original-owned'
  await fs.rename(database, old)
  if (kind === 'symlink') await fs.symlink(old, database)
  else { await fs.mkdir(database, { mode: 0o700 }); await fs.link(path.join(old, 'IDENTITY'), f.database) }
  const actual = await fs.stat(f.database); const original = await fs.stat(path.join(old, 'IDENTITY'))
  assert.equal(actual.ino, original.ino, 'final IDENTITY inode remains unchanged in this control')
  return async () => {
    if (kind === 'symlink') await fs.unlink(database)
    else { await fs.unlink(f.database); await fs.rmdir(database) }
    await fs.rename(old, database)
  }
}

for (const kind of ['symlink', 'hardlinked-identity']) {
  test('native database parent is part of prepared custody: ' + kind, async t => {
    const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
    const restore = await substitute(f, kind)
    try {
      const before = await inventory(f.root)
      await assert.rejects(readPreparedHc11Participant(token), /directory|rebound/)
      assert.deepEqual(await inventory(f.root), before, 'refusal never rewrites original activation evidence')
      assert.equal(owner.status().custodyHeld, true)
    } finally { await restore() }
    await assert.rejects(readPreparedHc11Participant(token), /fenced|closing/)
  })
}

test('legitimate native parent mode and metadata writes preserve custody; writable mode change refuses', async t => {
  const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
  const database = path.dirname(f.database); const initial = await fs.stat(database)
  assert.equal(initial.mode & 0o022, 0)
  assert.equal((await fs.stat(f.root)).mode & 0o077, 0)
  await fs.utimes(database, new Date(1000), new Date(1000))
  assert.equal((await readPreparedHc11Participant(token)).evidence.length, 1n, 'native directory mtime is not identity')
  const next = await fs.stat(database)
  assert.equal(next.ino, initial.ino); assert.equal(next.mode, initial.mode, 'participant never chmods historical native data')
  await fs.chmod(database, 0o777)
  try { await assert.rejects(readPreparedHc11Participant(token), /directory/) } finally { await fs.chmod(database, initial.mode & 0o777) }
})

test('an already substituted native database parent refuses before raw native open', async t => {
  const f = await fixture(t); const first = f.create(); await first.prepare(); assert.equal(await first.close(), true)
  const restore = await substitute(f, 'symlink')
  const original = Corestore.prototype._open; let nativeOpened = false
  Corestore.prototype._open = async function (...args) { nativeOpened = true; return original.apply(this, args) }
  try {
    const next = f.create(); const before = await inventory(f.root)
    await assert.rejects(next.prepare(), /directory/)
    assert.equal(nativeOpened, false)
    assert.deepEqual(await inventory(f.root), before)
  } finally { Corestore.prototype._open = original; await restore() }
})

for (const stage of ['get', 'close']) {
  test('database parent rebind during actual native ' + stage + ' cannot survive final custody verification', async t => {
    const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
    const entered = deferred(); const release = deferred(); const original = Hypercore.prototype[stage]
    Hypercore.prototype[stage] = async function (...args) { const result = await original.apply(this, args); entered.resolve(); await release.promise; return result }
    let restore
    try {
      const pending = readPreparedHc11Participant(token); await entered.promise
      restore = await substitute(f, stage === 'get' ? 'symlink' : 'hardlinked-identity')
      release.resolve(); Hypercore.prototype[stage] = original
      await assert.rejects(pending, /directory|rebound/)
      assert.equal(owner.status().custodyHeld, true)
    } finally { release.resolve(); Hypercore.prototype[stage] = original; if (restore) await restore() }
  })
}

test('source-owned guard fence catches parent replacement before original trigger publication', async t => {
  const f = await fixture(t); const owner = f.create(); const entered = deferred(); const release = deferred()
  const original = Hypercore.prototype.get
  Hypercore.prototype.get = async function (...args) { const result = await original.apply(this, args); entered.resolve(); await release.promise; return result }
  let restore
  try {
    const pending = owner.prepare(); await entered.promise
    restore = await substitute(f, 'hardlinked-identity')
    release.resolve(); Hypercore.prototype.get = original
    await assert.rejects(pending, /directory|rebound/)
    await assert.rejects(fs.stat(f.trigger), { code: 'ENOENT' }, 'no original trigger is published under substituted parent')
    assert.equal(owner.status().prepared, false); assert.equal(owner.status().custodyHeld, true)
  } finally { release.resolve(); Hypercore.prototype.get = original; if (restore) await restore() }
})

test('fresh database parent cannot be adopted after substitution during actual raw native ready', async t => {
  const f = await fixture(t); const owner = f.create(); const entered = deferred(); const release = deferred()
  const original = Corestore.prototype._open
  Corestore.prototype._open = async function (...args) { const result = await original.apply(this, args); entered.resolve(); await release.promise; return result }
  let restore
  try {
    const pending = owner.prepare(); await entered.promise
    restore = await substitute(f, 'hardlinked-identity')
    release.resolve(); Corestore.prototype._open = original
    await assert.rejects(pending, /directory|rebound/)
    await assert.rejects(fs.stat(f.trigger), { code: 'ENOENT' })
    assert.equal(owner.status().prepared, false); assert.equal(owner.status().custodyHeld, true)
  } finally { release.resolve(); Corestore.prototype._open = original; if (restore) await restore() }
})
