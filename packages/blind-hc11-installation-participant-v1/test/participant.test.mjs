import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { Hc11InstallationParticipantV1, readPreparedHc11Participant, STATUS } from '../index.js'
import { CORESTORE_GENERATION_ENVELOPE } from '../../core/core/persistence/corestore-generation-envelope.js'
import { encode } from '../../blind-protocol/checkpoint-format-successor/codec.js'
import { fixture, inventory, Corestore, Hypercore, deferred, child, sha, tick } from './helpers.mjs'

// Instruments delay/failure around actual native operations; never replaces
// cryptographic verification, sentinel data, an engine or an authority verdict.
test('actual guarded HC11 activation produces typed owned evidence, retained original bytes and native custody', async t => {
  const f = await fixture(t); const owner = f.create()
  const token = await owner.prepare()
  assert.deepEqual(token, {})
  const observed = await readPreparedHc11Participant(token)
  const trigger = await fs.readFile(f.trigger)
  const record = JSON.parse(trigger)
  assert.equal(observed.evidence.length, 1n); assert.equal(observed.evidence.fork, 0n)
  assert.equal(observed.evidence.activationKey.toString('hex'), record.activationSentinel.key)
  assert.equal(observed.evidence.activationBlockHash.toString('hex'), record.activationSentinel.blockSha256.slice(7))
  assert.equal(observed.evidence.databaseIdentityHash.toString('hex'), sha(await fs.readFile(f.database)))
  assert.equal(observed.evidence.envelopeManifestHash.toString('hex'), f.ceremony.manifestSha256.slice(7))
  assert.equal(observed.evidence.triggerReceiptHash.toString('hex'), sha(trigger))
  assert.deepEqual(observed.triggerBytes, trigger)
  assert.equal(observed.commonReadyAcknowledged, false); assert.equal(STATUS.sharedAuthorityComposed, false)
  assert.equal((await child('lock', f.root)).locked, false, 'independent process cannot acquire actual native custody')
  const original = encode('Hc11Evidence', observed.evidence)
  observed.evidence.rootId.fill(1); observed.triggerBytes.fill(1); observed.installationId.fill(1)
  assert.deepEqual(encode('Hc11Evidence', (await readPreparedHc11Participant(token)).evidence), original)
  assert.equal(await owner.close(), true)
  await assert.rejects(readPreparedHc11Participant(token), /fenced|closing/)
  assert.equal((await child('lock', f.root)).locked, true)
  const reopened = f.create(); const next = await reopened.prepare()
  assert.deepEqual((await readPreparedHc11Participant(next)).triggerBytes, trigger)
  assert.deepEqual(encode('Hc11Evidence', (await readPreparedHc11Participant(next)).evidence), original)
})

test('explicit profile, external pins and no injected authority: preflight refusal preserves fixture bytes', async t => {
  const f = await fixture(t); const before = await inventory(f.root)
  for (const extra of [{ store: {} }, { verifier: () => true }, { faultInjector: () => true }, { profileDigest: Buffer.alloc(32, 2) }, { rootId: Buffer.alloc(32) }]) assert.throws(() => new Hc11InstallationParticipantV1({ ...f.options, ...extra }))
  for (const field of ['expectedInstallationId', 'expectedManifestSha256', 'expectedAuthorityKeySha256']) {
    const owner = new Hc11InstallationParticipantV1({ ...f.options, envelope: { ...f.options.envelope, [field]: field === 'expectedInstallationId' ? '12'.repeat(32) : 'sha256:' + '12'.repeat(32) } })
    await assert.rejects(owner.prepare()); assert.equal(await owner.close(), true)
  }
  await assert.rejects(readPreparedHc11Participant(Object.freeze({})), /Forged/)
  const owner = f.create(); const aborted = new AbortController(); aborted.abort()
  await assert.rejects(owner.prepare({ signal: aborted.signal }))
  assert.deepEqual(await inventory(f.root), before)
})

test('same-process duplicate custody is rejected without mutating existing native or authority files', async t => {
  const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
  const before = await inventory(f.root)
  const duplicate = f.create(); await assert.rejects(duplicate.prepare(), /custody is already held/)
  assert.equal(await duplicate.close(), true)
  assert.deepEqual(await inventory(f.root), before)
  assert.equal((await readPreparedHc11Participant(token)).evidence.length, 1n)
})

for (const target of ['trigger', 'database', 'authority-key', 'manifest']) {
  test(`live ${target} tamper refuses evidence and fences owner`, async t => {
    const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
    const file = target === 'trigger' ? f.trigger : target === 'database' ? f.database : path.join(f.root, '.hiverelay-generation', target === 'manifest' ? 'envelope.v1.json' : 'authority-key.v1')
    const original = await fs.readFile(file)
    const damaged = Buffer.from(original); damaged[0] ^= 1; await fs.writeFile(file, damaged)
    const before = await inventory(f.root)
    await assert.rejects(readPreparedHc11Participant(token))
    assert.deepEqual(await inventory(f.root), before, 'refusal does not rewrite source/trigger authority')
    await fs.writeFile(file, original)
    await assert.rejects(readPreparedHc11Participant(token), /fenced|closing/, 'restoring bytes cannot clear runtime quarantine')
    assert.equal(owner.status().custodyHeld, true)
  })
}

test('same-byte source inode replacement cannot reuse a prepared token', async t => {
  const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
  const bytes = await fs.readFile(f.trigger); await fs.rename(f.trigger, f.trigger + '.owned-old')
  await fs.writeFile(f.trigger, bytes, { mode: 0o600 })
  await assert.rejects(readPreparedHc11Participant(token), /source changed/)
  assert.equal(owner.status().custodyHeld, true)
})

for (const mutation of ['append', 'fork']) {
  test(`actual native sentinel ${mutation} cannot create replacement activation authority`, async t => {
    const f = await fixture(t); const owner = f.create(); await owner.prepare(); assert.equal(await owner.close(), true)
    const trigger = await fs.readFile(f.trigger)
    const store = new Corestore(f.generation); await store.ready()
    const core = store.get({ name: CORESTORE_GENERATION_ENVELOPE.activationCoreName }); await core.ready()
    if (mutation === 'append') await core.append(Buffer.from('extra'))
    else { const original = await core.get(0); await core.truncate(0); await core.append(original); assert.equal(core.fork, 1) }
    await core.close(); await store.close()
    const next = f.create(); await assert.rejects(next.prepare())
    assert.deepEqual(await fs.readFile(f.trigger), trigger)
    assert.equal(next.status().prepared, false)
  })
}

test('abort during actual native ready retains custody until original work and close settle', async t => {
  const f = await fixture(t); const owner = f.create(); const entered = deferred(); const release = deferred()
  const original = Corestore.prototype._open
  Corestore.prototype._open = async function (...args) { await original.apply(this, args); entered.resolve(); await release.promise }
  t.after(() => { Corestore.prototype._open = original; release.resolve() })
  const controller = new AbortController(); let successes = 0
  const pending = owner.prepare({ signal: controller.signal }).then(value => { successes++; return value })
  await entered.promise; controller.abort()
  await assert.rejects(pending, /cancelled/)
  assert.equal(owner.status().inFlight, 1); assert.equal(owner.status().custodyHeld, true)
  assert.equal(await owner.close({ timeoutMillis: 20 }), false)
  assert.equal((await child('lock', f.root)).locked, false)
  release.resolve(); Corestore.prototype._open = original
  assert.equal(await owner.close({ timeoutMillis: 5000 }), true)
  assert.equal(successes, 0); assert.equal((await child('lock', f.root)).locked, true)
})

test('late native close does not free custody at the caller deadline', async t => {
  const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
  const entered = deferred(); const release = deferred(); const original = Corestore.prototype.close
  Corestore.prototype.close = async function (...args) { await original.apply(this, args); entered.resolve(); await release.promise }
  t.after(() => { Corestore.prototype.close = original; release.resolve() })
  const closing = owner.close({ timeoutMillis: 30 }); await entered.promise
  assert.equal(await closing, false); assert.equal(owner.status().custodyHeld, true)
  await assert.rejects(readPreparedHc11Participant(token), /fenced|closing/)
  assert.equal((await child('lock', f.root)).locked, false)
  release.resolve(); Corestore.prototype.close = original
  assert.equal(await owner.close({ timeoutMillis: 5000 }), true)
})

test('native close failure leaves custody fenced until the isolated owner process exits', async t => {
  const f = await fixture(t)
  const result = await child('failed-close', f.root)
  assert.equal(result.closed, false); assert.equal(result.refused, true); assert.equal(result.replacementRefused, true)
  assert.equal(result.status.custodyHeld, true); assert.equal(result.status.closed, false)
  assert.equal((await child('lock', f.root)).locked, true, 'process exit finally releases OS custody')
})

test('database mutation across actual async sentinel read is rejected after native close', async t => {
  const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
  const entered = deferred(); const release = deferred(); const original = Hypercore.prototype.get
  Hypercore.prototype.get = async function (...args) { const value = await original.apply(this, args); entered.resolve(); await release.promise; return value }
  t.after(() => { Hypercore.prototype.get = original; release.resolve() })
  const pending = readPreparedHc11Participant(token); await entered.promise
  await fs.writeFile(f.database, Buffer.from('rebound database identity'))
  release.resolve(); Hypercore.prototype.get = original
  await assert.rejects(pending, /source changed|Unsafe/)
  assert.equal(owner.status().custodyHeld, true)
})

test('native result delivered after monotonic deadline never yields a prepared token', async t => {
  const f = await fixture(t); const owner = f.create()
  const original = Hypercore.prototype.close; let genuineClosed = false
  Hypercore.prototype.close = async function (...args) {
    const result = await original.apply(this, args); genuineClosed = true
    const until = performance.now() + 1500
    while (performance.now() < until) { /* Hold only after actual native closure. */ }
    return result
  }
  t.after(() => { Hypercore.prototype.close = original })
  await assert.rejects(owner.prepare({ timeoutMillis: 1000 }), /cancelled|deadline/)
  Hypercore.prototype.close = original
  assert.equal(genuineClosed, true); assert.equal(owner.status().prepared, false)
  await tick(); assert.equal(await owner.close({ timeoutMillis: 5000 }), true)
})

test('abort during actual native evidence reread invalidates token and keeps custody until cleanup', async t => {
  const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
  const entered = deferred(); const release = deferred(); const original = Hypercore.prototype.close
  Hypercore.prototype.close = async function (...args) { await original.apply(this, args); entered.resolve(); await release.promise }
  t.after(() => { Hypercore.prototype.close = original; release.resolve() })
  const controller = new AbortController(); let successes = 0
  const pending = readPreparedHc11Participant(token, { signal: controller.signal }).then(value => { successes++; return value })
  await entered.promise; controller.abort()
  await assert.rejects(pending, /cancelled/)
  assert.equal(owner.status().inFlight, 1); assert.equal(owner.status().custodyHeld, true)
  assert.equal(await owner.close({ timeoutMillis: 20 }), false)
  release.resolve(); Hypercore.prototype.close = original
  assert.equal(await owner.close({ timeoutMillis: 5000 }), true)
  assert.equal(successes, 0)
  await assert.rejects(readPreparedHc11Participant(token), /fenced|closing/)
})

test('exact directory custody rejects path replacement even with preserved original activation bytes', async t => {
  const f = await fixture(t); const owner = f.create(); const token = await owner.prepare()
  const old = f.generation + '.owned-old'
  await fs.rename(f.generation, old)
  await fs.mkdir(f.generation, { mode: 0o700 })
  await assert.rejects(readPreparedHc11Participant(token), /rebound/)
  await fs.rmdir(f.generation); await fs.rename(old, f.generation)
  await assert.rejects(readPreparedHc11Participant(token), /fenced|closing/)
  assert.equal(owner.status().custodyHeld, true)
})
