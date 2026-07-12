import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  blindServiceDescriptorV1,
  blindStoreManifestV1,
  decodeCanonical,
  encodeCanonical
} from '@hiverelay/blind-protocol'
import {
  TwoSlotManifestStore,
  sealBlindStoreManifest,
  verifyBlindManifestSnapshot
} from '../manifest-store.js'
import {
  descriptorValue,
  manifestBytes
} from './coordinator-fixtures.js'

async function fixture (t) {
  const createdRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-blind-manifest-'))
  const root = await fs.realpath(createdRoot)
  const controlDirectory = path.join(root, 'control')
  await fs.chmod(root, 0o700)
  await fs.mkdir(controlDirectory, { mode: 0o700 })
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  const descriptor = descriptorValue()
  const canonicalBytes = encodeCanonical(blindServiceDescriptorV1, descriptor)
  const manifest = decodeCanonical(blindStoreManifestV1,
    manifestBytes({ descriptor, canonicalBytes }), { copyBytes: true })
  const manifestKey = b4a.alloc(32, 0x91)
  const expectedBindings = {
    storeId: manifest.storeId,
    relayPublicKey: manifest.relayPublicKey,
    durabilityProfileId: manifest.durabilityProfileId,
    durabilityContinuityHash: manifest.durabilityContinuityHash,
    durabilityProfileHash: manifest.durabilityProfileHash,
    formatMajor: manifest.formatMajor,
    formatMinor: manifest.formatMinor,
    storeFormatHash: manifest.storeFormatHash,
    specHash: manifest.specHash,
    abiHash: manifest.abiHash,
    mapGeneration: manifest.mapGeneration,
    bucketMapHash: manifest.bucketMapHash,
    writerFenceTokenHash: manifest.writerFenceTokenHash
  }
  return { root, controlDirectory, manifest, manifestKey, expectedBindings }
}

function createStore (state, options = {}) {
  return new TwoSlotManifestStore({
    controlDirectory: state.controlDirectory,
    manifestKey: state.manifestKey,
    expectedBindings: state.expectedBindings,
    faultInjector: options.faultInjector
  })
}

test('two-slot manifest initializes, links revisions, and rejects stale CAS', async t => {
  const state = await fixture(t)
  const store = createStore(state)
  await store.open()
  const genesis = await store.initialize(state.manifest)
  t.is(genesis.slot, 'both')
  t.is(genesis.revision, 0n)
  t.is(genesis.needsRepair, false)

  const next = await store.advance(genesis.hash, { epochFloor: state.manifest.epochFloor + 1 })
  t.is(next.revision, 1n)
  t.alike(next.manifest.previousManifestHash, genesis.hash)
  t.is(next.manifest.epochFloor, state.manifest.epochFloor + 1)
  t.is(next.slot, 'both')
  await t.exception(store.advance(genesis.hash, { epochFloor: state.manifest.epochFloor + 2 }), /expected hash is stale/)
  await store.close()
})

test('first-slot crash selects the unique linked high revision and repairs it', async t => {
  const state = await fixture(t)
  let armed = false
  const crashing = createStore(state, {
    faultInjector: async point => {
      if (armed && point === 'manifest:after-first-install') throw new Error('simulated manifest crash')
    }
  })
  await crashing.open()
  const genesis = await crashing.initialize(state.manifest)
  armed = true
  await t.exception(crashing.advance(genesis.hash, {
    epochFloor: state.manifest.epochFloor + 1
  }), /simulated manifest crash/)
  await crashing.close()

  const recovered = createStore(state)
  await recovered.open()
  const selected = await recovered.load()
  t.is(selected.revision, 1n)
  t.is(selected.needsRepair, true)
  t.alike(selected.manifest.previousManifestHash, genesis.hash)
  const repaired = await recovered.repair(selected.hash)
  t.is(repaired.slot, 'both')
  t.is(repaired.needsRepair, false)
  await recovered.close()
})

test('one corrupt slot is repairable but a valid equal-revision fork fails closed', async t => {
  const state = await fixture(t)
  const store = createStore(state)
  await store.open()
  const genesis = await store.initialize(state.manifest)
  const next = await store.advance(genesis.hash, { epochFloor: state.manifest.epochFloor + 1 })
  const slotA = path.join(state.controlDirectory, 'manifest-a.v1')
  const corrupted = await fs.readFile(slotA)
  corrupted[corrupted.byteLength - 1] ^= 1
  await fs.writeFile(slotA, corrupted)

  const surviving = await store.load()
  t.is(surviving.revision, 1n)
  t.is(surviving.needsRepair, true)
  const repaired = await store.repair(surviving.hash)
  t.is(repaired.needsRepair, false)

  const forkBytes = sealBlindStoreManifest({
    ...repaired.manifest,
    writerEpoch: repaired.manifest.writerEpoch + 1n
  }, state.manifestKey)
  await fs.writeFile(slotA, forkBytes)
  await t.exception(store.load(), /equal-revision manifest fork/)
  await store.close()
  t.alike(next.hash, surviving.hash)
})

test('wrong MAC key, binding drift, and pre-existing corrupt genesis fail closed', async t => {
  const state = await fixture(t)
  const store = createStore(state)
  await store.open()
  await store.initialize(state.manifest)
  await store.close()

  const wrongKey = new TwoSlotManifestStore({
    controlDirectory: state.controlDirectory,
    manifestKey: b4a.alloc(32, 0x92),
    expectedBindings: state.expectedBindings
  })
  await wrongKey.open()
  await t.exception(wrongKey.load(), /no valid manifest slot/)
  await wrongKey.close()

  const drift = new TwoSlotManifestStore({
    controlDirectory: state.controlDirectory,
    manifestKey: state.manifestKey,
    expectedBindings: { ...state.expectedBindings, mapGeneration: 2n }
  })
  await drift.open()
  await t.exception(drift.load(), /no valid manifest slot/)
  await drift.close()

  const corruptState = await fixture(t)
  await fs.writeFile(path.join(corruptState.controlDirectory, 'manifest-a.v1'), b4a.alloc(64, 7), { mode: 0o600 })
  const refusesOverwrite = createStore(corruptState)
  await refusesOverwrite.open()
  await t.exception(refusesOverwrite.initialize(corruptState.manifest), /refuses any existing slot/)
  await refusesOverwrite.close()
})

test('validation-only manifest load preserves recovery evidence and refuses every mutation', async t => {
  const state = await fixture(t)
  const writer = createStore(state)
  await writer.open()
  await writer.initialize(state.manifest)
  await writer.close()

  const slotA = path.join(state.controlDirectory, 'manifest-a.v1')
  const slotB = path.join(state.controlDirectory, 'manifest-b.v1')
  const temporary = path.join(state.controlDirectory, `.manifest-a.v1.${'1'.repeat(32)}.tmp`)
  await fs.writeFile(slotA, b4a.alloc(64, 0x41))
  await fs.writeFile(temporary, b4a.from('unfinished manifest bytes'), { mode: 0o600 })
  const before = await Promise.all([slotA, slotB, temporary].map(file => fs.readFile(file)))

  const validating = createStore(state)
  await validating.open({ validationOnly: true })
  const selected = await validating.load()
  t.is(selected.slot, 'b')
  t.is(selected.needsRepair, true)
  t.exception(() => validating.repair(selected.hash), /validation-only mode/)
  t.exception(() => validating.advance(selected.hash, { epochFloor: selected.manifest.epochFloor + 1 }),
    /validation-only mode/)
  t.exception(() => validating.initialize(state.manifest), /validation-only mode/)
  await validating.close()

  const after = await Promise.all([slotA, slotB, temporary].map(file => fs.readFile(file)))
  for (let index = 0; index < before.length; index++) t.alike(after[index], before[index])
})

test('validation-only manifest inspection leaves invalid temp, slot, key, and binding evidence untouched', async t => {
  const state = await fixture(t)
  const writer = createStore(state)
  await writer.open()
  await writer.initialize(state.manifest)
  await writer.close()

  const slotA = path.join(state.controlDirectory, 'manifest-a.v1')
  const slotB = path.join(state.controlDirectory, 'manifest-b.v1')
  const temporary = path.join(state.controlDirectory, `.manifest-b.v1.${'2'.repeat(32)}.tmp`)
  const symlinkTarget = path.join(state.root, 'invalid-temp-target')
  await fs.writeFile(symlinkTarget, b4a.from('do not delete'), { mode: 0o600 })
  await fs.symlink(symlinkTarget, temporary)

  const invalidTemp = createStore(state)
  await t.exception(invalidTemp.open({ validationOnly: true }), /temporary file is not a single-link regular file/)
  await invalidTemp.close()
  t.is((await fs.lstat(temporary)).isSymbolicLink(), true)
  t.alike(await fs.readFile(symlinkTarget), b4a.from('do not delete'))
  await fs.unlink(temporary)

  const before = await Promise.all([slotA, slotB].map(file => fs.readFile(file)))
  const wrongKey = new TwoSlotManifestStore({
    controlDirectory: state.controlDirectory,
    manifestKey: b4a.alloc(32, 0x92),
    expectedBindings: state.expectedBindings
  })
  await wrongKey.open({ validationOnly: true })
  await t.exception(wrongKey.load(), /no valid manifest slot/)
  await wrongKey.close()

  const wrongBinding = new TwoSlotManifestStore({
    controlDirectory: state.controlDirectory,
    manifestKey: state.manifestKey,
    expectedBindings: { ...state.expectedBindings, mapGeneration: 2n }
  })
  await wrongBinding.open({ validationOnly: true })
  await t.exception(wrongBinding.load(), /no valid manifest slot/)
  await wrongBinding.close()

  const after = await Promise.all([slotA, slotB].map(file => fs.readFile(file)))
  for (let index = 0; index < before.length; index++) t.alike(after[index], before[index])
})

test('manifest snapshots are branded to one active owner, generation, and selected hash', async t => {
  const state = await fixture(t)
  const store = createStore(state)
  await store.open()
  const genesis = await store.initialize(state.manifest)
  t.is(verifyBlindManifestSnapshot(genesis, state.controlDirectory), true)
  t.exception(() => verifyBlindManifestSnapshot(Object.freeze({ ...genesis }), state.controlDirectory), /forged/)

  const competing = createStore(state)
  await t.exception(competing.open(), /active in-process owner/)
  const next = await store.advance(genesis.hash, { epochFloor: state.manifest.epochFloor + 1 })
  t.exception(() => verifyBlindManifestSnapshot(genesis, state.controlDirectory), /stale-lifetime/)
  t.is(verifyBlindManifestSnapshot(next, state.controlDirectory), true)
  await store.close()
  t.exception(() => verifyBlindManifestSnapshot(next, state.controlDirectory), /stale-lifetime/)
})
