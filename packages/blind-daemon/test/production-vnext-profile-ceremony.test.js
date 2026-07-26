import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import test from 'brittle'
import {
  RESULT_SIGNATURE_DOMAIN_ID,
  blake2b256,
  blindServiceDescriptorV1,
  blindStoreManifestV1,
  decodeCanonical,
  encodeCanonical,
  hashStoreFormat,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { TwoSlotManifestStore } from '../manifest-store.js'
import { runVnextStoreGenesisCeremony, vnextStoreGenesisExpectedBindings } from '../production-vnext-profile.js'
import { enforceVnextManifestFloor } from '../production-runtime.js'
import { bindDurability, descriptorValue } from './coordinator-fixtures.js'

const MANIFEST_BINDING_FIELDS = Object.freeze([
  'relayPublicKey',
  'storeId',
  'durabilityProfileId',
  'durabilityContinuityHash',
  'durabilityProfileHash',
  'formatMajor',
  'formatMinor',
  'storeFormatHash',
  'specHash',
  'abiHash',
  'mapGeneration',
  'bucketMapHash',
  'writerEpoch',
  'writerFenceTokenHash'
])

function signCanonical (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(sodium.crypto_sign_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

function u64beBytes (value) {
  const output = b4a.alloc(8)
  output.writeBigUInt64BE(value)
  return output
}

async function failure (run) {
  try {
    await run()
  } catch (error) {
    return error
  }
  return null
}

function tuneStoreFormat (descriptor, storeFormatHash) {
  descriptor.durability.profileId = 1
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 2
  descriptor.durability.storeFormatHash = b4a.from(storeFormatHash)
  descriptor.build.storeFormatHash = b4a.from(storeFormatHash)
  bindDurability(descriptor)
  return descriptor
}

// A real signed descriptor chain built through the existing test helpers and
// signed with sodium exactly like production-vnext-profile-fixture.js does:
// the genesis descriptor (sequence 0) and its successor (sequence 1, the
// chain head the ceremony floors to).
async function ceremonyFixture (t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join('/tmp', 'hr-ceremony-')))
  await fs.chmod(root, 0o700)
  t.teardown(() => fs.rm(root, { recursive: true, force: true }).catch(() => {}))

  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const storeId = b4a.alloc(32, 0x63)
  const authorityBytes = await fs.readFile(new URL(
    '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc', import.meta.url))
  const storeFormatHash = hashStoreFormat(authorityBytes)

  const genesis = tuneStoreFormat(descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.from(storeId)
  }), storeFormatHash)
  const canonicalGenesis = signCanonical(blindServiceDescriptorV1, genesis,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  const successor = tuneStoreFormat(descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.from(storeId)
  }), storeFormatHash)
  successor.descriptorSequence = 1n
  successor.previousDescriptorHash = serviceDescriptorHash(canonicalGenesis)
  successor.descriptorNonce = b4a.alloc(32, 0x64)
  const canonicalSuccessor = signCanonical(blindServiceDescriptorV1, successor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  const mapGeneration = 1n
  const manifestKey = b4a.alloc(32, 0x91)
  // The documented deterministic derivation: both consistency tokens are
  // derived from the sealed identity so re-running is byte-identical.
  const bucketMapHash = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.bucket-map.v1', 'ascii'),
    storeId,
    u64beBytes(mapGeneration)
  ]))
  const partitionKey = blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.partition-key.v1', 'ascii'),
    storeId,
    manifestKey
  ]))

  return {
    root,
    storeRoot: path.join(root, 'store'),
    relaySecretKey,
    storeId,
    storeFormatHash,
    genesis: { descriptor: genesis, canonicalBytes: canonicalGenesis },
    successor: { descriptor: successor, canonicalBytes: canonicalSuccessor },
    args: {
      manifestKey,
      ownerFenceTokenHash: b4a.alloc(32, 0x72),
      partitionKey,
      bucketMapHash,
      mapGeneration
    }
  }
}

// The independent launch-side binding set (built from the descriptor and the
// ceremony arguments, never from the sealed bytes on disk).
function expectedBindings (descriptor, args) {
  const template = {
    relayPublicKey: b4a.from(descriptor.relayPublicKey),
    storeId: b4a.from(descriptor.storeId),
    durabilityProfileId: descriptor.durability.profileId,
    durabilityContinuityHash: b4a.from(descriptor.durabilityContinuityHash),
    durabilityProfileHash: b4a.from(descriptor.durabilityProfileHash),
    formatMajor: descriptor.durability.storeFormatMajor,
    formatMinor: descriptor.durability.storeFormatMinor,
    storeFormatHash: b4a.from(descriptor.durability.storeFormatHash),
    specHash: b4a.from(descriptor.build.specHash),
    abiHash: b4a.from(descriptor.build.abiHash),
    mapGeneration: args.mapGeneration,
    bucketMapHash: b4a.from(args.bucketMapHash),
    writerEpoch: 1n,
    writerFenceTokenHash: b4a.from(args.ownerFenceTokenHash)
  }
  return Object.freeze(Object.fromEntries(MANIFEST_BINDING_FIELDS.map(field => [field, template[field]])))
}

async function loadManifest (controlDirectory, manifestKey, bindings) {
  const store = new TwoSlotManifestStore({ controlDirectory, manifestKey, expectedBindings: bindings })
  await store.open({ validationOnly: true })
  try {
    return await store.load()
  } finally {
    await store.close()
  }
}

function ceremonyOn (fixture, chain = fixture.successor, overrides = {}) {
  return runVnextStoreGenesisCeremony({
    storeRoot: fixture.storeRoot,
    descriptor: chain.descriptor,
    descriptorCanonicalBytes: chain.canonicalBytes,
    ...fixture.args,
    ...overrides
  })
}

test('ceremony seals the two-slot manifest and checkpoint anchor under <root>/control', async t => {
  const fixture = await ceremonyFixture(t)
  const result = await ceremonyOn(fixture)

  t.ok(Object.isFrozen(result), 'ceremony result is frozen')
  t.ok(Object.isFrozen(result.manifestPaths), 'manifest paths are frozen')
  const rootStat = await fs.lstat(fixture.storeRoot)
  t.ok(rootStat.isDirectory(), 'ceremony created the store root')
  t.is(rootStat.mode & 0o777, 0o700, 'store root is daemon-private')
  t.is(result.storeRoot, fixture.storeRoot)
  t.is(result.controlDirectory, path.join(fixture.storeRoot, 'control'))
  t.is(result.manifestPaths.a, path.join(fixture.storeRoot, 'control', 'manifest-a.v1'))
  t.is(result.manifestPaths.b, path.join(fixture.storeRoot, 'control', 'manifest-b.v1'))

  const controlNames = (await fs.readdir(result.controlDirectory)).sort()
  t.ok(controlNames.includes('manifest-a.v1'), 'manifest slot a is installed')
  t.ok(controlNames.includes('manifest-b.v1'), 'manifest slot b is installed')
  t.absent(controlNames.includes('genesis-intent.v1'), 'genesis intent is removed after publication')
  t.ok(controlNames.includes(`checkpoint-${b4a.toString(result.checkpointHash, 'hex')}.v1`),
    'the checkpoint anchor file is installed under its header hash')
  t.absent(controlNames.some(name => name.includes('.tmp')), 'no artifact temporaries remain')

  for (const slot of [result.manifestPaths.a, result.manifestPaths.b]) {
    const stat = await fs.lstat(slot)
    t.is(stat.mode & 0o777, 0o600, `${path.basename(slot)} is private`)
  }
  const [slotA, slotB] = await Promise.all([fs.readFile(result.manifestPaths.a), fs.readFile(result.manifestPaths.b)])
  t.ok(b4a.equals(slotA, slotB), 'both slots carry the same sealed manifest')

  t.is(result.manifestRevision, 0n, 'genesis manifest is revision zero')
  t.is(result.manifestHash.byteLength, 32)
  t.is(result.checkpointSequence, 1n, 'validated recovery sees checkpoint sequence 1')
  t.is(result.checkpointWalSequence, 1n, 'checkpoint anchors WAL sequence 1')
  t.is(result.walHeadSequence, 1n)
  t.is(result.checkpointHash.byteLength, 32)
  t.absent(result.checkpointHash.every(byte => byte === 0), 'the pipeline filled the real checkpoint anchor')
  t.alike(result.recoveredWalSequences, [1n], 'exactly the genesis frame is recovered')
  t.alike(result.shadowWalSequences, [], 'no shadow frames exist at genesis')
})

test('sealed manifest MAC-verifies under the launch key and rejects a wrong key', async t => {
  const fixture = await ceremonyFixture(t)
  const result = await ceremonyOn(fixture)
  const bindings = expectedBindings(fixture.successor.descriptor, fixture.args)

  const snapshot = await loadManifest(result.controlDirectory, fixture.args.manifestKey, bindings)
  t.is(snapshot.revision, 0n)
  t.is(snapshot.needsRepair, false, 'both slots verify without repair')
  t.ok(b4a.equals(snapshot.hash, result.manifestHash), 'loaded hash matches the ceremony result')
  t.ok(b4a.equals(snapshot.manifest.checkpointHash, result.checkpointHash))
  t.is(snapshot.manifest.checkpointWalSequence, 1n)
  t.is(snapshot.manifest.durabilityProfileId, 1)

  const wrongKey = await failure(() => loadManifest(result.controlDirectory, b4a.alloc(32, 0x92), bindings))
  t.ok(wrongKey != null, 'a wrong manifest key fails closed')
  t.ok(/no valid manifest slot|MAC/.test(wrongKey.message), `wrong key surfaces MAC failure (${wrongKey.message})`)

  const wrongBindings = await failure(() => loadManifest(result.controlDirectory, fixture.args.manifestKey,
    { ...bindings, bucketMapHash: b4a.alloc(32, 0x81) }))
  t.ok(wrongBindings != null, 'a forged bucket-map binding fails closed')
  t.ok(/bucketMapHash|no valid manifest slot/.test(wrongBindings.message))
})

test('re-running the ceremony is idempotent and seals byte-identical material', async t => {
  const fixture = await ceremonyFixture(t)
  const first = await ceremonyOn(fixture)
  const firstBytes = await fs.readFile(first.manifestPaths.a)

  const second = await ceremonyOn(fixture)
  t.is(second.manifestRevision, 0n, 'manifest revision does not drift')
  t.is(second.checkpointWalSequence, 1n, 'checkpoint anchor stays at WAL sequence 1')
  t.is(second.checkpointSequence, 1n)
  t.alike(second.recoveredWalSequences, [1n], 're-run returns through validated recovery')
  t.ok(b4a.equals(second.manifestHash, first.manifestHash), 'no conflicting manifest is published')
  t.ok(b4a.equals(second.checkpointHash, first.checkpointHash), 'checkpoint anchor is byte-identical')
  t.ok(b4a.equals(await fs.readFile(second.manifestPaths.a), firstBytes), 'sealed slot bytes are identical')
  t.ok(b4a.equals(second.descriptorHashFloor, first.descriptorHashFloor))

  const controlNames = (await fs.readdir(first.controlDirectory)).sort()
  t.absent(controlNames.includes('genesis-intent.v1'), 'intent stays removed')
  t.absent(controlNames.some(name => name.includes('.tmp')), 're-run leaves no temporaries')
})

test('a corrupted manifest byte is rejected by TwoSlotManifestStore.load', async t => {
  const fixture = await ceremonyFixture(t)
  const result = await ceremonyOn(fixture)
  const bindings = expectedBindings(fixture.successor.descriptor, fixture.args)
  const originalA = await fs.readFile(result.manifestPaths.a)
  const originalB = await fs.readFile(result.manifestPaths.b)

  const tamperedA = b4a.from(originalA)
  tamperedA[10] ^= 0xff
  await fs.writeFile(result.manifestPaths.a, tamperedA, { mode: 0o600 })
  const degraded = await loadManifest(result.controlDirectory, fixture.args.manifestKey, bindings)
  t.is(degraded.slot, 'b', 'the intact slot still serves the manifest')
  t.is(degraded.needsRepair, true, 'one corrupted slot is detected as needing repair')

  const tamperedB = b4a.from(originalB)
  tamperedB[10] ^= 0xff
  await fs.writeFile(result.manifestPaths.b, tamperedB, { mode: 0o600 })
  const rejected = await failure(() => loadManifest(result.controlDirectory, fixture.args.manifestKey, bindings))
  t.ok(rejected != null, 'corrupting both slots fails closed')
  t.ok(/no valid manifest slot/.test(rejected.message), `tamper surfaces integrity failure (${rejected.message})`)

  await fs.writeFile(result.manifestPaths.a, originalA, { mode: 0o600 })
  await fs.writeFile(result.manifestPaths.b, originalB, { mode: 0o600 })
  const restored = await loadManifest(result.controlDirectory, fixture.args.manifestKey, bindings)
  t.is(restored.needsRepair, false, 'restored bytes verify again')
  t.ok(b4a.equals(restored.hash, result.manifestHash))
})

test('manifest floor fields match the descriptor chain head', async t => {
  const fixture = await ceremonyFixture(t)
  const successorHash = serviceDescriptorHash(fixture.successor.canonicalBytes)
  const genesisHash = serviceDescriptorHash(fixture.genesis.canonicalBytes)

  const result = await ceremonyOn(fixture, fixture.successor)
  t.is(result.descriptorSequenceFloor, fixture.successor.descriptor.descriptorSequence,
    'descriptorSequenceFloor is the chain head sequence')
  t.is(result.descriptorSequenceFloor, 1n)
  t.ok(b4a.equals(result.descriptorHashFloor, successorHash),
    'descriptorHashFloor is the chain head descriptor hash')
  t.absent(b4a.equals(result.descriptorHashFloor, genesisHash),
    'the floor binds the successor, not the genesis descriptor')

  const bindings = expectedBindings(fixture.successor.descriptor, fixture.args)
  const snapshot = await loadManifest(result.controlDirectory, fixture.args.manifestKey, bindings)
  t.is(snapshot.manifest.descriptorSequenceFloor, 1n, 'sealed manifest carries the chain head floor')
  t.ok(b4a.equals(snapshot.manifest.descriptorHashFloor, successorHash))
  t.is(snapshot.manifest.epochFloor, fixture.successor.descriptor.issuedEpoch,
    'epochFloor is the chain head issued epoch')

  const raw = await fs.readFile(result.manifestPaths.a)
  const decoded = decodeCanonical(blindStoreManifestV1, raw, { copyBytes: true })
  t.is(decoded.descriptorSequenceFloor, 1n, 'raw sealed bytes carry the floor')
  t.ok(b4a.equals(decoded.descriptorHashFloor, successorHash))
})

test('ceremony validates every input and fails closed before touching the store root', async t => {
  const fixture = await ceremonyFixture(t)

  const cases = []
  cases.push(['zero manifest key', { manifestKey: b4a.alloc(32) }, /manifestKey must be nonzero/])
  cases.push(['short manifest key', { manifestKey: b4a.alloc(16, 0x91) }, /manifestKey must be exactly 32 bytes/])
  cases.push(['zero partition key', { partitionKey: b4a.alloc(32) }, /partitionKey must be nonzero/])
  cases.push(['zero bucket-map hash', { bucketMapHash: b4a.alloc(32) }, /bucketMapHash must be nonzero/])
  cases.push(['zero owner fence token hash', { ownerFenceTokenHash: b4a.alloc(32) }, /ownerFenceTokenHash must be nonzero/])
  cases.push(['zero map generation', { mapGeneration: 0n }, /mapGeneration is outside its u64 bound/])
  cases.push(['mismatched canonical bytes', { descriptorCanonicalBytes: fixture.genesis.canonicalBytes },
    /descriptor does not match its canonical bytes/])
  cases.push(['empty canonical bytes', { descriptorCanonicalBytes: b4a.alloc(0) },
    /descriptorCanonicalBytes must be nonempty bytes/])
  cases.push(['out-of-range snapshot bound', { maximumSnapshotBytes: 1 }, /maximumSnapshotBytes is outside/])
  cases.push(['non-function fault injector', { faultInjector: 7 }, /faultInjector must be a function/])

  for (const [name, overrides, pattern] of cases) {
    const error = await failure(() => ceremonyOn(fixture, fixture.successor, overrides))
    t.ok(error != null, `${name} is refused`)
    t.is(error && error.code, 'BLIND_VNEXT_STORE_GENESIS_INVALID', `${name} carries the coded failure`)
    t.ok(pattern.test(error.message), `${name} explains itself (${error.message})`)
  }

  const relative = await failure(() => runVnextStoreGenesisCeremony({
    ...fixture.args,
    storeRoot: path.join('relative', 'store'),
    descriptor: fixture.successor.descriptor,
    descriptorCanonicalBytes: fixture.successor.canonicalBytes
  }))
  t.is(relative && relative.code, 'BLIND_VNEXT_STORE_GENESIS_INVALID', 'a relative store root is refused')

  const profile2 = tuneStoreFormat(descriptorValue({
    relayPublicKey: b4a.from(fixture.successor.descriptor.relayPublicKey),
    storeId: b4a.from(fixture.storeId)
  }), fixture.storeFormatHash)
  profile2.durability.profileId = 2
  const wrongProfile = await failure(() => ceremonyOn(fixture, fixture.successor, { descriptor: profile2 }))
  t.is(wrongProfile && wrongProfile.code, 'BLIND_VNEXT_STORE_GENESIS_INVALID')
  t.ok(/profile 1/.test(wrongProfile.message), 'durability profile 2 is refused before encoding')

  const untouched = await failure(() => fs.lstat(fixture.storeRoot))
  t.is(untouched && untouched.code, 'ENOENT', 'no store root was created by refused calls')
  t.is((await fs.readdir(fixture.root)).length, 0, 'the fixture directory stays pristine')
})

test('manifest floor enforcement: continuity, rollback, fork, refresh advance, absent manifest', async t => {
  const fixture = await ceremonyFixture(t)
  await ceremonyOn(fixture)
  const controlDirectory = path.join(fixture.storeRoot, 'control')
  const successorHash = serviceDescriptorHash(fixture.successor.canonicalBytes)
  const bindings = vnextStoreGenesisExpectedBindings(
    fixture.successor.descriptor, successorHash, fixture.args.mapGeneration, fixture.args.ownerFenceTokenHash)
  const enforce = (descriptorSequence, descriptorHash) => enforceVnextManifestFloor({
    controlDirectory,
    manifestKey: fixture.args.manifestKey,
    expectedBindings: bindings,
    descriptorSequence,
    descriptorHash
  })

  // Continuity: the activated head equals the sealed floor; no advance needed.
  const floor = await enforce(1n, successorHash)
  t.is(floor.descriptorSequenceFloor, 1n, 'the sealed floor is the chain head sequence')
  t.ok(b4a.equals(floor.descriptorHashFloor, successorHash), 'the sealed floor is the chain head hash')

  // Rollback: a presented descriptor below the persisted floor fails closed.
  const rollback = await failure(() => enforce(0n, successorHash))
  t.is(rollback && rollback.code, 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_ROLLBACK')

  // Fork: equal sequence but a different hash fails closed.
  const fork = await failure(() => enforce(1n, b4a.alloc(32, 0xee)))
  t.is(fork && fork.code, 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_FORK')

  // Refresh: a strictly newer descriptor advances the persisted floor, and the
  // advance itself persists (subsequent enforcement sees the new floor).
  const newHash = blake2b256(b4a.from('successor-refresh', 'ascii'))
  const advanced = await enforce(2n, newHash)
  t.is(advanced.descriptorSequenceFloor, 2n, 'a signed refresh advances the persisted floor')
  const afterAdvance = await loadManifest(controlDirectory, fixture.args.manifestKey, bindings)
  t.is(afterAdvance.manifest.descriptorSequenceFloor, 2n, 'the advanced floor is persisted in the manifest')
  const rollbackAfterAdvance = await failure(() => enforce(1n, successorHash))
  t.is(rollbackAfterAdvance && rollbackAfterAdvance.code, 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_ROLLBACK',
    'the pre-refresh descriptor is now below the persisted floor')

  // Absent manifest: a fresh store root with no sealed manifest fails closed.
  const empty = await fs.mkdtemp(path.join('/tmp', 'hr-floor-empty-'))
  t.teardown(() => fs.rm(empty, { recursive: true, force: true }).catch(() => {}))
  const emptyControl = path.join(empty, 'control')
  await fs.mkdir(emptyControl, { recursive: true, mode: 0o700 })
  const absent = await failure(() => enforceVnextManifestFloor({
    controlDirectory: emptyControl,
    manifestKey: fixture.args.manifestKey,
    expectedBindings: bindings,
    descriptorSequence: 1n,
    descriptorHash: successorHash
  }))
  t.ok(absent != null, 'an absent manifest is refused')
  t.ok(/no valid manifest slot|manifest/.test(absent.message), 'absent manifest fails closed')
})
