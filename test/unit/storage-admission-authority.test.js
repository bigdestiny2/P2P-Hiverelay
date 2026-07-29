import test from 'brittle'
import b4a from 'b4a'
import Corestore from 'corestore'
import { mkdtemp, readFile, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  markStorageCapExplicit,
  measureStorageTreeBytes,
  resolveStorageCap,
  sampleStorageFilesystem
} from '../../packages/core/config/storage-cap.js'
import {
  STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES,
  STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES,
  StorageAdmissionAuthority
} from '../../packages/core/config/storage-admission-authority.js'
import { Seeder } from '../../packages/core/core/relay-node/seeder.js'

const GiB = 1024 ** 3
const CAP = 10 * GiB
const STORAGE = '/verified/storage'
const K1 = 'a'.repeat(64)

function healthySample (checkedAt = Date.now()) {
  return {
    ok: true,
    checkedAt,
    storagePath: STORAGE,
    realpath: STORAGE,
    device: '42',
    totalBytes: 100 * GiB,
    freeBytes: 80 * GiB
  }
}

function authority (opts = {}) {
  const config = { storage: STORAGE, maxStorageBytes: opts.cap || CAP }
  return new StorageAdmissionAuthority(config, {
    getUsedBytes: opts.getUsedBytes || (() => 0),
    getActualBytes: opts.getActualBytes || (() => 0),
    sampleFilesystem: opts.sampleFilesystem || (() => healthySample()),
    sampleMaxAgeMs: opts.sampleMaxAgeMs || 60_000,
    recoveryKinds: opts.recoveryKinds
  })
}

function physicalSample (overrides = {}) {
  return {
    ...healthySample(),
    inode: '84',
    reserveBytes: 0,
    ...overrides,
    checkedAt: overrides.checkedAt ?? Date.now()
  }
}

class PhysicalProviderV1 {
  constructor (getUsedBytes = () => 0) {
    this.schemaVersion = 1
    this.providerId = 'provider-v1'
    this.scopeId = 'exclusive-storage-root'
    this.leaseId = 'root-lease'
    this.getUsedBytes = getUsedBytes
    this.generation = 0
    this.installCount = 0
    this.inspectCount = 0
    this.calls = []
    this.installHook = null
    this.inspectHook = null
    this.attestationHook = null
  }

  async installAbsoluteCeiling (request, priorLease) {
    const count = ++this.installCount
    this.calls.push({ type: 'install', request, priorLease })
    if (this.installHook) return this.installHook(request, priorLease, count)
    return {
      providerId: this.providerId,
      scopeId: this.scopeId,
      leaseId: this.leaseId,
      operationId: request.operationId,
      requestedAt: request.requestedAt,
      rootIdentity: request.storageIdentity ? { ...request.storageIdentity } : null,
      hardLimitBytes: request.ceilingAllocatedBytes,
      generation: ++this.generation
    }
  }

  async inspectAbsoluteCeiling (lease) {
    const count = ++this.inspectCount
    this.calls.push({ type: 'inspect', lease })
    if (this.inspectHook) return this.inspectHook(lease, count)
    let attestation = {
      schemaVersion: 1,
      active: true,
      exclusive: true,
      providerId: lease.providerId,
      scopeId: lease.scopeId,
      leaseId: lease.leaseId,
      operationId: lease.operationId,
      rootIdentity: lease.rootIdentity ? { ...lease.rootIdentity } : null,
      usedAllocatedBytes: this.getUsedBytes(),
      hardLimitBytes: lease.hardLimitBytes,
      generation: lease.generation,
      checkedAt: Math.max(Date.now(), lease.requestedAt)
    }
    if (this.attestationHook) attestation = this.attestationHook(attestation, lease, count)
    return attestation
  }
}

function physicalAuthority (opts = {}) {
  const getUsedBytes = opts.getUsedBytes || (() => 0)
  const provider = opts.provider || new PhysicalProviderV1(getUsedBytes)
  const authority = new StorageAdmissionAuthority({
    storage: STORAGE,
    maxStorageBytes: opts.cap || CAP
  }, {
    getUsedBytes,
    getActualBytes: () => 0,
    sampleFilesystem: opts.sampleFilesystem || (() => physicalSample()),
    sampleMaxAgeMs: opts.sampleMaxAgeMs || 60_000,
    physicalEnforcer: provider,
    recoveryKinds: []
  })
  return { authority, provider }
}

async function captureRejection (run) {
  try {
    await run()
    return null
  } catch (err) {
    return err
  }
}

function fakeCore (keyHex) {
  return {
    key: b4a.from(keyHex, 'hex'),
    discoveryKey: b4a.alloc(32),
    fork: 0,
    length: 0,
    byteLength: 0,
    async ready () {},
    async update () { return true },
    snapshot () {
      return {
        fork: this.fork,
        length: this.length,
        byteLength: this.byteLength,
        async ready () {},
        download: (...args) => this.download(...args),
        async close () {}
      }
    },
    download () { return { done: async () => {}, destroy () {} } },
    on () {},
    removeListener () {},
    async close () {}
  }
}

test('physical provider identity is constructor-bound and resolver updates are atomic', (t) => {
  const { authority, provider } = physicalAuthority()
  const originalUsed = authority.getUsedBytes
  const replacementUsed = () => 7
  const replacement = new PhysicalProviderV1()

  t.exception(
    () => authority.setResolvers({ physicalEnforcer: replacement, getUsedBytes: replacementUsed }),
    /physical storage enforcer changes require restart/
  )
  t.is(authority.physicalEnforcer, provider, 'rejected provider swap retains the constructor-bound provider')
  t.is(authority.getUsedBytes, originalUsed, 'rejected mixed update cannot partially replace resolvers')

  authority.setResolvers({ physicalEnforcer: provider, getUsedBytes: replacementUsed })
  t.is(authority.getUsedBytes, replacementUsed, 'same provider identity permits ordinary resolver refresh')
})

test('storage authority: drives and cores independently seal the recovery barrier', (t) => {
  const a = authority()
  a.refreshFilesystem()

  let result = a.admission(1, { refresh: false })
  t.is(result.reason, 'storage-recovery-inventory-pending')
  t.alike(result.pending, ['cores', 'drives'])

  t.is(a.markRecoveryReady('drives'), false)
  result = a.admission(1, { refresh: false })
  t.is(result.reason, 'storage-recovery-inventory-pending')
  t.alike(result.pending, ['cores'], 'one sealed inventory cannot open admission')

  t.is(a.markRecoveryReady('cores'), true)
  t.is(a.admission(1, { refresh: false }).allowed, true)
})

test('storage authority: synchronous cross-kind reservations cannot overcommit', (t) => {
  const a = authority({ recoveryKinds: [] })

  const drive = a.reserve('drive:app', 6 * GiB, { kind: 'drive' })
  t.is(drive.allowed, true)
  const core = a.reserve('core:feed', 5 * GiB, { kind: 'core' })
  t.is(core.allowed, false)
  t.is(core.reason, 'insufficient-storage')
  t.is(a.get('drive:app').state, 'reserved', 'pending reservation is immediately visible')

  t.is(a.rollback(drive), true)
  const retried = a.reserve('core:feed', 5 * GiB, { kind: 'core' })
  t.is(retried.allowed, true, 'exact rollback returns the reservation budget')
  t.is(a.commit(retried), true)
  t.is(a.get('core:feed').state, 'committed')
  t.is(a.release('core:feed'), true)
  t.is(a.admission(CAP, { refresh: true }).allowed, true, 'durable release returns the committed budget')
})

test('storage authority: existing promises consume physical headroom under an oversized logical cap', (t) => {
  const sample = {
    ...healthySample(),
    totalBytes: 100 * GiB,
    freeBytes: 23 * GiB
  }
  const a = authority({
    cap: 100 * GiB,
    recoveryKinds: [],
    sampleFilesystem: () => sample
  })
  const first = a.reserve('core:first', 10 * GiB, { kind: 'core' })
  t.ok(first.allowed)
  t.ok(a.commit(first))
  const second = a.reserve('core:second', 10 * GiB, { kind: 'core' })
  t.is(second.allowed, false)
  t.is(second.reason, 'insufficient-storage', 'unchanged free-space sample cannot be promised twice')
})

test('storage authority: exact usage never discounts the durable commitment', (t) => {
  const actual = new Map()
  let used = 0
  const a = authority({
    recoveryKinds: [],
    getUsedBytes: () => used,
    getActualBytes: key => actual.get(key) || 0
  })
  const first = a.reserve('drive:app', 6 * GiB)
  t.is(first.allowed, true)
  t.is(a.commit(first), true)

  actual.set('drive:app', 4 * GiB)
  used = 4 * GiB
  t.is(a.snapshot().committedRemainderBytes, 6 * GiB + STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES + STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES)
  t.is(a.admission(1).allowed, false, 'exact bytes plus the full promise already consume the cap')
  const tooLarge = a.reserve('core:feed', 5 * GiB)
  t.is(tooLarge.allowed, false)
})

test('storage authority: stale-high attribution after shrink cannot undercharge drive/core/outbox debt', (t) => {
  let used = GiB
  const actual = new Map([
    ['drive:app', Math.floor(1.5 * GiB)],
    ['core:feed', Math.floor(1.5 * GiB)],
    ['outboxlog:journal', Math.floor(1.5 * GiB)]
  ])
  const a = authority({
    recoveryKinds: [],
    getUsedBytes: () => used,
    getActualBytes: key => actual.get(key) || 0
  })
  for (const [key, kind] of [['drive:app', 'drive'], ['core:feed', 'core'], ['outboxlog:journal', 'outboxlog']]) {
    const token = a.reserve(key, 2 * GiB, { kind })
    t.ok(token.allowed)
    t.ok(a.commit(token, { actualBytes: actual.get(key) }))
  }
  // Simulate fork/truncate/compaction shrinking the exact tree while paced
  // caches/cumulative counters remain stale-high.
  used = GiB
  t.is(a.snapshot().committedRemainderBytes, 6 * GiB + (2 * STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES) + STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES, 'all three full promises and per-pin metadata remain charged')
  t.is(a.admission(4 * GiB).allowed, false, 'stale attribution cannot create phantom capacity')
})

test('storage authority: unknown legacy recovery is serve-only until authoritative re-pin measurement', (t) => {
  const a = authority({ getActualBytes: key => key === 'drive:legacy' ? GiB : 0 })
  a.adoptRecovery('drive:legacy', 'not-a-bound', { kind: 'drive' })
  a.markRecoveryReady('drives')
  a.markRecoveryReady('cores')

  t.is(a.get('drive:legacy').state, 'unknown-recovery')
  t.is(a.admission(1).reason, 'storage-commitment-unknown')
  t.is(a.reserve('drive:legacy', 2 * GiB).reason, 'storage-commitment-unknown')

  const measured = a.reserve('drive:legacy', 2 * GiB, { authoritativeSizeBytes: GiB, kind: 'drive' })
  t.is(measured.allowed, true)
  t.is(measured.reservedBytes, 2 * GiB + STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES + STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES)
  t.is(a.commit(measured), true)
  t.is(a.get('drive:legacy').boundBytes, 2 * GiB)
  t.is(a.admission(1).allowed, true)

  a.adoptRecovery('drive:too-large', null, { kind: 'drive' })
  const tooSmall = a.reserve('drive:too-large', GiB, { authoritativeSizeBytes: 2 * GiB, kind: 'drive' })
  t.is(tooSmall.allowed, false)
  t.is(tooSmall.reason, 'storage-bound-below-actual')
})

test('storage authority: every reservation refreshes the proof and rejects stale/remounted storage', (t) => {
  let sample = healthySample(1)
  const a = authority({ sampleFilesystem: () => sample, sampleMaxAgeMs: 5, recoveryKinds: [] })

  const stale = a.reserve('drive:stale', GiB)
  t.is(stale.allowed, false)
  t.is(stale.reason, 'storage-filesystem-sample-stale')

  sample = { ok: false, reason: 'storage-filesystem-device-mismatch', checkedAt: Date.now() }
  const remounted = a.reserve('drive:remounted', GiB)
  t.is(remounted.allowed, false)
  t.is(remounted.reason, 'storage-filesystem-device-mismatch')
  t.absent(a.get('drive:remounted'), 'invalid physical proof never installs a reservation')
})

test('filesystem sampler binds exact realpath/device and detects a transition around statfs', (t) => {
  const config = { storage: STORAGE, maxStorageBytes: CAP }
  markStorageCapExplicit(config, 'test')
  const directory = dev => ({ dev, isDirectory: () => true })
  resolveStorageCap(config, {
    stat: () => directory(42),
    realpath: () => STORAGE,
    statfs: () => ({ bsize: 1, blocks: 100 * GiB, bavail: 80 * GiB }),
    measureStorageBytes: () => 0
  })

  let statCalls = 0
  const transitioned = sampleStorageFilesystem(config, {
    checkedAt: 123,
    stat: () => directory(++statCalls === 3 ? 99 : 42),
    realpath: () => STORAGE,
    statfs: () => ({ bsize: 1, blocks: 100 * GiB, bavail: 80 * GiB })
  })
  t.is(transitioned.ok, false)
  t.is(transitioned.reason, 'storage-filesystem-changed-during-sample')

  const wrongRealpath = sampleStorageFilesystem(config, {
    stat: () => directory(42),
    realpath: () => '/unexpected/storage',
    statfs: () => { throw new Error('must fail before capacity sampling') }
  })
  t.is(wrongRealpath.reason, 'storage-filesystem-realpath-mismatch')
})

test('durable core write before authority commit stays reserved and fail-closed', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'storage-authority-crash-'))
  const persistPath = join(dir, 'seeded-cores.json')
  const a = authority({ recoveryKinds: [] })
  const originalCommit = a.commit.bind(a)
  a.commit = token => {
    t.ok(a.owns(token), 'durable write completed while reservation is still owned')
    a.failClosed('injected-post-persist-crash')
    return false
  }
  const core = fakeCore(K1)
  const seeder = new Seeder({ get: () => core }, {
    join () {},
    async leave () {}
  }, { storagePath: persistPath, storageAdmission: a })
  await seeder.start()

  let err = null
  try {
    await seeder.seedCore(K1, { maxStorageBytes: GiB })
  } catch (cause) {
    err = cause
  }
  t.ok(err && /commit failed/.test(err.message))
  t.is(err.durableAccepted, true)
  t.is(seeder.cores.has(K1), true, 'durably accepted core remains live')
  t.is(a.get(`core:${K1}`).state, 'reserved', 'conservative debt is never rolled back after durable acceptance')
  t.is(a.admission(1).reason, 'storage-reservation-authority-invariant-failed')
  t.alike(JSON.parse(await readFile(persistPath, 'utf8')), {
    schemaVersion: 3,
    cores: [{ key: K1, maxStorageBytes: GiB, state: 'bounded' }]
  })

  a.commit = originalCommit
  await seeder.stop()
})

test('authority revalidates identity and current free space after exact usage walk', (t) => {
  let phase = 0
  const samples = [
    { ...healthySample(), inode: '1', freeBytes: 80 * GiB },
    { ...healthySample(), inode: '1', freeBytes: 3 * GiB }
  ]
  const a = authority({
    recoveryKinds: [],
    getUsedBytes: () => { phase++; return 0 },
    sampleFilesystem: () => samples[Math.min(phase, 1)]
  })
  const result = a.reserve('drive:post-walk-free-drop', 2 * GiB)
  t.is(result.allowed, false)
  t.is(result.reason, 'storage-reserve-reached', 'post-walk statfs, not optimistic pre-walk free space, decides')

  phase = 0
  samples[1] = { ...samples[0], inode: '2' }
  const swapped = a.reserve('drive:post-walk-swap', GiB)
  t.is(swapped.allowed, false)
  t.is(swapped.reason, 'storage-filesystem-changed-during-usage-measurement')
})

test('authority never hides actual overshoot or permits an in-place bound shrink', (t) => {
  const actual = new Map()
  const a = authority({ recoveryKinds: [], getActualBytes: key => actual.get(key) || 0 })
  const token = a.reserve('drive:bounded', 2 * GiB)
  t.ok(token.allowed)
  t.ok(a.commit(token))
  actual.set('drive:bounded', 3 * GiB)
  t.is(a.admission(1).reason, 'storage-commitment-unknown')
  t.is(a.fatalReason, 'storage-actual-exceeds-commitment')

  const b = authority({ recoveryKinds: [] })
  const first = b.reserve('drive:no-shrink', 2 * GiB)
  t.ok(b.commit(first))
  const shrink = b.reserve('drive:no-shrink', GiB)
  t.is(shrink.allowed, false)
  t.is(shrink.reason, 'storage-bound-shrink-requires-release')
  t.is(b.get('drive:no-shrink').boundBytes, 2 * GiB)
})

test('bounded core refresh never mixes a pre-append byteLength with a post-append range', async (t) => {
  const seeder = new Seeder({}, {}, {})
  const lengths = [1, 2, 2, 2, 2, 2, 2, 2, 2, 2]
  const byteLengths = [100, 200, 200, 200, 200, 200]
  let downloads = 0
  const core = {
    fork: 0,
    get length () { return lengths.length > 1 ? lengths.shift() : 2 },
    get byteLength () { return byteLengths.length > 1 ? byteLengths.shift() : 200 },
    async update () { return true },
    snapshot () {
      return {
        fork: 0,
        length: 2,
        byteLength: 200,
        async ready () {},
        download () { downloads++; return { done: async () => {}, destroy () {} } },
        async close () {}
      }
    },
    download () { downloads++; return { done: async () => {}, destroy () {} } }
  }
  const entry = {
    core,
    publicKeyHex: K1,
    maxStorageBytes: 150,
    recoveryOnly: false,
    refreshing: null,
    range: null,
    retiringDownloads: []
  }
  t.is(await seeder._refreshBoundedDownload(entry), false)
  t.is(downloads, 0, 'stable post-append size exceeds cap, so no mixed range is authorized')
})

test('rejected core proof keeps its full reservation until late session settlement', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'storage-rejected-settlement-'))
  const persistPath = join(dir, 'seeded-cores.json')
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const bound = 8 * GiB
  const a = authority({ recoveryKinds: [] })
  let closeStarted
  let settleClose
  const closing = new Promise(resolve => { closeStarted = resolve })
  const closeGate = new Promise(resolve => { settleClose = resolve })
  const core = fakeCore(K1)
  core.update = async () => { throw new Error('injected proof rejection after tree ingress') }
  core.close = async () => { closeStarted(); await closeGate }
  const seeder = new Seeder({ get: () => core }, {
    join () {},
    async leave () {}
  }, { storagePath: persistPath, storageAdmission: a })
  await seeder.start()

  const rejected = seeder.seedCore(K1, { maxStorageBytes: bound })
  await closing
  const held = a.get(`core:${K1}`)
  t.is(held.state, 'reserved', 'failed proof remains fully charged while close can still settle writes')
  t.is(held.boundBytes, bound)
  t.is(held.overheadBytes, STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES)
  t.is(a.reserve('core:' + 'b'.repeat(64), 3 * GiB).allowed, false, 'late settlement cannot race capacity reuse')

  settleClose()
  await t.exception(rejected, /injected proof rejection/)
  t.is(a.get(`core:${K1}`), null, 'reservation returns only after the session settlement barrier')
})

test('many rejected keys leave only bounded residue and exact admission charges it on retry', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'storage-rejected-residue-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const store = new Corestore(dir)
  await store.ready()
  const config = {
    storage: dir,
    maxStorageBytes: measureStorageTreeBytes(dir) + 4 * 1024 * 1024
  }
  markStorageCapExplicit(config, 'test')
  resolveStorageCap(config)
  const admission = new StorageAdmissionAuthority(config, {
    getUsedBytes: () => measureStorageTreeBytes(dir),
    recoveryKinds: []
  })
  admission.refreshFilesystem()
  const seeder = new Seeder(store, {
    join () {},
    async leave () {}
  }, { storagePath: join(dir, 'seeded-cores.json'), storageAdmission: admission })
  await seeder.start()
  const before = measureStorageTreeBytes(dir)
  const attempts = 32
  for (let i = 0; i < attempts; i++) {
    const key = b4a.alloc(32)
    key.writeUInt32BE(i + 1, 28)
    await t.exception(
      seeder.seedCore(b4a.toString(key, 'hex'), { maxStorageBytes: 1 }),
      /authoritative core size unavailable/
    )
  }
  const after = measureStorageTreeBytes(dir)
  const growth = after - before
  t.ok(growth <= attempts * STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES, `${growth} bytes stay within per-attempt metadata overhead`)
  t.is(admission.snapshot().records.length, 0, 'all failed reservations settle and roll back')
  const retry = admission.admission(config.maxStorageBytes - after + 1)
  t.is(retry.allowed, false, 'exact tree residue is charged before the next reservation')
  await seeder.stop()
  await store.close()
})

test('physical provider v1: provider, scope, lease, and operation bindings are mandatory', async (t) => {
  const missingFields = ['providerId', 'scopeId', 'leaseId', 'operationId']
  for (const field of missingFields) {
    const { authority: a, provider } = physicalAuthority()
    provider.attestationHook = attestation => {
      const invalid = { ...attestation }
      delete invalid[field]
      return invalid
    }
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.code, 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE', `${field} is required`)
    t.is(err?.reason, 'physical-enforcer-attestation-invalid')
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
  }

  const { authority: a, provider } = physicalAuthority()
  provider.attestationHook = (attestation, lease) => ({
    ...attestation,
    operationId: lease.operationId + '-replayed'
  })
  const err = await captureRejection(() => a.activatePhysicalEnforcement())
  t.is(err?.reason, 'physical-enforcer-attestation-invalid', 'an attestation cannot be replayed under another operation')

  const first = physicalAuthority()
  const second = physicalAuthority()
  await first.authority.activatePhysicalEnforcement()
  await second.authority.activatePhysicalEnforcement()
  t.not(first.authority.physicalEnforcementSnapshot().operationId,
    second.authority.physicalEnforcementSnapshot().operationId,
    'fresh authorities use unpredictable operation bindings')
})

test('physical provider v1: candidate lease bindings are validated before inspection', async (t) => {
  for (const field of ['providerId', 'scopeId', 'leaseId', 'operationId']) {
    const { authority: a, provider } = physicalAuthority()
    provider.installHook = (request) => {
      const lease = {
        providerId: provider.providerId,
        scopeId: provider.scopeId,
        leaseId: provider.leaseId,
        operationId: request.operationId,
        requestedAt: request.requestedAt,
        rootIdentity: { ...request.storageIdentity },
        hardLimitBytes: request.ceilingAllocatedBytes,
        generation: 1
      }
      delete lease[field]
      return lease
    }
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-enforcer-lease-invalid', `lease ${field} is required`)
    t.is(provider.inspectCount, 0, 'an invalid candidate is never inspected')
  }

  for (const field of ['storagePath', 'realpath', 'device', 'inode']) {
    const { authority: a, provider } = physicalAuthority()
    provider.installHook = (request) => {
      const rootIdentity = { ...request.storageIdentity }
      delete rootIdentity[field]
      return {
        providerId: provider.providerId,
        scopeId: provider.scopeId,
        leaseId: provider.leaseId,
        operationId: request.operationId,
        requestedAt: request.requestedAt,
        rootIdentity,
        hardLimitBytes: request.ceilingAllocatedBytes,
        generation: 1
      }
    }
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-enforcer-lease-invalid', `lease identity ${field} is required`)
    t.is(provider.inspectCount, 0)
  }
})

test('physical provider v1: provider, scope, and lease cannot change across installs', async (t) => {
  for (const field of ['providerId', 'scopeId', 'leaseId']) {
    const { authority: a, provider } = physicalAuthority()
    const activation = await a.activatePhysicalEnforcement()
    t.is(activation.active, true)
    provider.attestationHook = (attestation, _lease, count) => count === 2
      ? { ...attestation, [field]: attestation[field] + '-changed' }
      : attestation
    let called = false
    const err = await captureRejection(() => a.runPhysicalMutation({ purpose: `changed-${field}` }, async () => {
      called = true
    }))
    t.is(err?.reason, 'physical-enforcer-attestation-invalid', `${field} continuity is enforced`)
    t.is(called, false, 'candidate proof fails before the mutation callback')
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
  }

  for (const field of ['providerId', 'scopeId', 'leaseId']) {
    const { authority: a, provider } = physicalAuthority()
    await a.activatePhysicalEnforcement()
    provider.installHook = (request, priorLease) => ({
      ...priorLease,
      [field]: priorLease[field] + '-changed',
      operationId: request.operationId,
      requestedAt: request.requestedAt,
      rootIdentity: { ...request.storageIdentity },
      hardLimitBytes: request.ceilingAllocatedBytes,
      generation: priorLease.generation + 1
    })
    const err = await captureRejection(() => a.runPhysicalMutation({ purpose: `lease-changed-${field}` }, async () => {}))
    t.is(err?.reason, 'physical-enforcer-lease-invalid', `candidate lease ${field} continuity is enforced`)
    t.is(provider.inspectCount, 1, 'invalid replacement is rejected before another inspect')
  }
})

test('physical provider v1: attestation state and numeric bounds fail closed', async (t) => {
  const invalidAttestations = [
    ['schema', attestation => ({ ...attestation, schemaVersion: 2 })],
    ['inactive', attestation => ({ ...attestation, active: false })],
    ['nonexclusive', attestation => ({ ...attestation, exclusive: false })],
    ['used-over-hard', attestation => ({
      ...attestation,
      usedAllocatedBytes: attestation.hardLimitBytes + 1
    })],
    ['hard-mismatch', attestation => ({
      ...attestation,
      hardLimitBytes: attestation.hardLimitBytes - 1
    })],
    ['generation-zero', attestation => ({ ...attestation, generation: 0 })]
  ]
  for (const [name, mutate] of invalidAttestations) {
    const { authority: a, provider } = physicalAuthority()
    provider.attestationHook = mutate
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-enforcer-attestation-invalid', `${name} attestation is rejected`)
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
  }

  {
    const { authority: a, provider } = physicalAuthority()
    provider.installHook = request => ({
      providerId: provider.providerId,
      scopeId: provider.scopeId,
      leaseId: provider.leaseId,
      operationId: request.operationId,
      requestedAt: request.requestedAt,
      rootIdentity: { ...request.storageIdentity },
      hardLimitBytes: request.ceilingAllocatedBytes + 1,
      generation: 1
    })
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-enforcer-lease-invalid', 'a provider cannot raise the requested ceiling')
  }

  {
    const { authority: a, provider } = physicalAuthority()
    provider.attestationHook = attestation => ({ ...attestation, usedAllocatedBytes: 1 })
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-enforcer-usage-mismatch', 'provider usage must equal the authority measurement')
  }
})

test('physical provider v1: storage identity must be complete and exact', async (t) => {
  const identityFields = ['storagePath', 'realpath', 'device', 'inode']
  for (const field of identityFields) {
    const sample = physicalSample()
    delete sample[field]
    const { authority: a } = physicalAuthority({ sampleFilesystem: () => ({ ...sample, checkedAt: Date.now() }) })
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-storage-identity-invalid', `sample ${field} cannot be omitted`)
  }

  for (const field of identityFields) {
    const { authority: a, provider } = physicalAuthority()
    provider.attestationHook = attestation => {
      const invalid = { ...attestation, rootIdentity: { ...attestation.rootIdentity } }
      delete invalid.rootIdentity[field]
      return invalid
    }
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-enforcer-attestation-invalid', `attested ${field} cannot be omitted`)
  }

  const { authority: a, provider } = physicalAuthority()
  provider.attestationHook = attestation => ({
    ...attestation,
    rootIdentity: { ...attestation.rootIdentity, device: 'different-device' }
  })
  const err = await captureRejection(() => a.activatePhysicalEnforcement())
  t.is(err?.reason, 'physical-enforcer-attestation-invalid', 'identity equality is exact')
})

test('physical provider v1: storage identity cannot change during or between proofs', async (t) => {
  {
    let samples = 0
    const { authority: a } = physicalAuthority({
      sampleFilesystem: () => physicalSample({ inode: ++samples === 1 ? '84' : '85' })
    })
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-storage-identity-changed', 'install and inspect must name the same root')
    t.is(a.physicalEnforcementActive, false)
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
  }

  {
    let inode = '84'
    const { authority: a, provider } = physicalAuthority({
      sampleFilesystem: () => physicalSample({ inode })
    })
    await a.activatePhysicalEnforcement()
    inode = '85'
    let called = false
    const err = await captureRejection(() => a.runPhysicalMutation({ purpose: 'remounted-root' }, async () => {
      called = true
    }))
    t.is(err?.reason, 'physical-enforcer-lease-invalid', 'a later install cannot rebind the stable lease')
    t.is(provider.inspectCount, 1, 'the changed-root candidate is rejected before inspection')
    t.is(called, false, 'no callback begins after a remount')
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
  }
})

test('physical provider v1: checkedAt is bound to the request freshness window', async (t) => {
  const cases = [
    ['missing', (_attestation, lease) => {
      const invalid = { ..._attestation }
      delete invalid.checkedAt
      return invalid
    }],
    ['before-request', (attestation, lease) => ({ ...attestation, checkedAt: lease.requestedAt - 1 })],
    ['too-far-future', (attestation, lease) => ({ ...attestation, checkedAt: lease.requestedAt + 2000 })]
  ]
  for (const [name, mutate] of cases) {
    const { authority: a, provider } = physicalAuthority({ sampleMaxAgeMs: 10 })
    provider.attestationHook = mutate
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.reason, 'physical-enforcer-attestation-invalid', `${name} checkedAt is rejected`)
  }
})

test('physical provider v1: every install strictly advances generation', async (t) => {
  const { authority: a, provider } = physicalAuthority()
  await a.activatePhysicalEnforcement()
  const priorGeneration = a.physicalEnforcementSnapshot().generation
  provider.installHook = (request, priorLease) => ({
    ...priorLease,
    operationId: request.operationId,
    requestedAt: request.requestedAt,
    hardLimitBytes: request.ceilingAllocatedBytes,
    rootIdentity: { ...request.storageIdentity },
    generation: priorGeneration
  })
  let called = false
  const err = await captureRejection(() => a.runPhysicalMutation({ purpose: 'stale-generation' }, async () => {
    called = true
  }))
  t.is(err?.reason, 'physical-enforcer-lease-invalid')
  t.is(called, false)
  t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
})

test('physical provider v1: post-mutation inspection requires generation equality', async (t) => {
  const { authority: a, provider } = physicalAuthority()
  await a.activatePhysicalEnforcement()
  provider.attestationHook = (attestation, _lease, count) => count === 3
    ? { ...attestation, generation: attestation.generation + 1 }
    : attestation
  let called = false
  const err = await captureRejection(() => a.runPhysicalMutation({ purpose: 'post-generation-change' }, async () => {
    called = true
  }))
  t.is(called, true, 'mutation completed before the invalid settlement proof')
  t.is(err?.reason, 'physical-enforcer-attestation-invalid')
  t.is(a.fatalReason, 'storage-physical-enforcement-ambiguous')
})

test('physical provider v1: invalid candidate does not replace the last proved lease', async (t) => {
  const { authority: a, provider } = physicalAuthority()
  await a.activatePhysicalEnforcement()
  const priorLease = a._physicalLease
  const priorAttestation = a.physicalEnforcementSnapshot()
  provider.attestationHook = (attestation, lease, count) => count === 2
    ? { ...attestation, operationId: lease.operationId + '-invalid' }
    : attestation
  let called = false
  const err = await captureRejection(() => a.runPhysicalMutation({ purpose: 'invalid-candidate' }, async () => {
    called = true
  }))
  t.is(err?.reason, 'physical-enforcer-attestation-invalid')
  t.is(called, false)
  t.is(a._physicalLease, priorLease, 'candidate lease remains staged until its proof validates')
  t.alike(a.physicalEnforcementSnapshot(), priorAttestation, 'last proved attestation remains authoritative')
})

test('physical provider v1: install and inspect throws are normalized and fail closed', async (t) => {
  {
    const { authority: a, provider } = physicalAuthority()
    const cause = new Error('backend install exploded')
    provider.installHook = async () => { throw cause }
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.code, 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE')
    t.is(err?.reason, 'physical-enforcer-install-failed')
    t.is(err?.cause, cause)
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
  }

  {
    const { authority: a, provider } = physicalAuthority()
    const cause = new Error('backend inspect exploded')
    provider.inspectHook = async () => { throw cause }
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.code, 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE')
    t.is(err?.reason, 'physical-enforcer-inspect-failed')
    t.is(err?.cause, cause)
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
  }
})

test('physical provider v1: throwing capability getters are normalized and fail closed', async (t) => {
  for (const field of ['schemaVersion', 'installAbsoluteCeiling', 'inspectAbsoluteCeiling']) {
    const provider = {
      schemaVersion: 1,
      async installAbsoluteCeiling () {},
      async inspectAbsoluteCeiling () {}
    }
    Object.defineProperty(provider, field, {
      get () { throw new Error(`injected ${field} getter failure`) }
    })
    const { authority: a } = physicalAuthority({ provider })
    const err = await captureRejection(() => a.activatePhysicalEnforcement())
    t.is(err?.code, 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE')
    t.is(err?.reason, 'physical-enforcer-capability-failed')
    t.ok(err?.cause?.message.includes(field))
    t.is(a.fatalReason, 'storage-physical-enforcement-invalid')
    t.is(a.physicalEnforcementActive, false)
  }
})

test('physical provider v1: zero-growth ceiling can activate at or above the logical cap', async (t) => {
  for (const used of [CAP, CAP + 1]) {
    const getUsedBytes = () => used
    const provider = new PhysicalProviderV1(getUsedBytes)
    const { authority: a } = physicalAuthority({ getUsedBytes, provider })
    const result = await a.activatePhysicalEnforcement({ purpose: 'serve-only-startup' })
    t.is(result.active, true)
    t.is(result.attestation.usedAllocatedBytes, used)
    t.is(result.attestation.hardLimitBytes, used, 'activation preserves existing bytes without authorizing growth')
  }
})

test('physical provider v1: a ceiling-equal mutation never invokes its callback', async (t) => {
  const getUsedBytes = () => CAP
  const provider = new PhysicalProviderV1(getUsedBytes)
  const { authority: a } = physicalAuthority({ getUsedBytes, provider })
  await a.activatePhysicalEnforcement()
  let called = false
  const err = await captureRejection(() => a.runPhysicalMutation({ purpose: 'at-ceiling' }, async () => {
    called = true
  }))
  t.is(err?.code, 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE')
  t.is(err?.reason, 'physical-ceiling-reached')
  t.is(called, false, 'no write callback can begin without physical growth headroom')
  t.is(a.fatalReason, null, 'ordinary capacity exhaustion does not corrupt authority state')
  t.is(a.physicalEnforcementActive, true)
})
