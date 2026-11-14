import test from 'brittle'
import Corestore from 'corestore'
import Hypercore from 'hypercore'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { StorageAdmissionAuthority } from '../../packages/core/config/storage-admission-authority.js'
import { measureStorageTreeBytes, resolveStorageCap } from '../../packages/core/config/storage-cap.js'
import {
  createHypercoreOutboxJournal,
  createPartitionedHypercoreOutboxJournal,
  OUTBOXLOG_STORAGE_COMMITMENT_KEY,
  bootstrapEmptyLegacyOutboxJournal,
  outboxRecoveryInventoryDigest
} from '../../packages/services/builtin/outboxlog/hypercore-journal.js'

const GiB = 1024 ** 3
const BOUND = 16 * 1024 ** 2
const APP = 'a'.repeat(64)
const DRIVE = 'drive:' + 'b'.repeat(64)
const CORE = 'core:' + 'c'.repeat(64)
const LEDGER = 'outboxlog/storage-consumed-v1'
const modes = [
  { name: 'outboxlog/operations', open: createHypercoreOutboxJournal },
  { name: 'outboxlog/outboxes/index', open: createPartitionedHypercoreOutboxJournal }
]
const entry = seq => ({ version: 1, seq, kind: 'create', appId: APP, inviteKey: '1'.repeat(64) })

async function fixture (t, mode = modes[0], initialize = true) {
  const dir = await mkdtemp(join(tmpdir(), 'hr-outbox-recovery-'))
  const stores = new Set()
  t.teardown(async () => {
    for (const store of stores) await store.close()
    await rm(dir, { recursive: true, force: true })
  })
  const makeAuthority = (unknown = false) => {
    const config = { storage: dir, maxStorageBytes: GiB }
    resolveStorageCap(config)
    const authority = new StorageAdmissionAuthority(config, { recoveryKinds: [], getUsedBytes: () => measureStorageTreeBytes(dir) })
    if (unknown) {
      authority.adoptRecovery(DRIVE, null, { kind: 'drive' })
      authority.adoptRecovery(CORE, null, { kind: 'core' })
    }
    return authority
  }
  const makeStore = async () => {
    const store = new Corestore(dir)
    stores.add(store)
    await store.ready()
    return store
  }
  const store = await makeStore()
  const authority = makeAuthority()
  const journal = initialize ? await mode.open({ store, storageAdmission: authority, maxJournalStorageBytes: BOUND }) : null
  return { dir, store, authority, journal, makeStore, makeAuthority, mode, key: `outboxlog:${mode.name}` }
}

async function bootstrapAuthorization (t, f, authority) {
  const dir = await mkdtemp(join(tmpdir(), 'hr-outbox-operator-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const pinned = async (name, value) => {
    const bytes = Buffer.from(JSON.stringify(value))
    const path = join(dir, name)
    await writeFile(path, bytes, { mode: 0o600 })
    return { path, sha256: createHash('sha256').update(bytes).digest('hex') }
  }
  const selectedPlan = await pinned('plan.json', { fixtureOnly: true })
  const irreversibleIntent = await pinned('intent.json', { selectedPlanSha256: selectedPlan.sha256 })
  const sample = authority.filesystemSample({ refresh: true })
  const keyPair = await f.store.createKeyPair(f.mode.name)
  const coreKey = Hypercore.key({ version: f.store.manifestVersion || 1, signers: [{ publicKey: keyPair.publicKey }] }).toString('hex')
  const plan = {
    schema: 'HiveRelayOfflineEmptyOutboxAuthorizationV1',
    action: 'initialize-exact-empty-single-outbox-journal',
    selectedPlan,
    irreversibleIntent,
    sourceCommit: '0'.repeat(40),
    sourceRoot: process.cwd(),
    rootIdentity: Object.fromEntries(['storagePath', 'realpath', 'device', 'inode'].map(k => [k, String(sample[k])])),
    operatorCapBytes: authority.config.maxStorageBytes,
    authorityRecordsSha256: outboxRecoveryInventoryDigest(authority),
    journal: { mode: 'hypercore', name: f.mode.name, coreKey, boundBytes: BOUND }
  }
  const authorization = await pinned('authorization.json', plan)
  return { plan, pinned, args: { store: f.store, storageAdmission: authority, name: f.mode.name, maxJournalStorageBytes: BOUND, authorizationPath: authorization.path, authorizationSha256: authorization.sha256 } }
}

test('outbox offline bootstrap requires selected proof, preserves unknown pins, and cold opens normally', async t => {
  const f = await fixture(t, modes[0], false)
  const authority = f.makeAuthority(true)
  const unknown = authority.snapshot().records
  await t.exception(f.mode.open({ store: f.store, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /storage-commitment-unknown/)
  const authorization = await bootstrapAuthorization(t, f, authority)
  const originalGet = f.store.get.bind(f.store)
  let creationCharged = false
  f.store.get = opts => {
    if (opts.name === f.mode.name && opts.createIfMissing !== false) {
      creationCharged = authority.get(f.key)?.boundBytes === BOUND
      if (!creationCharged) throw new Error('journal allocated before commitment')
    }
    return originalGet(opts)
  }
  const { journal, receipt } = await bootstrapEmptyLegacyOutboxJournal(authorization.args)
  f.store.get = originalGet
  t.ok(creationCharged)
  t.is(receipt.boundBytes, BOUND)
  t.is(receipt.authorizationSha256, authorization.args.authorizationSha256)
  t.alike(authority.snapshot().records.filter(r => r.kind !== 'outboxlog'), unknown)
  t.is(authority.reserve('core:' + 'd'.repeat(64), 1).reason, 'storage-commitment-unknown')
  await journal.close()
  await f.store.close()
  const store = await f.makeStore()
  const reopened = await f.mode.open({ store, storageAdmission: f.makeAuthority(true), maxJournalStorageBytes: BOUND })
  t.is(reopened.core.key.toString('hex'), receipt.coreKey)
  await reopened.close()
})

test('outbox offline bootstrap refuses changed pins, authority, identity and incomplete journal state before a grant', async t => {
  const f = await fixture(t, modes[0], false)
  const authority = f.makeAuthority(true)
  const auth = await bootstrapAuthorization(t, f, authority)
  await t.exception(bootstrapEmptyLegacyOutboxJournal({ ...auth.args, authorizationSha256: 'f'.repeat(64) }), /pin mismatch/)
  t.absent(authority.get(f.key))
  for (const delta of [
    { rootIdentity: { ...auth.plan.rootIdentity, inode: 'wrong' } },
    { authorityRecordsSha256: 'f'.repeat(64) },
    { operatorCapBytes: GiB + 1 },
    { journal: { ...auth.plan.journal, coreKey: 'e'.repeat(64) } },
    { selectedPlan: { ...auth.plan.selectedPlan, sha256: 'e'.repeat(64) } }
  ]) {
    const changed = await auth.pinned('altered.json', { ...auth.plan, ...delta })
    await t.exception(bootstrapEmptyLegacyOutboxJournal({ ...auth.args, authorizationPath: changed.path, authorizationSha256: changed.sha256 }), /mismatch/)
    t.absent(authority.get(f.key))
  }
  const core = f.store.get({ name: f.mode.name })
  await core.ready()
  await core.setUserData(LEDGER, Buffer.from('1'))
  await t.exception(bootstrapEmptyLegacyOutboxJournal(auth.args), /not pristine empty/)
  t.absent(authority.get(f.key))
})

test('outbox offline bootstrap refuses nonregular or oversized pinned files without waiting for writers', async t => {
  const f = await fixture(t, modes[0], false)
  const authority = f.makeAuthority(true)
  const auth = await bootstrapAuthorization(t, f, authority)
  const fifo = auth.args.authorizationPath + '.fifo'
  execFileSync('mkfifo', [fifo])
  // A bounded child proves that a FIFO cannot block before the fstat guard.
  const moduleUrl = new URL('../../packages/services/builtin/outboxlog/hypercore-journal.js', import.meta.url).href
  const script = `import { bootstrapEmptyLegacyOutboxJournal as boot } from ${JSON.stringify(moduleUrl)}; try { await boot({authorizationPath:process.argv[1],authorizationSha256:'0'.repeat(64)}) } catch (error) { if (/file invalid/.test(error.message)) process.exit(0); throw error } process.exit(1)`
  t.is(execFileSync(process.execPath, ['--input-type=module', '-e', script, fifo], { timeout: 3000 }).byteLength, 0)
  const large = auth.args.authorizationPath + '.large'
  await writeFile(large, Buffer.alloc(4 * 1024 * 1024 + 1), { mode: 0o600 })
  await t.exception(bootstrapEmptyLegacyOutboxJournal({ ...auth.args, authorizationPath: large }), /file invalid/)
  t.absent(authority.get(f.key))
})

for (const mode of modes) {
  test(`outbox recovery: ${mode.name} cold reopen preserves owned debt beside unknown pins`, async t => {
    const f = await fixture(t, mode)
    f.journal.appendSync(entry(1))
    await f.journal.flush()
    const debt = f.journal.storageController.consumedBytes
    await f.journal.close()
    await f.store.close()
    const store = await f.makeStore()
    const authority = f.makeAuthority(true)
    const unknown = [authority.get(DRIVE), authority.get(CORE)]
    const journal = await mode.open({ store, storageAdmission: authority, maxJournalStorageBytes: BOUND })
    t.alike(journal.loadSync(), [entry(1)])
    t.ok(journal.storageController.consumedBytes >= debt)
    t.is(authority.get(f.key).recovery, true)
    t.is(authority.get(f.key).boundBytes, BOUND)
    t.alike([authority.get(DRIVE), authority.get(CORE)], unknown)
    t.is(authority.reserve('core:' + 'd'.repeat(64), BOUND).reason, 'storage-commitment-unknown')
    journal.appendSync(entry(2))
    await journal.flush()
    await journal.close()
    await store.close()
    const thirdStore = await f.makeStore()
    const thirdAuthority = f.makeAuthority(true)
    const third = await mode.open({ store: thirdStore, storageAdmission: thirdAuthority, maxJournalStorageBytes: BOUND })
    t.alike(third.loadSync(), [entry(1), entry(2)], 'accepted operations survive a second real Corestore close/reopen')
    t.is(thirdAuthority.snapshot().records.filter(r => r.kind === 'outboxlog').length, 1)
    await t.exception(mode.open({ store: thirdStore, storageAdmission: thirdAuthority, maxJournalStorageBytes: BOUND }), /handoff unavailable/)
    t.ok(thirdAuthority.validateOwnedHandoff(third.storageController.ownershipHandoff, f.key), 'duplicate open cannot release the real owner')
    thirdAuthority.closeMutations('test-stop')
    t.exception(() => third.appendSync(entry(3)), /mutation blocked/)
    await third.close()
  })
}

test('outbox recovery: missing commitment never converts a legacy empty core into authorized recovery', async t => {
  const f = await fixture(t)
  await f.journal.close()
  const core = f.store.get({ name: f.mode.name })
  await core.ready()
  await core.setUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY, null)
  const authority = f.makeAuthority(true)
  await t.exception(f.mode.open({ store: f.store, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /storage-commitment-unknown/)
  t.absent(authority.get(f.key))
  t.absent(await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY))
})

test('outbox recovery: store namespace proof is required even for a writable core with matching userdata', async t => {
  const f = await fixture(t)
  const core = f.journal.core
  await f.journal.close()
  const raw = await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY)
  const authority = f.makeAuthority(true)
  await t.exception(f.mode.open({ core, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /storage-commitment-unknown/)
  const wrongStore = f.store.namespace('different-service')
  await t.exception(f.mode.open({ store: wrongStore, core, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /named owner mismatch/)
  await wrongStore.close()
  t.absent(authority.get(f.key))
  t.alike(await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY), raw)
})

test('outbox recovery: corrupt or mismatched durable commitment refuses before adoption or userdata writes', async t => {
  const f = await fixture(t)
  await f.journal.close()
  const core = f.journal.core
  const original = Buffer.from(await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY))
  const record = JSON.parse(original)
  const variants = [
    Buffer.from('{'), Buffer.alloc(16385, 32),
    ...[
      { version: 2 }, { coreKey: 'f'.repeat(64) }, { name: 'wrong-name' },
      { authorityKey: 'outboxlog:other' }, { mode: 'hypercore-outboxes' },
      { coreNamePrefix: 'other/' }, { boundBytes: BOUND + 1 },
      { consumedBytes: -1 }, { consumedBytes: BOUND + 1 },
      { consumedBytes: record.consumedBytes - 1 }, { extra: true }
    ].map(delta => Buffer.from(JSON.stringify({ ...record, ...delta })))
  ]
  for (const corrupt of variants) {
    await core.setUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY, corrupt)
    const authority = f.makeAuthority(true)
    await t.exception(f.mode.open({ store: f.store, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /commitment/)
    t.absent(authority.get(f.key))
    t.alike(await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY), corrupt)
  }
  await core.setUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY, original)
  await t.exception(f.mode.open({ store: f.store, storageAdmission: f.makeAuthority(true), maxJournalStorageBytes: BOUND * 2 }), /commitment/)
})

test('outbox recovery: valid JSON with bad operation shape or sequence is refused without blessing a core', async t => {
  for (const corrupt of [null, { ...entry(1), version: 2 }, entry(2), { ...entry(1), kind: 'unknown' }]) {
    const f = await fixture(t)
    await f.journal.close()
    const core = f.journal.core
    await core.append(Buffer.from(JSON.stringify(corrupt)))
    const prior = await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY)
    const authority = f.makeAuthority(true)
    await t.exception(f.mode.open({ store: f.store, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /corrupt operation or sequence/)
    t.absent(authority.get(f.key))
    t.alike(await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY), prior)
  }
})

test('outbox recovery: missing local partition block cannot wait for peers or acquire ownership', async t => {
  const f = await fixture(t, modes[1])
  f.journal.appendSync(entry(1))
  await f.journal.flush()
  const partition = [...f.journal._outboxes.values()][0].core
  await f.journal.close()
  await partition.clear(0, 1)
  const authority = f.makeAuthority(true)
  await t.exception(f.mode.open({ store: f.store, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /local block missing/)
  t.absent(authority.get(f.key))
})

test('outbox recovery measures an over-bound journal before decoding its history', async t => {
  const f = await fixture(t)
  f.journal.appendSync(entry(1))
  await f.journal.flush()
  await f.journal.close()
  const core = f.journal.core
  const info = core.info.bind(core)
  const get = core.get.bind(core)
  let reads = 0
  core.info = async () => ({ storage: { allocated: BOUND + 1 } })
  core.get = async (...args) => { reads++; return get(...args) }
  const authority = f.makeAuthority(true)
  await t.exception(f.mode.open({ store: f.store, core, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /exceeds aggregate bound/)
  t.is(reads, 0)
  t.absent(authority.get(f.key))
  core.info = info
  core.get = get
})

test('outbox recovery refuses duplicate global partition sequence before adoption', async t => {
  const f = await fixture(t, modes[1])
  f.journal.appendSync(entry(1))
  await f.journal.flush()
  const partition = [...f.journal._outboxes.values()][0].core
  await f.journal.close()
  await partition.append(Buffer.from(JSON.stringify(entry(1))))
  const authority = f.makeAuthority(true)
  await t.exception(f.mode.open({ store: f.store, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /corrupt operation or sequence/)
  t.absent(authority.get(f.key))
})

test('outbox recovery: interrupted two-record ledger persistence is detectable on cold initialization', async t => {
  const f = await fixture(t)
  const core = f.journal.core
  const setUserData = core.setUserData.bind(core)
  core.setUserData = async (key, value) => {
    if (key === OUTBOXLOG_STORAGE_COMMITMENT_KEY) throw new Error('injected durable commitment failure')
    return setUserData(key, value)
  }
  f.journal.appendSync(entry(1))
  await t.exception(f.journal.flush(), /injected durable commitment failure/)
  t.is(f.authority.fatalReason, 'outboxlog-storage-ledger-persistence-failed')
  t.is(core.length, 0, 'append was never dispatched after failed debt persistence')
  t.ok(f.authority.get(f.key), 'conservative commitment remains charged')
  core.setUserData = setUserData
  await f.journal.close()
  const authority = f.makeAuthority(true)
  await t.exception(f.mode.open({ store: f.store, storageAdmission: authority, maxJournalStorageBytes: BOUND }), /incomplete ledger/)
  t.absent(authority.get(f.key))
  t.ok(Number((await core.getUserData(LEDGER)).toString()) > JSON.parse(await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY)).consumedBytes)
})
