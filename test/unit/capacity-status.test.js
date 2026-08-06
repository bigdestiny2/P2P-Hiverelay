import test from 'brittle'
import { buildCapacityStatus } from '../../packages/core/core/relay-node/capacity-status.js'

const GiB = 1024 ** 3
const TiB = 1024 * GiB
const NOW = 1_800_000_000_000

function authority (overrides = {}) {
  const snapshot = {
    recoveryReady: true,
    acceptingMutations: true,
    fatalReason: null,
    physicalEnforcement: { active: true },
    records: [],
    ...overrides
  }
  let committedBytes = 0
  let pendingBytes = 0
  let unknownCommitments = 0
  for (const record of snapshot.records) {
    const debt = Number.isSafeInteger(record?.boundBytes) && Number.isSafeInteger(record?.overheadBytes)
      ? record.boundBytes + record.overheadBytes
      : null
    if (record?.state === 'committed' && Number.isSafeInteger(debt)) committedBytes += debt
    else if (record?.state === 'reserved' && Number.isSafeInteger(debt)) pendingBytes += debt
    else unknownCommitments++
  }
  return {
    physicalEnforcementActive: snapshot.physicalEnforcement?.active === true,
    capacitySnapshot: () => ({
      recoveryReady: snapshot.recoveryReady,
      acceptingMutations: snapshot.acceptingMutations,
      fatalReason: snapshot.fatalReason,
      physicalEnforcementActive: snapshot.physicalEnforcement?.active === true,
      committedBytes,
      pendingBytes,
      unknownCommitments,
      valid: true
    }),
    snapshot: () => { throw new Error('public capacity status must not clone the ledger') }
  }
}

test('capacity status builds a conservative plan from measured state', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'seeder-standard', maxStorageBytes: 500 * GiB },
    disk: { totalBytes: TiB, freeBytes: 900 * GiB, checkedAt: NOW - 1000 },
    storage: { diskBytes: 100 * GiB, totalBytes: 101 * GiB, diskMeasuredAt: NOW - 2000, diskMeasurementComplete: true },
    storageAdmission: authority({
      records: [
        { state: 'committed', boundBytes: 20 * GiB, overheadBytes: 1 * GiB },
        { state: 'reserved', boundBytes: 10 * GiB, overheadBytes: 2 * GiB }
      ]
    }),
    now: NOW
  })

  t.is(status.profileId, 'seeder-standard')
  t.ok(status.operatorDeclared)
  t.is(status.plan.usage.actualUsageBytes, 101 * GiB)
  t.is(status.plan.usage.committedBytes, 21 * GiB)
  t.is(status.plan.usage.pendingBytes, 12 * GiB)
  t.is(status.enforcement.unknownCommitments, 0)
  t.ok(status.measurements.fresh)
  t.absent(status.plan.observedFreeAssumed)
  t.absent(status.advertisement.eligible)
  t.is(status.advertisement.bytes, 0)
  t.ok(status.advertisement.blockReasons.includes('network-advertisement-not-implemented'))
})

test('capacity status reports a plan but blocks advertisement without hard enforcement', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'edge-community', maxStorageBytes: 10 * GiB },
    disk: { totalBytes: TiB, freeBytes: 900 * GiB, checkedAt: NOW - 1000 },
    storage: { diskBytes: GiB, totalBytes: GiB, diskMeasuredAt: NOW - 2000, diskMeasurementComplete: true },
    storageAdmission: authority({
      physicalEnforcement: null
    }),
    now: NOW
  })

  t.ok(status.plan, 'operator can inspect the planning budget')
  t.absent(status.advertisement.eligible)
  t.is(status.advertisement.bytes, 0, 'untrusted planning headroom never becomes a network offer')
  t.ok(status.advertisement.blockReasons.includes('physical-enforcement-unavailable'))
})

test('capacity status refuses to calculate headroom over unknown commitment debt', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'edge-community', maxStorageBytes: 10 * GiB },
    disk: { totalBytes: TiB, freeBytes: 900 * GiB, checkedAt: NOW - 1000 },
    storage: { diskBytes: GiB, totalBytes: GiB, diskMeasuredAt: NOW - 2000, diskMeasurementComplete: true },
    storageAdmission: authority({
      records: [{ state: 'unknown-recovery', boundBytes: null, overheadBytes: 0 }]
    }),
    now: NOW
  })

  t.is(status.plan, null)
  t.ok(status.advertisement.blockReasons.includes('storage-commitment-unknown'))
})

test('capacity status stays side-effect free and fails closed on missing evidence', (t) => {
  let admissions = 0
  const status = buildCapacityStatus({
    config: { maxStorageBytes: 10 * GiB },
    disk: { totalBytes: TiB },
    storage: { diskBytes: null, totalBytes: 0 },
    storageAdmission: {
      admission () { admissions++; throw new Error('must not run') },
      snapshot () { throw new Error('snapshot unavailable') }
    }
  })

  t.is(admissions, 0, 'status never triggers a filesystem admission walk')
  t.is(status.plan, null)
  t.alike(status.advertisement.blockReasons, [
    'capacity-profile-unset',
    'capacity-measurement-unavailable',
    'storage-authority-unavailable',
    'storage-commitment-unknown',
    'physical-enforcement-unavailable',
    'network-advertisement-not-implemented'
  ])
  t.absent(status.advertisement.eligible)
})

test('capacity status keeps a stale plan visible but advertises zero bytes', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'seeder-standard', maxStorageBytes: 100 * GiB },
    disk: { totalBytes: TiB, freeBytes: 500 * GiB, checkedAt: NOW - 10 * 60 * 1000 },
    storage: { diskBytes: GiB, totalBytes: GiB, diskMeasuredAt: NOW - 1000, diskMeasurementComplete: true },
    storageAdmission: authority(),
    now: NOW
  })

  t.ok(status.plan, 'stale measurements remain inspectable as planning evidence')
  t.absent(status.measurements.fresh)
  t.absent(status.advertisement.eligible)
  t.is(status.advertisement.bytes, 0)
  t.ok(status.advertisement.blockReasons.includes('capacity-measurement-stale'))
})

test('capacity status rejects a fresh but incomplete storage traversal', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'edge-community', maxStorageBytes: 100 * GiB },
    disk: { totalBytes: TiB, freeBytes: 500 * GiB, checkedAt: NOW - 1000 },
    storage: {
      diskBytes: GiB,
      totalBytes: GiB,
      diskMeasuredAt: NOW - 1000,
      diskMeasurementComplete: false
    },
    storageAdmission: authority(),
    now: NOW
  })

  t.is(status.plan, null)
  t.absent(status.measurements.complete)
  t.ok(status.advertisement.blockReasons.includes('capacity-measurement-incomplete'))
})
