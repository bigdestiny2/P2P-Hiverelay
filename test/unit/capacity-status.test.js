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
      capacityProfileId: snapshot.capacityProfileId ?? null,
      capacityCeilingBytes: snapshot.capacityCeilingBytes ?? null,
      capacityCeilingSource: snapshot.capacityCeilingSource ?? null,
      capacityCeilingReason: snapshot.capacityCeilingReason ?? null,
      operatorCapBytes: snapshot.operatorCapBytes ?? null,
      effectiveCapBytes: snapshot.effectiveCapBytes ?? null,
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

test('capacity status reports the enforced ceiling alongside the planned budget', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'edge-community', maxStorageBytes: 10 * GiB },
    disk: { totalBytes: TiB, freeBytes: 900 * GiB, checkedAt: NOW - 1000 },
    storage: { diskBytes: GiB, totalBytes: GiB, diskMeasuredAt: NOW - 2000, diskMeasurementComplete: true },
    storageAdmission: authority({
      capacityProfileId: 'edge-community',
      capacityCeilingBytes: Math.floor(10 * GiB * 0.35),
      capacityCeilingSource: 'capacity-profile:edge-community:durable',
      operatorCapBytes: 10 * GiB,
      effectiveCapBytes: Math.floor(10 * GiB * 0.35)
    }),
    now: NOW
  })

  t.is(status.enforcement.operatorCapBytes, 10 * GiB)
  t.is(status.enforcement.capacityCeilingBytes, Math.floor(10 * GiB * 0.35))
  t.is(status.enforcement.effectiveCapBytes, Math.floor(10 * GiB * 0.35))
  t.is(status.enforcement.capacityCeilingSource, 'capacity-profile:edge-community:durable')
  t.ok(status.enforcement.capacityCeilingApplied, 'the operator can see the ceiling is binding')
  t.is(status.enforcement.capacityCeilingBytes, status.plan.poolBytes.durable,
    'the enforced ceiling and the published durable pool are the same number')
  t.absent(status.advertisement.blockReasons.includes('capacity-profile-ceiling-unresolved'))
})

test('capacity status flags a declared profile whose ceiling could not be resolved', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'edge-community', maxStorageBytes: 10 * GiB },
    disk: { totalBytes: TiB, freeBytes: 900 * GiB, checkedAt: NOW - 1000 },
    storage: { diskBytes: GiB, totalBytes: GiB, diskMeasuredAt: NOW - 2000, diskMeasurementComplete: true },
    storageAdmission: authority({ capacityProfileId: 'edge-community' }),
    now: NOW
  })

  t.is(status.enforcement.capacityCeilingBytes, null)
  t.absent(status.enforcement.capacityCeilingApplied)
  t.ok(status.advertisement.blockReasons.includes('capacity-profile-ceiling-unresolved'))
})

test('a slow archive walk widens the freshness window instead of being permanently stale', (t) => {
  // A 40 TB pool takes ~12 minutes to walk. The sample is timestamped at the
  // START of the walk, so under the fixed 5-minute budget this hardware could
  // never once report a fresh measurement.
  const walkMs = 12 * 60 * 1000
  const archive = {
    config: { capacityProfile: 'archive-storage', maxStorageBytes: 30 * TiB },
    disk: { totalBytes: 40 * TiB, freeBytes: 20 * TiB, checkedAt: NOW - 1000 },
    storage: {
      diskBytes: 10 * TiB,
      totalBytes: 10 * TiB,
      diskMeasuredAt: NOW - walkMs - 30_000,
      diskMeasureDurationMs: walkMs,
      diskIntervalMs: 60_000,
      diskMeasurementComplete: true
    },
    storageAdmission: authority(),
    now: NOW
  }

  const status = buildCapacityStatus(archive)
  t.ok(status.measurements.fresh, 'a sample one walk-cycle old is as fresh as this hardware can be')
  t.ok(status.measurements.derivedWindow)
  t.is(status.measurements.durationMs, walkMs)
  t.is(status.measurements.maxAgeMs, 2 * walkMs + 60_000)
  t.is(status.measurements.floorMs, 5 * 60 * 1000, 'the strict floor is still reported')
  t.absent(status.advertisement.blockReasons.includes('capacity-measurement-stale'))

  const older = buildCapacityStatus({
    ...archive,
    storage: { ...archive.storage, diskMeasuredAt: NOW - 3 * walkMs }
  })
  t.absent(older.measurements.fresh, 'the widened window is still a window')
  t.ok(older.advertisement.blockReasons.includes('capacity-measurement-stale'))
})

test('a fast host keeps the strict freshness budget', (t) => {
  const status = buildCapacityStatus({
    config: { capacityProfile: 'seeder-standard', maxStorageBytes: 100 * GiB },
    disk: { totalBytes: TiB, freeBytes: 500 * GiB, checkedAt: NOW - 1000 },
    storage: {
      diskBytes: GiB,
      totalBytes: GiB,
      diskMeasuredAt: NOW - 6 * 60 * 1000,
      diskMeasureDurationMs: 120,
      diskIntervalMs: 60_000,
      diskMeasurementComplete: true
    },
    storageAdmission: authority(),
    now: NOW
  })

  t.is(status.measurements.maxAgeMs, 5 * 60 * 1000, 'a sub-second walk earns no extra allowance')
  t.absent(status.measurements.derivedWindow)
  t.absent(status.measurements.fresh)
  t.ok(status.advertisement.blockReasons.includes('capacity-measurement-stale'))
})

test('a storage root too slow to measure never buys an unbounded freshness window', (t) => {
  const walkMs = 90 * 60 * 1000
  const status = buildCapacityStatus({
    config: { capacityProfile: 'archive-storage', maxStorageBytes: 30 * TiB },
    disk: { totalBytes: 40 * TiB, freeBytes: 20 * TiB, checkedAt: NOW - 1000 },
    storage: {
      diskBytes: TiB,
      totalBytes: TiB,
      diskMeasuredAt: NOW - walkMs,
      diskMeasureDurationMs: walkMs,
      diskIntervalMs: 60_000,
      diskMeasurementComplete: true
    },
    storageAdmission: authority(),
    now: NOW
  })

  t.is(status.measurements.maxAgeMs, 60 * 60 * 1000, 'capped at the hard ceiling')
  t.ok(status.measurements.windowCapped)
  t.absent(status.measurements.fresh, 'an unmeasurable root stays fail-closed')
  t.ok(status.advertisement.blockReasons.includes('capacity-measurement-stale'))
})

test('the statfs sample keeps the strict floor even on slow-walking hardware', (t) => {
  const walkMs = 12 * 60 * 1000
  const status = buildCapacityStatus({
    config: { capacityProfile: 'archive-storage', maxStorageBytes: 30 * TiB },
    // A 20-minute-old disk sample is stale no matter how slow the tree walk is:
    // statfs costs the same on every host.
    disk: { totalBytes: 40 * TiB, freeBytes: 20 * TiB, checkedAt: NOW - 20 * 60 * 1000 },
    storage: {
      diskBytes: TiB,
      totalBytes: TiB,
      diskMeasuredAt: NOW - walkMs,
      diskMeasureDurationMs: walkMs,
      diskIntervalMs: 60_000,
      diskMeasurementComplete: true
    },
    storageAdmission: authority(),
    now: NOW
  })

  t.absent(status.measurements.fresh)
  t.ok(status.advertisement.blockReasons.includes('capacity-measurement-stale'))
})
