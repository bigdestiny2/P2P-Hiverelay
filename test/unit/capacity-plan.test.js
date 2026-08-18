import test from 'brittle'
import {
  CAPACITY_ENFORCED_POOL_ID,
  CAPACITY_PLAN_MODE,
  CAPACITY_POOL_IDS,
  CAPACITY_PROFILE_IDS,
  CAPACITY_PROFILES,
  CAPACITY_RESERVE_FLOOR_BYTES,
  isCapacityProfile,
  normalizeCapacityProfile,
  planBoundedCapacity,
  planCapacityBudget,
  planCapacityCeiling
} from '../../packages/core/config/capacity-plan.js'

const GiB = 1024 * 1024 * 1024
const TiB = 1024 * GiB
const TB = 1_000_000_000_000

function sumPools (plan) {
  return CAPACITY_POOL_IDS.reduce((total, id) => total + plan.poolBytes[id], 0)
}

test('capacity plan exposes the stable profile and pool vocabulary', (t) => {
  t.alike(CAPACITY_PROFILE_IDS, [
    'edge-community',
    'seeder-standard',
    'seeder-regional',
    'services-s2',
    'archive-storage'
  ])
  t.alike(CAPACITY_POOL_IDS, [
    'durable',
    'serviceControl',
    'repair',
    'cache',
    'burst'
  ])
  for (const id of CAPACITY_PROFILE_IDS) {
    const profile = CAPACITY_PROFILES[id]
    const total = CAPACITY_POOL_IDS.reduce((sum, pool) => sum + profile.poolWeights[pool], 0)
    t.is(total, profile.totalWeight, id + ' weights have one denominator')
    t.ok(total > 0, id + ' assigns capacity')
    t.ok(isCapacityProfile(id), id + ' validates')
  }
  t.absent(isCapacityProfile('SEEDER-STANDARD'))
  t.is(normalizeCapacityProfile('  SEEDER-STANDARD '), 'seeder-standard')
  t.exception.all(() => normalizeCapacityProfile(null), /must be a string/)
  t.exception.all(() => normalizeCapacityProfile('not-a-profile'), /unknown capacity profile/)
})

test('capacity plan rejects invalid profile and byte inputs', (t) => {
  t.exception.all(() => planBoundedCapacity(), /input is required/)
  t.exception.all(() => planBoundedCapacity({
    profileId: 'not-a-profile',
    observedUsableBytes: TiB
  }), /unknown capacity profile/)

  const base = { profileId: 'edge-community', observedUsableBytes: TiB }
  for (const observedUsableBytes of [undefined, null, '1024', -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    t.exception.all(() => planBoundedCapacity({ ...base, observedUsableBytes }), /observedUsableBytes/)
  }
  for (const [field, value] of [
    ['observedFreeBytes', null],
    ['observedFreeBytes', -1],
    ['operatorCapBytes', null],
    ['operatorCapBytes', -1],
    ['actualUsageBytes', null],
    ['actualUsageBytes', NaN],
    ['committedBytes', 0.5],
    ['pendingBytes', '1'],
    ['untrackedDebtBytes', Infinity]
  ]) {
    t.exception.all(() => planBoundedCapacity({ ...base, [field]: value }), new RegExp(field))
  }
  t.exception.all(() => planBoundedCapacity({
    ...base,
    actualUsageBytes: Number.MAX_SAFE_INTEGER,
    committedBytes: 1
  }), /conservative demand exceeds/)
  t.exception.all(() => planBoundedCapacity({
    ...base,
    observedFreeBytes: TiB + 1
  }), /observedFreeBytes cannot exceed/)
})

test('capacity plan clamps the reserve on disks below the 32 GiB floor', (t) => {
  const plan = planBoundedCapacity({
    profileId: 'edge-community',
    observedUsableBytes: 16 * GiB
  })

  t.is(CAPACITY_RESERVE_FLOOR_BYTES, 32 * GiB)
  t.is(plan.physicalReserveBytes, 16 * GiB, 'reserve cannot exceed the disk')
  t.is(plan.postReserveBytes, 0)
  t.is(plan.managedCapacityBytes, 0, 'managed capacity never becomes negative')
  t.is(sumPools(plan), 0)
  t.is(plan.availableBytes, 0)
  t.ok(plan.atCapacity)
  t.ok(plan.advertisingBlocked)
})

test('capacity pool allocation is integral, exact, and deterministic', (t) => {
  const plan = planBoundedCapacity({
    profileId: 'edge-community',
    observedUsableBytes: TiB,
    operatorCapBytes: 101
  })

  t.is(plan.mode, CAPACITY_PLAN_MODE)
  t.is(plan.managedCapacityBytes, 101)
  t.alike(plan.poolBytes, {
    durable: 36,
    serviceControl: 10,
    repair: 10,
    cache: 30,
    burst: 15
  })
  t.is(sumPools(plan), plan.managedCapacityBytes, 'every byte is assigned exactly once')
})

test('capacity plan takes the minimum of post-reserve hardware and the operator cap', (t) => {
  const capped = planBoundedCapacity({
    profileId: 'seeder-standard',
    observedUsableBytes: TiB,
    operatorCapBytes: 250 * GiB
  })
  t.is(capped.operatorCapBytes, 250 * GiB)
  t.is(capped.managedCapacityBytes, 250 * GiB)
  t.ok(capped.operatorCapApplied)

  const hardwareBound = planBoundedCapacity({
    profileId: 'seeder-standard',
    observedUsableBytes: TiB,
    operatorCapBytes: TiB
  })
  t.is(hardwareBound.operatorCapBytes, TiB, 'operator designation is preserved byte-for-byte')
  t.is(hardwareBound.managedCapacityBytes, hardwareBound.postReserveBytes)
  t.absent(hardwareBound.operatorCapApplied)

  const zero = planBoundedCapacity({
    profileId: 'seeder-standard',
    observedUsableBytes: TiB,
    operatorCapBytes: 0
  })
  t.is(zero.managedCapacityBytes, 0, 'an explicit zero cap is never raised')
})

test('capacity plan charges all debt conservatively and fails closed when overcommitted', (t) => {
  const plan = planBoundedCapacity({
    profileId: 'seeder-standard',
    observedUsableBytes: TiB,
    operatorCapBytes: 1000,
    actualUsageBytes: 400,
    committedBytes: 300,
    pendingBytes: 200,
    untrackedDebtBytes: 250
  })

  t.alike(plan.usage, {
    actualUsageBytes: 400,
    committedBytes: 300,
    pendingBytes: 200,
    untrackedDebtBytes: 250,
    futureDebtBytes: 750,
    conservativeDemandBytes: 1150
  })
  t.is(plan.availableBytes, 0)
  t.is(plan.advertisableBytes, 0)
  t.is(plan.overcommittedBytes, 150)
  t.ok(plan.atCapacity)
  t.ok(plan.advertisingBlocked)
})

test('advertisable bytes are bounded by worst-case durable-pool occupancy', (t) => {
  const plan = planBoundedCapacity({
    profileId: 'seeder-standard',
    observedUsableBytes: TiB,
    operatorCapBytes: 1000,
    actualUsageBytes: 40,
    committedBytes: 30,
    pendingBytes: 20,
    untrackedDebtBytes: 10
  })

  t.is(plan.availableBytes, 900, 'global managed headroom subtracts every debt source')
  t.is(plan.poolBytes.durable, 600)
  t.is(plan.advertisableBytes, 500, 'all existing debt is conservatively charged to durable')
})

test('live planning cannot claim free space consumed by co-resident apps', (t) => {
  const plan = planBoundedCapacity({
    profileId: 'edge-community',
    observedUsableBytes: TiB,
    observedFreeBytes: 170 * GiB,
    operatorCapBytes: 100 * GiB,
    actualUsageBytes: 10 * GiB
  })

  t.absent(plan.observedFreeAssumed)
  t.is(plan.logicalAvailableBytes, 90 * GiB, 'operator budget alone has 90 GiB left')
  t.is(
    plan.physicalHeadroomBytes,
    170 * GiB - plan.physicalReserveBytes,
    'whole-filesystem free space preserves the reserve for Umbrel and other apps'
  )
  t.is(plan.availableBytes, plan.physicalHeadroomBytes, 'physical headroom narrows logical headroom')

  const encumbered = planBoundedCapacity({
    profileId: 'edge-community',
    observedUsableBytes: TiB,
    observedFreeBytes: 170 * GiB,
    operatorCapBytes: 100 * GiB,
    committedBytes: 20 * GiB
  })
  t.is(encumbered.physicalHeadroomBytes, 0, 'future commitment debt consumes shared-disk free space before it can be offered')
  t.is(encumbered.availableBytes, 0)

  const offline = planBoundedCapacity({
    profileId: 'edge-community',
    observedUsableBytes: TiB,
    operatorCapBytes: 100 * GiB
  })
  t.ok(offline.observedFreeAssumed, 'offline hardware plans explicitly mark the free-space assumption')
})

test('services-s2 matches the reference payload-root budget', (t) => {
  const plan = planBoundedCapacity({
    profileId: 'services-s2',
    observedUsableBytes: 15.36 * TB
  })

  t.is(plan.physicalReserveBytes, 2.304 * TB, '15% of two 7.68 TB payload roots')
  t.is(plan.managedCapacityBytes, 13.056 * TB)
  t.alike(plan.poolBytes, {
    durable: 8 * TB,
    serviceControl: 0,
    repair: 2 * TB,
    cache: 1.5 * TB,
    burst: 1.556 * TB
  })
  t.is(sumPools(plan), plan.managedCapacityBytes)
})

test('the enforcement ceiling is the durable pool and can only narrow', (t) => {
  t.is(CAPACITY_ENFORCED_POOL_ID, 'durable', 'only the pool the planner already charges is enforceable')

  for (const profileId of CAPACITY_PROFILE_IDS) {
    for (const observedUsableBytes of [0, 32 * GiB, 200 * GiB, TiB, 40 * TiB]) {
      for (const operatorCapBytes of [undefined, 1, 10 * GiB, 500 * GiB, 100 * TiB]) {
        const ceiling = planCapacityCeiling({ profileId, observedUsableBytes, operatorCapBytes })
        t.ok(Number.isSafeInteger(ceiling.ceilingBytes) && ceiling.ceilingBytes >= 0)
        if (operatorCapBytes !== undefined) {
          t.ok(ceiling.ceilingBytes <= operatorCapBytes, 'a profile never raises the operator cap')
        }
        t.ok(ceiling.ceilingBytes <= observedUsableBytes, 'a profile never exceeds the measured filesystem')

        const plan = planBoundedCapacity({ profileId, observedUsableBytes, operatorCapBytes })
        t.is(ceiling.ceilingBytes, plan.poolBytes.durable,
          'enforcement and the published plan agree byte-for-byte')
      }
    }
  }
})

test('a filesystem at or below the planning reserve enforces a zero ceiling', (t) => {
  const ceiling = planCapacityCeiling({
    profileId: 'edge-community',
    observedUsableBytes: CAPACITY_RESERVE_FLOOR_BYTES
  })
  t.is(ceiling.managedCapacityBytes, 0)
  t.is(ceiling.ceilingBytes, 0, 'small boot media may route and index but holds no durable commitment')
  t.is(ceiling.source, 'capacity-profile:edge-community:durable')
})

test('the shipped Umbrel default narrows a 10 GiB cap to its durable share', (t) => {
  // umbrel-app/docker-compose.yml: HIVERELAY_MAX_STORAGE=10GB + edge-community.
  const ceiling = planCapacityCeiling({
    profileId: 'edge-community',
    observedUsableBytes: 4 * TB,
    operatorCapBytes: 10 * 1_000_000_000
  })
  t.is(ceiling.managedCapacityBytes, 10 * 1_000_000_000, 'the operator cap still bounds managed capacity')
  t.is(ceiling.ceilingBytes, 3_500_000_000, '35% of managed capacity is durable payload')
})

test('capacity budget rejects unusable inputs instead of guessing a ceiling', (t) => {
  t.exception.all(() => planCapacityBudget({ profileId: 'nope', observedUsableBytes: TiB }),
    /unknown capacity profile/)
  for (const observedUsableBytes of [undefined, null, -1, 1.5, Infinity, '1024']) {
    t.exception.all(() => planCapacityBudget({ profileId: 'edge-community', observedUsableBytes }),
      /observedUsableBytes/)
  }
  t.exception.all(() => planCapacityBudget({
    profileId: 'edge-community',
    observedUsableBytes: TiB,
    operatorCapBytes: -1
  }), /operatorCapBytes/)
  t.exception.all(() => planCapacityCeiling(null), /input is required/)
})
