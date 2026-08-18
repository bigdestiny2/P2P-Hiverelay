/**
 * Capacity profiles are planning inputs, not storage enforcement.
 *
 * The existing storage admission authority remains the runtime source of
 * truth. This module turns a measured, post-parity filesystem size into a
 * bounded budget that management/status surfaces and future schedulers can
 * reason about without treating every byte on a host as available to
 * HiveRelay.
 */

export const CAPACITY_PLAN_SCHEMA_VERSION = 1
export const CAPACITY_PLAN_MODE = 'planning-only'
export const CAPACITY_RESERVE_BASIS_POINTS = 1500
export const CAPACITY_RESERVE_FLOOR_BYTES = 32 * 1024 * 1024 * 1024

// The one pool an operator-declared profile is allowed to enforce today.
// Until commitments carry a durable poolId (roadmap R1/R2) there is no
// attribution that could charge a byte to cache, repair, or service state, so
// every existing byte is charged to `durable` by both the planner and the
// admission ceiling. Enforcing the same pool the planner already reports keeps
// status and enforcement arithmetically identical.
export const CAPACITY_ENFORCED_POOL_ID = 'durable'

export const CAPACITY_POOL_IDS = Object.freeze([
  'durable',
  'serviceControl',
  'repair',
  'cache',
  'burst'
])

const PROFILE_WEIGHTS = {
  'edge-community': [35, 10, 10, 30, 15],
  'seeder-standard': [60, 10, 15, 15, 0],
  'seeder-regional': [60, 10, 15, 15, 0],

  // S2 keeps service state on its separate mirrored state volume. These
  // weights describe the two independent 7.68 TB payload roots. At the S2
  // reference size they yield 8 TB durable, 2 TB repair, 1.5 TB cache, and
  // 1.556 TB burst/slack after the physical reserve.
  'services-s2': [8000, 0, 2000, 1500, 1556],
  'archive-storage': [70, 5, 20, 5, 0]
}

function profileFromWeights (id, weights) {
  const pools = {}
  let totalWeight = 0
  for (let i = 0; i < CAPACITY_POOL_IDS.length; i++) {
    const weight = weights[i]
    pools[CAPACITY_POOL_IDS[i]] = weight
    totalWeight += weight
  }
  return Object.freeze({
    id,
    totalWeight,
    poolWeights: Object.freeze(pools)
  })
}

export const CAPACITY_PROFILE_IDS = Object.freeze(Object.keys(PROFILE_WEIGHTS))

export const CAPACITY_PROFILES = Object.freeze(Object.fromEntries(
  CAPACITY_PROFILE_IDS.map(id => [id, profileFromWeights(id, PROFILE_WEIGHTS[id])])
))

export function isCapacityProfile (value) {
  return typeof value === 'string' &&
    Object.prototype.hasOwnProperty.call(CAPACITY_PROFILES, value)
}

export function normalizeCapacityProfile (value) {
  if (typeof value !== 'string') throw new TypeError('capacity profile must be a string')
  const normalized = value.trim().toLowerCase()
  if (!isCapacityProfile(normalized)) {
    throw new RangeError('unknown capacity profile: ' + String(value))
  }
  return normalized
}

function byteCount (name, value, { optional = false } = {}) {
  if (optional && value === undefined) return null
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(name + ' must be a finite, non-negative safe integer')
  }
  return value
}

function safeSum (name, values) {
  let total = 0n
  for (const value of values) total += BigInt(value)
  if (total > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(name + ' exceeds the safe integer range')
  }
  return Number(total)
}

function reserveBytes (observedUsableBytes) {
  if (observedUsableBytes === 0) return 0
  const proportional = Number(
    (BigInt(observedUsableBytes) * BigInt(CAPACITY_RESERVE_BASIS_POINTS)) / 10_000n
  )
  return Math.min(
    observedUsableBytes,
    Math.max(CAPACITY_RESERVE_FLOOR_BYTES, proportional)
  )
}

function allocatePools (managedCapacityBytes, profile) {
  const capacity = BigInt(managedCapacityBytes)
  const denominator = BigInt(profile.totalWeight)
  const allocations = []
  let allocated = 0n

  for (let i = 0; i < CAPACITY_POOL_IDS.length; i++) {
    const id = CAPACITY_POOL_IDS[i]
    const weight = BigInt(profile.poolWeights[id])
    const numerator = capacity * weight
    const bytes = numerator / denominator
    allocations.push({ id, index: i, bytes, remainder: numerator % denominator })
    allocated += bytes
  }

  // Largest-remainder allocation keeps every pool integral while assigning
  // every managed byte exactly once. Declaration order is the stable tie-break.
  const remainderBytes = Number(capacity - allocated)
  allocations.sort((left, right) => {
    if (left.remainder === right.remainder) return left.index - right.index
    return left.remainder > right.remainder ? -1 : 1
  })
  for (let i = 0; i < remainderBytes; i++) allocations[i].bytes += 1n
  allocations.sort((left, right) => left.index - right.index)

  return Object.freeze(Object.fromEntries(
    allocations.map(({ id, bytes }) => [id, Number(bytes)])
  ))
}

/**
 * Reduce a measured filesystem plus an optional operator cap to the bounded
 * pool budget both the planner and the admission ceiling must agree on.
 *
 * This is deliberately free of usage, commitment, and free-space terms: those
 * change on every sample, while the budget is a stable property of the declared
 * hardware role. Keeping the two apart lets the runtime derive an enforcement
 * ceiling from one cheap `statfs` field without waiting for a storage tree walk.
 */
export function planCapacityBudget (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('capacity budget input is required')
  }
  const profileId = normalizeCapacityProfile(input.profileId)
  const profile = CAPACITY_PROFILES[profileId]
  const observedUsableBytes = byteCount('observedUsableBytes', input.observedUsableBytes)
  const operatorCapBytes = byteCount('operatorCapBytes', input.operatorCapBytes, { optional: true })

  const physicalReserveBytes = reserveBytes(observedUsableBytes)
  const postReserveBytes = observedUsableBytes - physicalReserveBytes
  const managedCapacityBytes = operatorCapBytes === null
    ? postReserveBytes
    : Math.min(postReserveBytes, operatorCapBytes)

  return {
    profileId,
    observedUsableBytes,
    physicalReserveBytes,
    postReserveBytes,
    operatorCapBytes,
    operatorCapApplied: operatorCapBytes !== null && operatorCapBytes < postReserveBytes,
    managedCapacityBytes,
    poolBytes: allocatePools(managedCapacityBytes, profile)
  }
}

/**
 * Derive the storage ceiling an operator-declared profile imposes.
 *
 * The result is only ever a narrowing of `operatorCapBytes`: the managed
 * capacity is already `min(post-reserve, operator cap)` and the enforced pool is
 * a fraction of that, so the ceiling cannot exceed the operator's own value. A
 * ceiling of zero is a valid answer — a payload filesystem at or below the
 * planning reserve supports routing and metadata but no durable commitments.
 *
 * Throws for an unknown profile or an unmeasurable filesystem. Callers must
 * treat a throw as fail-closed, never as "no ceiling".
 */
export function planCapacityCeiling (input) {
  const budget = planCapacityBudget(input)
  return Object.freeze({
    profileId: budget.profileId,
    poolId: CAPACITY_ENFORCED_POOL_ID,
    source: `capacity-profile:${budget.profileId}:${CAPACITY_ENFORCED_POOL_ID}`,
    observedUsableBytes: budget.observedUsableBytes,
    physicalReserveBytes: budget.physicalReserveBytes,
    managedCapacityBytes: budget.managedCapacityBytes,
    operatorCapBytes: budget.operatorCapBytes,
    ceilingBytes: budget.poolBytes[CAPACITY_ENFORCED_POOL_ID]
  })
}

/**
 * Build a conservative bounded-capacity plan.
 *
 * `observedUsableBytes` is the measured post-parity size of the exact
 * filesystem that will hold the planned pools. `observedFreeBytes` should be
 * supplied for a live/shared filesystem so unrelated workloads cannot be
 * mistaken for HiveRelay headroom. It defaults to the full filesystem only
 * for offline hardware planning. `operatorCapBytes`, when supplied, is an
 * upper bound and is never raised to match the hardware.
 *
 * Actual usage, durable commitments, pending reservations, and untracked debt
 * are deliberately added together. Some deployments can prove that actual
 * bytes are contained within a commitment, but the planning layer does not
 * assume that proof. Double accounting here is safer than advertising the same
 * byte twice. Runtime admission must still be decided by the storage admission
 * authority and a fresh filesystem sample.
 */
export function planBoundedCapacity (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('capacity plan input is required')
  }

  const budget = planCapacityBudget(input)
  const {
    profileId,
    observedUsableBytes,
    physicalReserveBytes,
    postReserveBytes,
    operatorCapBytes,
    managedCapacityBytes,
    poolBytes
  } = budget

  const suppliedFreeBytes = byteCount('observedFreeBytes', input.observedFreeBytes, { optional: true })
  if (suppliedFreeBytes !== null && suppliedFreeBytes > observedUsableBytes) {
    throw new RangeError('observedFreeBytes cannot exceed observedUsableBytes')
  }
  const observedFreeBytes = suppliedFreeBytes === null
    ? observedUsableBytes
    : suppliedFreeBytes
  const actualUsageBytes = byteCount(
    'actualUsageBytes',
    input.actualUsageBytes === undefined ? 0 : input.actualUsageBytes
  )
  const committedBytes = byteCount(
    'committedBytes',
    input.committedBytes === undefined ? 0 : input.committedBytes
  )
  const pendingBytes = byteCount(
    'pendingBytes',
    input.pendingBytes === undefined ? 0 : input.pendingBytes
  )
  const untrackedDebtBytes = byteCount(
    'untrackedDebtBytes',
    input.untrackedDebtBytes === undefined ? 0 : input.untrackedDebtBytes
  )

  const conservativeDemandBytes = safeSum('conservative demand', [
    actualUsageBytes,
    committedBytes,
    pendingBytes,
    untrackedDebtBytes
  ])
  // Actual bytes are already reflected in filesystem free space. Future debt
  // is not: committed bounds, pending reservations, and untracked obligations
  // may still materialize as writes, so reserve them again on the physical
  // side before treating any remaining free byte as offerable.
  const futureDebtBytes = safeSum('future debt', [
    committedBytes,
    pendingBytes,
    untrackedDebtBytes
  ])
  const physicalHeadroomBytes = Math.max(
    0,
    observedFreeBytes - physicalReserveBytes - futureDebtBytes
  )
  const logicalAvailableBytes = Math.max(0, managedCapacityBytes - conservativeDemandBytes)
  const availableBytes = Math.min(logicalAvailableBytes, physicalHeadroomBytes)
  const overcommittedBytes = Math.max(0, conservativeDemandBytes - managedCapacityBytes)

  // With only global usage evidence, assume every existing byte may belong to
  // the durable pool. This is intentionally stricter than global headroom.
  const durableAvailableBytes = Math.max(0, poolBytes.durable - conservativeDemandBytes)
  const advertisableBytes = Math.min(availableBytes, durableAvailableBytes)

  return Object.freeze({
    schemaVersion: CAPACITY_PLAN_SCHEMA_VERSION,
    mode: CAPACITY_PLAN_MODE,
    profileId,
    observedUsableBytes,
    observedFreeBytes,
    observedFreeAssumed: suppliedFreeBytes === null,
    reservePolicy: Object.freeze({
      basisPoints: CAPACITY_RESERVE_BASIS_POINTS,
      floorBytes: CAPACITY_RESERVE_FLOOR_BYTES
    }),
    physicalReserveBytes,
    postReserveBytes,
    operatorCapBytes,
    operatorCapApplied: budget.operatorCapApplied,
    managedCapacityBytes,
    physicalHeadroomBytes,
    poolBytes,
    usage: Object.freeze({
      actualUsageBytes,
      committedBytes,
      pendingBytes,
      untrackedDebtBytes,
      futureDebtBytes,
      conservativeDemandBytes
    }),
    logicalAvailableBytes,
    availableBytes,
    advertisableBytes,
    overcommittedBytes,
    atCapacity: availableBytes === 0,
    advertisingBlocked: advertisableBytes === 0
  })
}
