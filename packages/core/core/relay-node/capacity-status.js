import {
  CAPACITY_PLAN_MODE,
  isCapacityProfile,
  planBoundedCapacity
} from '../../config/capacity-plan.js'

export const CAPACITY_MEASUREMENT_MAX_AGE_MS = 5 * 60 * 1000

// Hard upper bound on the derived freshness window. A storage tree that cannot
// be walked within this budget cannot produce trustworthy capacity evidence at
// any cadence, so it stays fail-closed rather than being granted an ever-wider
// window. Reaching it is an operator signal: split the store, or accept that
// this root is not capacity-measurable.
export const CAPACITY_MEASUREMENT_MAX_AGE_CEILING_MS = 60 * 60 * 1000

function bytes (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function timestamp (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function duration (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

/**
 * Derive the freshness window for the storage tree walk.
 *
 * The walk is timestamped at its START, so on large hardware the newest
 * finished sample is already `duration + interval` old the moment it lands. A
 * fixed 5-minute budget therefore marked every archive-class relay permanently
 * stale — exactly the hardware the capacity work exists for. The window is
 * instead derived from the host's own observed walk cost, then hard-capped.
 *
 * `floorMs` is still the minimum: fast hosts get the strict budget.
 */
export function measurementWindowMs ({
  floorMs = CAPACITY_MEASUREMENT_MAX_AGE_MS,
  durationMs = null,
  intervalMs = null,
  ceilingMs = CAPACITY_MEASUREMENT_MAX_AGE_CEILING_MS
} = {}) {
  const observed = duration(durationMs)
  const cadence = duration(intervalMs)
  if (observed === null) return { windowMs: floorMs, derived: false, exceedsCeiling: false }
  // Two walks plus one cadence gap: the newest finished sample is already
  // `duration + interval` old, and doubling the walk absorbs one pass that ran
  // slower than the last. Hosts that finish well inside the floor keep the
  // floor — the derived window only ever engages where the floor is
  // unachievable by construction.
  const required = 2 * observed + (cadence ?? 0)
  if (required <= floorMs) return { windowMs: floorMs, derived: false, exceedsCeiling: false }
  if (required > ceilingMs) {
    // Do not widen past the ceiling. The host keeps the capped window, which it
    // will usually miss — so it degrades to fail-closed instead of silently
    // buying itself an unbounded freshness allowance.
    return { windowMs: ceilingMs, derived: true, exceedsCeiling: true }
  }
  return { windowMs: required, derived: true, exceedsCeiling: false }
}

function isFreshMeasurement (measuredAt, now, maxAgeMs) {
  return measuredAt !== null && measuredAt <= now && (now - measuredAt) <= maxAgeMs
}

function authoritySnapshot (authority) {
  if (!authority || typeof authority.capacitySnapshot !== 'function') return null
  try {
    const snapshot = authority.capacitySnapshot()
    return snapshot && typeof snapshot === 'object' ? snapshot : null
  } catch (_) {
    return null
  }
}

function commitmentSummary (snapshot) {
  if (!snapshot) {
    return { committedBytes: 0, pendingBytes: 0, unknownCommitments: 0, valid: false }
  }
  const committedBytes = bytes(snapshot.committedBytes)
  const pendingBytes = bytes(snapshot.pendingBytes)
  const unknownCommitments = bytes(snapshot.unknownCommitments)
  return {
    committedBytes: committedBytes ?? 0,
    pendingBytes: pendingBytes ?? 0,
    unknownCommitments: unknownCommitments ?? 1,
    valid: snapshot.valid === true && committedBytes !== null &&
      pendingBytes !== null && unknownCommitments !== null
  }
}

/**
 * Build a cheap, side-effect-free capacity snapshot for status surfaces.
 *
 * This intentionally does not call admission(), refresh statfs, or walk the
 * storage tree: a public status request must not trigger synchronous disk IO.
 * The plan is emitted only after StorageAccounting has a real disk measure,
 * Network advertisement remains unconditionally disabled until a later wire
 * protocol has one fresh, identity-bound authority sample and assignment
 * lease; independent cached planning samples are not such proof.
 */
export function buildCapacityStatus ({
  config = {},
  disk = null,
  storage = null,
  storageAdmission = null,
  now = Date.now(),
  measurementMaxAgeMs = CAPACITY_MEASUREMENT_MAX_AGE_MS
} = {}) {
  const currentTime = timestamp(now) ?? Date.now()
  const floorMs = Number.isSafeInteger(measurementMaxAgeMs) && measurementMaxAgeMs > 0
    ? measurementMaxAgeMs
    : CAPACITY_MEASUREMENT_MAX_AGE_MS
  const freshness = measurementWindowMs({
    floorMs,
    durationMs: storage && storage.diskMeasureDurationMs,
    intervalMs: storage && storage.diskIntervalMs
  })
  const maxAgeMs = freshness.windowMs
  const configuredProfile = config && config.capacityProfile
  const profileId = isCapacityProfile(configuredProfile) ? configuredProfile : null
  const observedUsableBytes = bytes(disk && disk.totalBytes)
  const observedFreeBytes = bytes(disk && disk.freeBytes)
  const diskMeasureBytes = bytes(storage && storage.diskBytes)
  const storageTotalBytes = bytes(storage && storage.totalBytes)
  const actualUsageBytes = diskMeasureBytes === null
    ? null
    : Math.max(diskMeasureBytes, storageTotalBytes ?? diskMeasureBytes)
  const diskCheckedAt = timestamp(disk && disk.checkedAt)
  const storageMeasuredAt = timestamp(storage && storage.diskMeasuredAt)
  const measurementComplete = storage?.diskMeasurementComplete === true
  const operatorCapBytes = bytes(config && config.maxStorageBytes)
  const snapshot = authoritySnapshot(storageAdmission)
  const commitments = commitmentSummary(snapshot)
  const physicalEnforcementActive = snapshot?.physicalEnforcementActive === true
  // The ceiling an operator-declared profile imposes on new adoption. This is
  // the one number on this surface that is enforced rather than planned: the
  // admission authority derives it from the same profile and the same
  // filesystem size on every reservation.
  const ceilingBytes = bytes(snapshot?.capacityCeilingBytes)
  const effectiveCapBytes = bytes(snapshot?.effectiveCapBytes)
  const measurementAvailable = observedUsableBytes !== null && observedFreeBytes !== null &&
    actualUsageBytes !== null && operatorCapBytes !== null
  const measurementUsable = measurementAvailable && measurementComplete
  // The statfs sample is cheap on every host, so it keeps the strict floor.
  // Only the storage tree walk gets the derived, hardware-sized window.
  const measurementFresh = measurementUsable &&
    isFreshMeasurement(diskCheckedAt, currentTime, floorMs) &&
    isFreshMeasurement(storageMeasuredAt, currentTime, maxAgeMs)

  let plan = null
  if (profileId && measurementUsable && snapshot && commitments.valid &&
      commitments.unknownCommitments === 0) {
    try {
      plan = planBoundedCapacity({
        profileId,
        observedUsableBytes,
        observedFreeBytes,
        operatorCapBytes,
        actualUsageBytes,
        committedBytes: commitments.committedBytes,
        pendingBytes: commitments.pendingBytes,
        // Unknown recovery is not assigned a guessed size. It is represented
        // as an explicit blocker below, so no network-advertisable byte can be
        // derived while the debt is unbounded.
        untrackedDebtBytes: 0
      })
    } catch (_) {
      plan = null
    }
  }

  const blockReasons = []
  if (!profileId) {
    blockReasons.push(configuredProfile == null
      ? 'capacity-profile-unset'
      : 'capacity-profile-invalid')
  }
  if (!measurementAvailable) {
    blockReasons.push('capacity-measurement-unavailable')
  } else if (!measurementComplete) {
    blockReasons.push('capacity-measurement-incomplete')
  } else if (!measurementFresh) {
    blockReasons.push('capacity-measurement-stale')
  }
  if (!snapshot) blockReasons.push('storage-authority-unavailable')
  if (snapshot && snapshot.recoveryReady !== true) blockReasons.push('storage-recovery-pending')
  if (snapshot && snapshot.acceptingMutations !== true) blockReasons.push('storage-mutations-stopped')
  if (snapshot && typeof snapshot.fatalReason === 'string' && snapshot.fatalReason) {
    blockReasons.push('storage-authority-fatal')
  }
  if (!commitments.valid || commitments.unknownCommitments > 0) {
    blockReasons.push('storage-commitment-unknown')
  }
  if (!physicalEnforcementActive) blockReasons.push('physical-enforcement-unavailable')
  if (profileId && ceilingBytes === null) blockReasons.push('capacity-profile-ceiling-unresolved')
  if (plan && plan.advertisingBlocked) blockReasons.push('capacity-full')
  blockReasons.push('network-advertisement-not-implemented')

  const uniqueBlockReasons = [...new Set(blockReasons)]

  return {
    schemaVersion: 1,
    mode: CAPACITY_PLAN_MODE,
    profileId,
    operatorDeclared: profileId !== null,
    plan,
    measurements: {
      complete: measurementComplete,
      fresh: measurementFresh,
      maxAgeMs,
      floorMs,
      derivedWindow: freshness.derived,
      windowCapped: freshness.exceedsCeiling,
      durationMs: duration(storage && storage.diskMeasureDurationMs),
      diskCheckedAt,
      storageMeasuredAt
    },
    enforcement: {
      logicalAdmissionActive: snapshot !== null,
      recoveryReady: snapshot?.recoveryReady === true,
      acceptingMutations: snapshot?.acceptingMutations === true,
      fatal: typeof snapshot?.fatalReason === 'string' && snapshot.fatalReason.length > 0,
      committedBytes: commitments.committedBytes,
      pendingBytes: commitments.pendingBytes,
      unknownCommitments: commitments.unknownCommitments,
      physicalEnforcementActive,
      // Enforced, not planned. `capacityCeilingBytes` is what a declared
      // profile narrows new adoption to; `effectiveCapBytes` is what admission
      // actually compares used bytes against.
      operatorCapBytes: bytes(snapshot?.operatorCapBytes),
      capacityCeilingBytes: ceilingBytes,
      capacityCeilingSource: typeof snapshot?.capacityCeilingSource === 'string'
        ? snapshot.capacityCeilingSource
        : null,
      effectiveCapBytes,
      capacityCeilingApplied: ceilingBytes !== null && effectiveCapBytes !== null &&
        effectiveCapBytes === ceilingBytes && ceilingBytes < (bytes(snapshot?.operatorCapBytes) ?? Infinity)
    },
    advertisement: {
      eligible: false,
      bytes: 0,
      blockReasons: uniqueBlockReasons
    }
  }
}
