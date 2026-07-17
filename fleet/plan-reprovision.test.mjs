import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  REPROVISION_INPUT_SCHEMA,
  buildFleetReprovisionPlan,
  verifyFleetReprovisionPlanDigest
} from './plan-reprovision.mjs'

const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)
const HASH_C = 'c'.repeat(64)
const HASH_D = 'd'.repeat(64)

test('current raw inventory fails closed instead of becoming PG-7 evidence', async () => {
  const inventory = JSON.parse(await readFile(new URL('./relays.json', import.meta.url), 'utf8'))
  const report = buildFleetReprovisionPlan({
    schema: REPROVISION_INPUT_SCHEMA,
    inventory,
    targetRelay: 'utah',
    artifact: { sourceCommit: 'f716b6e36553e98959e54cde29f91e839042657e' }
  })
  const blockers = report.blockers.map(blocker => blocker.id)

  assert.equal(report.status, 'blocked')
  assert.equal(report.inventory.relayCount, 9)
  assert.equal(report.inventory.channels.canary, 3)
  assert.equal(report.inventory.channels.stable, 6)
  assert.equal(report.inventory.regionCount, 4)
  assert.equal(report.inventory.declaredNominalDiskGB, 2138)
  assert.equal(report.inventory.declaredDiskIsObservedCapacityEvidence, false)
  assert.ok(blockers.includes('RC_ARTIFACT_DIGEST_REQUIRED'))
  assert.ok(blockers.includes('TARGET_CONTRACT_HASHES_REQUIRED'))
  assert.ok(blockers.includes('SIGNED_FLEET_INVENTORY_REQUIRED'))
  assert.ok(blockers.includes('RELAY_METADATA_INCOMPLETE'))
  assert.ok(blockers.includes('RETENTION_CENSUS_REQUIRED'))
  assert.ok(blockers.includes('CAPACITY_EVIDENCE_REQUIRED'))
  assert.ok(blockers.includes('REPLICA_FLOOR_EVIDENCE_REQUIRED'))
  assert.ok(blockers.includes('ISOLATED_RESTORE_PROOF_REQUIRED'))
  assert.ok(blockers.includes('D7_DUAL_READ_ROLLBACK_ARTIFACT_REQUIRED'))
  assert.ok(blockers.includes('ROLLBACK_DRILL_PROOF_REQUIRED'))
  assert.equal(report.authority.authorizesMutation, false)
  assert.equal(report.authority.releaseReady, false)
  assert.equal(report.authority.pg7Passed, false)
  assert.equal(verifyFleetReprovisionPlanDigest(report), true)
})

test('complete synthetic evidence creates only a reviewable dry plan', () => {
  const report = buildFleetReprovisionPlan(completeInput())

  assert.equal(report.status, 'ready-for-operator-review')
  assert.deepEqual(report.blockers, [])
  assert.equal(report.targetRelay, 'relay-a')
  assert.equal(report.newRootId, 'root-a-vnext')
  assert.equal(report.dryRun, true)
  assert.equal(report.authority.authorizesMutation, false)
  assert.equal(report.authority.authorizesReprovision, false)
  assert.equal(report.authority.authorizesRelease, false)
  assert.equal(report.authority.releaseReady, false)
  assert.equal(report.authority.pg5Passed, false)
  assert.equal(report.authority.pg7Passed, false)
  assert.equal(verifyFleetReprovisionPlanDigest(report), true)
})

test('capacity and replica floors fail closed', () => {
  const input = completeInput()
  input.capacityProjection.afterDrainFreeBytes = input.capacityProjection.minimumFreeBytes - 1
  input.replicaProjection.afterDrainMinimumByFamily.CELL = 1
  const report = buildFleetReprovisionPlan(input)
  const blockers = report.blockers.map(blocker => blocker.id)

  assert.equal(report.status, 'blocked')
  assert.ok(blockers.includes('CAPACITY_FLOOR_NOT_MET'))
  assert.ok(blockers.includes('REPLICA_FLOOR_NOT_MET'))
})

test('D-7 rejects a legacy-only rollback target', () => {
  const input = completeInput()
  input.rollback.readerMode = 'legacy-only'
  const report = buildFleetReprovisionPlan(input)

  assert.equal(report.status, 'blocked')
  assert.ok(report.blockers.some(blocker =>
    blocker.id === 'D7_DUAL_READ_ROLLBACK_ARTIFACT_REQUIRED'))
})

test('duplicate relay names make an exact target ambiguous', () => {
  const input = completeInput()
  input.inventory.relays.push(relay('relay-a', 'root-other'))
  const report = buildFleetReprovisionPlan(input)
  const blockers = report.blockers.map(blocker => blocker.id)

  assert.equal(report.status, 'blocked')
  assert.ok(blockers.includes('DUPLICATE_RELAY_NAMES'))
  assert.ok(blockers.includes('TARGET_RELAY_AMBIGUOUS'))
})

test('new root cannot collide with any existing relay root', () => {
  const input = completeInput()
  input.newRootId = 'root-b'
  const report = buildFleetReprovisionPlan(input)

  assert.equal(report.status, 'blocked')
  assert.ok(report.blockers.some(blocker =>
    blocker.id === 'NEW_ROOT_COLLIDES_WITH_EXISTING_ROOT'))
})

test('stale and materially future inventory timestamps fail closed', () => {
  const staleInput = completeInput()
  staleInput.inventory.observedAt = '2026-07-17T11:00:00Z'
  const stale = buildFleetReprovisionPlan(staleInput)
  const futureInput = completeInput()
  futureInput.inventory.observedAt = '2026-07-17T12:20:00Z'
  const future = buildFleetReprovisionPlan(futureInput)

  assert.ok(stale.blockers.some(blocker => blocker.id === 'FLEET_INVENTORY_STALE'))
  assert.ok(future.blockers.some(blocker => blocker.id === 'FLEET_INVENTORY_FROM_FUTURE'))
})

test('report digest detects plan tampering', () => {
  const report = buildFleetReprovisionPlan(completeInput())
  const altered = structuredClone(report)
  altered.inventory.relayCount++

  assert.equal(verifyFleetReprovisionPlanDigest(report), true)
  assert.equal(verifyFleetReprovisionPlanDigest(altered), false)
})

function completeInput () {
  return {
    schema: REPROVISION_INPUT_SCHEMA,
    targetRelay: 'relay-a',
    newRootId: 'root-a-vnext',
    evaluatedAt: '2026-07-17T12:05:00Z',
    maximumInventoryAgeSeconds: 600,
    artifact: {
      releaseId: 'vnext-rc.1',
      releaseSequence: 1,
      sourceCommit: '1'.repeat(40),
      sha256: HASH_A
    },
    targetContracts: {
      specHash: HASH_A,
      storeFormatHash: HASH_B,
      privateIpcV2Hash: HASH_C
    },
    inventory: {
      evidenceDigest: HASH_D,
      signatureVerified: true,
      observedAt: '2026-07-17T12:00:00Z',
      relays: [
        relay('relay-a', 'root-a'),
        relay('relay-b', 'root-b'),
        relay('relay-c', 'root-c')
      ]
    },
    retentionCensus: {
      evidenceDigest: HASH_A,
      uniqueUnknownObjects: 0
    },
    capacityProjection: {
      evidenceDigest: HASH_B,
      afterDrainFreeBytes: 10_000,
      minimumFreeBytes: 8_000
    },
    replicaProjection: {
      evidenceDigest: HASH_C,
      afterDrainMinimumByFamily: { CELL: 3, INBOX: 3, CORE: 3 },
      floorByFamily: { CELL: 2, INBOX: 2, CORE: 2 }
    },
    restore: {
      evidenceDigest: HASH_D,
      isolated: true,
      passed: true
    },
    rollback: {
      evidenceDigest: HASH_A,
      drillPassed: true,
      readerMode: 'blind-plus-legacy-dual-read',
      artifactSha256: HASH_B,
      oldRootRetained: true
    }
  }
}

function relay (name, rootId) {
  return {
    name,
    channel: 'canary',
    region: 'test',
    diskGB: 100,
    operatorId: `operator-${name}`,
    hostId: `host-${name}`,
    failureDomain: `failure-${name}`,
    roleProfile: 'blind-cell',
    storageGeneration: 'hc11-cs7-v1',
    admissionClass: 'test',
    retentionDisposition: 'census-complete',
    rootId,
    protocolHashes: {
      specHash: HASH_A,
      storeFormatHash: HASH_B,
      privateIpcV2Hash: HASH_C
    },
    clockTrust: {
      trusted: true,
      evidenceDigest: HASH_A
    },
    capacity: {
      observedUsableBytes: 100_000,
      observedUsedBytes: 25_000,
      evidenceDigest: HASH_B
    },
    backup: {
      offNode: true,
      isolatedRestorePassed: true,
      evidenceDigest: HASH_C
    }
  }
}
