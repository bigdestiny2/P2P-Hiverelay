#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const REPROVISION_INPUT_SCHEMA = 'hiverelay/fleet-reprovision-input/v1'
export const REPROVISION_PLAN_SCHEMA = 'hiverelay/fleet-reprovision-plan/v1'

const DIGEST = /^[a-f0-9]{64}$/
const COMMIT = /^[a-f0-9]{40}$/
const DURABLE_FAMILIES = Object.freeze(['CELL', 'INBOX', 'CORE'])
const REQUIRED_RELAY_FIELDS = Object.freeze([
  'operatorId',
  'hostId',
  'failureDomain',
  'roleProfile',
  'storageGeneration',
  'admissionClass',
  'retentionDisposition',
  'rootId'
])

export function buildFleetReprovisionPlan (input = {}) {
  const blockers = []
  const addBlocker = (id, detail) => {
    if (!blockers.some(blocker => blocker.id === id)) blockers.push({ id, detail })
  }
  const inventory = isObject(input.inventory) ? input.inventory : {}
  const relays = Array.isArray(inventory.relays) ? inventory.relays : []
  const targetRelay = nonEmpty(input.targetRelay) ? input.targetRelay : null
  const targetMatches = relays.filter(relay => relay?.name === targetRelay)
  const target = targetMatches.length === 1 ? targetMatches[0] : null
  const artifact = isObject(input.artifact) ? input.artifact : {}
  const targetContracts = isObject(input.targetContracts) ? input.targetContracts : {}

  if (input.schema !== REPROVISION_INPUT_SCHEMA) {
    addBlocker('INPUT_SCHEMA_INVALID', `schema must be ${REPROVISION_INPUT_SCHEMA}`)
  }
  if (!targetRelay) addBlocker('TARGET_RELAY_REQUIRED', 'name exactly one relay')
  else if (targetMatches.length === 0) {
    addBlocker('TARGET_RELAY_NOT_FOUND', `${targetRelay} is not present in the inventory`)
  } else if (targetMatches.length > 1) {
    addBlocker('TARGET_RELAY_AMBIGUOUS', `${targetRelay} appears ${targetMatches.length} times`)
  }

  if (!COMMIT.test(artifact.sourceCommit || '')) {
    addBlocker('SOURCE_COMMIT_REQUIRED', 'bind the plan to one exact 40-character source commit')
  }
  if (!DIGEST.test(artifact.sha256 || '')) {
    addBlocker('RC_ARTIFACT_DIGEST_REQUIRED', 'bind the plan to one immutable SHA-256 release artifact')
  }
  if (!nonEmpty(artifact.releaseId)) {
    addBlocker('RC_RELEASE_ID_REQUIRED', 'bind the plan to one immutable release identity')
  }
  if (!positiveInteger(artifact.releaseSequence)) {
    addBlocker('RC_RELEASE_SEQUENCE_REQUIRED', 'bind the plan to a positive monotonic release sequence')
  }
  if (!validTargetContracts(targetContracts)) {
    addBlocker(
      'TARGET_CONTRACT_HASHES_REQUIRED',
      'specHash, storeFormatHash, and privateIpcV2Hash must be exact SHA-256 values'
    )
  }

  if (!DIGEST.test(inventory.evidenceDigest || '') || inventory.signatureVerified !== true) {
    addBlocker(
      'SIGNED_FLEET_INVENTORY_REQUIRED',
      'inventory needs an externally verified evidence digest and operator signature'
    )
  }
  if (!validTimestamp(inventory.observedAt)) {
    addBlocker('FLEET_INVENTORY_TIMESTAMP_REQUIRED', 'inventory observedAt must be a valid timestamp')
  }
  inspectInventoryFreshness(inventory.observedAt, input, addBlocker)
  if (relays.length === 0) {
    addBlocker('FLEET_INVENTORY_EMPTY', 'inventory must contain at least one relay')
  }
  const duplicateRelayNames = duplicateValues(relays.map(relay => relay?.name).filter(nonEmpty))
  if (duplicateRelayNames.length > 0) {
    addBlocker(
      'DUPLICATE_RELAY_NAMES',
      `relay names must be unique: ${duplicateRelayNames.join(', ')}`
    )
  }

  const incompleteRelays = relays
    .map(relay => inspectRelay(relay))
    .filter(result => result.missing.length > 0)
  if (incompleteRelays.length > 0) {
    addBlocker(
      'RELAY_METADATA_INCOMPLETE',
      incompleteRelays.map(result => `${result.name}: ${result.missing.join(', ')}`).join('; ')
    )
  }
  if (target && inspectRelay(target).missing.includes('backup')) {
    addBlocker(
      'TARGET_BACKUP_PROOF_REQUIRED',
      `${target.name} needs off-node backup and isolated-restore evidence`
    )
  }

  inspectRetention(input.retentionCensus, addBlocker)
  inspectCapacity(input.capacityProjection, addBlocker)
  inspectReplicaFloors(input.replicaProjection, addBlocker)
  inspectRestore(input.restore, addBlocker)
  inspectRollback(input.rollback, addBlocker)

  if (!nonEmpty(input.newRootId)) {
    addBlocker('NEW_ROOT_ID_REQUIRED', 'name the disposable empty root before an operator acts')
  } else {
    const rootOwner = relays.find(relay => relay?.rootId === input.newRootId)
    if (rootOwner) {
      addBlocker(
        'NEW_ROOT_COLLIDES_WITH_EXISTING_ROOT',
        `${input.newRootId} is already owned by ${rootOwner.name || '<unnamed>'}`
      )
    }
  }

  const inventorySummary = summarizeInventory(relays)
  const body = {
    schema: REPROVISION_PLAN_SCHEMA,
    inputSchema: input.schema || null,
    dryRun: true,
    status: blockers.length === 0 ? 'ready-for-operator-review' : 'blocked',
    evidenceClass: 'local-static-plan-not-observed-reprovision',
    claimBoundary: 'This report performs no SSH, network, channel, key, service, root, or fleet mutation. A blocker-free plan is still not deployment authority, observed convergence, PG-5, PG-7, release readiness, or GA evidence.',
    targetRelay,
    newRootId: nonEmpty(input.newRootId) ? input.newRootId : null,
    artifact: {
      releaseId: nonEmpty(artifact.releaseId) ? artifact.releaseId : null,
      releaseSequence: positiveInteger(artifact.releaseSequence) ? artifact.releaseSequence : null,
      sourceCommit: COMMIT.test(artifact.sourceCommit || '') ? artifact.sourceCommit : null,
      sha256: DIGEST.test(artifact.sha256 || '') ? artifact.sha256 : null
    },
    targetContracts: validTargetContracts(targetContracts) ? targetContracts : null,
    inventory: {
      evidenceDigest: DIGEST.test(inventory.evidenceDigest || '') ? inventory.evidenceDigest : null,
      signatureVerified: inventory.signatureVerified === true,
      observedAt: validTimestamp(inventory.observedAt) ? inventory.observedAt : null,
      evaluatedAt: validTimestamp(input.evaluatedAt) ? input.evaluatedAt : null,
      maximumAgeSeconds: positiveInteger(input.maximumInventoryAgeSeconds)
        ? input.maximumInventoryAgeSeconds
        : null,
      ...inventorySummary
    },
    projections: summarizeProjections(input),
    blockers,
    proposedSequence: proposedSequence(targetRelay),
    authority: {
      authorizesMutation: false,
      authorizesReprovision: false,
      authorizesRelease: false,
      releaseReady: false,
      pg5Passed: false,
      pg7Passed: false,
      requiredNextAuthority: blockers.length === 0
        ? 'independent review, immutable RC acceptance, and an explicit human fleet-operation lease'
        : 'supply the missing local evidence; do not operate the fleet'
    }
  }
  return { ...body, planDigest: sha256(stableStringify(body)) }
}

export function verifyFleetReprovisionPlanDigest (report) {
  if (!isObject(report) || !DIGEST.test(report.planDigest || '')) return false
  const { planDigest, ...body } = report
  return planDigest === sha256(stableStringify(body))
}

function inspectRelay (relay) {
  const name = nonEmpty(relay?.name) ? relay.name : '<unnamed>'
  const missing = []
  for (const field of REQUIRED_RELAY_FIELDS) {
    if (!nonEmpty(relay?.[field])) missing.push(field)
  }
  if (!validTargetContracts(relay?.protocolHashes)) missing.push('protocolHashes')
  if (!isObject(relay?.clockTrust) ||
      relay.clockTrust.trusted !== true ||
      !DIGEST.test(relay.clockTrust.evidenceDigest || '')) {
    missing.push('clockTrust')
  }
  if (!isObject(relay?.capacity) ||
      !nonNegativeInteger(relay.capacity.observedUsableBytes) ||
      !nonNegativeInteger(relay.capacity.observedUsedBytes) ||
      relay.capacity.observedUsedBytes > relay.capacity.observedUsableBytes ||
      !DIGEST.test(relay.capacity.evidenceDigest || '')) {
    missing.push('capacity')
  }
  if (!isObject(relay?.backup) ||
      relay.backup.offNode !== true ||
      relay.backup.isolatedRestorePassed !== true ||
      !DIGEST.test(relay.backup.evidenceDigest || '')) {
    missing.push('backup')
  }
  return { name, missing }
}

function inspectRetention (retention, addBlocker) {
  if (!isObject(retention) ||
      !DIGEST.test(retention.evidenceDigest || '') ||
      !nonNegativeInteger(retention.uniqueUnknownObjects)) {
    addBlocker(
      'RETENTION_CENSUS_REQUIRED',
      'supply a digest-bound census with an exact uniqueUnknownObjects count'
    )
    return
  }
  if (retention.uniqueUnknownObjects !== 0) {
    addBlocker(
      'UNIQUE_OR_UNKNOWN_OBJECTS_PRESENT',
      `${retention.uniqueUnknownObjects} unique or unknown objects remain`
    )
  }
}

function inspectInventoryFreshness (observedAt, input, addBlocker) {
  if (!validTimestamp(input.evaluatedAt) || !positiveInteger(input.maximumInventoryAgeSeconds)) {
    addBlocker(
      'INVENTORY_FRESHNESS_WINDOW_REQUIRED',
      'supply evaluatedAt and a positive maximumInventoryAgeSeconds'
    )
    return
  }
  if (!validTimestamp(observedAt)) return
  const ageMillis = Date.parse(input.evaluatedAt) - Date.parse(observedAt)
  const maximumAgeMillis = input.maximumInventoryAgeSeconds * 1000
  const maximumFutureSkewMillis = 300 * 1000
  if (ageMillis > maximumAgeMillis) {
    addBlocker(
      'FLEET_INVENTORY_STALE',
      `inventory age ${Math.floor(ageMillis / 1000)}s exceeds ${input.maximumInventoryAgeSeconds}s`
    )
  } else if (ageMillis < -maximumFutureSkewMillis) {
    addBlocker(
      'FLEET_INVENTORY_FROM_FUTURE',
      `inventory observedAt is ${Math.ceil(-ageMillis / 1000)}s ahead of evaluatedAt`
    )
  }
}

function inspectCapacity (projection, addBlocker) {
  if (!isObject(projection) ||
      !DIGEST.test(projection.evidenceDigest || '') ||
      !nonNegativeInteger(projection.afterDrainFreeBytes) ||
      !nonNegativeInteger(projection.minimumFreeBytes)) {
    addBlocker(
      'CAPACITY_EVIDENCE_REQUIRED',
      'supply observed, digest-bound after-drain capacity and its minimum floor'
    )
    return
  }
  if (projection.afterDrainFreeBytes < projection.minimumFreeBytes) {
    addBlocker(
      'CAPACITY_FLOOR_NOT_MET',
      `${projection.afterDrainFreeBytes} after-drain bytes are below ${projection.minimumFreeBytes}`
    )
  }
}

function inspectReplicaFloors (projection, addBlocker) {
  if (!isObject(projection) ||
      !DIGEST.test(projection.evidenceDigest || '') ||
      !isObject(projection.afterDrainMinimumByFamily) ||
      !isObject(projection.floorByFamily)) {
    addBlocker(
      'REPLICA_FLOOR_EVIDENCE_REQUIRED',
      'supply digest-bound after-drain and required replica floors by durable family'
    )
    return
  }
  const missing = DURABLE_FAMILIES.filter(family =>
    !positiveInteger(projection.afterDrainMinimumByFamily[family]) ||
    !positiveInteger(projection.floorByFamily[family]))
  if (missing.length > 0) {
    addBlocker(
      'REPLICA_FLOOR_EVIDENCE_REQUIRED',
      `missing positive after-drain/floor values for ${missing.join(', ')}`
    )
    return
  }
  const violations = DURABLE_FAMILIES.filter(family =>
    projection.afterDrainMinimumByFamily[family] < projection.floorByFamily[family])
  if (violations.length > 0) {
    addBlocker(
      'REPLICA_FLOOR_NOT_MET',
      violations.map(family =>
        `${family} ${projection.afterDrainMinimumByFamily[family]} < ${projection.floorByFamily[family]}`
      ).join(', ')
    )
  }
}

function inspectRestore (restore, addBlocker) {
  if (!isObject(restore) ||
      !DIGEST.test(restore.evidenceDigest || '') ||
      restore.isolated !== true ||
      restore.passed !== true) {
    addBlocker(
      'ISOLATED_RESTORE_PROOF_REQUIRED',
      'supply digest-bound evidence for a passing isolated restore'
    )
  }
}

function inspectRollback (rollback, addBlocker) {
  if (!isObject(rollback) ||
      rollback.readerMode !== 'blind-plus-legacy-dual-read' ||
      !DIGEST.test(rollback.artifactSha256 || '')) {
    addBlocker(
      'D7_DUAL_READ_ROLLBACK_ARTIFACT_REQUIRED',
      'D-7 permits only an exact blind-plus-legacy dual-read rollback artifact'
    )
  }
  if (!isObject(rollback) ||
      !DIGEST.test(rollback.evidenceDigest || '') ||
      rollback.drillPassed !== true) {
    addBlocker(
      'ROLLBACK_DRILL_PROOF_REQUIRED',
      'supply digest-bound evidence for a passing rollback and forward-recovery drill'
    )
  }
  if (!isObject(rollback) || rollback.oldRootRetained !== true) {
    addBlocker(
      'OLD_ROOT_RETENTION_REQUIRED',
      'retain the old root through the dual-read, restore, and rollback window'
    )
  }
}

function summarizeInventory (relays) {
  const channels = {}
  const regions = new Set()
  let declaredNominalDiskGB = 0
  for (const relay of relays) {
    const channel = nonEmpty(relay?.channel) ? relay.channel : 'unknown'
    channels[channel] = (channels[channel] || 0) + 1
    if (nonEmpty(relay?.region)) regions.add(relay.region)
    if (typeof relay?.diskGB === 'number' && Number.isFinite(relay.diskGB) && relay.diskGB >= 0) {
      declaredNominalDiskGB += relay.diskGB
    }
  }
  return {
    relayCount: relays.length,
    channels,
    regionCount: regions.size,
    declaredNominalDiskGB,
    declaredDiskIsObservedCapacityEvidence: false
  }
}

function summarizeProjections (input) {
  return {
    retentionCensusDigest: validDigest(input.retentionCensus?.evidenceDigest),
    uniqueUnknownObjects: nonNegativeInteger(input.retentionCensus?.uniqueUnknownObjects)
      ? input.retentionCensus.uniqueUnknownObjects
      : null,
    capacityEvidenceDigest: validDigest(input.capacityProjection?.evidenceDigest),
    afterDrainFreeBytes: nonNegativeInteger(input.capacityProjection?.afterDrainFreeBytes)
      ? input.capacityProjection.afterDrainFreeBytes
      : null,
    minimumFreeBytes: nonNegativeInteger(input.capacityProjection?.minimumFreeBytes)
      ? input.capacityProjection.minimumFreeBytes
      : null,
    replicaEvidenceDigest: validDigest(input.replicaProjection?.evidenceDigest),
    afterDrainMinimumByFamily: isObject(input.replicaProjection?.afterDrainMinimumByFamily)
      ? input.replicaProjection.afterDrainMinimumByFamily
      : null,
    floorByFamily: isObject(input.replicaProjection?.floorByFamily)
      ? input.replicaProjection.floorByFamily
      : null,
    restoreEvidenceDigest: validDigest(input.restore?.evidenceDigest),
    rollbackEvidenceDigest: validDigest(input.rollback?.evidenceDigest)
  }
}

function proposedSequence (targetRelay) {
  const target = targetRelay || '<one-explicit-relay>'
  return [
    { order: 1, action: 'freeze-inputs', guard: 'independently accept exact source, artifact, contract hashes, and signed inventory' },
    { order: 2, action: 'stop-on-unknown-custody', guard: 'uniqueUnknownObjects must equal zero' },
    { order: 3, action: 'prove-restore', guard: 'off-node backup must pass an isolated restore before drain' },
    { order: 4, action: `project-drain:${target}`, guard: 'capacity and per-family replica floors must remain satisfied without the target' },
    { order: 5, action: `drain-one:${target}`, guard: 'requires a separate explicit human fleet-operation lease' },
    { order: 6, action: 'provision-distinct-empty-root', guard: 'run only the exact accepted artifact; preserve only explicitly approved identities' },
    { order: 7, action: 'restore-or-republish', guard: 'T1 from authoritative publishers; blind data only through receipts and client-owned state' },
    { order: 8, action: 'verify-convergence', guard: 'heads, proofs, capacity, clocks, quotas, storage generation, and contract hashes must match' },
    { order: 9, action: 'observe-and-soak', guard: 'do not advance another node before the required windows pass' },
    { order: 10, action: 'retain-old-root', guard: 'D-7 allows only the exact dual-read rollback artifact; never target a legacy-only writer' }
  ]
}

function validTargetContracts (value) {
  return isObject(value) &&
    DIGEST.test(value.specHash || '') &&
    DIGEST.test(value.storeFormatHash || '') &&
    DIGEST.test(value.privateIpcV2Hash || '')
}

function validTimestamp (value) {
  return nonEmpty(value) && Number.isFinite(Date.parse(value))
}

function validDigest (value) {
  return DIGEST.test(value || '') ? value : null
}

function duplicateValues (values) {
  const seen = new Set()
  const duplicates = new Set()
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value)
    seen.add(value)
  }
  return [...duplicates].sort()
}

function positiveInteger (value) {
  return Number.isSafeInteger(value) && value > 0
}

function nonNegativeInteger (value) {
  return Number.isSafeInteger(value) && value >= 0
}

function nonEmpty (value) {
  return typeof value === 'string' && value.length > 0
}

function isObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function stableStringify (value) {
  return JSON.stringify(sortValue(value))
}

function sortValue (value) {
  if (Array.isArray(value)) return value.map(sortValue)
  if (!isObject(value)) return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, sortValue(value[key])]))
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function usage () {
  return [
    'Usage: node fleet/plan-reprovision.mjs [options]',
    '',
    'Options:',
    '  --inventory FILE        Fleet inventory (default: fleet/relays.json)',
    '  --state FILE            Local reprovision evidence/input document',
    '  --target-relay NAME     Exactly one relay to project',
    '  --source-commit SHA     Exact source commit override',
    '  --artifact-sha256 SHA   Exact immutable release artifact override',
    '  --release-id ID         Immutable release identity override',
    '  --release-sequence N    Monotonic release sequence override',
    '  --as-of TIMESTAMP        Timestamp used for inventory freshness',
    '  --max-inventory-age N    Maximum accepted inventory age in seconds',
    '  --out FILE              Write the report locally instead of stdout',
    '  --pretty | --compact    JSON formatting',
    '  --require-ready         Exit 2 when local evidence is incomplete',
    '',
    'There is deliberately no execute, SSH, deploy, channel, key, or root-mutation mode.'
  ].join('\n')
}

async function main (argv) {
  const args = parseArgs(argv)
  if (args.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  const inventory = JSON.parse(await readFile(resolve(args.inventory || 'fleet/relays.json'), 'utf8'))
  const state = args.state
    ? JSON.parse(await readFile(resolve(args.state), 'utf8'))
    : {}
  const input = {
    ...state,
    schema: state.schema || REPROVISION_INPUT_SCHEMA,
    inventory,
    targetRelay: args.targetRelay || state.targetRelay,
    evaluatedAt: args.asOf || state.evaluatedAt || new Date().toISOString(),
    maximumInventoryAgeSeconds: args.maxInventoryAge
      ? Number(args.maxInventoryAge)
      : state.maximumInventoryAgeSeconds,
    artifact: {
      ...(isObject(state.artifact) ? state.artifact : {}),
      ...(args.sourceCommit ? { sourceCommit: args.sourceCommit } : {}),
      ...(args.artifactSha256 ? { sha256: args.artifactSha256 } : {}),
      ...(args.releaseId ? { releaseId: args.releaseId } : {}),
      ...(args.releaseSequence ? { releaseSequence: Number(args.releaseSequence) } : {})
    }
  }
  const report = buildFleetReprovisionPlan(input)
  const output = `${JSON.stringify(report, null, args.pretty ? 2 : 0)}\n`
  if (args.out) await writeFile(resolve(args.out), output)
  else process.stdout.write(output)
  if (args.requireReady && report.status !== 'ready-for-operator-review') process.exitCode = 2
}

function parseArgs (argv) {
  const result = { pretty: true, requireReady: false, help: false }
  const valued = new Map([
    ['--inventory', 'inventory'],
    ['--state', 'state'],
    ['--target-relay', 'targetRelay'],
    ['--source-commit', 'sourceCommit'],
    ['--artifact-sha256', 'artifactSha256'],
    ['--release-id', 'releaseId'],
    ['--release-sequence', 'releaseSequence'],
    ['--as-of', 'asOf'],
    ['--max-inventory-age', 'maxInventoryAge'],
    ['--out', 'out']
  ])
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]
    if (valued.has(arg)) {
      const value = argv[++index]
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value`)
      result[valued.get(arg)] = value
    } else if (arg === '--pretty') result.pretty = true
    else if (arg === '--compact') result.pretty = false
    else if (arg === '--require-ready') result.requireReady = true
    else if (arg === '--help' || arg === '-h') result.help = true
    else throw new Error(`unknown argument ${arg}`)
  }
  return result
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`fleet reprovision planner: ${error.message}\n`)
    process.exitCode = 1
  })
}
