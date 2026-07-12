#!/usr/bin/env node

import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { ABI_RELEASE_BLOCKERS } from '../packages/blind-protocol/registry.js'
import { PRIVATE_IPC_STATUS } from '../packages/blind-ipc/index.js'
import { BLIND_CLIENT_BROWSER_ARTIFACT_STATUS } from '../packages/blind-client/browser-artifact.js'
import { BLIND_CELL_RUNTIME_BLOCKERS } from '../packages/blind-daemon/cell-runtime-adapter.js'
import { BLIND_CORE_RUNTIME_BLOCKERS } from '../packages/blind-daemon/core-runtime-adapter.js'
import { BLIND_CORE_STORAGE_BLOCKERS } from '../packages/blind-daemon/core-storage-engine.js'
import { BLIND_INBOX_RUNTIME_BLOCKERS } from '../packages/blind-daemon/inbox-runtime-adapter.js'
import { BLIND_INBOX_STORAGE_BLOCKERS } from '../packages/blind-daemon/inbox-storage-engine.js'
import { PRODUCTION_RUNTIME_EXCLUSIONS } from '../packages/blind-daemon/production-runtime.js'
import { BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS } from '../packages/blind-daemon/storage-engine.js'

const here = path.dirname(fileURLToPath(import.meta.url))

export const LEGACY_RETIREMENT_POLICY_PATH = path.resolve(
  here,
  '../deploy/blind/legacy-retirement-policy.json'
)

const GATE_IDS = Object.freeze(['G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8'])
const COMPONENT_IDS = Object.freeze([
  'legacy-service-plane',
  'outboxlog',
  'witness-repair',
  'shard-custody',
  'seed-storage-gateway',
  'catalog-federation-index',
  'notify',
  'poker',
  'compute-trust-services',
  'legacy-circuit-forward',
  'edge-transports',
  'legacy-client-verifier',
  'operator-control-economics',
  'peerit-legacy-consumer-plane'
])
const FORBIDDEN_CLAIM_IDS = Object.freeze([
  'self-description-proves-runtime',
  'signed-roster-proves-independence',
  'ciphertext-label-proves-blindness',
  'multiple-keys-prove-operators',
  'attestation-proves-retrieval',
  'tor-advertisement-proves-anonymity',
  'client-verification-proves-availability',
  'unseed-proves-erasure',
  'opaque-poker-proves-generic',
  'hand-edited-authorization'
])
const REAL_EVIDENCE_IDS = Object.freeze([
  'executable-production-composition',
  'plaintext-sentinel-absence',
  'canonical-capability-result',
  'transactional-wal-recovery',
  'private-ipc-peer-credentials',
  'retrieval-proof',
  'independent-operator-failure-domain',
  'cross-runtime-client-parity',
  'migration-restore-drill',
  'observed-zero-traffic'
])
const RETIREMENT_SEQUENCE_IDS = Object.freeze(['freeze', 'compose', 'migrate', 'drain', 'remove'])
const DISPOSITIONS = new Set([
  'migrate-then-retire',
  'externalize-from-base',
  'retain-isolated',
  'adapt-and-retain'
])

const BLOCKER_AUTHORITIES = Object.freeze([
  Object.freeze({ source: 'blind-protocol.ABI_RELEASE_BLOCKERS', blockers: ABI_RELEASE_BLOCKERS }),
  Object.freeze({ source: 'blind-ipc.PRIVATE_IPC_STATUS.releaseBlockers', blockers: PRIVATE_IPC_STATUS.releaseBlockers }),
  Object.freeze({ source: 'blind-client.BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.releaseBlockers', blockers: BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.releaseBlockers }),
  Object.freeze({ source: 'blind-daemon.PRODUCTION_RUNTIME_EXCLUSIONS', blockers: PRODUCTION_RUNTIME_EXCLUSIONS }),
  Object.freeze({ source: 'blind-daemon.BLIND_CELL_RUNTIME_BLOCKERS', blockers: BLIND_CELL_RUNTIME_BLOCKERS }),
  Object.freeze({ source: 'blind-daemon.BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS', blockers: BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS }),
  Object.freeze({ source: 'blind-daemon.BLIND_INBOX_RUNTIME_BLOCKERS', blockers: BLIND_INBOX_RUNTIME_BLOCKERS }),
  Object.freeze({ source: 'blind-daemon.BLIND_INBOX_STORAGE_BLOCKERS', blockers: BLIND_INBOX_STORAGE_BLOCKERS }),
  Object.freeze({ source: 'blind-daemon.BLIND_CORE_RUNTIME_BLOCKERS', blockers: BLIND_CORE_RUNTIME_BLOCKERS }),
  Object.freeze({ source: 'blind-daemon.BLIND_CORE_STORAGE_BLOCKERS', blockers: BLIND_CORE_STORAGE_BLOCKERS })
])

// These are code-owned blockers, not deployment JSON. Each must be replaced by
// an executable evidence authority before legacy deletion can ever authorize.
export const LEGACY_RETIREMENT_EVIDENCE_BLOCKERS = Object.freeze([
  'G2_BLINDNESS_SENTINEL_EVIDENCE_AUTHORITY_UNASSEMBLED',
  'G3_LEGACY_SEMANTIC_PARITY_EVIDENCE_AUTHORITY_UNASSEMBLED',
  'G4_LEGACY_DURABILITY_SCALE_EVIDENCE_AUTHORITY_UNASSEMBLED',
  'G5_INDEPENDENT_OPERATOR_EVIDENCE_AUTHORITY_UNASSEMBLED',
  'G6_CONSUMER_PARITY_EVIDENCE_AUTHORITY_UNASSEMBLED',
  'G7_MIGRATION_RESTORE_EVIDENCE_AUTHORITY_UNASSEMBLED',
  'G8_ZERO_TRAFFIC_RETIREMENT_EVIDENCE_AUTHORITY_UNASSEMBLED'
])

export async function loadLegacyRetirementPolicy (policyPath = LEGACY_RETIREMENT_POLICY_PATH) {
  const bytes = await fs.readFile(policyPath)
  if (bytes.byteLength === 0 || bytes.byteLength > 1024 * 1024) {
    policyFailure('legacy retirement policy must be 1..1048576 bytes')
  }
  let policy
  try {
    policy = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    policyFailure(`legacy retirement policy is not valid JSON: ${error.message}`)
  }
  return validateLegacyRetirementPolicy(policy)
}

export function validateLegacyRetirementPolicy (policy) {
  assertPlainObject(policy, 'policy')
  rejectAuthorizationBooleans(policy)
  assertExactKeys(policy, [
    'policyVersion',
    'policyId',
    'decisionAuthority',
    'authorizationRule',
    'gates',
    'components',
    'forbiddenClaims',
    'realEvidence',
    'retirementSequence'
  ], 'policy')
  if (policy.policyVersion !== 1) policyFailure('policyVersion must equal 1')
  if (policy.policyId !== 'hiverelay.blind.legacy-retirement.v1') {
    policyFailure('policyId does not match the registered retirement policy')
  }
  if (policy.decisionAuthority !== 'computed-production-blockers-only') {
    policyFailure('decisionAuthority must remain computed-production-blockers-only')
  }

  assertPlainObject(policy.authorizationRule, 'authorizationRule')
  assertExactKeys(policy.authorizationRule, [
    'computedBy',
    'rule',
    'editableDecisionFields',
    'blockerSources',
    'retirementEvidenceSource'
  ], 'authorizationRule')
  if (policy.authorizationRule.computedBy !== 'scripts/verify-blind-legacy-retirement-policy.mjs') {
    policyFailure('authorizationRule.computedBy does not name the registered verifier')
  }
  if (policy.authorizationRule.editableDecisionFields !== 'forbidden') {
    policyFailure('authorizationRule.editableDecisionFields must equal forbidden')
  }
  if (policy.authorizationRule.retirementEvidenceSource !==
      'blind-legacy-retirement.LEGACY_RETIREMENT_EVIDENCE_BLOCKERS') {
    policyFailure('authorizationRule.retirementEvidenceSource does not name the code-owned authority')
  }
  assertNonEmptyString(policy.authorizationRule.rule, 'authorizationRule.rule')
  assertExactStringArray(
    policy.authorizationRule.blockerSources,
    BLOCKER_AUTHORITIES.map(authority => authority.source),
    'authorizationRule.blockerSources'
  )

  assertExactIdRows(policy.gates, GATE_IDS, 'gates', row => {
    assertExactKeys(row, ['id', 'title', 'requirement', 'evidence'], `gate ${row.id}`)
    assertNonEmptyString(row.title, 'gate.title')
    assertNonEmptyString(row.requirement, 'gate.requirement')
    assertNonEmptyStringArray(row.evidence, 'gate.evidence')
  })
  const gateIds = new Set(GATE_IDS)
  assertExactIdRows(policy.components, COMPONENT_IDS, 'components', row => {
    assertExactKeys(row, [
      'id',
      'legacyPaths',
      'disposition',
      'replacement',
      'extract',
      'deletionGates'
    ], `component ${row.id}`)
    assertNonEmptyStringArray(row.legacyPaths, 'component.legacyPaths')
    if (!DISPOSITIONS.has(row.disposition)) {
      policyFailure(`component ${row.id} has an unknown disposition`)
    }
    assertNonEmptyStringArray(row.replacement, 'component.replacement')
    assertNonEmptyStringArray(row.extract, 'component.extract')
    assertNonEmptyStringArray(row.deletionGates, 'component.deletionGates')
    if (!row.deletionGates.includes('G8')) {
      policyFailure(`component ${row.id} must require G8 before removal`)
    }
    for (const gate of row.deletionGates) {
      if (!gateIds.has(gate)) policyFailure(`component ${row.id} references unknown gate ${gate}`)
    }
  })
  assertExactIdRows(policy.forbiddenClaims, FORBIDDEN_CLAIM_IDS, 'forbiddenClaims', row => {
    assertExactKeys(row, [
      'id',
      'claim',
      'whyInvalid',
      'requiredEvidence'
    ], `forbidden claim ${row.id}`)
    assertNonEmptyString(row.claim, 'forbiddenClaim.claim')
    assertNonEmptyString(row.whyInvalid, 'forbiddenClaim.whyInvalid')
    assertNonEmptyStringArray(row.requiredEvidence, 'forbiddenClaim.requiredEvidence')
  })
  assertExactIdRows(policy.realEvidence, REAL_EVIDENCE_IDS, 'realEvidence', row => {
    assertExactKeys(row, ['id', 'evidence', 'proves', 'codeAnchors'], `real evidence ${row.id}`)
    assertNonEmptyString(row.evidence, 'realEvidence.evidence')
    assertNonEmptyStringArray(row.proves, 'realEvidence.proves')
    assertNonEmptyStringArray(row.codeAnchors, 'realEvidence.codeAnchors')
  })
  assertExactIdRows(policy.retirementSequence, RETIREMENT_SEQUENCE_IDS, 'retirementSequence', row => {
    assertExactKeys(row, ['id', 'requires', 'action'], `retirement sequence ${row.id}`)
    assertNonEmptyStringArray(row.requires, 'retirementSequence.requires')
    assertNonEmptyString(row.action, 'retirementSequence.action')
    for (const gate of row.requires) {
      if (!gateIds.has(gate)) policyFailure(`retirement phase ${row.id} references unknown gate ${gate}`)
    }
  })
  assertExactStringArray(
    policy.retirementSequence.at(-1).requires,
    GATE_IDS,
    'retirementSequence.remove.requires'
  )
  return policy
}

export function productionRetirementBlockers () {
  const rows = []
  for (const authority of BLOCKER_AUTHORITIES) {
    if (!Array.isArray(authority.blockers)) {
      policyFailure(`production blocker source ${authority.source} is not an array`)
    }
    for (const code of authority.blockers) {
      assertNonEmptyString(code, `production blocker from ${authority.source}`)
      rows.push(Object.freeze({ source: authority.source, code }))
    }
  }
  return Object.freeze(rows)
}

export function evaluateLegacyRetirement (policy) {
  validateLegacyRetirementPolicy(policy)
  const productionBlockers = productionRetirementBlockers()
  const evidenceBlockers = LEGACY_RETIREMENT_EVIDENCE_BLOCKERS.map(code => Object.freeze({
    source: 'blind-legacy-retirement.LEGACY_RETIREMENT_EVIDENCE_BLOCKERS',
    code
  }))
  const blockers = Object.freeze([...productionBlockers, ...evidenceBlockers])
  const blockingCodes = Object.freeze([...new Set(blockers.map(row => row.code))].sort())
  const blockerSources = Object.freeze([...new Set(blockers.map(row => row.source))].sort())
  const authorized = blockers.length === 0
  return Object.freeze({
    policyId: policy.policyId,
    policyVersion: policy.policyVersion,
    decisionAuthority: policy.decisionAuthority,
    status: authorized ? 'authorized' : 'blocked',
    authorized,
    blockerCount: blockers.length,
    productionBlockerCount: productionBlockers.length,
    retirementEvidenceBlockerCount: evidenceBlockers.length,
    blockingCodes,
    blockerSources,
    requiredGates: GATE_IDS,
    componentCount: COMPONENT_IDS.length,
    blockers
  })
}

export function assertLegacyRetirementAuthorized (policy) {
  const report = evaluateLegacyRetirement(policy)
  if (report.authorized) return report
  const error = new Error(`legacy retirement is blocked by ${report.blockerCount} code-owned blockers`)
  error.code = 'BLIND_LEGACY_RETIREMENT_BLOCKED'
  error.report = report
  throw error
}

function rejectAuthorizationBooleans (value, at = 'policy') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectAuthorizationBooleans(entry, `${at}[${index}]`))
    return
  }
  if (!value || typeof value !== 'object') return
  for (const [key, entry] of Object.entries(value)) {
    const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase()
    if (typeof entry === 'boolean' && AUTHORIZATION_BOOLEAN_KEYS.has(normalized)) {
      policyFailure(`${at}.${key} is a forbidden hand-editable authorization boolean`)
    }
    rejectAuthorizationBooleans(entry, `${at}.${key}`)
  }
}

const AUTHORIZATION_BOOLEAN_KEYS = new Set([
  'authorized',
  'authorization',
  'allowdeletion',
  'candelete',
  'deletionauthorized',
  'retirementauthorized',
  'legacyretirementauthorized',
  'approvedfordeletion',
  'retirementready',
  'deletionready'
])

function assertExactIdRows (rows, expectedIds, field, inspect) {
  if (!Array.isArray(rows)) policyFailure(`${field} must be an array`)
  assertExactStringArray(rows.map(row => {
    assertPlainObject(row, `${field} row`)
    assertNonEmptyString(row.id, `${field} row id`)
    return row.id
  }), expectedIds, `${field} ids`)
  for (const row of rows) inspect(row)
}

function assertExactStringArray (actual, expected, field) {
  if (!Array.isArray(actual) || actual.length !== expected.length ||
      actual.some((value, index) => value !== expected[index])) {
    policyFailure(`${field} must equal the registered ordered values`)
  }
}

function assertExactKeys (value, expected, field) {
  assertPlainObject(value, field)
  const actual = Object.keys(value).sort()
  const sortedExpected = [...expected].sort()
  if (actual.length !== sortedExpected.length ||
      actual.some((key, index) => key !== sortedExpected[index])) {
    policyFailure(`${field} must contain exactly the registered fields`)
  }
}

function assertNonEmptyStringArray (value, field) {
  if (!Array.isArray(value) || value.length === 0) policyFailure(`${field} must be a non-empty array`)
  const seen = new Set()
  for (const entry of value) {
    assertNonEmptyString(entry, field)
    if (seen.has(entry)) policyFailure(`${field} contains a duplicate value`)
    seen.add(entry)
  }
}

function assertNonEmptyString (value, field) {
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim()) {
    policyFailure(`${field} must be a non-empty trimmed string`)
  }
}

function assertPlainObject (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    policyFailure(`${field} must be a plain object`)
  }
}

function policyFailure (message) {
  const error = new Error(message)
  error.code = 'BLIND_LEGACY_RETIREMENT_POLICY_INVALID'
  throw error
}

async function main () {
  const args = new Set(process.argv.slice(2))
  for (const arg of args) {
    if (arg !== '--json' && arg !== '--require-authorized') {
      throw new Error(`unknown argument: ${arg}`)
    }
  }
  const policy = await loadLegacyRetirementPolicy()
  const report = evaluateLegacyRetirement(policy)
  process.stdout.write(`${JSON.stringify(report, null, args.has('--json') ? 2 : 0)}\n`)
  if (args.has('--require-authorized') && !report.authorized) process.exitCode = 1
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`${error.stack || error.message}\n`)
    process.exitCode = 1
  })
}
