#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const repoRoot = path.resolve(path.dirname(scriptPath), '..')
const defaultRemediation = path.join(repoRoot, 'docs', 'vnext', 'protocol-remediation.json')
const defaultProgram = path.join(repoRoot, 'docs', 'vnext', 'program-state.json')
const CR_IDS = Array.from({ length: 8 }, (_, index) => `CR-${index + 1}`)
const FINAL_AUTHORITY_PATHS = [
  'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json',
  'packages/blind-protocol/hiverelay-blind-abi-v1.cenc',
  'packages/blind-protocol/vector-manifest-v1.cenc',
  'packages/blind-protocol/wire-runtime-authority.js'
]
const SAFE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/
const SHA1 = /^[0-9a-f]{40}$/

if (path.resolve(process.argv[1] || '') === scriptPath) {
  try {
    const remediationPath = process.argv[2] ? path.resolve(process.argv[2]) : defaultRemediation
    const programPath = process.argv[3] ? path.resolve(process.argv[3]) : defaultProgram
    const remediation = JSON.parse(fs.readFileSync(remediationPath, 'utf8'))
    const program = JSON.parse(fs.readFileSync(programPath, 'utf8'))
    const result = validateVnextProtocolRemediation(remediation, program, { repoRoot })
    console.log(JSON.stringify({ status: 'pass', remediationPath, programPath, ...result }, null, 2))
  } catch (err) {
    console.error(`vNext protocol-remediation check: ${safeError(err)}`)
    process.exitCode = 1
  }
}

export function validateVnextProtocolRemediation (remediation, program, options = {}) {
  const root = path.resolve(options.repoRoot || repoRoot)
  object(remediation, 'protocol remediation')
  exactKeys(remediation, [
    'schema', 'sourceAudit', 'candidateProtocolCommit', 'authorityPolicy',
    'requiredDecisions', 'controls', 'requiredBeforeFreeze'
  ], 'protocol remediation')
  equal(remediation.schema, 'hiverelay-vnext-protocol-remediation-v1', 'protocol remediation schema')
  safeReference(remediation.sourceAudit, 'source audit')
  if (!SHA1.test(remediation.candidateProtocolCommit || '')) throw new Error('candidate protocol commit must be a full lowercase SHA-1')

  validateAuthorityPolicy(remediation.authorityPolicy, root)
  exactStringSet(remediation.requiredDecisions, ['D-6', 'D-7'], 'required decisions')
  validateControls(remediation.controls)
  uniqueStrings(remediation.requiredBeforeFreeze, 'requiredBeforeFreeze')
  if (remediation.requiredBeforeFreeze.length < 5) throw new Error('requiredBeforeFreeze is incomplete')
  for (const row of remediation.requiredBeforeFreeze) boundedString(row, 'freeze requirement', 16, 512)

  object(program, 'program state')
  if (!Array.isArray(program.decisions) || !Array.isArray(program.gates)) throw new Error('program state lacks decisions or gates')
  const decisions = new Map(program.decisions.map(row => [row.id, row]))
  const d6 = decisions.get('D-6')
  const d7 = decisions.get('D-7')
  if (!d6 || !d7) throw new Error('program state lacks D-6 or D-7')
  const pg2 = program.gates.find(row => row.id === 'PG-2')
  if (!pg2) throw new Error('program state lacks PG-2')
  const controlsPassed = remediation.controls.every(row => row.gateStatus === 'passed')
  const d6Resolved = !String(d6.status || '').startsWith('pending-')
  const d7Ratified = d7.status === 'approved'
  const freezeEligible = controlsPassed && d6Resolved && d7Ratified && pg2.status === 'passed'
  if (remediation.authorityPolicy.freezeAllowed !== freezeEligible) {
    throw new Error(`authority freezeAllowed must equal computed eligibility ${freezeEligible}`)
  }
  if (freezeEligible) {
    if (remediation.authorityPolicy.status !== 'frozen' || remediation.authorityPolicy.finalAuthorityForbidden) {
      throw new Error('eligible authority must explicitly move from draft-only to frozen')
    }
  } else if (remediation.authorityPolicy.status !== 'draft-only' || !remediation.authorityPolicy.finalAuthorityForbidden) {
    throw new Error('ineligible authority must remain draft-only and forbid final paths')
  }

  return {
    schema: remediation.schema,
    authorityStatus: remediation.authorityPolicy.status,
    freezeEligible,
    pendingControls: remediation.controls.filter(row => row.gateStatus !== 'passed').map(row => row.id),
    blockingDecisions: [
      ...(d6Resolved ? [] : ['D-6']),
      ...(d7Ratified ? [] : ['D-7'])
    ]
  }
}

function validateAuthorityPolicy (value, root) {
  object(value, 'authorityPolicy')
  exactKeys(value, ['status', 'freezeAllowed', 'finalAuthorityForbidden', 'finalAuthorityPaths'], 'authorityPolicy')
  if (!['draft-only', 'frozen'].includes(value.status)) throw new Error('authorityPolicy status is invalid')
  if (typeof value.freezeAllowed !== 'boolean' || typeof value.finalAuthorityForbidden !== 'boolean') {
    throw new Error('authorityPolicy booleans are invalid')
  }
  exactStringSet(value.finalAuthorityPaths, FINAL_AUTHORITY_PATHS, 'final authority paths')
  if (!value.finalAuthorityForbidden) return
  const present = FINAL_AUTHORITY_PATHS.filter(relative => fs.existsSync(path.join(root, relative)))
  if (present.length > 0) throw new Error(`final authority paths are forbidden before freeze: ${present.join(', ')}`)
}

function validateControls (rows) {
  if (!Array.isArray(rows)) throw new Error('controls must be an array')
  const ids = rows.map(row => row?.id)
  if (ids.length !== CR_IDS.length || new Set(ids).size !== ids.length || CR_IDS.some(id => !ids.includes(id))) {
    throw new Error(`controls must contain exactly ${CR_IDS.join(', ')}`)
  }
  for (const row of rows) {
    object(row, `control ${row.id}`)
    exactKeys(row, ['id', 'implementationStatus', 'gateStatus', 'requiredValidations', 'evidence'], `control ${row.id}`)
    if (!['missing', 'partial', 'implemented'].includes(row.implementationStatus)) throw new Error(`control ${row.id} implementationStatus is invalid`)
    if (!['blocked', 'pending', 'passed'].includes(row.gateStatus)) throw new Error(`control ${row.id} gateStatus is invalid`)
    uniqueStrings(row.requiredValidations, `control ${row.id} requiredValidations`)
    if (row.requiredValidations.length === 0) throw new Error(`control ${row.id} has no required validation`)
    for (const ref of row.requiredValidations) safeReference(ref, `control ${row.id} validation`)
    uniqueStrings(row.evidence, `control ${row.id} evidence`)
    for (const ref of row.evidence) safeReference(ref, `control ${row.id} evidence`)
    if ((row.gateStatus === 'passed' || row.implementationStatus !== 'missing') && row.evidence.length === 0) {
      throw new Error(`control ${row.id} requires evidence for its claimed progress`)
    }
    if (row.gateStatus === 'passed' && row.implementationStatus !== 'implemented') {
      throw new Error(`passed control ${row.id} must be implemented`)
    }
  }
}

function exactStringSet (actual, expected, label) {
  uniqueStrings(actual, label)
  if (actual.length !== expected.length || expected.some(value => !actual.includes(value))) {
    throw new Error(`${label} must contain exactly ${expected.join(', ')}`)
  }
}

function safeReference (value, label) {
  if (!SAFE_REFERENCE.test(value || '') || value.startsWith('/') || value.includes('..')) throw new Error(`${label} is unsafe`)
}

function uniqueStrings (values, label) {
  if (!Array.isArray(values) || values.some(value => typeof value !== 'string')) throw new Error(`${label} must be a string array`)
  if (new Set(values).size !== values.length) throw new Error(`${label} must not contain duplicates`)
}

function boundedString (value, label, minimum, maximum) {
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum || hasControlChars(value)) {
    throw new Error(`${label} must be a bounded printable string`)
  }
}

function object (value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
}

function exactKeys (value, keys, label) {
  const extra = Object.keys(value).filter(key => !keys.includes(key))
  const missing = keys.filter(key => !Object.hasOwn(value, key))
  if (extra.length || missing.length) throw new Error(`${label} has invalid keys (extra=${extra.join(',') || 'none'} missing=${missing.join(',') || 'none'})`)
}

function equal (actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} must equal ${JSON.stringify(expected)}`)
}

function hasControlChars (value) {
  return Array.from(value).some(character => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127
  })
}

function safeError (err) {
  return Array.from(String(err?.message || err || 'unknown error'), character => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127 ? ' ' : character
  }).join('').slice(0, 1200)
}
