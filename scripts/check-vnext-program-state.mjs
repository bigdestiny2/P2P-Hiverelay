#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const repoRoot = path.resolve(path.dirname(scriptPath), '..')
const DEFAULT_STATE = path.join(repoRoot, 'docs', 'vnext', 'program-state.json')

const DECISIONS = ['D-1', 'D-2', 'D-3', 'D-4', 'D-5', 'D-6', 'D-7']
const GATES = Array.from({ length: 11 }, (_, index) => `PG-${index}`)
const TRACKS = [
  'T00', 'T01', 'T01B', 'T02', 'T03', 'T04', 'T05', 'T06', 'T07', 'T08',
  'T09', 'T10', 'T11', 'T12', 'T13', 'T14', 'T14M', 'T15', 'T15H', 'T16',
  'T17', 'T18', 'T19', 'T20', 'T21'
]
const PROFILES = [
  'public-t1-gateway',
  'direct-blind-g2s',
  'g3-randomized-cells',
  'split-web-ohttp-v1',
  'browser-hc11-cs7'
]
const SHA1 = /^[0-9a-f]{40}$/
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/
const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._/@#-]{0,255}$/

if (path.resolve(process.argv[1] || '') === scriptPath) {
  try {
    const statePath = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_STATE
    const state = JSON.parse(fs.readFileSync(statePath, 'utf8'))
    const result = validateVnextProgramState(state)
    console.log(JSON.stringify({ status: 'pass', path: statePath, ...result }, null, 2))
  } catch (err) {
    console.error(`vNext program-state check: ${safeError(err)}`)
    process.exitCode = 1
  }
}

export function validateVnextProgramState (state) {
  object(state, 'program state')
  exactKeys(state, ['schema', 'releaseTrain', 'profiles', 'decisions', 'gates', 'tracks',
    'lastHiveRelayConductorPass', 'lastOwnerDecisionPass', 'activeShipTrack'], 'program state')
  equal(state.schema, 'hiverelay-vnext-program-state-v1', 'program state schema')

  validateReleaseTrain(state.releaseTrain)
  validateProfiles(state.profiles)
  validateDecisions(state.decisions)
  validateGates(state.gates)
  validateTracks(state.tracks)
  validatePassRecord(state.lastHiveRelayConductorPass, 'lastHiveRelayConductorPass')
  validatePassRecord(state.lastOwnerDecisionPass, 'lastOwnerDecisionPass')
  validateActiveShipTrack(state.activeShipTrack)

  return {
    schema: state.schema,
    profiles: state.profiles.length,
    pendingDecisions: state.decisions.filter(row => row.status.startsWith('pending-')).map(row => row.id),
    passedGates: state.gates.filter(row => row.status === 'passed').map(row => row.id),
    activeTracks: state.tracks.filter(row => row.status === 'in-progress').map(row => row.id)
  }
}

function validateReleaseTrain (value) {
  object(value, 'releaseTrain')
  exactKeys(value, ['candidatePattern', 'artifactBaseline', 'integrationBase'], 'releaseTrain')
  equal(value.candidatePattern, 'v0.26.0-rc.N', 'release candidate pattern')
  object(value.artifactBaseline, 'artifactBaseline')
  exactKeys(value.artifactBaseline, ['tag', 'commit'], 'artifactBaseline')
  equal(value.artifactBaseline.tag, 'v0.24.3', 'artifact baseline tag')
  if (!SHA1.test(value.artifactBaseline.commit || '')) throw new Error('artifact baseline commit must be a full lowercase SHA-1')
  object(value.integrationBase, 'integrationBase')
  exactKeys(value.integrationBase, ['branch', 'commit'], 'integrationBase')
  if (!SAFE_TOKEN.test(value.integrationBase.branch || '')) throw new Error('integration branch is invalid')
  if (!SHA1.test(value.integrationBase.commit || '')) throw new Error('integration base commit must be a full lowercase SHA-1')
}

function validateProfiles (rows) {
  exactIdSet(rows, PROFILES, 'profiles')
  const gateSet = new Set(GATES)
  for (const row of rows) {
    keysAllowing(row, ['id', 'status', 'claim', 'requiredGates'], ['liveTip', 'priority', 'remaining'], `profile ${row.id}`)
    if (!['spec-only', 'discovery-only', 'hardening', 'candidate', 'promoted', 'active-ship-track', 'parked-per-D-1'].includes(row.status)) {
      throw new Error(`profile ${row.id} status is invalid`)
    }
    boundedString(row.claim, `profile ${row.id} claim`, 16, 512)
    uniqueStrings(row.requiredGates, `profile ${row.id} requiredGates`)
    if (row.requiredGates.some(id => !gateSet.has(id))) throw new Error(`profile ${row.id} names an unknown gate`)
  }
}

function validateDecisions (rows) {
  exactIdSet(rows, DECISIONS, 'decisions')
  for (const row of rows) {
    keysAllowing(row, [
      'id', 'owner', 'deadline', 'status', 'question', 'recommendation',
      'recommendationRationale', 'affectedProfiles', 'blocks',
      'supersededAssumptions', 'selected', 'rationale', 'evidence'
    ], ['decidedAt', 'followedRecommendation', 'recommendationWas', 'note'], `decision ${row.id}`)
    if (!['pending-owner', 'pending-owner-legal', 'approved', 'rejected', 'deferred', 'decided'].includes(row.status)) {
      throw new Error(`decision ${row.id} status is invalid`)
    }
    if (row.decidedAt !== undefined && (typeof row.decidedAt !== 'string' || !ISO_INSTANT.test(row.decidedAt))) throw new Error(`decision ${row.id} decidedAt is invalid`)
    if (!SAFE_TOKEN.test(row.owner || '')) throw new Error(`decision ${row.id} owner is invalid`)
    if (row.deadline !== null && !isCanonicalDate(row.deadline)) throw new Error(`decision ${row.id} deadline is invalid`)
    boundedString(row.question, `decision ${row.id} question`, 16, 512)
    boundedString(row.recommendation, `decision ${row.id} recommendation`, 3, 128)
    boundedString(row.recommendationRationale, `decision ${row.id} recommendation rationale`, 16, 512)
    uniqueStrings(row.affectedProfiles, `decision ${row.id} affectedProfiles`)
    if (row.affectedProfiles.length === 0 || row.affectedProfiles.some(id => !PROFILES.includes(id))) {
      throw new Error(`decision ${row.id} affectedProfiles are invalid`)
    }
    safeEvidence(row.blocks, `decision ${row.id} blocks`)
    if (row.blocks.length === 0) throw new Error(`decision ${row.id} must name a blocked boundary`)
    uniqueStrings(row.supersededAssumptions, `decision ${row.id} supersededAssumptions`)
    if (row.supersededAssumptions.length === 0) throw new Error(`decision ${row.id} must name a superseded assumption`)
    for (const assumption of row.supersededAssumptions) {
      boundedString(assumption, `decision ${row.id} superseded assumption`, 8, 512)
    }
    safeEvidence(row.evidence, `decision ${row.id} evidence`)
    const pending = row.status.startsWith('pending-')
    if (pending && row.selected !== null) throw new Error(`pending decision ${row.id} cannot encode a selection`)
    if (pending && row.rationale !== null) throw new Error(`pending decision ${row.id} cannot encode a rationale`)
    // A 'decided' row carries decidedAt instead of a forward deadline; the
    // older resolved statuses still require the deadline they were set against.
    if (!pending && row.status === 'decided' && row.decidedAt === undefined) {
      throw new Error(`decided decision ${row.id} requires decidedAt`)
    }
    if (!pending && row.status !== 'decided' && row.deadline === null) throw new Error(`resolved decision ${row.id} requires its decision deadline`)
    if (!pending && (!SAFE_TOKEN.test(row.selected || '') || row.evidence.length === 0)) {
      throw new Error(`resolved decision ${row.id} requires a selected option and evidence`)
    }
    if (!pending) boundedString(row.rationale, `decision ${row.id} rationale`, 16, 1024)
  }
}

function validateGates (rows) {
  exactIdSet(rows, GATES, 'gates')
  for (const row of rows) {
    keysAllowing(row, ['id', 'status', 'evidence'], ['notes'], `gate ${row.id}`)
    if (!['pending', 'in-progress', 'blocked', 'passed', 'decided-with-open-followups'].includes(row.status)) throw new Error(`gate ${row.id} status is invalid`)
    safeEvidence(row.evidence, `gate ${row.id} evidence`)
    if (row.status === 'passed' && row.evidence.length === 0) throw new Error(`passed gate ${row.id} requires evidence`)
  }
}

function validateTracks (rows) {
  exactIdSet(rows, TRACKS, 'tracks')
  for (const row of rows) {
    exactKeys(row, ['id', 'status', 'handoffs'], `track ${row.id}`)
    if (!['pending', 'in-progress', 'blocked', 'completed'].includes(row.status)) throw new Error(`track ${row.id} status is invalid`)
    // Handoffs are prose notes, not reference tokens.
    uniqueStrings(row.handoffs, `track ${row.id} handoffs`)
    for (const handoff of row.handoffs) boundedString(handoff, `track ${row.id} handoff`, 8, 512)
    if (row.status === 'completed' && row.handoffs.length === 0) throw new Error(`completed track ${row.id} requires a handoff`)
  }
}

// The conductor/owner pass ledgers are append-only records of what was done
// and decided; their fields are free-form except the timestamps, which pin
// the ledger to an ISO instant so later passes order correctly.
function validatePassRecord (value, label) {
  object(value, label)
  if (typeof value.at !== 'string' || !ISO_INSTANT.test(value.at)) throw new Error(`${label}.at must be an ISO instant`)
}

function validateActiveShipTrack (value) {
  object(value, 'activeShipTrack')
  exactKeys(value, ['id', 'setAt', 'reason', 'posture', 'fleetBlockedUntil'], 'activeShipTrack')
  if (typeof value.id !== 'string' || value.id.length === 0) throw new Error('activeShipTrack.id must be a non-empty string')
  if (typeof value.setAt !== 'string' || !ISO_INSTANT.test(value.setAt)) throw new Error('activeShipTrack.setAt must be an ISO instant')
  if (typeof value.posture !== 'string' || value.posture.length === 0) throw new Error('activeShipTrack.posture must be a non-empty string')
}

function exactIdSet (rows, expected, label) {
  if (!Array.isArray(rows)) throw new Error(`${label} must be an array`)
  const ids = rows.map((row, index) => {
    object(row, `${label}[${index}]`)
    return row.id
  })
  if (new Set(ids).size !== ids.length) throw new Error(`${label} contains duplicate ids`)
  if (ids.length !== expected.length || expected.some(id => !ids.includes(id))) {
    throw new Error(`${label} must contain exactly ${expected.join(', ')}`)
  }
}

function safeEvidence (values, label) {
  uniqueStrings(values, label)
  for (const value of values) {
    if (!SAFE_TOKEN.test(value) || value.startsWith('/') || value.includes('..')) throw new Error(`${label} contains an unsafe reference`)
  }
}

function uniqueStrings (values, label) {
  if (!Array.isArray(values) || values.some(value => typeof value !== 'string')) throw new Error(`${label} must be a string array`)
  if (new Set(values).size !== values.length) throw new Error(`${label} must not contain duplicates`)
}

function boundedString (value, label, min, max) {
  if (typeof value !== 'string' || value.length < min || value.length > max || hasControlChars(value)) {
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

function keysAllowing (value, required, optional, label) {
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new Error(`${label} is missing required key ${key}`)
  }
  const allowed = new Set([...required, ...optional])
  const extra = Object.keys(value).filter(key => !allowed.has(key))
  if (extra.length) throw new Error(`${label} has unexpected keys (${extra.join(',')})`)
}

function equal (actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} must equal ${JSON.stringify(expected)}`)
}

function safeError (err) {
  return Array.from(String(err?.message || err || 'unknown error'), character => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127 ? ' ' : character
  }).join('').slice(0, 1000)
}

function hasControlChars (value) {
  return Array.from(value).some(character => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127
  })
}

function isCanonicalDate (value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00.000Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}
