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
const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/

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
  exactKeys(state, ['schema', 'releaseTrain', 'profiles', 'decisions', 'gates', 'tracks'], 'program state')
  equal(state.schema, 'hiverelay-vnext-program-state-v1', 'program state schema')

  validateReleaseTrain(state.releaseTrain)
  validateProfiles(state.profiles)
  validateDecisions(state.decisions)
  validateGates(state.gates)
  validateTracks(state.tracks)

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
  equal(value.candidatePattern, 'v0.25.0-rc.N', 'release candidate pattern')
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
    exactKeys(row, ['id', 'status', 'claim', 'requiredGates'], `profile ${row.id}`)
    if (!['spec-only', 'discovery-only', 'hardening', 'candidate', 'promoted'].includes(row.status)) {
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
    exactKeys(row, ['id', 'status', 'question', 'recommendation', 'selected', 'evidence'], `decision ${row.id}`)
    if (!['pending-owner', 'pending-owner-legal', 'approved', 'rejected', 'deferred'].includes(row.status)) {
      throw new Error(`decision ${row.id} status is invalid`)
    }
    boundedString(row.question, `decision ${row.id} question`, 16, 512)
    boundedString(row.recommendation, `decision ${row.id} recommendation`, 3, 128)
    safeEvidence(row.evidence, `decision ${row.id} evidence`)
    const pending = row.status.startsWith('pending-')
    if (pending && row.selected !== null) throw new Error(`pending decision ${row.id} cannot encode a selection`)
    if (!pending && (!SAFE_TOKEN.test(row.selected || '') || row.evidence.length === 0)) {
      throw new Error(`resolved decision ${row.id} requires a selected option and evidence`)
    }
  }
}

function validateGates (rows) {
  exactIdSet(rows, GATES, 'gates')
  for (const row of rows) {
    exactKeys(row, ['id', 'status', 'evidence'], `gate ${row.id}`)
    if (!['pending', 'in-progress', 'blocked', 'passed'].includes(row.status)) throw new Error(`gate ${row.id} status is invalid`)
    safeEvidence(row.evidence, `gate ${row.id} evidence`)
    if (row.status === 'passed' && row.evidence.length === 0) throw new Error(`passed gate ${row.id} requires evidence`)
  }
}

function validateTracks (rows) {
  exactIdSet(rows, TRACKS, 'tracks')
  for (const row of rows) {
    exactKeys(row, ['id', 'status', 'handoffs'], `track ${row.id}`)
    if (!['pending', 'in-progress', 'blocked', 'completed'].includes(row.status)) throw new Error(`track ${row.id} status is invalid`)
    safeEvidence(row.handoffs, `track ${row.id} handoffs`)
    if (row.status === 'completed' && row.handoffs.length === 0) throw new Error(`completed track ${row.id} requires a handoff`)
  }
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
