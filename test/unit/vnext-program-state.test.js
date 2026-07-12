import test from 'brittle'
import fs from 'node:fs'
import { validateVnextProgramState } from '../../scripts/check-vnext-program-state.mjs'

const canonical = JSON.parse(fs.readFileSync(new URL('../../docs/vnext/program-state.json', import.meta.url), 'utf8'))

test('vNext program state validates the canonical release train without approving pending decisions', (t) => {
  const result = validateVnextProgramState(structuredClone(canonical))
  t.is(result.schema, 'hiverelay-vnext-program-state-v1')
  t.is(result.profiles, 5)
  t.alike(result.pendingDecisions, ['D-1', 'D-2', 'D-3', 'D-4', 'D-5', 'D-6', 'D-7'])
  t.alike(result.passedGates, [])
  t.alike(result.activeTracks, ['T00', 'T01', 'T05'])
})

test('vNext program state rejects recommendation-as-authorization drift', (t) => {
  const state = structuredClone(canonical)
  state.decisions[0].selected = state.decisions[0].recommendation
  t.exception(() => validateVnextProgramState(state), /pending decision D-1 cannot encode a selection/)
})

test('vNext program state rejects evidence-free completion and promotion', (t) => {
  const gate = structuredClone(canonical)
  gate.gates[0].status = 'passed'
  t.exception(() => validateVnextProgramState(gate), /passed gate PG-0 requires evidence/)

  const track = structuredClone(canonical)
  track.tracks[0].status = 'completed'
  t.exception(() => validateVnextProgramState(track), /completed track T00 requires a handoff/)
})

test('vNext program state rejects missing ids, unsafe evidence, and baseline drift', (t) => {
  const missing = structuredClone(canonical)
  missing.gates.pop()
  t.exception(() => validateVnextProgramState(missing), /gates must contain exactly/)

  const unsafe = structuredClone(canonical)
  unsafe.gates[0].evidence.push('../invented.json')
  t.exception(() => validateVnextProgramState(unsafe), /unsafe reference/)

  const drift = structuredClone(canonical)
  drift.releaseTrain.artifactBaseline.commit = 'a'.repeat(40)
  drift.releaseTrain.artifactBaseline.tag = 'v0.24.2'
  t.exception(() => validateVnextProgramState(drift), /artifact baseline tag/)
})
