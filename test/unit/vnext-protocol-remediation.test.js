import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { validateVnextProtocolRemediation } from '../../scripts/check-vnext-protocol-remediation.mjs'

const remediation = JSON.parse(fs.readFileSync(new URL(
  '../../docs/vnext/protocol-remediation.json', import.meta.url), 'utf8'))
const program = JSON.parse(fs.readFileSync(new URL(
  '../../docs/vnext/program-state.json', import.meta.url), 'utf8'))

test('vNext protocol remediation keeps the audited candidate draft-only', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vnext-protocol-control-'))
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  const result = validateVnextProtocolRemediation(
    structuredClone(remediation), structuredClone(program), { repoRoot: root })
  t.is(result.authorityStatus, 'draft-only')
  t.absent(result.freezeEligible)
  t.alike(result.blockingDecisions, ['D-6', 'D-7'])
  t.is(result.pendingControls.length, 8)
})

test('vNext protocol remediation rejects final authorities before freeze', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vnext-protocol-final-'))
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  const relative = remediation.authorityPolicy.finalAuthorityPaths[0]
  const target = path.join(root, relative)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, '{}\n')
  t.exception(() => validateVnextProtocolRemediation(
    structuredClone(remediation), structuredClone(program), { repoRoot: root }),
  /final authority paths are forbidden before freeze/)
})

test('vNext protocol remediation computes freeze eligibility from controls, decisions, and PG-2', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vnext-protocol-eligible-'))
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  const state = structuredClone(remediation)
  const board = structuredClone(program)
  for (const row of state.controls) {
    row.implementationStatus = 'implemented'
    row.gateStatus = 'passed'
    row.evidence = [`evidence/${row.id}.json`]
  }
  board.decisions.find(row => row.id === 'D-6').status = 'approved'
  board.decisions.find(row => row.id === 'D-7').status = 'approved'
  board.gates.find(row => row.id === 'PG-2').status = 'passed'

  t.exception(() => validateVnextProtocolRemediation(state, board, { repoRoot: root }),
    /freezeAllowed must equal computed eligibility true/)

  state.authorityPolicy.status = 'frozen'
  state.authorityPolicy.freezeAllowed = true
  state.authorityPolicy.finalAuthorityForbidden = false
  const result = validateVnextProtocolRemediation(state, board, { repoRoot: root })
  t.ok(result.freezeEligible)
  t.alike(result.pendingControls, [])
  t.alike(result.blockingDecisions, [])
})

test('vNext protocol remediation rejects invented control progress', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vnext-protocol-evidence-'))
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  const state = structuredClone(remediation)
  state.controls[0].gateStatus = 'passed'
  state.controls[0].implementationStatus = 'partial'
  t.exception(() => validateVnextProtocolRemediation(
    state, structuredClone(program), { repoRoot: root }), /passed control CR-1 must be implemented/)
})
