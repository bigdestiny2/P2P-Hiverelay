// Ordinary fixture producer/replay. Uses frozen semantic entry streams, opens no store.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { populatedCellState } from './cell-predecessor-fixture.js'
import { populatedInboxState, expiredInboxState } from './inbox-predecessor-fixture.js'
import { createBlindCellControlSnapshotSemanticAuthority, streamBlindCellControlSnapshotEntries, reconstructBlindCellControlSnapshot } from '../../blind-daemon/cell-control-snapshot.js'
import { createBlindInboxControlSnapshotSemanticAuthority, streamBlindInboxControlSnapshotEntries, reconstructBlindInboxControlSnapshot } from '../../blind-daemon/inbox-control-snapshot.js'
import { canonicalJSON } from './codec.js'

const families = [
  ['cell-populated', 1, populatedCellState, createBlindCellControlSnapshotSemanticAuthority, streamBlindCellControlSnapshotEntries, reconstructBlindCellControlSnapshot],
  ['inbox-populated-retry', 2, populatedInboxState, createBlindInboxControlSnapshotSemanticAuthority, streamBlindInboxControlSnapshotEntries, reconstructBlindInboxControlSnapshot],
  ['inbox-expired-append', 2, expiredInboxState, createBlindInboxControlSnapshotSemanticAuthority, streamBlindInboxControlSnapshotEntries, reconstructBlindInboxControlSnapshot]
]
const fixtures = []
for (const [id, role, make, authority, stream, reconstruct] of families) {
  const state = make(); const auth = authority(); const entries = []
  for await (const entry of stream(auth, state)) entries.push(entry)
  const header = { relayPublicKey: state.relayPublicKey, storeId: state.storeId, durabilityContinuityHash: state.durabilityContinuityHash, walSequence: 7n, walHash: Buffer.alloc(32, 4) }
  const result = await reconstruct(auth, { header, checkpointHeader: { ...header, coveredWalSequence: header.walSequence, coveredWalHash: header.walHash, epochFloor: state.epochFloor }, declaredEntryCount: entries.length, entries })
  const recovered = role === 1 ? result.cellState : result.inboxState
  assert.equal(recovered.spends.size, state.spends.size)
  const rows = entries.map(e => { assert.equal(e.key[0], role + 1); return { kind: e.entryKind, subtype: e.key[1], key: e.key.subarray(2), value: e.value } })
  assert.ok(rows.some(r => r.kind === 1))
  fixtures.push({ id, role, identity: { relayPublicKey: state.relayPublicKey, storeId: state.storeId, durabilityContinuityHash: state.durabilityContinuityHash }, floors: { epoch: state.epochFloor, clockUnsafe: state.clockUnsafe ? 1 : 0, recoveryGap: 0 }, rows, entries: rows.length, recoveredSpends: recovered.spends.size, accounting: Object.fromEntries(Object.entries(recovered.accounting).filter(([key]) => key !== 'stagingByProfile')) })
}
const sourcePins = Object.fromEntries(['cell', 'inbox'].map(role => {
  const path = `packages/blind-daemon/test/${role}-control-snapshot.test.js`
  return [path, createHash('sha256').update(readFileSync(new URL(`../../blind-daemon/test/${role}-control-snapshot.test.js`, import.meta.url))).digest('hex')]
}))
const bytes = Buffer.from(canonicalJSON({ sourcePins, fixtures, fixtureEvidenceOnly: true, engineHydration: false }) + '\n')
const path = new URL('./populated-family-fixtures.json', import.meta.url)
if (process.argv.includes('--check')) assert.deepEqual(readFileSync(path), bytes)
else writeFileSync(path, bytes)
console.log(JSON.stringify({ check: process.argv.includes('--check'), families: fixtures.map(f => ({ id: f.id, rows: f.entries, spends: f.recoveredSpends, accounting: f.accounting })), sha256: createHash('sha256').update(bytes).digest('hex'), actualFrozenSemanticReconstruction: true, engineHydration: false }))
