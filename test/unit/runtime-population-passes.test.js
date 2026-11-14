import test from 'brittle'
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

function fixtureNode (t, opts = {}) {
  const storage = mkdtempSync(join(tmpdir(), 'runtime-population-'))
  t.teardown(() => rmSync(storage, { recursive: true, force: true }))
  return new RelayNode({ storage, enableAPI: false, enableServices: false, ...opts })
}

function page (entries, complete, highWater) {
  return {
    entries,
    examined: entries.length,
    gcExamined: 0,
    reclaimed: 0,
    complete,
    completedHighWater: complete ? highWater : 0,
    nextHighWater: highWater,
    cyclesCompleted: complete ? 1 : 0
  }
}

test('runtime pass budgets reject ambiguous numeric values at construction', async (t) => {
  const fields = {
    registryScanBudget: 64,
    replicationCheckBudget: 64,
    anchorCheckBudget: 32,
    repairBudget: 32,
    repairMaxConcurrent: 3,
    custodyExpiryBudget: 32,
    custodyWitnessBudget: 32,
    acceptanceReconcileBudget: 32
  }
  const invalid = [0, -1, 1.5, NaN, Infinity, '1']
  for (const [field, maximum] of Object.entries(fields)) {
    for (const value of [...invalid, maximum + 1]) {
      await t.exception.all(() => fixtureNode(t, { [field]: value }), new RegExp(field))
    }
  }
})

test('replication health publishes only a completed high-water cycle', async (t) => {
  const node = fixtureNode(t)
  const a = 'a'.repeat(64)
  const b = 'b'.repeat(64)
  const pages = [
    page([{ appKey: a, replicationFactor: 2 }], false, 2),
    page([{ appKey: b, replicationFactor: 1 }], true, 2)
  ]
  node.config.replicationRepairEnabled = false
  node.seedingRegistry = {
    getActiveRequestsPage: () => pages.shift(),
    getRelaysForApp: async (key) => key === a
      ? []
      : [{ relayPubkey: 'c'.repeat(64) }, { relayPubkey: 'd'.repeat(64) }]
  }

  const first = await node._checkReplicationHealth()
  t.is(first.complete, false)
  t.is(node._replicationHealth.size, 0, 'partial state stays private')
  t.is(node._replicationHealthBuild.size, 1)

  const second = await node._checkReplicationHealth()
  t.is(second.complete, true)
  t.is(node._replicationHealth.size, 2, 'full aggregate publishes atomically')
  t.is(node._replicationHealth.get(a).state, 'under-replicated')
  t.is(node._replicationHealth.get(b).state, 'healthy')
})

test('anchor health publishes only after a completed page cycle', async (t) => {
  const node = fixtureNode(t)
  const a = { anchored: true, storageProvedDriveVersion: 1, drive: { version: 1 } }
  const b = { anchored: true, storageProvedDriveVersion: 1, drive: { version: 1 } }
  const pages = [
    page([{ key: 'a'.repeat(64), value: a }], false, 2),
    page([{ key: 'b'.repeat(64), value: b }], true, 2)
  ]
  node.appRegistry = {
    physicalReadOnly: false,
    page: () => pages.shift(),
    recordAnchorCheck: () => true,
    clearAnchored: () => true
  }
  node.appLifecycle = { _isDriveFullyReplicated: async () => true }

  await node._runAnchorCheck()
  t.is(node._anchorCheckAggregate.checked, 0, 'partial aggregate is not visible')
  await node._runAnchorCheck()
  t.is(node._anchorCheckAggregate.checked, 2)
  t.is(node._anchorCheckAggregate.anchored, 2)
  t.is(node._anchorCheckAggregate.completedHighWater, 2)
})

test('custody witness budget one advances outer and child work separately', async (t) => {
  const node = fixtureNode(t, { custodyWitnessBudget: 1 })
  const now = Date.now()
  const intentId = 'd'.repeat(64)
  const relayPubkey = 'e'.repeat(64)
  const intent = { intentId, retainUntil: now - 1, blindContentId: 'f'.repeat(64) }
  let witnessed = 0
  node.swarm = { keyPair: { publicKey: Buffer.alloc(32, 1) } }
  node.seedingRegistry = {
    getCustodyIntentPage: () => page([{ key: intentId, value: intent }], true, 1),
    getCustodyWitnessWork: () => ({
      intent,
      sourceRetirement: null,
      candidates: [{ relayPubkey }],
      examined: 1,
      complete: true,
      nextCursor: 0
    })
  }
  node.createCustodyExpiryWitness = async () => { witnessed++ }

  const outer = await node._runCustodyExpiryWitnessPass(now)
  t.is(outer.examined, 1)
  t.is(outer.complete, false)
  t.is(witnessed, 0, 'no child promise launches without budget')

  const child = await node._runCustodyExpiryWitnessPass(now)
  t.is(child.examined, 1)
  t.is(child.complete, true)
  t.is(child.completedHighWater, 1)
  t.is(witnessed, 1)
})

test('runtime cursor ownership is explicitly released on stop', (t) => {
  const node = fixtureNode(t)
  const appConsumers = []
  const registryConsumers = []
  node.appRegistry = {
    releasePopulationConsumer: consumer => appConsumers.push(consumer)
  }
  node.seedingRegistry = {
    releasePopulationConsumer: (population, consumer) => registryConsumers.push(`${population}:${consumer}`)
  }
  node._custodyWitnessProofCursor.set('intent', 3)
  node._custodyWitnessActiveIntent = { intentId: 'intent' }

  node._releaseRuntimePopulationConsumers()
  t.ok(appConsumers.includes('repair'))
  t.ok(appConsumers.includes('anchor'))
  t.ok(registryConsumers.includes('requests:replication-monitor'))
  t.ok(registryConsumers.includes('custody-intents:custody-witness'))
  t.is(node._custodyWitnessProofCursor.size, 0)
  t.is(node._custodyWitnessActiveIntent, null)
})
