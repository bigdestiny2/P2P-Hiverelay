import test from 'brittle'
import { ReputationSystem } from 'p2p-hiverelay/incentive/reputation/index.js'
import { mkdtemp, rm, readdir, readFile } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

test('ReputationSystem - records challenges and computes score', async (t) => {
  const rep = new ReputationSystem()
  const relay = 'abc123'

  rep.recordChallenge(relay, true, 200)
  rep.recordChallenge(relay, true, 300)
  rep.recordChallenge(relay, false, 0)

  const record = rep.getRecord(relay)
  t.is(record.totalChallenges, 3)
  t.is(record.passedChallenges, 2)
  t.is(record.failedChallenges, 1)
  t.ok(record.score >= 0, 'score is non-negative')
  t.is(record.avgLatencyMs, 250)
})

test('ReputationSystem - reliability calculation', async (t) => {
  const rep = new ReputationSystem()
  const relay = 'def456'

  for (let i = 0; i < 8; i++) rep.recordChallenge(relay, true, 100)
  for (let i = 0; i < 2; i++) rep.recordChallenge(relay, false, 0)

  const reliability = rep.getReliability(relay)
  t.is(reliability, 0.8, '80% reliability')
})

test('ReputationSystem - decay reduces scores', async (t) => {
  const rep = new ReputationSystem()
  const relay = 'ghi789'

  rep.recordChallenge(relay, true, 100)
  const before = rep.getScore(relay)

  rep.applyDecay()
  const after = rep.getScore(relay)

  t.ok(after < before, 'score decreased after decay')
})

test('ReputationSystem - leaderboard ranking', async (t) => {
  const rep = new ReputationSystem()

  // Create 3 relays with different scores
  for (let i = 0; i < 15; i++) rep.recordChallenge('relay-a', true, 100)
  for (let i = 0; i < 12; i++) rep.recordChallenge('relay-b', true, 200)
  for (let i = 0; i < 10; i++) rep.recordChallenge('relay-c', true, 500)

  const board = rep.getLeaderboard()
  t.is(board.length, 3)
  t.is(board[0].relay, 'relay-a', 'highest score first')
})

test('ReputationSystem - leaderboard ties are deterministic', async (t) => {
  const rep = new ReputationSystem()
  rep.import({
    'relay-b': reputationRecord({ score: 100, avgLatencyMs: 250 }),
    'relay-a': reputationRecord({ score: 100, avgLatencyMs: 250 }),
    'relay-c': reputationRecord({ score: 100, avgLatencyMs: 250 })
  })

  t.alike(rep.getLeaderboard().map(r => r.relay), ['relay-a', 'relay-b', 'relay-c'])
})

test('ReputationSystem - selectRelays picks best', async (t) => {
  const rep = new ReputationSystem()

  for (let i = 0; i < 20; i++) rep.recordChallenge('good', true, 100)
  for (let i = 0; i < 15; i++) rep.recordChallenge('ok', true, 300)
  for (let i = 0; i < 10; i++) rep.recordChallenge('bad', false, 0)
  for (let i = 0; i < 5; i++) rep.recordChallenge('bad', true, 1000)

  const selected = rep.selectRelays(2)
  t.is(selected.length, 2)
  t.is(selected[0], 'good', 'best relay selected first')
})

test('ReputationSystem - selectRelays ties are deterministic', async (t) => {
  const rep = new ReputationSystem()
  rep.import({
    'relay-b': reputationRecord({ score: 100, avgLatencyMs: 100 }),
    'relay-a': reputationRecord({ score: 100, avgLatencyMs: 100 }),
    'relay-c': reputationRecord({ score: 100, avgLatencyMs: 100 })
  })

  t.alike(rep.selectRelays(3), ['relay-a', 'relay-b', 'relay-c'])
})

test('ReputationSystem - export and import', async (t) => {
  const rep1 = new ReputationSystem()
  for (let i = 0; i < 10; i++) rep1.recordChallenge('relay-x', true, 150)

  const exported = rep1.export()

  const rep2 = new ReputationSystem()
  rep2.import(exported)

  t.is(rep2.getScore('relay-x'), rep1.getScore('relay-x'))
  t.is(rep2.getReliability('relay-x'), 1.0)
})

test('ReputationSystem - export order is deterministic and skips forbidden keys', async (t) => {
  const rep = new ReputationSystem()
  const poisoned = JSON.parse(JSON.stringify({
    'relay-c': reputationRecord({ score: 3 }),
    'relay-a': reputationRecord({ score: 1 }),
    constructor: reputationRecord({ score: 99 }),
    'relay-b': reputationRecord({ score: 2 })
  }))
  Object.defineProperty(poisoned, '__proto__', {
    value: reputationRecord({ score: 99 }),
    enumerable: true
  })
  rep.import(poisoned)

  const exported = rep.export()
  t.alike(Object.keys(exported), ['relay-a', 'relay-b', 'relay-c'])
  t.absent(Object.prototype.hasOwnProperty.call(exported, '__proto__'))
  t.absent(Object.prototype.hasOwnProperty.call(exported, 'constructor'))
})

test('ReputationSystem - import sanitizes malformed persisted records', async (t) => {
  const rep = new ReputationSystem()
  rep.import({
    relay: {
      score: -10,
      totalChallenges: 10.9,
      passedChallenges: 50,
      failedChallenges: 50,
      avgLatencyMs: -1,
      totalBytesServed: '2048',
      totalUptimeHours: Number.POSITIVE_INFINITY,
      region: '<region>',
      geoBonus: 'yes',
      firstSeen: 123,
      lastActivity: 456
    },
    bad: null
  })

  const record = rep.getRecord('relay')
  t.is(record.score, 0)
  t.is(record.totalChallenges, 10)
  t.is(record.passedChallenges, 10)
  t.is(record.failedChallenges, 0)
  t.is(record.avgLatencyMs, 0)
  t.is(record.totalBytesServed, 2048)
  t.is(record.totalUptimeHours, 0)
  t.is(record.geoBonus, false)
  t.is(rep.getRecord('bad'), null)
})

test('ReputationSystem - save is atomic: round-trips and leaves no .tmp', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-rep-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const filePath = join(dir, 'reputation.json')

  const rep = new ReputationSystem()
  for (let i = 0; i < 5; i++) rep.recordChallenge('relay-z', true, 120)
  await rep.save(filePath)

  // The tmp file must have been renamed away, never left behind.
  const files = await readdir(dir)
  t.absent(files.some(f => f.endsWith('.tmp')), 'no leftover .tmp after save')
  t.ok(files.includes('reputation.json'), 'final file present')

  const reloaded = await ReputationSystem.load(filePath)
  t.is(reloaded.getScore('relay-z'), rep.getScore('relay-z'), 'round-trips through disk')
})

test('ReputationSystem - failed save preserves the existing file (no corruption)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-rep-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const filePath = join(dir, 'reputation.json')

  // Seed a known-good file.
  const good = new ReputationSystem()
  for (let i = 0; i < 3; i++) good.recordChallenge('relay-g', true, 100)
  await good.save(filePath)
  const goodBytes = await readFile(filePath, 'utf8')

  // Force the write to fail: point save at a path whose parent is a FILE,
  // so writeFile(tmp) throws. The original file must be untouched and no
  // tmp must be left behind.
  const rep = new ReputationSystem()
  rep.recordChallenge('relay-bad', true, 100)
  let errored = false
  rep.on('save-error', () => { errored = true })
  await rep.save(join(filePath, 'nested.json')) // filePath is a file, not a dir

  t.ok(errored, 'save-error emitted on failure')
  t.is(await readFile(filePath, 'utf8'), goodBytes, 'existing file untouched on failed save')
  const files = await readdir(dir)
  t.absent(files.some(f => f.endsWith('.tmp')), 'no leftover .tmp after failed save')
})

function reputationRecord (overrides = {}) {
  return {
    score: 100,
    totalChallenges: 10,
    passedChallenges: 10,
    failedChallenges: 0,
    avgLatencyMs: 100,
    totalBytesServed: 0,
    totalUptimeHours: 0,
    region: 'test',
    geoBonus: false,
    firstSeen: 1,
    lastActivity: 2,
    ...overrides
  }
}
