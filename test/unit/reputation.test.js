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

test('ReputationSystem - export and import', async (t) => {
  const rep1 = new ReputationSystem()
  for (let i = 0; i < 10; i++) rep1.recordChallenge('relay-x', true, 150)

  const exported = rep1.export()

  const rep2 = new ReputationSystem()
  rep2.import(exported)

  t.is(rep2.getScore('relay-x'), rep1.getScore('relay-x'))
  t.is(rep2.getReliability('relay-x'), 1.0)
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
