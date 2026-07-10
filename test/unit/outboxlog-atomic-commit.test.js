import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { appendFile, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { hostname, tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  DEFAULT_OUTBOXLOG_NAMESPACE,
  OUTBOXLOG_MAX_REPLAY_COMMIT_BYTES,
  OutboxLogApp,
  canonicalOutboxRecord,
  createJsonlOutboxJournal,
  createMemoryOutboxJournal,
  createMemoryOutboxPersistence,
  createOutboxLog
} from '../../packages/services/builtin/outboxlog/index.js'
import {
  createOutboxLogHttpState,
  createOutboxLogTokenAuth,
  handleOutboxLogRoute
} from '../../packages/services/builtin/outboxlog/http-adapter.js'

const EMPTY_ROOT = sha256('')

test('outboxlog atomic commit: durable genesis is one journal transaction and retries are idempotent', (t) => {
  const writer = keyPair(41)
  const journal = durableMemoryJournal()
  const log = createOutboxLog({ journal })
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'p1', title: 'genesis', meta: { nested: {} } } }]
  })

  const receipt = log.sync.commit(writer.publicKeyHex, built.commit)
  t.alike(receipt, {
    ok: true,
    durable: true,
    commitId: built.commit.commitId,
    appId: writer.publicKeyHex,
    inviteKey: receipt.inviteKey,
    head: { version: 1, count: 1, root: built.head.root },
    relayVersion: 2
  })
  t.is(log.sync.get(writer.publicKeyHex, 'post!p1').title, 'genesis')
  t.is(log.sync.directory().heads[writer.publicKeyHex].version, 1)
  t.is(journal.entries().length, 1)
  t.is(journal.entries()[0].kind, 'commit')

  t.alike(log.sync.commit(writer.publicKeyHex, built.commit), receipt, 'same envelope returns the original receipt')
  t.is(journal.entries().length, 1, 'retry does not append another transaction')

  const retryWithNewTransportTimestamp = structuredClone(built.commit)
  retryWithNewTransportTimestamp.mutations[0].timestamp = 'changed-after-response-loss'
  t.alike(log.sync.commit(writer.publicKeyHex, retryWithNewTransportTimestamp), receipt, 'unsigned transport metadata cannot poison commitId replay')
  const unknownWrapper = structuredClone(built.commit)
  unknownWrapper.untrusted = 'poison'
  t.is(throws(() => log.sync.commit(writer.publicKeyHex, unknownWrapper)).status, 400, 'unknown commit wrapper fields fail closed')
  const algorithmPoison = structuredClone(built.commit)
  algorithmPoison.mutations[0].data._alg = 'not-ed25519'
  t.is(throws(() => log.sync.commit(writer.publicKeyHex, algorithmPoison)).status, 400, 'unsigned algorithm metadata cannot poison an existing commitId')
  for (const field of ['_sig', '_k', '_dk', '_ns', '_alg']) {
    const nestedPoison = structuredClone(built.commit)
    nestedPoison.mutations[0].data.meta = { nested: { [field]: 'unsigned-poison' } }
    t.is(throws(() => log.sync.commit(writer.publicKeyHex, nestedPoison)).status, 400, 'nested reserved field ' + field + ' cannot poison an existing commitId')
  }
  t.alike(log.sync.commit(writer.publicKeyHex, built.commit), receipt, 'the original retry still returns its durable receipt after metadata poison')
  t.is(journal.entries().length, 1)
})

test('outboxlog signatures: nested reserved metadata is rejected even when signature verification is disabled', (t) => {
  const writer = keyPair(69)
  const journal = durableMemoryJournal()
  const log = createOutboxLog({ journal, verifyAppend: false })
  log.sync.create(writer.publicKeyHex)
  const data = {
    id: 'nested-reserved',
    _ns: DEFAULT_OUTBOXLOG_NAMESPACE,
    body: { items: [{ metadata: { _alg: 'unsigned' } }] }
  }

  t.is(throws(() => canonicalOutboxRecord('post', data)).status, 400, 'canonical signing rejects nested reserved metadata')
  t.is(throws(() => log.sync.append(writer.publicKeyHex, { type: 'post', data })).status, 400, 'storage admission rejects independently of the verifier')
  t.is(journal.entries().length, 1, 'rejected nested metadata never reaches durable storage')
})

test('outboxlog atomic commit: CAS blocks stale signed replay and validates next head', (t) => {
  const writer = keyPair(42)
  const journal = durableMemoryJournal()
  const log = createOutboxLog({ journal })
  const first = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'p1' } }]
  })
  log.sync.commit(writer.publicKeyHex, first.commit)

  const stale = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'old-replay' } }],
    createdAt: 2000
  })
  t.is(throws(() => log.sync.commit(writer.publicKeyHex, stale.commit)).status, 409)
  t.is(log.sync.get(writer.publicKeyHex, 'post!old-replay'), null)

  const cases = [
    { name: 'version', opts: { headVersion: 9 } },
    { name: 'count', opts: { headCount: 9 } },
    { name: 'root', opts: { headRoot: 'f'.repeat(64) } }
  ]
  for (const item of cases) {
    const invalid = transition(writer, {
      expected: { version: 1, root: first.head.root },
      base: first.census,
      mutations: [{ type: 'post', fields: { id: 'bad-' + item.name } }],
      createdAt: 3000 + cases.indexOf(item),
      ...item.opts
    })
    t.is(throws(() => log.sync.commit(writer.publicKeyHex, invalid.commit)).status, 400, item.name)
  }

  const second = transition(writer, {
    expected: { version: 1, root: first.head.root },
    base: first.census,
    mutations: [{ type: 'post', fields: { id: 'p2' } }],
    createdAt: 4000
  })
  const receipt = log.sync.commit(writer.publicKeyHex, second.commit)
  t.alike(receipt.head, { version: 2, count: 2, root: second.head.root })
  t.is(receipt.relayVersion, 4)
  t.is(journal.entries().length, 2)
})

test('outboxlog atomic commit: rejects cross-owner, head mutations, and authorization mismatch without allocation', (t) => {
  const writer = keyPair(43)
  const foreign = keyPair(44)
  const journal = durableMemoryJournal()
  const log = createOutboxLog({ journal })
  const good = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'p1' } }]
  })

  const crossOwner = structuredClone(good.commit)
  crossOwner.mutations[0].data = signRecord(foreign, 'post', { id: 'p1', author: foreign.publicKeyHex })
  t.is(throws(() => log.sync.commit(writer.publicKeyHex, crossOwner)).status, 400)

  const headMutation = structuredClone(good.commit)
  headMutation.mutations[0].type = 'head'
  t.is(throws(() => log.sync.commit(writer.publicKeyHex, headMutation)).status, 400)

  const badBinding = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'p1' } }],
    authorizationMutationSigs: ['a'.repeat(128)],
    createdAt: 5000
  })
  t.is(throws(() => log.sync.commit(writer.publicKeyHex, badBinding.commit)).status, 400)

  t.is(log.sync.status(writer.publicKeyHex).inviteKey, null, 'invalid genesis never allocates a group')
  t.is(journal.entries().length, 0)
})

test('outboxlog atomic commit: journal failure is not acknowledged and does not allocate', (t) => {
  const writer = keyPair(45)
  const journal = {
    durableSync: true,
    loadSync: () => [],
    appendSync: () => { throw new Error('disk full') }
  }
  const log = createOutboxLog({ journal })
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'p1' } }]
  })

  const err = throws(() => log.sync.commit(writer.publicKeyHex, built.commit))
  t.is(err.status, 500)
  t.is(log.sync.status(writer.publicKeyHex).inviteKey, null)
  t.is(log.sync.get(writer.publicKeyHex, 'post!p1'), null)
  t.is(log.sync.capabilities().atomicCommit.durable, false)
})

test('outboxlog atomic commit: admission rejects commits larger than the replay bound through engine and App', (t) => {
  const writer = keyPair(68)
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: Array.from({ length: 18 }, (_, i) => ({
      type: 'post',
      fields: { id: 'oversized-' + i, body: 'x'.repeat(60000) }
    }))
  })
  t.ok(Buffer.byteLength(JSON.stringify(built.commit)) > OUTBOXLOG_MAX_REPLAY_COMMIT_BYTES, 'fixture crosses the exact replay ceiling')

  const engineJournal = durableMemoryJournal()
  const engine = createOutboxLog({ journal: engineJournal })
  t.is(throws(() => engine.sync.commit(writer.publicKeyHex, built.commit)).status, 413, 'direct engine admission rejects')
  t.is(engineJournal.entries().length, 0, 'oversized engine request never reaches the journal')
  t.is(engine.sync.status(writer.publicKeyHex).inviteKey, null, 'oversized engine request never allocates')

  const appJournal = durableMemoryJournal()
  const app = new OutboxLogApp({ engine: createOutboxLog({ journal: appJournal }) })
  t.is(throws(() => app.commit(writer.publicKeyHex, built.commit)).status, 413, 'ServiceProvider App admission rejects')
  t.is(appJournal.entries().length, 0, 'oversized App request never reaches the journal')
})

test('outboxlog journal uncertainty: every mutation family fences every later writer before another append', (t) => {
  const cases = [
    {
      name: 'create',
      kind: 'create',
      mutate: ({ log, writer }) => log.sync.create(writer.publicKeyHex)
    },
    {
      name: 'append',
      kind: 'append',
      setup: ({ log, writer }) => log.sync.create(writer.publicKeyHex),
      mutate: ({ log, writer }) => log.sync.append(writer.publicKeyHex, {
        type: 'post',
        data: signRecord(writer, 'post', { id: 'append-failure', author: writer.publicKeyHex })
      })
    },
    {
      name: 'commit',
      kind: 'commit',
      mutate: ({ log, writer, commit }) => log.sync.commit(writer.publicKeyHex, commit.commit)
    },
    {
      name: 'takedown',
      kind: 'takedown',
      mutate: ({ log, writer }) => log.sync.takedown(writer.publicKeyHex, 'post!failure')
    },
    {
      name: 'restore',
      kind: 'takedown',
      setup: ({ log, writer }) => log.sync.takedown(writer.publicKeyHex, 'post!failure'),
      mutate: ({ log, writer }) => log.sync.restore(writer.publicKeyHex, 'post!failure')
    },
    {
      name: 'sweep',
      kind: 'sweep',
      setup: ({ log, writer }) => log.sync.create(writer.publicKeyHex),
      mutate: ({ log }) => log.sync.sweepGhosts({ ttlMs: 0, now: Date.now() + 1 })
    }
  ]

  for (const mode of ['before', 'after']) {
    for (let i = 0; i < cases.length; i++) {
      const item = cases[i]
      const writer = keyPair(70 + i)
      const journal = uncertainJournal()
      const log = createOutboxLog({ journal })
      const commit = transition(writer, {
        expected: { version: 0, root: EMPTY_ROOT },
        mutations: [{ type: 'post', fields: { id: 'commit-failure' } }]
      })
      const context = { log, writer, commit }
      if (item.setup) item.setup(context)
      journal.fail(item.kind, mode)

      t.is(throws(() => item.mutate(context)).status, 500, item.name + ' ' + mode + ' uncertainty rejects the triggering mutation')
      const callsAtFence = journal.callCount()
      const followupWriter = keyPair(90 + i)
      const followupCommit = transition(followupWriter, {
        expected: { version: 0, root: EMPTY_ROOT },
        mutations: [{ type: 'post', fields: { id: 'must-not-append' } }]
      })
      const followups = [
        () => log.sync.create(followupWriter.publicKeyHex),
        () => log.sync.append(followupWriter.publicKeyHex, {
          type: 'post',
          data: signRecord(followupWriter, 'post', { id: 'must-not-append', author: followupWriter.publicKeyHex })
        }),
        () => log.sync.commit(followupWriter.publicKeyHex, followupCommit.commit),
        () => log.sync.takedown(followupWriter.publicKeyHex, 'post!must-not-append'),
        () => log.sync.restore(followupWriter.publicKeyHex, 'post!must-not-append'),
        () => log.sync.sweepGhosts({ ttlMs: 0, now: Date.now() + 1 })
      ]
      for (const followup of followups) t.is(throws(followup).status, 503, item.name + ' ' + mode + ' fence blocks later mutation')
      t.is(journal.callCount(), callsAtFence, item.name + ' ' + mode + ' fence prevents every later journal append')
      const capabilities = log.sync.capabilities()
      t.is(capabilities.ready, false, item.name + ' ' + mode + ' removes bridge readiness')
      t.is(capabilities.atomicCommit.durable, false, item.name + ' ' + mode + ' removes durable capability')
      t.is(capabilities.atomicCommit.ready, false, item.name + ' ' + mode + ' removes atomic readiness')
      t.alike(capabilities.legacyWrites, { create: false, append: false }, item.name + ' ' + mode + ' removes legacy readiness')
    }
  }
})

test('outboxlog atomic commit: JSONL replay restores rows and the original receipt', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-atomic-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'operations.jsonl')
  const writer = keyPair(46)
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'persisted' } }]
  })
  const first = createOutboxLog({ journalPath: path })
  const receipt = first.sync.commit(writer.publicKeyHex, built.commit)
  const before = await readFile(path, 'utf8')
  first.close()

  const reloaded = createOutboxLog({ journalPath: path })
  t.is(reloaded.sync.get(writer.publicKeyHex, 'post!persisted').id, 'persisted')
  t.alike(reloaded.sync.commit(writer.publicKeyHex, built.commit), receipt)
  t.is(await readFile(path, 'utf8'), before, 'replayed retry does not grow the journal')
  reloaded.close()
})

test('outboxlog JSONL ownership: overlap is refused, close/stop release, same-host stale owners recover, remote owners do not', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-owner-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const overlapPath = join(dir, 'overlap.jsonl')
  const first = createJsonlOutboxJournal(overlapPath)
  t.ok(throws(() => createJsonlOutboxJournal(overlapPath)).message.includes('writer owner'), 'overlapping writer is refused')
  first.close()
  const replacement = createJsonlOutboxJournal(overlapPath)
  replacement.close()

  const invalidPath = join(dir, 'invalid-config.jsonl')
  t.ok(throws(() => createOutboxLog({ journalPath: invalidPath, maxGroups: 2, maxCommitHistoryTotal: 1 })).message.includes('reserve'), 'constructor validation fails before taking ownership')
  const afterInvalidConfig = createJsonlOutboxJournal(invalidPath)
  afterInvalidConfig.close()

  const closedPath = join(dir, 'closed-config.jsonl')
  const closedEngine = createOutboxLog()
  closedEngine.close()
  t.is(throws(() => closedEngine.configurePersistence({ journalPath: closedPath })).status, 503, 'closed engine rejects configuration before taking a lease')
  const afterClosedConfig = createJsonlOutboxJournal(closedPath)
  t.ok(afterClosedConfig.ready, 'rejected closed-engine configuration leaves no writer lock')
  afterClosedConfig.close()

  const retryPath = join(dir, 'configure-retry.jsonl')
  const blocker = createJsonlOutboxJournal(retryPath)
  const configurable = createOutboxLog()
  t.ok(throws(() => configurable.configurePersistence({ journalPath: retryPath })).message.includes('writer owner'), 'contended runtime configuration fails closed')
  blocker.close()
  t.is(configurable.configurePersistence({ journalPath: retryPath }), true, 'failed configuration is transactional and can retry')
  configurable.close()

  const stalePath = join(dir, 'stale.jsonl')
  const identityProbe = createJsonlOutboxJournal(stalePath)
  const sameHostOwner = JSON.parse(await readFile(identityProbe.paths().lock, 'utf8'))
  identityProbe.close()
  await writeFile(stalePath + '.writer.lock', JSON.stringify({
    ...sameHostOwner,
    pid: 2147483647,
    token: '1'.repeat(64),
    createdAt: 1
  }))
  const recovered = createJsonlOutboxJournal(stalePath)
  t.ok(recovered.ready, 'definitely absent same-host pid is safely reclaimed')
  recovered.close()

  const remotePath = join(dir, 'remote.jsonl')
  await writeFile(remotePath + '.writer.lock', JSON.stringify({
    ...sameHostOwner,
    hostname: hostname(),
    hostId: sameHostOwner.hostId === 'f'.repeat(64) ? 'e'.repeat(64) : 'f'.repeat(64),
    pid: 2147483647,
    token: '2'.repeat(64),
    createdAt: 1
  }))
  t.ok(throws(() => createJsonlOutboxJournal(remotePath)).message.includes('unverifiable'), 'remote/shared-volume owner is never presumed dead')

  const providerPath = join(dir, 'provider.jsonl')
  const app = new OutboxLogApp({ sweep: false })
  await app.start({ config: { outboxlog: { journalPath: providerPath, legacyWrites: false, sweep: false } } })
  t.ok(throws(() => createJsonlOutboxJournal(providerPath)).message.includes('writer owner'), 'provider owns the path while running')
  await app.stop()
  t.is(app.sync.capabilities().ready, false, 'closed provider no longer advertises mutation readiness')
  await app.stop()
  const afterStop = createJsonlOutboxJournal(providerPath)
  t.ok(afterStop.ready, 'provider stop releases ownership for a clean restart')
  afterStop.close()
})

test('outboxlog configurePersistence: failed partial replay restores all engine state before a repaired retry', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-config-transaction-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'operations.jsonl')
  const a = 'a'.repeat(64)
  const b = 'b'.repeat(64)
  const c = 'c'.repeat(64)
  const source = createOutboxLog({ journalPath: path, verifyAppend: false })
  source.sync.create(a)
  source.sync.append(a, { type: 'post', data: { id: 'p1', _ns: DEFAULT_OUTBOXLOG_NAMESPACE } })
  source.sync.create(b)
  source.close()

  const lines = (await readFile(path, 'utf8')).trimEnd().split('\n').map(line => JSON.parse(line))
  lines[2].seq = 99
  await writeFile(path, lines.map(line => JSON.stringify(line)).join('\n') + '\n')

  const engine = createOutboxLog({ verifyAppend: false })
  engine.sync.create(c)
  engine.sync.append(c, { type: 'post', data: { id: 'preexisting', _ns: DEFAULT_OUTBOXLOG_NAMESPACE } })
  engine.sync.takedown(c, 'post!preexisting')
  const before = engine.snapshot()
  t.is(throws(() => engine.configurePersistence({ journalPath: path })).status, 500, 'corrupt tail fails after earlier entries were tentatively replayed')
  t.alike(engine.snapshot(), before, 'failed configuration restores every mutable state surface')
  t.is(engine.sync.status(a).viewLength, 0, 'partial group replay is absent after rollback')

  lines[2].seq = 3
  await writeFile(path, lines.map(line => JSON.stringify(line)).join('\n') + '\n')
  t.is(engine.configurePersistence({ journalPath: path }), true, 'repaired persistence can be configured on the same engine')
  t.is(engine.sync.heads([a]).heads[a], 1, 'repaired retry applies the append exactly once')
  t.is(engine.sync.get(a, 'post!p1').id, 'p1')
  t.ok(engine.sync.status(b).inviteKey, 'later group is restored after repair')
  t.alike(engine.sync.takedowns(), { takedowns: [{ appId: c, key: 'post!preexisting' }], count: 1 }, 'pre-existing moderation state survives failure and repaired retry')
  engine.close()
})

test('outboxlog atomic commit: JSONL recovery truncates only a torn final tail and rejects interior corruption', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-torn-tail-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'operations.jsonl')
  const writer = keyPair(61)
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'safe' } }]
  })
  const first = createOutboxLog({ journalPath: path })
  first.sync.commit(writer.publicKeyHex, built.commit)
  const complete = await readFile(path, 'utf8')
  first.close()

  await appendFile(path, '{"version":1,"seq":2')
  const recovered = createOutboxLog({ journalPath: path })
  t.is(recovered.sync.get(writer.publicKeyHex, 'post!safe').id, 'safe')
  t.is(await readFile(path, 'utf8'), complete, 'unacknowledged final fragment was durably truncated')
  recovered.close()

  await writeFile(path, complete + 'not-json\n' + complete)
  const corrupt = throws(() => createOutboxLog({ journalPath: path }))
  t.ok(corrupt.message.includes('corrupt interior journal entry'), 'complete interior corruption fails closed')
})

test('outboxlog atomic commit: generational checkpoints compact, survive corrupt active checkpoint, and stay bounded', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-checkpoint-fallback-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'operations.jsonl')
  const writer = keyPair(62)
  const firstTransition = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'p1' } }]
  })
  const first = createOutboxLog({ journalPath: path, checkpointInterval: 1 })
  first.sync.commit(writer.publicKeyHex, firstTransition.commit)
  const secondTransition = transition(writer, {
    expected: { version: 1, root: firstTransition.head.root },
    base: firstTransition.census,
    mutations: [{ type: 'post', fields: { id: 'p2' } }],
    createdAt: 2000
  })
  const secondReceipt = first.sync.commit(writer.publicKeyHex, secondTransition.commit)
  first.close()

  await writeFile(path + '.g2.checkpoint.json', '{corrupt-checkpoint')
  const recovered = createOutboxLog({ journalPath: path, checkpointInterval: 1 })
  t.is(recovered.sync.get(writer.publicKeyHex, 'post!p1').id, 'p1')
  t.is(recovered.sync.get(writer.publicKeyHex, 'post!p2').id, 'p2', 'fallback checkpoint plus both journal generations recovers the tail')
  t.alike(recovered.sync.commit(writer.publicKeyHex, secondTransition.commit), secondReceipt, 'original durable receipt replays after fallback recovery')

  const thirdTransition = transition(writer, {
    expected: { version: 2, root: secondTransition.head.root },
    base: secondTransition.census,
    mutations: [{ type: 'post', fields: { id: 'p3' } }],
    createdAt: 3000
  })
  recovered.sync.commit(writer.publicKeyHex, thirdTransition.commit)
  const fourthTransition = transition(writer, {
    expected: { version: 3, root: thirdTransition.head.root },
    base: thirdTransition.census,
    mutations: [{ type: 'post', fields: { id: 'p4' } }],
    createdAt: 4000
  })
  recovered.sync.commit(writer.publicKeyHex, fourthTransition.commit)

  const files = await readdir(dir)
  t.is(files.filter(name => /operations\.jsonl\.g\d+\.jsonl$/.test(name)).length, 2, 'only active and fallback journal generations remain after repair')
  t.is(files.filter(name => /operations\.jsonl\.g\d+\.checkpoint\.json$/.test(name)).length, 2, 'only active and fallback checkpoints remain after repair')
  recovered.close()
  const restarted = createOutboxLog({ journalPath: path, checkpointInterval: 1 })
  t.is(restarted.sync.get(writer.publicKeyHex, 'post!p4').id, 'p4')
  restarted.close()
})

test('outboxlog checkpoint uncertainty: every fault stage fences until restart and preserves the acknowledged receipt', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-checkpoint-faults-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const stages = [
    'before-checkpoint-file',
    'after-checkpoint-file',
    'before-journal-file',
    'after-journal-file',
    'before-manifest-file',
    'manifest-after-rename-before-directory-fsync',
    'after-manifest-file',
    'before-cleanup',
    'after-cleanup'
  ]

  for (let i = 0; i < stages.length; i++) {
    const stage = stages[i]
    const path = join(dir, stage, 'operations.jsonl')
    const writer = keyPair(110 + i)
    const built = transition(writer, {
      expected: { version: 0, root: EMPTY_ROOT },
      mutations: [{ type: 'post', fields: { id: 'durable-' + i } }]
    })
    let injected = 0
    const first = createOutboxLog({
      journalPath: path,
      checkpointInterval: 1,
      journalFaultInjector (current) {
        if (current !== stage) return
        injected++
        throw new Error('injected checkpoint fault at ' + stage)
      }
    })
    const receipt = first.sync.commit(writer.publicKeyHex, built.commit)
    t.is(injected, 1, stage + ' fault was reached')
    t.is(receipt.durable, true, stage + ' commit was fsynced before checkpoint maintenance')
    t.is(first.sync.capabilities().ready, false, stage + ' fences process readiness')
    const next = transition(writer, {
      expected: { version: 1, root: built.head.root },
      base: built.census,
      mutations: [{ type: 'post', fields: { id: 'blocked-' + i } }],
      createdAt: 2000 + i
    })
    t.is(throws(() => first.sync.commit(writer.publicKeyHex, next.commit)).status, 503, stage + ' prevents writes in the desynchronized process')
    first.close()

    const restarted = createOutboxLog({ journalPath: path, checkpointInterval: 1 })
    t.is(restarted.sync.get(writer.publicKeyHex, 'post!durable-' + i).id, 'durable-' + i, stage + ' restart recovers the acknowledged row')
    t.alike(restarted.sync.commit(writer.publicKeyHex, built.commit), receipt, stage + ' original lost-response retry recovers its receipt')
    t.is(restarted.sync.capabilities().ready, true, stage + ' clean restart restores readiness')
    restarted.close()
  }
})

test('outboxlog atomic commit: forced tiny journal byte quota rotates before exhaustion and restarts', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-journal-quota-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const sizingPath = join(dir, 'sizing.jsonl')
  const writer = keyPair(67)
  const firstTransition = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'quota-1' } }]
  })
  const sizing = createOutboxLog({ journalPath: sizingPath })
  sizing.sync.commit(writer.publicKeyHex, firstTransition.commit)
  const oneEntryBytes = Buffer.byteLength(await readFile(sizingPath, 'utf8'))
  sizing.close()

  const path = join(dir, 'operations.jsonl')
  const log = createOutboxLog({ journalPath: path, maxJournalBytes: oneEntryBytes + 64 })
  const firstReceipt = log.sync.commit(writer.publicKeyHex, firstTransition.commit)
  const secondTransition = transition(writer, {
    expected: { version: 1, root: firstTransition.head.root },
    base: firstTransition.census,
    mutations: [{ type: 'post', fields: { id: 'quota-2' } }],
    createdAt: 2000
  })
  log.sync.commit(writer.publicKeyHex, secondTransition.commit)
  const thirdTransition = transition(writer, {
    expected: { version: 2, root: secondTransition.head.root },
    base: secondTransition.census,
    mutations: [{ type: 'post', fields: { id: 'quota-3' } }],
    createdAt: 3000
  })
  log.sync.commit(writer.publicKeyHex, thirdTransition.commit)

  const files = await readdir(dir)
  t.ok(files.includes('operations.jsonl.manifest.json'), 'quota pressure activated generational compaction')
  t.ok(files.filter(name => /operations\.jsonl\.g\d+\.jsonl$/.test(name)).length <= 2, 'quota rotations retain bounded generations')
  log.close()
  const restarted = createOutboxLog({ journalPath: path, maxJournalBytes: oneEntryBytes + 64 })
  t.is(restarted.sync.get(writer.publicKeyHex, 'post!quota-3').id, 'quota-3')
  t.alike(restarted.sync.commit(writer.publicKeyHex, firstTransition.commit), firstReceipt, 'compaction retains the original receipt inside the bounded window')
})

test('outboxlog atomic commit: latest receipt per outbox survives cross-author global pressure', (t) => {
  const writers = [keyPair(63), keyPair(64), keyPair(65)]
  const journal = durableMemoryJournal()
  const log = createOutboxLog({
    journal,
    maxGroups: 3,
    maxCommitReceiptsPerGroup: 1,
    maxCommitTombstonesPerGroup: 8,
    maxCommitHistoryTotal: 3
  })
  const a1 = transition(writers[0], {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'a1' } }]
  })
  const a1Receipt = log.sync.commit(writers[0].publicKeyHex, a1.commit)
  const a2 = transition(writers[0], {
    expected: { version: 1, root: a1.head.root },
    base: a1.census,
    mutations: [{ type: 'post', fields: { id: 'a2' } }],
    createdAt: 2000
  })
  const a2Receipt = log.sync.commit(writers[0].publicKeyHex, a2.commit)
  for (let i = 1; i < writers.length; i++) {
    const commit = transition(writers[i], {
      expected: { version: 0, root: EMPTY_ROOT },
      mutations: [{ type: 'post', fields: { id: 'pressure-' + i } }],
      createdAt: 3000 + i
    })
    log.sync.commit(writers[i].publicKeyHex, commit.commit)
  }

  t.alike(log.sync.commit(writers[0].publicKeyHex, a2.commit), a2Receipt, 'quiet author latest lost-response retry remains replayable')
  t.is(throws(() => log.sync.commit(writers[0].publicKeyHex, a1.commit)).status, 409, 'older history may expire outside the advertised bounded window')
  t.is(log._stats().commitHistoryCount, 3, 'global receipt history remains bounded without a permanent write cliff')
  t.is(log.sync.capabilities().atomicCommit.idempotency.latestPerOutbox, true)
  t.ok(a1Receipt.durable)
})

test('outboxlog atomic commit: cross-author receipt eviction survives JSONL checkpoint and restart', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-cross-author-restart-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'operations.jsonl')
  const writers = [keyPair(120), keyPair(121), keyPair(122)]
  const opts = {
    journalPath: path,
    checkpointInterval: 1,
    maxGroups: 3,
    maxCommitReceiptsPerGroup: 1,
    maxCommitTombstonesPerGroup: 8,
    maxCommitHistoryTotal: 3
  }
  const first = createOutboxLog(opts)
  const a1 = transition(writers[0], {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'a1' } }]
  })
  first.sync.commit(writers[0].publicKeyHex, a1.commit)
  const a2 = transition(writers[0], {
    expected: { version: 1, root: a1.head.root },
    base: a1.census,
    mutations: [{ type: 'post', fields: { id: 'a2' } }],
    createdAt: 2000
  })
  const a2Receipt = first.sync.commit(writers[0].publicKeyHex, a2.commit)
  for (let i = 1; i < writers.length; i++) {
    const pressure = transition(writers[i], {
      expected: { version: 0, root: EMPTY_ROOT },
      mutations: [{ type: 'post', fields: { id: 'pressure-' + i } }],
      createdAt: 3000 + i
    })
    first.sync.commit(writers[i].publicKeyHex, pressure.commit)
  }
  first.close()

  const restarted = createOutboxLog(opts)
  t.alike(restarted.sync.commit(writers[0].publicKeyHex, a2.commit), a2Receipt, 'quiet author latest receipt survives checkpoint/restart and other-author pressure')
  t.is(throws(() => restarted.sync.commit(writers[0].publicKeyHex, a1.commit)).status, 409, 'evicted older receipt remains expired after restart')
  t.is(restarted._stats().commitHistoryCount, 3, 'restored global history remains bounded')
  restarted.close()
})

test('outboxlog atomic-only startup requires an opened fsync-probed path and disabled legacy writes', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'outboxlog-readiness-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const missingPathApp = new OutboxLogApp({ legacyWrites: false })
  const missingPath = await rejectsAsync(missingPathApp.start({ config: { outboxlog: { legacyWrites: false } } }))
  t.ok(missingPath.message.includes('journalPath'))

  const blocker = join(dir, 'not-a-directory')
  await writeFile(blocker, 'file')
  const unwritableApp = new OutboxLogApp()
  const unwritable = await rejectsAsync(unwritableApp.start({ config: { outboxlog: { legacyWrites: false, journalPath: join(blocker, 'operations.jsonl') } } }))
  t.ok(['EEXIST', 'ENOTDIR', 'EACCES'].includes(unwritable.code), 'unopenable journal fails startup')

  const validPath = join(dir, 'operations.jsonl')
  const readyApp = new OutboxLogApp()
  await readyApp.start({ config: { outboxlog: { legacyWrites: false, journalPath: validPath, sweep: false } } })
  const capabilities = readyApp.sync.capabilities()
  t.is(capabilities.ready, true)
  t.is(capabilities.atomicCommit.ready, true)
  t.alike(capabilities.legacyWrites, { create: false, append: false })
  await readyApp.stop()
})

test('outboxlog atomic commit: delayed retry survives hot receipt cache pressure and checkpoint reload', (t) => {
  const writer = keyPair(66)
  const persistence = createMemoryOutboxPersistence()
  const journal = durableMemoryJournal()
  const firstCommit = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'first' } }]
  })
  const first = createOutboxLog({ persistence, journal, checkpointInterval: 1, maxCommitReceiptsPerGroup: 1 })
  const firstReceipt = first.sync.commit(writer.publicKeyHex, firstCommit.commit)
  const secondCommit = transition(writer, {
    expected: { version: 1, root: firstCommit.head.root },
    base: firstCommit.census,
    mutations: [{ type: 'post', fields: { id: 'second' } }],
    createdAt: 2000
  })
  first.sync.commit(writer.publicKeyHex, secondCommit.commit)

  const reloaded = createOutboxLog({ persistence, journal, checkpointInterval: 1, maxCommitReceiptsPerGroup: 1 })
  t.alike(reloaded.sync.commit(writer.publicKeyHex, firstCommit.commit), firstReceipt)
  t.is(journal.entries().length, 2, 'delayed retry does not append after receipt moved to durable tombstones')
})

test('outboxlog atomic commit: checkpoint reload preserves bounded receipt state', (t) => {
  const writer = keyPair(49)
  const persistence = createMemoryOutboxPersistence()
  const journal = durableMemoryJournal()
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'checkpointed' } }]
  })
  const first = createOutboxLog({ persistence, journal, checkpointInterval: 1, maxCommitReceiptsPerGroup: 1 })
  const receipt = first.sync.commit(writer.publicKeyHex, built.commit)

  const reloaded = createOutboxLog({ persistence, journal, checkpointInterval: 1, maxCommitReceiptsPerGroup: 1 })
  t.alike(reloaded.sync.commit(writer.publicKeyHex, built.commit), receipt)
  t.is(journal.entries().length, 1)
  t.is(persistence.snapshot().groups[0][1].commits.length, 1)
})

test('outboxlog atomic commit HTTP: capability preflight, receipt, and stale CAS status', async (t) => {
  const writer = keyPair(47)
  const engine = createOutboxLog({ journal: durableMemoryJournal() })
  const app = new OutboxLogApp({ engine })
  const auth = createOutboxLogTokenAuth()
  const token = auth.issue()
  const ctx = { outboxLogApp: app, auth, state: createOutboxLogHttpState() }

  const capabilities = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/sync/capabilities', null, { 'x-pear-token': token }), capabilities, ctx)
  t.is(capabilities.statusCode, 200)
  t.alike(jsonBody(capabilities).atomicCommit, {
    schema: 1,
    method: 'POST',
    route: '/api/sync/commit',
    enabled: true,
    durable: true,
    ready: true,
    cas: true,
    idempotent: true,
    idempotency: {
      mode: 'bounded',
      latestPerOutbox: true,
      hotReceiptsPerOutbox: 4096,
      tombstonesPerOutbox: 16384,
      aggregateEntries: 40000,
      extraHistoryEntries: 20000
    }
  })

  const status = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/bridge/status', null, { 'x-pear-token': token }), status, ctx)
  t.alike(jsonBody(status).atomicCommit, jsonBody(capabilities).atomicCommit)

  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'http' } }]
  })
  const committed = fakeRes()
  await handleOutboxLogRoute(jsonReq('/api/sync/commit', { appId: writer.publicKeyHex, commit: built.commit }, token), committed, ctx)
  t.is(committed.statusCode, 200)
  t.is(jsonBody(committed).durable, true)

  const stale = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'stale' } }],
    createdAt: 6000
  })
  const rejected = fakeRes()
  await handleOutboxLogRoute(jsonReq('/api/sync/commit', { appId: writer.publicKeyHex, commit: stale.commit }, token), rejected, ctx)
  t.is(rejected.statusCode, 409)
  t.alike(jsonBody(rejected), { error: 'stale head' })
})

test('outboxlog bridge status: journal fence is reported as ready false', async (t) => {
  const writer = keyPair(130)
  const journal = uncertainJournal()
  const engine = createOutboxLog({ journal })
  journal.fail('create', 'after')
  t.is(throws(() => engine.sync.create(writer.publicKeyHex)).status, 500)

  const auth = createOutboxLogTokenAuth()
  const token = auth.issue()
  const status = fakeRes()
  await handleOutboxLogRoute(
    fakeReq('GET', '/api/bridge/status', null, { 'x-pear-token': token }),
    status,
    { outboxLogApp: new OutboxLogApp({ engine }), auth, state: createOutboxLogHttpState() }
  )
  const body = jsonBody(status)
  t.is(status.statusCode, 200)
  t.is(body.ready, false, 'bridge readiness follows sync.capabilities().ready')
  t.is(body.atomicCommit.ready, false)
  t.is(body.atomicCommit.durable, false)
  t.alike(body.legacyWrites, { create: false, append: false })
})

test('outboxlog atomic commit: a non-durable engine advertises false and rejects acknowledgements', (t) => {
  const writer = keyPair(48)
  const log = createOutboxLog({ journal: createMemoryOutboxJournal() })
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'p1' } }]
  })
  t.is(log.sync.capabilities().atomicCommit.durable, false)
  t.is(throws(() => log.sync.commit(writer.publicKeyHex, built.commit)).status, 503)
})

test('outboxlog atomic commit: production mode disables replayable legacy writes while commit remains available', (t) => {
  const writer = keyPair(50)
  const log = createOutboxLog({ journal: durableMemoryJournal(), legacyWrites: false })
  const built = transition(writer, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'atomic-only' } }]
  })

  t.alike(log.sync.capabilities().legacyWrites, { create: false, append: false })
  t.is(throws(() => log.sync.create(writer.publicKeyHex)).status, 403)
  t.is(throws(() => log.sync.append(writer.publicKeyHex, built.commit.mutations[0])).status, 403)
  t.is(log.sync.commit(writer.publicKeyHex, built.commit).durable, true)
  t.is(log.sync.get(writer.publicKeyHex, 'post!atomic-only').id, 'atomic-only')
})

test('outboxlog atomic commit: binding a legacy ghost still enforces namespace outbox capacity', (t) => {
  const occupied = keyPair(51)
  const ghost = keyPair(52)
  const journal = durableMemoryJournal()
  const log = createOutboxLog({
    journal,
    namespaces: { outbox: { blind: false, caps: { maxOutboxes: 1 } } }
  })
  log.sync.create(occupied.publicKeyHex, { namespace: 'outbox' })
  log.sync.create(ghost.publicKeyHex)
  const built = transition(ghost, {
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'post', fields: { id: 'capacity-bypass' } }]
  })

  t.is(throws(() => log.sync.commit(ghost.publicKeyHex, built.commit)).status, 503)
  t.is(log.sync.get(ghost.publicKeyHex, 'post!capacity-bypass'), null)
  t.is(journal.entries().length, 2)
})

function transition (writer, opts) {
  const expected = opts.expected
  const census = new Map(opts.base || [])
  const mutations = opts.mutations.map((mutation) => {
    const data = mutation.data || signRecord(writer, mutation.type, {
      author: writer.publicKeyHex,
      ...mutation.fields
    })
    const key = mutation.type.replace(':', '!') + '!' + data.id
    census.set(key, key + '\x00' + data._sig)
    return { type: mutation.type, data, timestamp: '2026-07-10T00:00:00.000Z' }
  })
  const censusValues = [...census.values()].sort()
  const computedRoot = sha256(censusValues.join('\x01'))
  const head = signRecord(writer, 'head', {
    id: writer.publicKeyHex,
    author: writer.publicKeyHex,
    version: opts.headVersion === undefined ? expected.version + 1 : opts.headVersion,
    count: opts.headCount === undefined ? censusValues.length : opts.headCount,
    root: opts.headRoot || computedRoot,
    updatedAt: opts.createdAt || 1000
  })
  const fields = {
    appId: writer.publicKeyHex,
    expectedVersion: expected.version,
    expectedRoot: expected.root,
    mutationSigs: opts.authorizationMutationSigs || mutations.map(mutation => mutation.data._sig),
    headSig: head._sig,
    createdAt: opts.createdAt || 1000
  }
  const commitId = sha256(canonicalOutboxRecord('commit-id', fields))
  const authorization = signRecord(writer, 'commit', { id: commitId, ...fields })
  return {
    head,
    census,
    commit: {
      schema: 1,
      commitId,
      expected: { ...expected },
      mutations,
      head: { type: 'head', data: head, timestamp: '2026-07-10T00:00:00.000Z' },
      authorization
    }
  }
}

function durableMemoryJournal () {
  return createMemoryOutboxJournal([], { durableSync: true })
}

function uncertainJournal () {
  const entries = []
  let armedKind = null
  let armedMode = null
  let calls = 0
  return {
    durableSync: true,
    ready: true,
    loadSync: () => structuredClone(entries),
    appendSync (entry) {
      calls++
      if (entry.kind === armedKind && armedMode === 'before') throw new Error('injected pre-append uncertainty')
      entries.push(structuredClone(entry))
      if (entry.kind === armedKind && armedMode === 'after') throw new Error('injected post-append uncertainty')
    },
    markFailed () {
      this.ready = false
    },
    fail (kind, mode) {
      armedKind = kind
      armedMode = mode
    },
    callCount () {
      return calls
    }
  }
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey, publicKeyHex: b4a.toString(publicKey, 'hex') }
}

function signRecord (writer, type, fields) {
  const data = {
    ...fields,
    _k: writer.publicKeyHex,
    _dk: 'd'.repeat(64),
    _ns: DEFAULT_OUTBOXLOG_NAMESPACE,
    _alg: 'ed25519'
  }
  const message = `pear.app.${data._dk}:${data._ns}:${canonicalOutboxRecord(type, data)}`
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, b4a.from(message, 'utf8'), writer.secretKey)
  return { ...data, _sig: b4a.toString(signature, 'hex') }
}

function sha256 (value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex')
}

function throws (fn) {
  try {
    fn()
  } catch (err) {
    return err
  }
  throw new Error('expected function to throw')
}

async function rejectsAsync (promise) {
  try {
    await promise
  } catch (err) {
    return err
  }
  throw new Error('expected promise to reject')
}

function fakeReq (method, url, body = null, headers = {}) {
  const req = Readable.from(body == null ? [] : [body])
  req.method = method
  req.url = url
  req.headers = { ...headers }
  req.socket = { remoteAddress: '127.0.0.1' }
  return req
}

function jsonReq (url, body, token) {
  const text = JSON.stringify(body)
  return fakeReq('POST', url, text, {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(text)),
    'x-pear-token': token
  })
}

function fakeRes () {
  const res = new EventEmitter()
  res.headers = {}
  res.statusCode = null
  res.body = ''
  res.setHeader = function (name, value) { this.headers[name] = value }
  res.getHeader = function (name) { return this.headers[name] }
  res.hasHeader = function (name) { return this.headers[name] !== undefined }
  res.writeHead = function (status) { this.statusCode = status }
  res.end = function (body = '') { this.body = String(body); this.emit('finish') }
  return res
}

function jsonBody (res) {
  return JSON.parse(res.body)
}
