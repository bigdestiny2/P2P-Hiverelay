import test from 'brittle'
import {
  OUTBOXLOG_SEED_REAFFIRM_DEFAULT_MS,
  OutboxLogApp
} from '../../packages/services/builtin/outboxlog/index.js'

const STORAGE_BOUND = 4 * 1024 * 1024

// Fake seeder that records every authority-owned announcement. Mirrors the real
// seeder's idempotency: re-announcing an already-recorded key is a cheap no-op.
function createFakeSeeder () {
  const calls = []
  const bounds = []
  const seen = new Set()
  return {
    calls,
    bounds,
    seen,
    async announceAuthorityOwnedCore (core, opts) {
      const keyHex = typeof core === 'string' ? core : core.key
      calls.push(keyHex)
      bounds.push(opts && opts.maxStorageBytes)
      seen.add(keyHex)
      return { keyHex }
    },
    async withdrawAuthorityOwnedCore (core) {
      const keyHex = typeof core === 'string' ? core : core.key
      seen.delete(keyHex)
      return true
    }
  }
}

// Fake hypercore-outboxes journal whose seedCores(seeder) hands a couple of
// cores to the seeder, matching the real journal's contract (index + outboxes).
function createFakeJournal (keys = ['idx00', 'outbox-a', 'outbox-b']) {
  let flushed = 0
  return {
    flushed: () => flushed,
    async seedCores (seeder, opts = {}) {
      if (!seeder || typeof seeder.announceAuthorityOwnedCore !== 'function') {
        throw new Error('fake journal: seeder with announceAuthorityOwnedCore() required')
      }
      flushed++
      const seeded = []
      for (const key of keys) {
        await seeder.announceAuthorityOwnedCore(key, { maxStorageBytes: opts.maxStorageBytes })
        seeded.push({ role: key === keys[0] ? 'index' : 'outbox', coreKey: key })
      }
      return seeded
    }
  }
}

// Build an OutboxLogApp with the persistence engine/swarm stubbed so start()
// touches no real store/swarm. We inject the journal directly and let start()
// leave it in place (persistence path is not exercised here).
function createApp (opts = {}) {
  const engine = {
    sync: {},
    swarm: null,
    subscribe () {},
    async flush () {}
  }
  const swarm = { destroy () {} }
  const app = new OutboxLogApp({ engine, swarm, persistence: false, seedMaxStorageBytes: STORAGE_BOUND, ...opts })
  // Capture log output instead of writing to the console.
  const logs = { warn: [], info: [] }
  app._logSeedWarn = (msg) => { logs.warn.push(msg) }
  app._logSeedInfo = (msg) => { logs.info.push(msg) }
  app.__logs = logs
  return app
}

test('default seedReaffirmMs is 600000 (10 min)', (t) => {
  const app = createApp()
  t.is(app.seedReaffirmMs, OUTBOXLOG_SEED_REAFFIRM_DEFAULT_MS)
  t.is(app.seedReaffirmMs, 600000)
})

test('opts.seedReaffirmMs overrides the default', (t) => {
  const app = createApp({ seedReaffirmMs: 250 })
  t.is(app.seedReaffirmMs, 250)
})

test('config.outboxlog.seedReaffirmMs overrides opts at start()', async (t) => {
  const app = createApp({ seedReaffirmMs: 250, journal: createFakeJournal() })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()
  await app.start({ config: { outboxlog: { seedReaffirmMs: 999 } }, node: { seeder } })
  t.is(app.seedReaffirmMs, 999)
})

test('start() does an initial seed and arms an unref\'d re-affirm timer', async (t) => {
  const journal = createFakeJournal(['idx', 'ob-1', 'ob-2'])
  const app = createApp({ seedReaffirmMs: 500, journal })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })

  // Initial one-shot seed happened.
  t.alike(seeder.calls, ['idx', 'ob-1', 'ob-2'])
  t.alike(seeder.bounds, [STORAGE_BOUND, STORAGE_BOUND, STORAGE_BOUND])
  t.is(journal.flushed(), 1)
  t.ok(app._seedTimer, 'a re-affirm timer is armed')
  // The timer must not hold the event loop open on a long-running relay.
  t.absent(app._seedTimer.hasRef(), 'timer is unref\'d')
  t.is(app.__logs.warn.length, 0)
})

test('missing fleet seed bound keeps the journal local-only', async (t) => {
  const journal = createFakeJournal(['idx'])
  const app = createApp({ seedMaxStorageBytes: null, journal })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })

  t.alike(seeder.calls, [])
  t.absent(app._seedTimer)
  t.ok(app.__logs.warn.some(message => message.includes('seedMaxStorageBytes')))
  await t.exception(app.seedPersistenceCores(), /seedMaxStorageBytes/)
})

test('re-affirm routine seeds again (idempotent) when invoked directly', async (t) => {
  const journal = createFakeJournal(['idx', 'ob-1'])
  const app = createApp({ seedReaffirmMs: 500, journal })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })
  const afterInitial = seeder.calls.length
  t.is(afterInitial, 2)

  // Drive the re-affirm deterministically (no wall-clock reliance).
  await app._safeSeed()

  t.is(seeder.calls.length, afterInitial + 2, 're-affirm re-seeds the same cores')
  t.is(seeder.seen.size, 2, 'still only two distinct cores (idempotent)')
  t.is(journal.flushed(), 2)
})

test('short interval re-affirm fires within a bounded wait', async (t) => {
  const journal = createFakeJournal(['idx', 'ob-1'])
  const app = createApp({ seedReaffirmMs: 5, journal })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })
  t.is(seeder.calls.length, 2, 'initial seed')

  // Bounded wait for at least one re-affirm tick.
  const deadline = Date.now() + 500
  while (seeder.calls.length < 4 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  t.ok(seeder.calls.length >= 4, 'periodic re-affirm fired at least once')
})

test('seedReaffirmMs = 0 does the one-shot seed but arms NO timer', async (t) => {
  const journal = createFakeJournal(['idx', 'ob-1'])
  const app = createApp({ seedReaffirmMs: 0, journal })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })

  t.is(seeder.calls.length, 2, 'initial one-shot seed still runs')
  t.absent(app._seedTimer, 'no periodic timer when re-affirm disabled')
})

test('node.seeder = null: start() does not throw, warns once, seeds nothing', async (t) => {
  const journal = createFakeJournal()
  const app = createApp({ seedReaffirmMs: 500, journal })
  t.teardown(() => app.stop())

  await app.start({ config: { outboxlog: {} }, node: { seeder: null } })

  t.is(journal.flushed(), 0, 'nothing seeded without a seeder')
  t.absent(app._seedTimer, 'no timer armed without a seeder')
  t.is(app.__logs.warn.length, 1, 'exactly one warning')
  t.ok(app.__logs.warn[0].includes('node.seeder unavailable'))
  // The app is otherwise started.
  t.is(app.journal, journal)
})

test('seeder present but lacking revocable authority-owned announcer: warns once, seeds nothing', async (t) => {
  const journal = createFakeJournal()
  const app = createApp({ seedReaffirmMs: 500, journal })
  t.teardown(() => app.stop())

  await app.start({ config: { outboxlog: {} }, node: { seeder: {} } })

  t.is(journal.flushed(), 0)
  t.absent(app._seedTimer)
  t.is(app.__logs.warn.length, 1)
})

test('a seed failure is caught and logged, never crashes start()', async (t) => {
  const journal = {
    async seedCores () { throw new Error('boom') }
  }
  const app = createApp({ seedReaffirmMs: 500, journal })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  // Must resolve, not reject.
  await app.start({ config: { outboxlog: {} }, node: { seeder } })

  t.is(app.__logs.warn.length, 1, 'the failure is logged')
  t.ok(app.__logs.warn[0].includes('boom'))
  // Timer is still armed so a later tick can succeed.
  t.ok(app._seedTimer)
})

test('non-hypercore journal (no seedCores): start() seeds nothing, no warning', async (t) => {
  const app = createApp({ seedReaffirmMs: 500 }) // journal stays null
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })

  t.is(seeder.calls.length, 0)
  t.absent(app._seedTimer)
  t.is(app.__logs.warn.length, 0)
})

test('stop() clears the re-affirm timer; a second stop is safe', async (t) => {
  const journal = createFakeJournal()
  const app = createApp({ seedReaffirmMs: 500, journal })
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })
  t.ok(app._seedTimer, 'timer armed')

  await app.stop()
  t.absent(app._seedTimer, 'timer cleared on stop')

  // A second stop must not throw.
  await app.stop()
  t.absent(app._seedTimer)
})

test('double start() does not leak a second timer', async (t) => {
  const journal = createFakeJournal()
  const app = createApp({ seedReaffirmMs: 500, journal })
  t.teardown(() => app.stop())
  const seeder = createFakeSeeder()

  await app.start({ config: { outboxlog: {} }, node: { seeder } })
  const first = app._seedTimer
  await app.start({ config: { outboxlog: {} }, node: { seeder } })
  t.is(app._seedTimer, first, 'the same timer handle is reused (no leak)')
})
