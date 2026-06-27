import test from 'brittle'
import {
  parseDedupReclaimOptions,
  runDedupReclaimAction
} from '../../packages/core/core/relay-node/api-dedup-reclaim.js'

test('api dedup reclaim: defaults to dry-run with zero retained superseded versions', async (t) => {
  const calls = []
  const node = {
    eviction: {
      async reclaimSuperseded (opts) {
        calls.push(opts)
        return { dryRun: opts.dryRun, reclaimed: [], skipped: [], freedBytes: 0, candidates: 0 }
      }
    }
  }

  const out = await runDedupReclaimAction({ body: {}, node })

  t.is(out.status, 200)
  t.is(out.payload.ok, true)
  t.is(out.payload.dryRun, true)
  t.alike(calls, [{ dryRun: true, retainVersions: 0, max: undefined }])
})

test('api dedup reclaim: parses execute, retainVersions, and max without numeric coercion', async (t) => {
  const calls = []
  const node = {
    eviction: {
      async reclaimSuperseded (opts) {
        calls.push(opts)
        return { dryRun: opts.dryRun, reclaimed: [{ appKey: 'a'.repeat(64), bytes: 7 }], freedBytes: 7, candidates: 1 }
      }
    }
  }

  const out = await runDedupReclaimAction({
    body: { execute: true, retainVersions: 2, max: 3 },
    node
  })

  t.is(out.status, 200)
  t.is(out.payload.ok, true)
  t.is(out.payload.dryRun, false)
  t.is(out.payload.freedBytes, 7)
  t.alike(calls, [{ dryRun: false, retainVersions: 2, max: 3 }])

  const parsed = parseDedupReclaimOptions({ execute: 'true', retainVersions: 0 })
  t.ok(parsed.ok)
  t.is(parsed.options.dryRun, true, 'only boolean true executes destructive reclaim')
})

test('api dedup reclaim: rejects malformed body and integer options before reclaiming', async (t) => {
  const node = {
    eviction: {
      async reclaimSuperseded () {
        t.fail('invalid requests must not reach eviction manager')
      }
    }
  }

  const cases = [
    [null, 'JSON body object required'],
    [[], 'JSON body object required'],
    [{ retainVersions: -1 }, 'retainVersions must be a non-negative integer'],
    [{ retainVersions: 1.5 }, 'retainVersions must be a non-negative integer'],
    [{ retainVersions: '1' }, 'retainVersions must be a non-negative integer'],
    [{ max: 0 }, 'max must be a positive integer'],
    [{ max: 2.5 }, 'max must be a positive integer'],
    [{ max: '2' }, 'max must be a positive integer'],
    [{ max: Number.MAX_SAFE_INTEGER + 1 }, 'max must be a positive integer']
  ]

  for (const [body, message] of cases) {
    const out = await runDedupReclaimAction({ body, node })
    t.is(out.status, 400)
    t.ok(out.payload.error.includes(message), message)
  }
})

test('api dedup reclaim: reports unavailable eviction manager', async (t) => {
  const out = await runDedupReclaimAction({
    body: {},
    node: { eviction: {} }
  })

  t.is(out.status, 503)
  t.is(out.payload.error, 'dedup reclaim not available (eviction manager not enabled)')
})

test('api dedup reclaim: redacts unexpected reclaim failures and emits raw error internally', async (t) => {
  const error = new Error('filesystem path /data/private/core leaked')
  const events = []
  const node = {
    eviction: {
      async reclaimSuperseded () {
        throw error
      }
    }
  }

  const out = await runDedupReclaimAction({
    body: { execute: true },
    node,
    emit: (...args) => events.push(args)
  })

  t.is(out.status, 500)
  t.ok(out.payload.error.startsWith('reclaim-failed: '))
  t.absent(out.payload.error.includes('/data/private'))
  t.is(events.length, 1)
  t.is(events[0][0], 'dedup-reclaim-error')
  t.is(events[0][1].error, error)
})
