// outboxlog-sweep.test.js — ghost-outbox sweep: reclaim group slots leaked by
// writers that created an outbox and never appended (the peerit web client's
// identity-per-refresh churn era minted one per page load until 2026-07-08).
//
// Contract:
//  - ghost = rows.size 0 AND version 0 AND createdAt older than ttlMs
//    (no createdAt = legacy = infinitely old);
//  - deletions are journaled (kind 'sweep') so replay cannot resurrect them;
//  - the snapshot checkpoint path agrees;
//  - stale swarm descriptors for swept appIds are pruned (the per-boot replay
//    amplifier), unattributable descriptors are kept;
//  - a swept appId can immediately create again (client self-heal path);
//  - the admin surface exposes POST /api/admin/sweep behind the admin token.

import test from 'brittle'
import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import { OutboxLogApp, OUTBOXLOG_SWEEP_DEFAULT_TTL_MS, createOutboxSwarmHub } from 'p2p-hiveservices/builtin/outboxlog/index.js'
import {
  createOutboxLog,
  createMemoryOutboxJournal,
  createMemoryOutboxPersistence,
  DEFAULT_SWEEP_TTL_MS,
  OUTBOXLOG_JOURNAL_VERSION
} from 'p2p-hiveservices/builtin/outboxlog/outbox-log.js'
import {
  createOutboxLogAdminAuth,
  createOutboxLogTokenAuth,
  createOutboxLogHttpState,
  handleOutboxLogRoute
} from 'p2p-hiveservices/builtin/outboxlog/http-adapter.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)
const D = 'd'.repeat(64)

const permissive = () => true
const engineOpts = (extra = {}) => ({ verifyAppend: permissive, ...extra })

// ---- fakes shared with outboxlog-http-adapter.test.js ------------------------
function fakeReq (method, url, body = null, headers = {}) {
  const chunks = body === null || body === undefined ? [] : [body]
  const req = Readable.from(chunks)
  req.method = method
  req.url = url
  req.headers = { ...headers }
  req.socket = { remoteAddress: headers.remoteAddress || '127.0.0.1' }
  return req
}
function jsonReq (method, url, body, token = '') {
  const text = JSON.stringify(body || {})
  const headers = {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(text))
  }
  if (token) headers['x-pear-token'] = token
  return fakeReq(method, url, text, headers)
}
function fakeRes () {
  const res = new EventEmitter()
  res.headers = {}
  res.statusCode = null
  res.body = ''
  res.chunks = []
  res.ended = false
  res.setHeader = function (name, value) { this.headers[name] = value }
  res.getHeader = function (name) { return this.header(name) }
  res.hasHeader = function (name) { return this.header(name) !== undefined }
  res.header = function (name) {
    const lower = name.toLowerCase()
    const key = Object.keys(this.headers).find(key => key.toLowerCase() === lower)
    return key ? this.headers[key] : undefined
  }
  res.writeHead = function (status) { this.statusCode = status }
  res.write = function (chunk) { this.chunks.push(String(chunk)); return true }
  res.end = function (body = '') { this.body = String(body); this.ended = true; this.emit('finish') }
  return res
}
const parseBody = (res) => JSON.parse(res.body)

test('sweep: empty groups die, groups with rows survive, slot is reusable', (t) => {
  const engine = createOutboxLog(engineOpts())
  engine.sync.create(A) // ghost
  engine.sync.create(B) // ghost
  engine.sync.create(C) // becomes a real author
  engine.sync.append(C, { type: 'post', data: { id: 'p1', body: 'hello' } })

  const res = engine.sweepGhosts({ ttlMs: 0 })
  t.is(res.swept, 2, 'both empty groups swept')
  t.is(res.remaining, 1, 'author group remains')
  t.is(engine._stats().groups, 1, 'group table agrees')
  t.alike(engine.sync.range(C, {}).map(r => r.key), ['post!p1'], 'author rows untouched')

  // Client self-heal path: a swept appId can create again immediately.
  const recreated = engine.sync.create(A)
  t.ok(recreated && recreated.inviteKey && recreated.inviteKey.length === 64, 'swept appId creates a fresh group on demand')

  // Idempotent: nothing new to sweep (A is young again).
  const again = engine.sweepGhosts({ ttlMs: DEFAULT_SWEEP_TTL_MS })
  t.is(again.swept, 0, 'young empty group survives the TTL')
})

test('sweep: TTL gates on createdAt; legacy (no createdAt) counts as infinitely old', (t) => {
  const engine = createOutboxLog(engineOpts())
  engine.sync.create(A) // createdAt = now

  t.is(engine.sweepGhosts({ ttlMs: 60_000 }).swept, 0, 'younger than TTL -> kept')
  t.is(engine.sweepGhosts({ ttlMs: 60_000, now: Date.now() + 120_000 }).swept, 1, 'older than TTL -> swept')

  // Legacy journal entry without createdAt (pre-sweep builds): loads, and is
  // sweepable under ANY ttl — every timestamp-less empty group is churn-era.
  const journal = createMemoryOutboxJournal([{
    version: OUTBOXLOG_JOURNAL_VERSION,
    seq: 1,
    kind: 'create',
    appId: B,
    inviteKey: 'f'.repeat(64),
    namespace: null
  }])
  const legacy = createOutboxLog(engineOpts({ journal }))
  t.is(legacy._stats().groups, 1, 'legacy create replays')
  t.is(legacy.sweepGhosts({ ttlMs: 365 * 24 * 60 * 60 * 1000 }).swept, 1, 'legacy empty group swept despite a huge TTL')
})

test('sweep: survives journal replay AND the snapshot checkpoint path', (t) => {
  const journal = createMemoryOutboxJournal()
  const persistence = createMemoryOutboxPersistence()
  const engine = createOutboxLog(engineOpts({ journal, persistence }))
  engine.sync.create(A)
  engine.sync.create(B)
  engine.sync.append(B, { type: 'post', data: { id: 'p1', body: 'kept' } })

  t.is(engine.sweepGhosts({ ttlMs: 0 }).swept, 1, 'ghost swept')

  // Journal replay: a fresh engine over the same journal must NOT resurrect A.
  const replayed = createOutboxLog(engineOpts({ journal: createMemoryOutboxJournal(journal.entries()) }))
  t.is(replayed._stats().groups, 1, 'replayed engine holds only the author group')
  t.alike(replayed.sync.range(B, {}).map(r => r.key), ['post!p1'], 'author content survives replay')
  t.is(replayed.sync.heads([A]).heads[A], 0, 'swept appId reads as version 0 (unknown outbox)')

  // Snapshot checkpoint: flush() bakes the deletion into the snapshot too.
  engine.flush()
  const fromSnapshot = createOutboxLog(engineOpts({ persistence: createMemoryOutboxPersistence(persistence.loadSync()) }))
  t.is(fromSnapshot._stats().groups, 1, 'snapshot-restored engine holds only the author group')

  // createdAt round-trips through the snapshot (so TTLs stay correct across restarts).
  const snap = persistence.loadSync()
  const bEntry = snap.groups.find(([appId]) => appId === B)
  t.ok(Number.isFinite(bEntry[1].createdAt), 'createdAt persisted in the snapshot')
})

test('sweep: prunes stale swarm descriptors, keeps live + unattributable ones', (t) => {
  const swarm = createOutboxSwarmHub()
  const engine = createOutboxLog(engineOpts({ swarm }))
  engine.sync.create(A) // ghost
  engine.sync.create(B)
  engine.sync.append(B, { type: 'post', data: { id: 'p1' } })

  // Remember descriptors the way the wire does: join a topic, send data.
  const { channelId } = swarm.join('peerit-gossip-v1', {})
  swarm.send(channelId, 'peer-x', JSON.stringify({ t: 'outbox-desc', pub: A, appId: A, inviteKey: 'k' }))
  swarm.send(channelId, 'peer-x', JSON.stringify({ t: 'outbox-desc', pub: B, appId: B, inviteKey: 'k' }))
  swarm.send(channelId, 'peer-x', 'not-json-at-all')
  swarm.send(channelId, 'peer-x', JSON.stringify({ some: 'other-app-format' }))

  const res = engine.sweepGhosts({ ttlMs: 0 })
  t.is(res.swept, 1, 'ghost group swept')
  t.is(res.descriptorsPruned, 1, "exactly the ghost's descriptor pruned")
  const kept = swarm._snapshotDescriptors()['peerit-gossip-v1']
  t.is(kept.length, 3, 'live descriptor + both unattributable blobs kept')
  t.ok(kept.some(d => d.includes(B)), "the live author's descriptor survives")
  t.ok(!kept.some(d => d.includes('"appId":"' + A + '"')), "the ghost's descriptor is gone")
})

test('sweep: takedown suppressions SURVIVE the ghost sweep', (t) => {
  // DO-NOT-SERVE is an operator legal posture keyed by opaque id: it must
  // outlive the group. A swept id can return (writer re-appends the same key,
  // or a future journal import re-introduces it), so the sweep must never
  // silently re-expose a taken-down record.
  const engine = createOutboxLog(engineOpts())
  engine.sync.create(A)
  engine.takedown(A, 'post!x', 'notice-1') // suppression can exist without rows (serve-time)
  t.is(engine.takedowns().count, 1)
  t.is(engine.sweepGhosts({ ttlMs: 0 }).swept, 1)
  t.is(engine.takedowns().count, 1, 'suppression retained across the sweep')
  t.ok(engine.isSuppressed(A, 'post!x'))

  // The retention is not decorative: a re-created outbox re-appending the same
  // key is still suppressed at serve time.
  engine.sync.create(A)
  engine.sync.append(A, { type: 'post', data: { id: 'x', body: 'illegal' } })
  t.is(engine.sync.get(A, 'post!x'), null, 're-appended taken-down record stays suppressed')
})

test('sweep: retained suppressions survive journal replay of the sweep', (t) => {
  const journal = createMemoryOutboxJournal()
  const first = createOutboxLog(engineOpts({ journal }))
  first.sync.create(A)
  first.takedown(A, 'post!x', 'notice-2')
  first.sweepGhosts({ ttlMs: 0 })
  t.ok(first.isSuppressed(A, 'post!x'))

  const replayed = createOutboxLog(engineOpts({ journal }))
  t.ok(replayed.isSuppressed(A, 'post!x'), 'sweep replay neither resurrects the group nor drops the suppression')
  t.is(replayed.takedowns().takedowns[0].reason, 'notice-2', 'audit reason survives replay')
})

test('OutboxLogApp: config-driven startup sweep + timer lifecycle', async (t) => {
  const app = new OutboxLogApp({ verifyAppend: permissive })
  app.sync.create(A) // churn-era ghost sitting in state before start()
  app.sync.create(B)
  app.sync.append(B, { type: 'post', data: { id: 'p1' } })

  await app.start({ config: { outboxlog: { sweep: { ttlMs: 0, intervalMs: 60_000 } } } })
  t.is(app.engine._stats().groups, 1, 'startup sweep reclaimed the backlog immediately')
  t.ok(app._sweepTimer, 'periodic sweep timer armed')
  await app.stop()
  t.is(app._sweepTimer, null, 'stop() clears the sweep timer')

  const off = new OutboxLogApp({ verifyAppend: permissive })
  off.sync.create(C)
  await off.start({ config: { outboxlog: { sweep: false } } })
  t.is(off.engine._stats().groups, 1, 'sweep: false leaves ghosts alone')
  t.is(off._sweepTimer, null, 'no timer when disabled')
  await off.stop()

  t.is(OUTBOXLOG_SWEEP_DEFAULT_TTL_MS, 24 * 60 * 60 * 1000, 'default TTL is 24h')
})

test('admin surface: POST /api/admin/sweep behind the admin token', async (t) => {
  const app = new OutboxLogApp({ verifyAppend: permissive })
  const auth = createOutboxLogTokenAuth()
  const adminAuth = createOutboxLogAdminAuth({ tokens: ['admintok'] })
  const ctx = { outboxLogApp: app, auth, state: createOutboxLogHttpState(), adminAuth, ssePingMs: 60_000 }
  const token = ctx.auth.issue()

  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId: A }, token), fakeRes(), ctx)
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/create', { appId: D }, token), fakeRes(), ctx)
  await handleOutboxLogRoute(jsonReq('POST', '/api/sync/append', { appId: D, op: { type: 'post', data: { id: 'p1' } } }, token), fakeRes(), ctx)

  // Browser sync token must NOT be able to sweep.
  const withSyncToken = fakeRes()
  await handleOutboxLogRoute(jsonReq('POST', '/api/admin/sweep', { ttlMs: 0 }, token), withSyncToken, ctx)
  t.is(withSyncToken.statusCode, 401, 'browser token rejected on the sweep surface')

  // Authorized sweep with ttlMs: 0 (break-glass "sweep everything empty NOW").
  const adminReq = jsonReq('POST', '/api/admin/sweep', { ttlMs: 0 })
  adminReq.headers['x-pear-admin-token'] = 'admintok'
  const adminRes = fakeRes()
  await handleOutboxLogRoute(adminReq, adminRes, ctx)
  t.is(adminRes.statusCode, 200)
  const body = parseBody(adminRes)
  t.is(body.swept, 1, 'ghost swept via the admin endpoint')
  t.is(body.remaining, 1, 'author group remains')

  // Wrong method → 405.
  const getReq = fakeReq('GET', '/api/admin/sweep')
  getReq.headers['x-pear-admin-token'] = 'admintok'
  const getRes = fakeRes()
  await handleOutboxLogRoute(getReq, getRes, ctx)
  t.is(getRes.statusCode, 405, 'GET rejected')
})
