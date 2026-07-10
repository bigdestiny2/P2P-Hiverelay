import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  DEFAULT_OUTBOXLOG_NAMESPACE,
  OutboxLogApp,
  canonicalOutboxRecord,
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
    mutations: [{ type: 'post', fields: { id: 'p1', title: 'genesis' } }]
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

  const conflicting = structuredClone(built.commit)
  conflicting.mutations[0].timestamp = 'changed-after-response-loss'
  const conflict = throws(() => log.sync.commit(writer.publicKeyHex, conflicting))
  t.is(conflict.status, 409)
  t.is(journal.entries().length, 1)
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

  const reloaded = createOutboxLog({ journalPath: path })
  t.is(reloaded.sync.get(writer.publicKeyHex, 'post!persisted').id, 'persisted')
  t.alike(reloaded.sync.commit(writer.publicKeyHex, built.commit), receipt)
  t.is(await readFile(path, 'utf8'), before, 'replayed retry does not grow the journal')
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
    cas: true,
    idempotent: true
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
