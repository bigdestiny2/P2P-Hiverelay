/**
 * GIGA DoD cross-feature journey — namespace × blind
 * (docs/GIGA-RELEASE-ARCHITECTURE.md §7 "Cross-feature journeys":
 * "two apps sharing one relay's outboxlog under distinct blind namespaces,
 * with takedown"; docs/NAMESPACE.md).
 *
 * What this proves (composition, not internals), all over the relay's real
 * HTTP bridge into a RelayNode-loaded outboxlog service:
 *   1. Sealed round-trip: two app writers share one relay under distinct
 *      blind namespaces; a client-sealed record appends and reads back
 *      with the relay holding ciphertext only (stored body is a blind
 *      sealed body; the plaintext never appears in the served record).
 *   2. Plaintext-shaped records are hard-rejected (400) — both a record
 *      whose body is not a sealed body and a sealed record carrying a
 *      BLIND_FORBIDDEN_FIELDS marker.
 *   3. Operator opaque-id takedown: DO-NOT-SERVE via the admin surface
 *      (admin key, never the browser token) suppresses the record from
 *      reads without content exposure — the row stays in storage and the
 *      audit surface lists only opaque ids; restore reverses it.
 *   4. Cross-namespace replay is rejected: the namespace is inside the
 *      ed25519 signature domain, so a record signed for appalpha fails
 *      verification when replayed as appbeta — and an appalpha record
 *      replayed into an appbeta-bound outbox is refused as well.
 *
 * Realization: real RelayNode + its real ServiceRegistry + a real
 * OutboxLogApp (in-memory persistence — the durability backend is
 * orthogonal to this journey) on a hyperswarm testnet; clients drive the
 * real /api/sync and /api/admin HTTP surface. The RelayNode-boots-
 * outboxlog-with-hypercore-journal path on a fresh store is separately
 * broken upstream of these journeys — see the marked GAP test below.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import {
  OutboxLogApp,
  canonicalOutboxRecord,
  createOutboxBlindSealAAD,
  createOutboxBlindSealKey,
  isOutboxBlindRecord,
  openOutboxBlindPayload,
  sealOutboxBlindPayload,
  verifyOutboxRecordSignature
} from 'p2p-hiveservices/builtin/outboxlog/index.js'

const ADMIN_KEY = 'journey-operator-admin-key'
const NS_ALPHA = 'appalpha'
const NS_BETA = 'appbeta'

const NAMESPACES = {
  [NS_ALPHA]: { blind: true, caps: { maxOutboxes: 4, maxEntriesPerOutbox: 8, maxValueBytes: 16 * 1024 } },
  [NS_BETA]: { blind: true, caps: { maxOutboxes: 4, maxEntriesPerOutbox: 8, maxValueBytes: 16 * 1024 } }
}

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-journey-namespace-blind-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

function pickPort () {
  return 49000 + Math.floor(Math.random() * 10000)
}

function writerKeyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey, publicKeyHex: b4a.toString(publicKey, 'hex') }
}

// Same signing shape the app clients use (test/unit/outboxlog-blind-seal.test.js):
// the namespace is part of the signed payload — `pear.app.<driveKey>:<ns>:<record>`.
function signRecord (writer, fields = {}, type = 'message') {
  const namespace = fields._ns || NS_ALPHA
  const data = {
    id: fields.id || 'm1',
    author: writer.publicKeyHex,
    ...fields,
    _k: writer.publicKeyHex,
    _dk: fields._dk || 'd'.repeat(64),
    _ns: namespace,
    _alg: 'ed25519'
  }
  const signed = `pear.app.${data._dk}:${data._ns}:${canonicalOutboxRecord(type, data)}`
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, b4a.from(signed, 'utf8'), writer.secretKey)
  return { ...data, _sig: b4a.toString(signature, 'hex') }
}

async function postJson (port, requestPath, body, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${requestPath}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body)
  })
  return { status: res.status, body: await res.json().catch(() => null) }
}

async function getJson (port, requestPath, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${requestPath}`, { headers })
  return { status: res.status, body: await res.json().catch(() => null) }
}

test('journey namespace × blind: two apps share one relay under blind namespaces — sealed I/O, rejection, takedown, replay', async (t) => {
  const dir = tmpdir(t)
  const relayStorage = path.join(dir, 'relay')
  fs.mkdirSync(relayStorage, { recursive: true })

  const testnet = await createTestnet(3)
  const apiPort = pickPort()

  const relay = new RelayNode({
    storage: relayStorage,
    bootstrapNodes: testnet.bootstrap,
    enableAPI: true,
    apiPort,
    apiHost: '127.0.0.1',
    enableRelay: false,
    enableSeeding: true,
    enableServices: true,
    plugins: [],
    enableNetworkDiscovery: false,
    enableHolesail: false,
    outboxlog: { adminKey: ADMIN_KEY }
  })
  t.teardown(async () => {
    try { await relay.stop() } catch {}
    try { await testnet.destroy() } catch {}
  })
  await relay.start()

  // Real OutboxLogApp registered into the running relay's real
  // ServiceRegistry — same provider object the PluginLoader would build,
  // with in-memory persistence (the hypercore journal's RelayNode boot path
  // is broken on fresh stores — GAP test below). Everything this journey
  // asserts (namespace registry, blind-seal enforcement, signature domain,
  // takedown surface, HTTP bridge) is untouched by the persistence backend.
  const outboxApp = new OutboxLogApp({ persistence: false, namespaces: NAMESPACES })
  relay.serviceRegistry.register(outboxApp)
  await relay.serviceRegistry.startAll(relay._buildServiceContext())
  t.is(relay.serviceRegistry.services.get('outboxlog')?.status, 'running', 'outboxlog service running inside the relay')

  const token = (await postJson(apiPort, '/api/token', {})).body.token
  t.ok(token, 'browser bridge token issued')
  const auth = { 'X-Pear-Token': token }
  const bridge = await getJson(apiPort, '/api/bridge/status', auth)
  t.alike(bridge.body, { ready: true, service: 'outboxlog' }, 'outboxlog HTTP bridge live on the relay')

  // Two app writers, one relay, two blind namespaces.
  const alpha = writerKeyPair(41)
  const beta = writerKeyPair(42)
  t.is((await postJson(apiPort, '/api/sync/create', { appId: alpha.publicKeyHex, namespace: NS_ALPHA }, auth)).status, 200)
  t.is((await postJson(apiPort, '/api/sync/create', { appId: beta.publicKeyHex, namespace: NS_BETA }, auth)).status, 200)

  // ─── 1. Sealed round-trip — ciphertext only at the relay ──────────────
  const sealKey = createOutboxBlindSealKey()
  const keyId = 'alpha-room:main@1'
  const aad = createOutboxBlindSealAAD({ namespace: NS_ALPHA, appId: alpha.publicKeyHex, type: 'message', id: 'm1', keyId })
  const sealedBody = sealOutboxBlindPayload({ text: 'alpha room secret' }, { key: sealKey, aad, keyId })
  const record = signRecord(alpha, { id: 'm1', _ns: NS_ALPHA, body: sealedBody }, 'message')

  const appended = await postJson(apiPort, '/api/sync/append', { appId: alpha.publicKeyHex, op: { type: 'message', data: record } }, auth)
  t.is(appended.status, 200, 'sealed record accepted: ' + JSON.stringify(appended.body))
  t.alike(appended.body, { ok: true, key: 'message!m1' })

  const served = await getJson(apiPort, `/api/sync/get?appId=${alpha.publicKeyHex}&key=${encodeURIComponent('message!m1')}`, auth)
  t.is(served.status, 200)
  t.ok(isOutboxBlindRecord(served.body), 'relay stores/serves a blind sealed body')
  t.absent(JSON.stringify(served.body).includes('alpha room secret'), 'no plaintext anywhere in the served record')
  t.alike(
    openOutboxBlindPayload(served.body.body, { key: sealKey, aad }),
    { text: 'alpha room secret' },
    'client re-opens the round-tripped ciphertext with the room key + aad'
  )

  // ─── 2. Plaintext-shaped records are hard-rejected ────────────────────
  const plaintextShaped = signRecord(alpha, { id: 'm2', _ns: NS_ALPHA, body: { text: 'relay must never store this' } }, 'message')
  const rejectedPlain = await postJson(apiPort, '/api/sync/append', { appId: alpha.publicKeyHex, op: { type: 'message', data: plaintextShaped } }, auth)
  t.is(rejectedPlain.status, 400, 'non-sealed body hard-rejected on a blind namespace')
  t.ok(/namespace policy/.test(rejectedPlain.body?.error || ''), 'rejected by the blind namespace policy: ' + rejectedPlain.body?.error)

  const forbiddenField = signRecord(alpha, { id: 'm3', _ns: NS_ALPHA, body: sealedBody, dataKey: 'deadbeef' }, 'message')
  const rejectedField = await postJson(apiPort, '/api/sync/append', { appId: alpha.publicKeyHex, op: { type: 'message', data: forbiddenField } }, auth)
  t.is(rejectedField.status, 400, 'BLIND_FORBIDDEN_FIELDS marker hard-rejected even with a sealed body')

  const ghosted = await getJson(apiPort, `/api/sync/get?appId=${alpha.publicKeyHex}&key=${encodeURIComponent('message!m2')}`, auth)
  t.is(ghosted.body, null, 'rejected record never entered the outbox')

  // ─── 3. Operator opaque-id takedown — tombstone without exposure ──────
  const wrongAuth = await postJson(apiPort, '/api/admin/takedown', { appId: alpha.publicKeyHex, key: 'message!m1' }, auth)
  t.is(wrongAuth.status, 401, 'browser token never reaches the admin surface')

  const dropped = await postJson(apiPort, '/api/admin/takedown', { appId: alpha.publicKeyHex, key: 'message!m1' }, { 'X-Pear-Admin-Token': ADMIN_KEY })
  t.is(dropped.status, 200)
  t.alike(dropped.body, { appId: alpha.publicKeyHex, key: 'message!m1', suppressed: true }, 'opaque-id takedown applied')

  const tombstoned = await getJson(apiPort, `/api/sync/get?appId=${alpha.publicKeyHex}&key=${encodeURIComponent('message!m1')}`, auth)
  t.is(tombstoned.body, null, 'subsequent reads serve the tombstone (null), not the content')

  const audit = await getJson(apiPort, '/api/admin/takedowns', { 'X-Pear-Admin-Token': ADMIN_KEY })
  t.alike(audit.body, { takedowns: [{ appId: alpha.publicKeyHex, key: 'message!m1' }], count: 1 },
    'audit surface lists opaque ids only')
  t.absent(JSON.stringify(audit.body).includes('alpha room secret'), 'audit surface exposes no content')

  // The row itself is untouched in storage — suppression is serve-time only.
  const engine = relay.serviceRegistry.services.get('outboxlog').provider.engine
  t.ok(engine.isSuppressed(alpha.publicKeyHex, 'message!m1'), 'engine marks the opaque id suppressed')
  const storedRows = engine.snapshot().groups.find(([id]) => id === alpha.publicKeyHex)[1].rows
  t.ok(storedRows.some(([key]) => key === 'message!m1'), 'record remains in storage after takedown')

  const restored = await postJson(apiPort, '/api/admin/restore', { appId: alpha.publicKeyHex, key: 'message!m1' }, { 'X-Pear-Admin-Token': ADMIN_KEY })
  t.alike(restored.body, { appId: alpha.publicKeyHex, key: 'message!m1', suppressed: false })
  const servedAgain = await getJson(apiPort, `/api/sync/get?appId=${alpha.publicKeyHex}&key=${encodeURIComponent('message!m1')}`, auth)
  t.ok(isOutboxBlindRecord(servedAgain.body), 'restore reverses the tombstone; sealed body serves again')

  // ─── 4. Cross-namespace replay is rejected (namespace ∈ signature domain)
  // Replay the exact signed alpha record as appbeta: the signature no longer
  // verifies — the namespace is inside the signed payload.
  const replayed = { ...record, _ns: NS_BETA }
  const replay = await postJson(apiPort, '/api/sync/append', { appId: alpha.publicKeyHex, op: { type: 'message', data: replayed } }, auth)
  t.is(replay.status, 400, 'cross-namespace replay rejected over the wire')
  t.ok(/bad signature/.test(replay.body?.error || ''), 'rejected at the signature check: ' + replay.body?.error)
  t.absent(
    verifyOutboxRecordSignature({ appId: alpha.publicKeyHex, type: 'message', data: replayed }, { namespaces: NAMESPACES }),
    'direct evidence: the alpha signature does not verify under appbeta'
  )

  // And the intact alpha record replayed into the beta-bound outbox is refused too.
  const crossOutbox = await postJson(apiPort, '/api/sync/append', { appId: beta.publicKeyHex, op: { type: 'message', data: record } }, auth)
  t.is(crossOutbox.status, 400, 'alpha record cannot land in the beta-bound outbox')
  const betaOutbox = await getJson(apiPort, `/api/sync/get?appId=${beta.publicKeyHex}&key=${encodeURIComponent('message!m1')}`, auth)
  t.is(betaOutbox.body, null, 'beta outbox never gained the replayed record')
})

// ─── MARKED GAP (GIGA DoD §7 "Cross-feature journeys" — namespace rows) ──
//
// RelayNode + PluginLoader + outboxlog with the operator-required bounded
// persistence backend (`outboxlog.journal: 'hypercore'`) does NOT boot on a
// fresh disk store with the vendored hypercore 11.34.1 / corestore 7.11.1:
//
//   1. createHypercoreOutboxJournal probes the named journal core via
//      `store.get({ name, createIfMissing: false })`. On a fresh store that
//      open fails STORAGE_EMPTY — and the failed core is never evicted from
//      corestore's tracker, so the follow-up `store.get({ name })` creation
//      resumes the same poisoned core and fails STORAGE_EMPTY again
//      (reproduced standalone: probe → create on an empty Corestore).
//   2. Even with the journal core pre-created, JournalStorageController
//      .measureExact() throws "OutboxLog exact core storage info
//      unavailable" because `core.info({ storage: true }).storage` is null
//      with the vendored hypercore.
//
// Consequence: an operator enabling `plugins: ['outboxlog']` with the
// bounded-persistence journal (the ONLY persistence shape RelayNode's
// storage-admission gate accepts) gets SERVICE_START_FAILED on first boot.
// The journeys above therefore register the real OutboxLogApp with
// in-memory persistence (its documented constructor option); the
// namespace/blind/takedown semantics under test are independent of the
// durability backend.
//
// This skipped test encodes the expected composition once the journal's
// probe/measure path is repaired — unskip it as the fix verification.
test.skip('gap: RelayNode boots outboxlog with hypercore journal on a fresh store (GIGA DoD §7)', async (t) => {
  const dir = tmpdir(t)
  const relayStorage = path.join(dir, 'relay')
  fs.mkdirSync(relayStorage, { recursive: true })
  const testnet = await createTestnet(3)
  const relay = new RelayNode({
    storage: relayStorage,
    bootstrapNodes: testnet.bootstrap,
    enableAPI: false,
    enableRelay: false,
    enableSeeding: true,
    enableServices: true,
    plugins: ['outboxlog'],
    enableNetworkDiscovery: false,
    enableHolesail: false,
    outboxlog: {
      journal: 'hypercore',
      maxJournalStorageBytes: 16 * 1024 * 1024,
      namespaces: NAMESPACES
    }
  })
  t.teardown(async () => {
    try { await relay.stop() } catch {}
    try { await testnet.destroy() } catch {}
  })
  await relay.start()
  t.is(relay.serviceRegistry.services.get('outboxlog')?.status, 'running',
    'outboxlog boots with the bounded hypercore journal on a fresh store')
})
