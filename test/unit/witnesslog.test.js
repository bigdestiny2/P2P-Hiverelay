import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  WITNESSLOG_NAMESPACE,
  WitnessLogApp,
  canonicalWitnessRecord,
  createWitnessRecord,
  redactWitnessRecord,
  signWitnessRecord,
  targetMatchesWitnessRecord,
  verifyWitnessOutboxRecord,
  verifyWitnessRecord,
  witnessRecordMarker
} from '../../packages/services/builtin/witnesslog/index.js'

const OBSERVED_AT = '2026-07-02T12:00:00.000Z'
const EXPIRES_AT = '2026-07-02T12:30:00.000Z'
const NOW = Date.parse('2026-07-02T12:05:00.000Z')
const TARGET = 'a'.repeat(64)
const TARGET_HASH = 'b'.repeat(64)

test('witnesslog record: signs, verifies, canonicalizes, and redacts target keys', (t) => {
  const observer = keyPair(1)
  const base = witnessInput(observer)
  const created = createWitnessRecord(base)
  const signed = signWitnessRecord(base, observer.secretKey)

  t.is(created.id, signed.id)
  t.is(canonicalWitnessRecord(base), canonicalWitnessRecord(signed))
  t.ok(verifyWitnessRecord(signed, { now: NOW }))
  t.absent(verifyWitnessRecord({ ...signed, result: { ...signed.result, latencyMs: 999 } }, { now: NOW }))

  const redacted = redactWitnessRecord(signed)
  t.absent(redacted.target.key)
  t.is(redacted.target.keyHash, TARGET_HASH)
  t.ok(targetMatchesWitnessRecord(signed, TARGET))
  t.ok(targetMatchesWitnessRecord(signed, TARGET_HASH))

  const marker = witnessRecordMarker(signed)
  t.alike(marker, {
    id: signed.id,
    observedAt: OBSERVED_AT,
    expiresAt: EXPIRES_AT,
    observer: observer.publicKeyHex,
    relay: 'https://relay.example/',
    target: TARGET_HASH,
    targetKind: 'hypercore',
    ok: true,
    latencyMs: 42,
    httpStatus: 200,
    errorCode: null
  })
})

test('witnesslog record: timestamp policy rejects future, stale, and expired observations', (t) => {
  const observer = keyPair(2)
  const future = signWitnessRecord(witnessInput(observer, {
    observedAt: '2026-07-02T13:00:00.000Z',
    expiresAt: '2026-07-02T13:30:00.000Z'
  }), observer.secretKey)
  const stale = signWitnessRecord(witnessInput(observer, {
    observedAt: '2026-07-01T11:00:00.000Z',
    expiresAt: '2026-07-01T11:30:00.000Z'
  }), observer.secretKey)
  const expired = signWitnessRecord(witnessInput(observer, {
    observedAt: '2026-07-02T11:00:00.000Z',
    expiresAt: '2026-07-02T11:30:00.000Z'
  }), observer.secretKey)

  t.absent(verifyWitnessRecord(future, { now: NOW }))
  t.absent(verifyWitnessRecord(stale, { now: NOW, maxAgeMs: 30 * 60 * 1000 }))
  t.absent(verifyWitnessRecord(expired, { now: NOW }))
})

test('witnesslog app: appends signed observations, ranges by target, and emits markers', (t) => {
  const observer = keyPair(3)
  const app = new WitnessLogApp({ verify: { now: NOW } })
  const signed = signWitnessRecord(witnessInput(observer), observer.secretKey)
  const live = []
  const unsubscribe = app.subscribe({ target: TARGET_HASH }, marker => live.push(marker))

  t.alike(app.append(signed), { ok: true, key: 'availability!' + signed.id, id: signed.id })
  unsubscribe()

  const page = app.list({ target: TARGET_HASH })
  t.is(page.count, 1)
  t.is(page.total, 1)
  t.is(page.records[0].id, signed.id)
  t.absent(page.records[0].target.key)
  t.is(page.records[0].target.keyHash, TARGET_HASH)

  const markers = app.markers({ target: TARGET })
  t.is(markers.count, 1)
  t.is(markers.markers[0].id, signed.id)
  t.is(live.length, 1)
  t.is(live[0].topic, 'witness/' + TARGET_HASH)
})

test('witnesslog app: rejects foreign outbox writers before storage', (t) => {
  const observer = keyPair(4)
  const foreign = keyPair(5)
  const signed = signWitnessRecord(witnessInput(observer), observer.secretKey)
  const app = new WitnessLogApp({ verify: { now: NOW } })
  const bad = {
    appId: foreign.publicKeyHex,
    data: { ...signed, _ns: WITNESSLOG_NAMESPACE }
  }

  t.absent(verifyWitnessOutboxRecord(bad, { now: NOW }))
  const err = throws(() => app.sync.append(foreign.publicKeyHex, { type: 'availability', data: bad.data }))
  t.is(err.status, 400)
  t.is(app.list().count, 0)
})

test('witnesslog app: default file persistence restores signed observations', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'witnesslog-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const observer = keyPair(6)
  const signed = signWitnessRecord(witnessInput(observer), observer.secretKey)
  const first = new WitnessLogApp({ verify: { now: NOW } })
  await first.start({ config: { storage: dir }, node: { id: 'relay-a' } })
  t.alike(first.append(signed), { ok: true, key: 'availability!' + signed.id, id: signed.id })
  await first.stop()

  const second = new WitnessLogApp({ verify: { now: NOW } })
  await second.start({ config: { storage: dir }, node: { id: 'relay-b' } })
  const page = second.list({ target: TARGET_HASH })
  t.is(page.count, 1)
  t.is(page.records[0].id, signed.id)
  t.absent(page.records[0].target.key)
  await second.stop()
})

function witnessInput (observer, fields = {}) {
  return {
    observedAt: fields.observedAt || OBSERVED_AT,
    expiresAt: fields.expiresAt || EXPIRES_AT,
    observer: {
      publicKey: observer.publicKeyHex,
      appId: 'probe-agent'
    },
    relay: {
      url: 'https://relay.example',
      operatorKey: 'c'.repeat(64)
    },
    target: {
      kind: 'hypercore',
      key: TARGET,
      keyHash: TARGET_HASH
    },
    probe: {
      nonce: 'nonce-1',
      method: 'gateway-head',
      range: { start: 0, end: 1024 }
    },
    result: {
      ok: true,
      httpStatus: 200,
      latencyMs: 42,
      bytes: 1024,
      headSeq: 7,
      digest: 'sha256:' + 'd'.repeat(64)
    }
  }
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return {
    publicKey,
    secretKey,
    publicKeyHex: b4a.toString(publicKey, 'hex')
  }
}

function throws (fn) {
  try {
    fn()
  } catch (err) {
    return err
  }
  throw new Error('expected function to throw')
}
