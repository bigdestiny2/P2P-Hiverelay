import b4a from 'b4a'
import test from 'brittle'
import {
  EncryptedIntentStore,
  INTENT_STATE,
  MemoryIntentBackend,
  createAesGcmIntentSealer,
  createClientIntent,
  decodeClientIntent,
  encodeClientIntent,
  journalSignedIntent
} from '../control.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'

const runtime = createNodeCryptoRuntime()

function bytes (value) {
  return b4a.alloc(32, value)
}

function fixture () {
  return createClientIntent({
    runtime,
    intentId: bytes(1),
    logicalId: bytes(2),
    continuityRoot: bytes(3),
    storeId: bytes(4),
    descriptorHash: bytes(5),
    descriptorSequence: 7n,
    endpointId: 1,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1,
    familyId: 2,
    operationId: 1,
    requestCommitment: bytes(6),
    clientNonce: bytes(7),
    operationBytes: b4a.from('SIGNED_OPAQUE_OPERATION_SENTINEL_62f8a7', 'ascii')
  })
}

test('client intent codec is byte-exact, bounded and rejects noncanonical reserved state', t => {
  const intent = fixture()
  const encoded = encodeClientIntent(intent)
  const decoded = decodeClientIntent(encoded)
  t.alike(decoded.intentId, intent.intentId)
  t.alike(decoded.operationBytes, intent.operationBytes)
  t.is(decoded.state, INTENT_STATE.JOURNALED)
  t.alike(encodeClientIntent(decoded), encoded)

  const reserved = b4a.from(encoded)
  reserved[262] = 1
  t.exception(() => decodeClientIntent(reserved), /reserved bytes/)
  t.exception(() => encodeClientIntent({ ...intent, operationBytes: b4a.alloc(4 * 1024 * 1024 + 1) }), /byte bound/)
})

test('encrypted intent store persists no operation plaintext and recovers exact retry bytes after restart', async t => {
  const backend = new MemoryIntentBackend()
  const sealer = createAesGcmIntentSealer(runtime, bytes(9))
  const store = new EncryptedIntentStore({ backend, sealer })
  const intent = fixture()
  const createSeed = bytes(10)
  await journalSignedIntent(store, intent, { ephemeralSecrets: [createSeed] })
  t.alike(createSeed, b4a.alloc(32))

  const raw = [...backend.records.values()][0].ciphertext
  t.absent(b4a.toString(raw, 'latin1').includes('SIGNED_OPAQUE_OPERATION_SENTINEL_62f8a7'))
  t.alike((await store.read(intent.intentId)).value.operationBytes, intent.operationBytes)

  await store.update(intent.intentId, value => ({ ...value, state: INTENT_STATE.TARGET_PREPARED }))
  await store.update(intent.intentId, value => ({
    ...value,
    state: INTENT_STATE.SENT,
    mayHaveCommitted: true,
    attemptCount: value.attemptCount + 1
  }))
  await store.update(intent.intentId, value => ({ ...value, state: INTENT_STATE.PENDING_UNKNOWN }))

  const restarted = new EncryptedIntentStore({ backend, sealer })
  const recovered = await restarted.read(intent.intentId)
  t.is(recovered.value.state, INTENT_STATE.PENDING_UNKNOWN)
  t.is(recovered.value.mayHaveCommitted, true)
  t.alike(recovered.value.operationBytes, intent.operationBytes)

  await restarted.update(intent.intentId, value => ({ ...value, state: INTENT_STATE.TARGET_PREPARED }))
  await restarted.update(intent.intentId, value => ({
    ...value,
    state: INTENT_STATE.SENT,
    attemptCount: value.attemptCount + 1
  }))
  t.is((await restarted.read(intent.intentId)).value.attemptCount, 2)
})

test('intent CAS forbids identity mutation, result-before-verification and authenticated-ciphertext replay', async t => {
  const backend = new MemoryIntentBackend()
  const store = new EncryptedIntentStore({
    backend,
    sealer: createAesGcmIntentSealer(runtime, bytes(11))
  })
  const intent = fixture()
  await store.create(intent)
  await t.exception(store.update(intent.intentId, value => ({
    ...value,
    state: INTENT_STATE.TARGET_PREPARED,
    operationBytes: b4a.from('changed')
  })), /immutable intent identity/)
  await t.exception(store.update(intent.intentId, value => ({
    ...value,
    resultBytes: b4a.from([1])
  })), /only after complete verification/)

  const key = (await backend.keys())[0]
  const record = backend.records.get(key)
  record.ciphertext[record.ciphertext.byteLength - 1] ^= 1
  await t.exception(store.read(intent.intentId), /authentication failed/)
})
