import { openSync, constants } from '../runtime.js'
import FDLock from 'fd-lock'
import { BareIntentBackend } from '../index.js'

const [mode, directory, key, revision = '0', ciphertext = '', stopPhase = ''] = Bare.argv.slice(2)
const send = value => console.log(JSON.stringify(value))
try {
  if (mode === 'raw-lock') {
    const lock = new FDLock(openSync(directory + '/.writer-lock', constants.O_RDWR | constants.O_NOFOLLOW))
    await lock.ready()
    await lock.close()
    send({ locked: true })
  } else {
    const backend = new BareIntentBackend(directory, {
      onCommitPhase: async phase => {
        if (mode === 'kill-cas' && phase === stopPhase) {
          send({ phase })
          setInterval(() => {}, 1000)
          setTimeout(() => Bare.exit(2), 45000)
          await new Promise(() => {})
        }
      }
    })
    await backend.ready()
    if (mode === 'hold') {
      send({ held: true })
      setInterval(() => {}, 1000)
      setTimeout(() => Bare.exit(2), 45000)
      await new Promise(() => {})
    }
    if (mode === 'intent-send' || mode === 'intent-recover') {
      const { EncryptedIntentStore, INTENT_STATE, createAesGcmIntentSealer, createClientIntent } = await import('./.baseline/packages/blind-client/intent.js')
      const { createBareCryptoRuntime } = await import('./.baseline/packages/blind-client/runtime/bare.js')
      const runtime = createBareCryptoRuntime()
      const store = new EncryptedIntentStore({ backend, sealer: createAesGcmIntentSealer(runtime, Buffer.alloc(32, 9)) })
      const id = Buffer.alloc(32, 1)
      if (mode === 'intent-send') {
        await store.create(createClientIntent({
          runtime,
          intentId: id,
          logicalId: Buffer.alloc(32, 2),
          continuityRoot: Buffer.alloc(32, 3),
          storeId: Buffer.alloc(32, 4),
          descriptorHash: Buffer.alloc(32, 5),
          descriptorSequence: 7n,
          endpointId: 1,
          transportId: 1,
          transportSupportBit: 1,
          privacyProfileBit: 1,
          familyId: 2,
          operationId: 1,
          requestCommitment: Buffer.alloc(32, 6),
          clientNonce: Buffer.alloc(32, 7),
          operationBytes: Buffer.from('SIGNED_CAPABILITY_SENTINEL_INTENT_RESTART_20260905')
        }))
        await store.update(id, value => ({ ...value, state: INTENT_STATE.TARGET_PREPARED }))
        await store.update(id, value => ({ ...value, state: INTENT_STATE.SENT, mayHaveCommitted: true, attemptCount: 1 }))
      } else {
        const before = await store.read(id)
        if (before.value.state !== INTENT_STATE.SENT) throw new Error('restart must recover SENT first')
        await store.update(id, value => ({ ...value, state: INTENT_STATE.PENDING_UNKNOWN }))
      }
      const record = await store.read(id)
      send({
        state: record.value.state,
        revision: String(record.revision),
        logicalId: record.value.logicalId.toString('hex'),
        operation: record.value.operationBytes.toString('hex'),
        commitment: record.value.requestCommitment.toString('hex'),
        nonce: record.value.clientNonce.toString('hex'),
        mayHaveCommitted: record.value.mayHaveCommitted,
        attemptCount: record.value.attemptCount
      })
    } else {
      const changed = mode === 'read' ? null : await backend.compareAndSwap(key, BigInt(revision), Buffer.from(ciphertext, 'hex'))
      const record = await backend.read(key)
      send({ changed, revision: String(record.revision), ciphertext: record.ciphertext?.toString('hex') })
    }
    await backend.close()
  }
} catch (error) {
  send({ error: error.code || 'ERROR', message: error.message })
  Bare.exitCode = 1
}
