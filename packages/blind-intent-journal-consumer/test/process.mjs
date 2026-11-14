/* global Bare */
import b4a from 'b4a'
import { BoundedNativeIntentBackend, DurableIntentJournal } from '../index.js'
import { INTENT_STATE, createClientIntent, createAesGcmIntentSealer } from '../../blind-client/intent.js'

const isBare = typeof Bare !== 'undefined'
const [adapter, mode, directory] = (isBare ? Bare.argv : process.argv).slice(2)
const runtime = isBare
  ? (await import('../../blind-client/runtime/bare.js')).createBareCryptoRuntime()
  : (await import('../../blind-client/runtime/node.js')).createNodeCryptoRuntime()
let backend
if (adapter === 'node') backend = new (await import('../../blind-intent-store-node/index.js')).NodeIntentBackend(directory)
else if (adapter === 'bare') backend = new (await import('../../blind-intent-store-bare/index.js')).BareIntentBackend(directory)
else if (adapter === 'pear') backend = new (await import('../../blind-intent-pear-consumer/index.cjs')).PearIntentBackend(directory)
else throw Error('Unknown adapter')
if (mode === 'copy-admission') {
  const bounded = new BoundedNativeIntentBackend(backend, { maxRecords: 6, maxTotalBytes: 1024 })
  try {
    await bounded.ready()
    class AliasedBytes extends Uint8Array { slice () { return this.subarray() } }
    const inputs = [b4a.from([7]), new Uint8Array([11]), new AliasedBytes([13]), b4a.from([17]), new Uint8Array([19]), new AliasedBytes([23])]
    const expected = inputs.map(value => value[0])
    const keys = inputs.map((value, i) => 'intent:' + (i + 1).toString(16).padStart(64, '0'))
    const writes = inputs.map((value, i) => bounded.compareAndSwap(keys[i], 0n, value))
    for (const value of inputs) value[0] = 99
    const changed = await Promise.all(writes)
    const stored = []
    for (const key of keys) stored.push((await bounded.read(key)).ciphertext[0])
    console.log(JSON.stringify({ adapter, runtime: isBare ? Bare.version : process.version, embeddedRuntime: backend.runtime?.runtime, vector: 'six-admitted-and-queued-owned-copies', inputTypes: inputs.map(value => value.constructor.name), expected, stored, changed }))
    if (JSON.stringify(stored) !== JSON.stringify(expected) || !changed.every(Boolean)) throw Error('Admitted ciphertext changed')
  } finally { await bounded.close() }
} else {
  const id = b4a.alloc(32, 1)
  const key = 'intent:' + b4a.toString(id, 'hex')
  const journal = new DurableIntentJournal({
    backend,
    sealer: createAesGcmIntentSealer(runtime, b4a.alloc(32, mode === 'wrong-key' ? 10 : 9)),
    policy: { maxRecords: 2, maxTotalBytes: 2048, maxCiphertextBytes: 1024 },
    recoveryFloors: ['create', 'kill-sent'].includes(mode) ? [] : [{ key, revision: 3n }]
  })
  try {
    const recovery = await journal.ready()
    if (['create', 'kill-sent'].includes(mode)) {
      await journal.create(createClientIntent({
        runtime,
        intentId: id,
        logicalId: b4a.alloc(32, 2),
        continuityRoot: b4a.alloc(32, 3),
        storeId: b4a.alloc(32, 4),
        descriptorHash: b4a.alloc(32, 5),
        descriptorSequence: 7n,
        endpointId: 1,
        transportId: 1,
        transportSupportBit: 1,
        privacyProfileBit: 1,
        familyId: 2,
        operationId: 1,
        requestCommitment: b4a.alloc(32, 6),
        clientNonce: b4a.alloc(32, 7),
        operationBytes: b4a.from('PRIVATE_CAPABILITY_AND_SAME_OPERATION_JOURNAL_V1')
      }))
      await journal.update(id, value => ({ ...value, state: INTENT_STATE.TARGET_PREPARED }))
      await journal.update(id, value => ({ ...value, state: INTENT_STATE.SENT, mayHaveCommitted: true, attemptCount: 1 }))
    }
    const record = await journal.read(id)
    const executable = isBare ? (await import('bare-os')).default.execPath() : process.execPath
    const pid = isBare ? (await import('bare-os')).default.pid() : process.pid
    console.log(JSON.stringify({
      adapter,
      runtime: isBare ? Bare.version : process.version,
      pid,
      executable,
      embeddedPid: backend.runtime?.pid,
      embeddedRuntime: backend.runtime?.runtime,
      embeddedExecutable: backend.runtime?.executable,
      embeddedExecutableSha256: backend.runtime?.executableSha256,
      recovery,
      record: {
        revision: String(record.revision),
        state: record.value.state,
        mayHaveCommitted: record.value.mayHaveCommitted,
        logicalId: b4a.toString(record.value.logicalId, 'hex'),
        nonce: b4a.toString(record.value.clientNonce, 'hex'),
        commitment: b4a.toString(record.value.requestCommitment, 'hex'),
        operation: b4a.toString(record.value.operationBytes, 'hex')
      }
    }))
    if (mode === 'kill-sent') await new Promise(() => { setInterval(() => {}, 1000) })
  } catch (error) {
    console.log(JSON.stringify({ error: error.code || 'ERROR', message: error.message }))
    if (isBare) Bare.exitCode = 1
    else process.exitCode = 1
  } finally { await journal.close() }
}
