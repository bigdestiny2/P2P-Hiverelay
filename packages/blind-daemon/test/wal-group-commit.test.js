import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import { BlindTransactionStore } from '../transaction-store.js'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

const PARTITION_KEY = b4a.alloc(32, 0x81)
const OWNER_FENCE = b4a.alloc(32, 0x91)
const CONTINUITY = b4a.alloc(32, 0x94)

// Captured from the pre-group-commit store (wal.v2/HRWL, format frozen by the
// store-format authority): three single-appender frames over the fixed keys
// above. Group commit must reproduce these exact bytes for a lone appender.
const GOLDEN_WAL_HEX = '4852574c02c9000000f5000000000000000151515151515151515151515151515151515151515151515151515151515151510007000000000000000191919191919191919191919191919191919191919191919191919191919191910000001500000000000000000000000000000000000000000000000000000000000000009494949494949494949494949494949494949494949494949494949494949494d809e3293b3d1b15741e2741f8032620e45830e30d18c0857b87403a97ca9bba67726f75702d636f6d6d69742d676f6c64656e2d31ea271ce45bd6b2d494da2a06dccb8408363cb19501cb7fd9345a9449bfd8343e4852574c02ca000000f500000000000000025252525252525252525252525252525252525252525252525252525252525252000800000000000000019191919191919191919191919191919191919191919191919191919191919191000000152cefedd578de31fdc906c6401d2b1ec3a97ea7f88ae1e6bad2c77552aae45a8b949494949494949494949494949494949494949494949494949494949494949477727790304e0a0f70082a5b949bf7dcbb0d189ae309aef35decf48968421a0267726f75702d636f6d6d69742d676f6c64656e2d32b70ace070e9a2e4dda3af2fced5a00e4d0b53127f1e7fd9e0561873982f2268b4852574c02cb000000f50000000000000003535353535353535353535353535353535353535353535353535353535353535300090000000000000001919191919191919191919191919191919191919191919191919191919191919100000015c87271c6758b235104ef4204115f08d528492879c7c0e4f3950e958ba90704289494949494949494949494949494949494949494949494949494949494949494f5472fd279d6303c4a3d825d7fd7b45e2746a598a5bfe352f6bcc91e736c98d867726f75702d636f6d6d69742d676f6c64656e2d33454b5bd67d37370f1c199eb4b0245984d2859dfaa9799c50758c3d314a6b7ab9'
const GOLDEN_FRAME_HASHES = [
  '2cefedd578de31fdc906c6401d2b1ec3a97ea7f88ae1e6bad2c77552aae45a8b',
  'c87271c6758b235104ef4204115f08d528492879c7c0e4f3950e958ba9070428',
  '2c955af1fdfd42e340cb8a19cde55b1df36357f9e3a8c03633191c5d215a37e0'
]

async function temporaryRoot (t, name = 'hiverelay-wal-group-commit-') {
  const root = await createBlindBoundaryScratch(name)
  t.teardown(async () => removeBlindBoundaryScratch(root))
  return root
}

function storeOptions (root, overrides = {}) {
  return {
    root,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: OWNER_FENCE,
    durabilityContinuityHash: CONTINUITY,
    ...overrides
  }
}

function memberValue (index, type = 201) {
  return {
    type,
    transactionId: b4a.alloc(32, 0x40 + index),
    virtualBucket: index % 8,
    payload: b4a.from(`group-member-${index}`, 'ascii')
  }
}

// Starts count appenders behind one gate. Releasing the gate enqueues every
// appender in index order inside a single event-loop turn, so the drain
// admits them as exactly one commit group.
function gatedAppenders (store, count, applyFor) {
  let release
  const gate = new Promise(resolve => { release = resolve })
  const commits = []
  for (let index = 0; index < count; index++) {
    commits.push((async () => {
      await gate
      return store.appendAndApply(memberValue(index), frame => {
        if (applyFor) return applyFor(index, frame)
      })
    })())
  }
  return { commits, release: () => release() }
}

test('concurrent appenders commit as one group in WAL order with a contiguous hash chain', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const memberCount = 16
  const applied = []
  const { commits, release } = gatedAppenders(store, memberCount, (index, frame) => {
    applied.push(index)
  })
  release()
  const frames = await Promise.all(commits)
  t.is(frames.length, memberCount)
  for (let index = 0; index < memberCount; index++) {
    t.is(frames[index].sequence, BigInt(index + 1), 'sequences are contiguous in admission order')
    if (index > 0) {
      t.ok(b4a.equals(frames[index].previousWalHash, frames[index - 1].walHash), 'hash chain follows admission order')
    }
  }
  t.alike(applied, Array.from({ length: memberCount }, (_, index) => index), 'applies ran in admission order')
  t.is(store.walSequence, BigInt(memberCount))
  t.ok(b4a.equals(store.walHash, frames[memberCount - 1].walHash))
  await store.close()

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(frame))
  t.is(replayed.length, memberCount, 'every group frame is readable after reopen')
  for (let index = 0; index < memberCount; index++) {
    t.is(replayed[index].sequence, BigInt(index + 1))
    t.ok(b4a.equals(replayed[index].walHash, frames[index].walHash))
    t.ok(b4a.equals(replayed[index].transactionId, frames[index].transactionId))
  }
  t.is(reopened.walSequence, BigInt(memberCount))
  t.ok(b4a.equals(reopened.walHash, store.walHash))
  await reopened.close()
})

test('one datasync per commit group under concurrency, one per frame when serial', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  let datasyncs = 0
  let fullSyncs = 0
  const handle = store.handle
  const originalDatasync = handle.datasync.bind(handle)
  const originalSync = handle.sync.bind(handle)
  handle.datasync = async () => { datasyncs++; return originalDatasync() }
  handle.sync = async () => { fullSyncs++; return originalSync() }
  t.teardown(() => { handle.datasync = originalDatasync; handle.sync = originalSync })

  for (let index = 0; index < 8; index++) {
    await store.append(memberValue(index, 202))
  }
  t.is(datasyncs, 8, 'serial appends stay fsync-bound per frame')
  t.is(fullSyncs, 0, 'WAL frames use datasync-class durability')

  const { commits, release } = gatedAppenders(store, 16, null)
  release()
  await Promise.all(commits)
  t.is(datasyncs, 9, 'the 16-member group shared a single datasync')
  t.is(fullSyncs, 0)
  await store.close()
})

test('single-appender commits are byte-identical to the pre-group-commit store', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = []
  frames.push(await store.append({
    type: 201,
    transactionId: b4a.alloc(32, 0x51),
    virtualBucket: 7,
    payload: b4a.from('group-commit-golden-1', 'ascii')
  }))
  let fenceCalls = 0
  frames.push(await store.appendAndApply({
    type: 202,
    transactionId: b4a.alloc(32, 0x52),
    virtualBucket: 8,
    payload: b4a.from('group-commit-golden-2', 'ascii')
  }, () => {}, {
    prewriteFence () { fenceCalls++ }
  }))
  frames.push(await store.appendAndApply({
    type: 203,
    transactionId: b4a.alloc(32, 0x53),
    virtualBucket: 9,
    payload: b4a.from('group-commit-golden-3', 'ascii')
  }, () => {}))
  await store.close()

  t.is(fenceCalls, 1)
  const walBytes = await fs.readFile(path.join(root, 'control', 'wal.v2'))
  t.is(b4a.toString(walBytes, 'hex'), GOLDEN_WAL_HEX, 'wal.v2 bytes match the pre-group-commit golden vector')
  for (let index = 0; index < GOLDEN_FRAME_HASHES.length; index++) {
    t.is(b4a.toString(frames[index].walHash, 'hex'), GOLDEN_FRAME_HASHES[index])
  }
})

test('recovery replays grouped appends identically across multiple commit groups', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const waves = []
  for (let wave = 0; wave < 2; wave++) {
    const { commits, release } = gatedAppenders(store, 8, null)
    release()
    waves.push(await Promise.all(commits))
  }
  const frames = waves.flat()
  t.is(frames.length, 16)
  for (let index = 0; index < frames.length; index++) {
    t.is(frames[index].sequence, BigInt(index + 1), 'groups chain contiguously across drain turns')
    if (index > 0) t.ok(b4a.equals(frames[index].previousWalHash, frames[index - 1].walHash))
  }
  const headHash = b4a.from(store.walHash)
  await store.close()

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(frame))
  t.is(replayed.length, frames.length)
  for (let index = 0; index < frames.length; index++) {
    t.is(replayed[index].sequence, frames[index].sequence)
    t.ok(b4a.equals(replayed[index].walHash, frames[index].walHash))
    t.ok(b4a.equals(replayed[index].payload, frames[index].payload))
  }
  t.ok(b4a.equals(reopened.walHash, headHash), 'recovered head hash matches the grouped writer')
  await reopened.close()
})

test('fault hooks fire per frame with frame sequences inside a commit group', async t => {
  const root = await temporaryRoot(t)
  const calls = []
  const store = new BlindTransactionStore(storeOptions(root, {
    faultInjector: async (point, context) => {
      if (point === 'wal:after-write' || point === 'wal:after-sync') {
        calls.push(`${point}:${context.sequence}`)
      }
    }
  }))
  await store.open(() => {})
  const { commits, release } = gatedAppenders(store, 3, null)
  release()
  await Promise.all(commits)
  t.alike(calls, [
    'wal:after-write:1',
    'wal:after-write:2',
    'wal:after-write:3',
    'wal:after-sync:1',
    'wal:after-sync:2',
    'wal:after-sync:3'
  ], 'per-frame faults bracket the single group datasync in admission order')
  await store.close()
})

test('a mid-group after-write fault poisons the store and rejects every member', async t => {
  const root = await temporaryRoot(t)
  let injected = false
  const store = new BlindTransactionStore(storeOptions(root, {
    faultInjector: async (point, context) => {
      if (!injected && point === 'wal:after-write' && context.sequence === 2n) {
        injected = true
        throw new Error('injected after-write crash')
      }
    }
  }))
  await store.open(() => {})
  const applied = []
  const { commits, release } = gatedAppenders(store, 3, index => { applied.push(index) })
  release()
  const settled = await Promise.all(commits.map(commit => commit.then(
    frame => ({ ok: true, frame }),
    error => ({ ok: false, error })
  )))
  t.is(settled[0].ok, false)
  t.is(settled[0].error.message, 'transaction store requires recovery after an interrupted WAL append')
  t.is(settled[1].ok, false)
  t.is(settled[1].error.message, 'injected after-write crash', 'the fault owner sees the raw error')
  t.is(settled[2].ok, false)
  t.is(settled[2].error.message, 'transaction store requires recovery after an interrupted WAL append')
  t.is(applied.length, 0, 'no member applies when the group fails before its sync')
  t.is(store.poisoned, true)
  await t.exception(store.append(memberValue(9)), /requires recovery/)
  await store.close()

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(frame))
  t.is(replayed.length, 2, 'frames written before the injected crash recover; the unwritten third does not')
  t.is(reopened.walSequence, 2n)
  await reopened.close()
})

test('a mid-group after-sync fault keeps earlier members resolved and poisons later ones', async t => {
  const root = await temporaryRoot(t)
  let injected = false
  const store = new BlindTransactionStore(storeOptions(root, {
    faultInjector: async (point, context) => {
      if (!injected && point === 'wal:after-sync' && context.sequence === 2n) {
        injected = true
        throw new Error('injected post-fsync crash')
      }
    }
  }))
  await store.open(() => {})
  const applied = []
  const { commits, release } = gatedAppenders(store, 3, index => { applied.push(index) })
  release()
  const settled = await Promise.all(commits.map(commit => commit.then(
    frame => ({ ok: true, frame }),
    error => ({ ok: false, error })
  )))
  t.is(settled[0].ok, true, 'the member completed before the fault stays resolved')
  t.is(settled[0].frame.sequence, 1n)
  t.is(settled[1].ok, false)
  t.is(settled[1].error.message, 'injected post-fsync crash')
  t.is(settled[2].ok, false)
  t.is(settled[2].error.message, 'transaction store requires recovery after an interrupted WAL append')
  t.alike(applied, [0], 'only the first member applied')
  t.is(store.poisoned, true)
  t.is(store.walSequence, 1n, 'the in-memory head stops at the last fully completed frame')
  await store.close()

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(frame))
  t.is(replayed.length, 3, 'the group datasync made every frame durable before the fault')
  t.is(reopened.walSequence, 3n)
  await reopened.close()
})

test('a mid-group applyFrame failure poisons after sync exactly like the serial path', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const applied = []
  const { commits, release } = gatedAppenders(store, 3, index => {
    if (index === 1) throw new Error('apply refused')
    applied.push(index)
  })
  release()
  const settled = await Promise.all(commits.map(commit => commit.then(
    frame => ({ ok: true, frame }),
    error => ({ ok: false, error })
  )))
  t.is(settled[0].ok, true)
  t.is(settled[0].frame.sequence, 1n)
  t.is(settled[1].ok, false)
  t.is(settled[1].error.message, 'apply refused')
  t.is(settled[2].ok, false)
  t.is(settled[2].error.message, 'transaction store requires recovery after an interrupted WAL append')
  t.alike(applied, [0], 'the apply of a later group member never runs')
  t.is(store.poisoned, true)
  t.is(store.walSequence, 2n, 'the head advanced past the refusing frame, as in the serial path')
  await store.close()

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(frame))
  t.is(replayed.length, 3, 'all group frames stayed durable and replay on recovery')
  t.is(reopened.walSequence, 3n)
  await reopened.close()
})
