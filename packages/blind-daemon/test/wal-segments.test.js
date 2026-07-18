import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import {
  BlindTransactionStore,
  BlindWalIntegrityError
} from '../transaction-store.js'
import {
  BlindStoreSession,
  acquireBlindStoreSessionTransactionLease
} from '../store-session.js'
import {
  scanBlindWalV2ForAnchoredRecovery,
  verifyBlindWalRecoveryScanResult
} from '../wal-recovery-scan.js'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

const PARTITION_KEY = b4a.alloc(32, 0x81)
const OWNER_FENCE = b4a.alloc(32, 0x91)
const CONTINUITY = b4a.alloc(32, 0x94)
const SEGMENT_MAX_BYTES = 64 * 1024
const FRAME_PAYLOAD_BYTES = 8000
const FRAME_BYTES = 224 + FRAME_PAYLOAD_BYTES // 8224 → seven frames per 64 KiB segment

// Captured from the pre-segmentation store (single growing wal.v2/HRWL, the
// format this phase segments): five single-appender frames over the fixed
// keys above. The cutover must import this exact file as the live segment,
// replay it byte-for-byte, and seal it without breaking the hash chain.
const GOLDEN_WAL_HEX = '4852574c02c9000000f200000000000000015151515151515151515151515151515151515151515151515151515151515151000100000000000000019191919191919191919191919191919191919191919191919191919191919191000000120000000000000000000000000000000000000000000000000000000000000000949494949494949494949494949494949494949494949494949494949494949471c376c15bf7b8ac7dcc12041d195971f02d9814450bf72a4b7bce1ba29c56006d6967726174696f6e2d676f6c64656e2d319a3330d5e3be15f13536d442e9f2d04d723e7e41cbb02a53ee1fcc7adf0a92674852574c02ca000000f20000000000000002525252525252525252525252525252525252525252525252525252525252525200020000000000000001919191919191919191919191919191919191919191919191919191919191919100000012ce8f5edeae3943cb18c5d903572ea5feccf69ef5dca1e1aa0b2820f605c9d4db9494949494949494949494949494949494949494949494949494949494949494b0ed88d52d9b8ba7c5662ec4f85d20f2151d028da3ce266f1a39af03a418755f6d6967726174696f6e2d676f6c64656e2d32b53203059e4ec81b522c6e4303bd9f2d33506ef5e75615d85e9ce922baa672554852574c02cb000000f2000000000000000353535353535353535353535353535353535353535353535353535353535353530003000000000000000191919191919191919191919191919191919191919191919191919191919191910000001219b507a1a7e52b3ba66e91607e94b70e1695a980cf681bcf0aec743da12a31919494949494949494949494949494949494949494949494949494949494949494de5bc44ddcb297bb2a8b4023ee72b7ab61c66abea00ae2d362cb0eb61fbddab36d6967726174696f6e2d676f6c64656e2d333a476ecef536cbfea5095eb57ad53d788ea9c306d847718f1adf35a8c0687fd94852574c02cc000000f200000000000000045454545454545454545454545454545454545454545454545454545454545454000400000000000000019191919191919191919191919191919191919191919191919191919191919191000000122e61431a1c3508aa68127027926fa39bcfce923b7462bf71dff7fc40b0019b239494949494949494949494949494949494949494949494949494949494949494198cd8f6be9ef6f9cb4ca2e340548d991a1d0a6270819aaec64f1e285fd55c026d6967726174696f6e2d676f6c64656e2d34084381465b261ea9e870b4f650ba75da6d73a18a218e6a727ab82787c93aa05d4852574c02cd000000f20000000000000005555555555555555555555555555555555555555555555555555555555555555500050000000000000001919191919191919191919191919191919191919191919191919191919191919100000012b37b16a02c0ee5c6b26cb9850affc6a30224a2e944be12b922cfd55ebf8d43f89494949494949494949494949494949494949494949494949494949494949494db4d446450ad140bc3b51ab6e32ae0e784e378bf3456b49f27506b1fb8afc7ad6d6967726174696f6e2d676f6c64656e2d3589c4f31ee65ecd14bced204acc960b88d4c6053f136ab4f16cb64615f53948de'
const GOLDEN_WAL_BYTES = 1210
const GOLDEN_FRAME_HASHES = [
  'ce8f5edeae3943cb18c5d903572ea5feccf69ef5dca1e1aa0b2820f605c9d4db',
  '19b507a1a7e52b3ba66e91607e94b70e1695a980cf681bcf0aec743da12a3191',
  '2e61431a1c3508aa68127027926fa39bcfce923b7462bf71dff7fc40b0019b23',
  'b37b16a02c0ee5c6b26cb9850affc6a30224a2e944be12b922cfd55ebf8d43f8',
  'e06698399f7885a1be70390a9a78690e9c23ce13286f6ed4255e2fb7f0f4c676'
]

async function temporaryRoot (t, name = 'hiverelay-wal-segments-') {
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
    walSegmentMaxBytes: SEGMENT_MAX_BYTES,
    ...overrides
  }
}

function frameValue (index) {
  return {
    type: 200 + (index % 50),
    transactionId: b4a.alloc(32, index),
    virtualBucket: index % 8,
    payload: b4a.alloc(FRAME_PAYLOAD_BYTES, index)
  }
}

function segmentName (first, last) {
  const hex = value => value.toString(16).padStart(16, '0')
  return `wal-${hex(first)}-${hex(last)}.v2`
}

async function appendFrames (store, from, to) {
  const frames = []
  for (let index = from; index <= to; index++) frames.push(await store.append(frameValue(index)))
  return frames
}

async function sealedSegmentNames (root) {
  const names = await fs.readdir(path.join(root, 'control'))
  return names.filter(name => name.startsWith('wal-')).sort()
}

async function rejectsIntegrity (t, promise, pattern) {
  try {
    await promise
    t.fail('expected the WAL to fail closed')
  } catch (error) {
    t.is(error.name, 'BlindWalIntegrityError')
    if (pattern) t.ok(pattern.test(error.message), `"${error.message}" matches ${pattern}`)
  }
}

async function rejectsType (t, promise, pattern) {
  try {
    await promise
    t.fail('expected a TypeError')
  } catch (error) {
    t.ok(error instanceof TypeError, `${error} is a TypeError`)
    if (pattern) t.ok(pattern.test(error.message), `"${error.message}" matches ${pattern}`)
  }
}

// Starts count appenders behind one gate so the drain admits them as exactly
// one commit group, exactly like the group-commit admission rule.
function gatedAppenders (store, from, count, applied) {
  let release
  const gate = new Promise(resolve => { release = resolve })
  const commits = []
  for (let index = from; index < from + count; index++) {
    commits.push((async () => {
      await gate
      return store.appendAndApply(frameValue(index), frame => {
        if (applied) applied.push(Number(frame.sequence))
      })
    })())
  }
  return { commits, release: () => release() }
}

test('segment rollover seals the live segment at a group boundary and keeps the chain continuous', async t => {
  const root = await temporaryRoot(t)
  const faults = []
  const store = new BlindTransactionStore(storeOptions(root, {
    faultInjector: async point => {
      if (point.startsWith('wal:after-segment')) faults.push(point)
    }
  }))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 16)
  t.is(store.walSequence, 16n)
  t.alike(store.sealedWalSegments.map(segment => segment.name), [segmentName(1, 7), segmentName(8, 14)])
  t.is(store.liveSegmentFirstSequence, 15n)
  t.is(store.walOffset, 2 * FRAME_BYTES)
  t.alike(faults, [
    'wal:after-segment-seal',
    'wal:after-segment-rollover',
    'wal:after-segment-seal',
    'wal:after-segment-rollover'
  ])
  t.alike(await sealedSegmentNames(root), [segmentName(1, 7), segmentName(8, 14)])
  const sealedBytes = await fs.stat(path.join(root, 'control', segmentName(1, 7)))
  t.is(sealedBytes.size, 7 * FRAME_BYTES, 'sealed segment ends exactly on the group boundary')
  await store.close()

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(frame))
  t.is(replayed.length, 16, 'every frame replays across the segment boundary')
  for (let index = 0; index < 16; index++) {
    t.is(replayed[index].sequence, BigInt(index + 1))
    t.ok(b4a.equals(replayed[index].walHash, frames[index].walHash))
    if (index > 0) t.ok(b4a.equals(replayed[index].previousWalHash, frames[index - 1].walHash))
  }
  t.alike(reopened.sealedWalSegments.map(segment => segment.name), [segmentName(1, 7), segmentName(8, 14)])
  t.is(reopened.liveSegmentFirstSequence, 15n)
  await reopened.close()
})

test('a commit group never straddles a segment boundary', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 14)
  t.alike(await sealedSegmentNames(root), [segmentName(1, 7)])
  t.is(store.walOffset, 7 * FRAME_BYTES)

  const applied = []
  const { commits, release } = gatedAppenders(store, 15, 3, applied)
  release()
  const groupFrames = await Promise.all(commits)
  t.alike(groupFrames.map(frame => Number(frame.sequence)), [15, 16, 17])
  t.ok(b4a.equals(groupFrames[0].previousWalHash, frames[13].walHash), 'hash chain crosses the rollover')
  t.alike(applied, [15, 16, 17], 'group applies in admission order')
  t.alike(await sealedSegmentNames(root), [segmentName(1, 7), segmentName(8, 14)])
  const liveStat = await fs.stat(path.join(root, 'control', 'wal.v2'))
  t.is(liveStat.size, 3 * FRAME_BYTES, 'the whole group landed together in the fresh live segment')
  await store.close()

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(Number(frame.sequence)))
  t.alike(replayed, Array.from({ length: 17 }, (_, index) => index + 1))
  await reopened.close()
})

test('checkpoint-anchored recovery replays only post-anchor frames', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 16)
  await store.close()
  const anchor = { sequence: frames[9].sequence, hash: frames[9].walHash }

  const anchored = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await anchored.open(frame => replayed.push(Number(frame.sequence)), { checkpointAnchor: anchor })
  t.alike(replayed, [11, 12, 13, 14, 15, 16], 'covered frames are verified but not applied')
  t.is(anchored.walSequence, 16n)
  t.ok(b4a.equals(anchored.walHash, frames[15].walHash))
  await anchored.close()

  const covered = new BlindTransactionStore(storeOptions(root))
  const coveredReplay = []
  await covered.open(frame => coveredReplay.push(Number(frame.sequence)), {
    checkpointAnchor: anchor,
    replayCoveredFrames: true
  })
  t.alike(coveredReplay, Array.from({ length: 16 }, (_, index) => index + 1),
    'prune-tolerant full replay applies every retained frame')
  await covered.close()

  const wrongHash = new BlindTransactionStore(storeOptions(root))
  await rejectsIntegrity(t, wrongHash.open(() => {}, {
    checkpointAnchor: { sequence: frames[9].sequence, hash: frames[10].walHash }
  }), /anchor hash mismatch/)

  const missing = new BlindTransactionStore(storeOptions(root))
  await rejectsIntegrity(t, missing.open(() => {}, {
    checkpointAnchor: { sequence: 20n, hash: frames[15].walHash }
  }), /does not contain the exact checkpoint anchor/)

  await rejectsType(t,
    new BlindTransactionStore(storeOptions(root)).open(() => {}, { replayCoveredFrames: true }),
    /replayCoveredFrames requires a checkpoint anchor/)
  await rejectsType(t,
    new BlindTransactionStore(storeOptions(root)).open(() => {}, { anchor: null }),
    /unknown field anchor/)
  await rejectsType(t,
    new BlindTransactionStore(storeOptions(root)).open(() => {}, {
      checkpointAnchor: { sequence: 0n, hash: frames[0].walHash }
    }),
    /sequence must be nonzero/)
})

test('boundary anchor after pruning replays post-anchor frames only', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 16)
  await store.close()
  const anchor = { sequence: frames[13].sequence, hash: frames[13].walHash }

  const writer = new BlindTransactionStore(storeOptions(root))
  await writer.open(() => {})
  const result = await writer.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: 15n })
  t.alike(result.prunedSegments.map(segment => segment.name), [segmentName(1, 7), segmentName(8, 14)])
  t.alike(await sealedSegmentNames(root), [])
  await writer.close()

  await rejectsIntegrity(t,
    new BlindTransactionStore(storeOptions(root)).open(() => {}),
    /begins after genesis without a checkpoint anchor/)

  const anchored = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await anchored.open(frame => replayed.push(Number(frame.sequence)), { checkpointAnchor: anchor })
  t.alike(replayed, [15, 16], 'the first retained frame must chain to the anchor hash')
  t.is(anchored.walSequence, 16n)
  await anchored.close()

  const wrongHash = new BlindTransactionStore(storeOptions(root))
  await rejectsIntegrity(t, wrongHash.open(() => {}, {
    checkpointAnchor: { sequence: frames[13].sequence, hash: frames[12].walHash }
  }))
})

test('pruning enforces the checkpoint anchor and the spent-marker retention floor', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 16)
  await store.close()

  const writer = new BlindTransactionStore(storeOptions(root))
  await writer.open(() => {})
  const anchor = { sequence: frames[13].sequence, hash: frames[13].walHash }

  const floorInsideSecond = await writer.pruneWalSegments({
    checkpointAnchor: anchor,
    retainFromSequence: 10n
  })
  t.alike(floorInsideSecond.prunedSegments.map(segment => segment.name), [segmentName(1, 7)],
    'a segment at or above the floor survives even when checkpoint-covered')
  t.alike(await sealedSegmentNames(root), [segmentName(8, 14)])

  const retainEverything = await writer.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: 1n })
  t.alike(retainEverything.prunedSegments, [], 'floor 1 retains every segment')
  t.alike(await sealedSegmentNames(root), [segmentName(8, 14)])

  await rejectsIntegrity(t, writer.pruneWalSegments({
    checkpointAnchor: { sequence: 20n, hash: frames[15].walHash },
    retainFromSequence: 15n
  }), /ahead of the WAL head/)
  await rejectsIntegrity(t, writer.pruneWalSegments({
    checkpointAnchor: { sequence: frames[13].sequence, hash: frames[12].walHash },
    retainFromSequence: 15n
  }), /anchor hash mismatch/)
  await rejectsIntegrity(t, writer.pruneWalSegments({
    checkpointAnchor: { sequence: frames[4].sequence, hash: frames[4].walHash },
    retainFromSequence: 15n
  }), /anchor frame is not retained/)
  await rejectsType(t,
    writer.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: 0n }),
    /retainFromSequence must be nonzero/)
  await rejectsType(t,
    writer.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: 15n, extra: true }),
    /unknown field extra/)
  await rejectsType(t, writer.pruneWalSegments({ retainFromSequence: 15n }), /checkpointAnchor must be an object/)

  const headAnchor = { sequence: frames[15].sequence, hash: frames[15].walHash }
  const headPrune = await writer.pruneWalSegments({ checkpointAnchor: headAnchor, retainFromSequence: 15n })
  t.alike(headPrune.prunedSegments.map(segment => segment.name), [segmentName(8, 14)],
    'the O(1) head anchor path verifies against the in-memory head')
  t.alike(await sealedSegmentNames(root), [])
  await writer.close()

  const anchored = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await anchored.open(frame => replayed.push(Number(frame.sequence)), { checkpointAnchor: headAnchor })
  t.alike(replayed, [], 'the anchor frame itself survived inside the live segment')
  t.is(anchored.walSequence, 16n)
  await anchored.close()
})

test('crash mid-prune leaves a contiguous retained prefix and an unpoisoned writer', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 16)
  await store.close()

  let pruneFaults = 0
  const writer = new BlindTransactionStore(storeOptions(root, {
    faultInjector: async point => {
      if (point === 'wal:after-segment-prune' && pruneFaults === 0) {
        pruneFaults++
        throw new Error('simulated crash mid-prune')
      }
    }
  }))
  const recovered = []
  await writer.open(frame => recovered.push(frame))
  const anchor = { sequence: recovered[13].sequence, hash: recovered[13].walHash }
  await t.exception(
    writer.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: 15n }),
    /simulated crash mid-prune/
  )
  t.is(pruneFaults, 1)
  t.alike(await sealedSegmentNames(root), [segmentName(8, 14)],
    'the oldest segment is deleted, the rest of the prefix is untouched')

  const extra = await writer.append(frameValue(17))
  t.is(extra.sequence, 17n, 'a prune fault does not poison the writer')
  const retry = await writer.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: 15n })
  t.alike(retry.prunedSegments.map(segment => segment.name), [segmentName(1, 7), segmentName(8, 14)],
    'a retried prune tolerates the already-deleted segment')
  t.alike(await sealedSegmentNames(root), [])
  await writer.close()

  const anchored = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await anchored.open(frame => replayed.push(Number(frame.sequence)), { checkpointAnchor: anchor })
  t.alike(replayed, [15, 16, 17])
  await anchored.close()
})

test('interior segment loss or corruption fails closed', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  await appendFrames(store, 1, 16)
  await store.close()
  const control = path.join(root, 'control')
  const middle = path.join(control, segmentName(8, 14))
  const middleBytes = await fs.readFile(middle)

  await fs.unlink(middle)
  await rejectsIntegrity(t, new BlindTransactionStore(storeOptions(root)).open(() => {}))
  await fs.writeFile(middle, middleBytes, { mode: 0o600 })

  const corrupted = b4a.from(middleBytes)
  corrupted[1000] ^= 0xff
  await fs.writeFile(middle, corrupted, { mode: 0o600 })
  await rejectsIntegrity(t, new BlindTransactionStore(storeOptions(root)).open(() => {}))
  await fs.writeFile(middle, middleBytes, { mode: 0o600 })

  await fs.truncate(middle, middleBytes.byteLength - 100)
  await rejectsIntegrity(t, new BlindTransactionStore(storeOptions(root)).open(() => {}), /ends inside a frame/)
  await fs.writeFile(middle, middleBytes, { mode: 0o600 })

  await fs.writeFile(path.join(control, 'wal-not-a-segment.v2'), b4a.alloc(16), { mode: 0o600 })
  await rejectsIntegrity(t, new BlindTransactionStore(storeOptions(root)).open(() => {}), /unexpected WAL segment entry/)
  await fs.unlink(path.join(control, 'wal-not-a-segment.v2'))

  const overlap = path.join(control, segmentName(7, 12))
  await fs.writeFile(overlap, b4a.alloc(16), { mode: 0o600 })
  await rejectsIntegrity(t, new BlindTransactionStore(storeOptions(root)).open(() => {}), /interior gap/)
  await fs.unlink(overlap)

  const restored = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await restored.open(frame => replayed.push(Number(frame.sequence)))
  t.alike(replayed, Array.from({ length: 16 }, (_, index) => index + 1), 'restored segments recover')
  await restored.close()
})

test('torn tail truncation stays legal only at the live segment tail', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  await appendFrames(store, 1, 16)
  await store.close()
  const walPath = path.join(root, 'control', 'wal.v2')
  const completeSize = (await fs.stat(walPath)).size
  await fs.appendFile(walPath, b4a.alloc(17, 0xff))

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await reopened.open(frame => replayed.push(Number(frame.sequence)))
  t.alike(replayed, Array.from({ length: 16 }, (_, index) => index + 1))
  t.is((await fs.stat(walPath)).size, completeSize, 'the torn live tail was truncated')
  t.alike(await sealedSegmentNames(root), [segmentName(1, 7), segmentName(8, 14)])
  const extra = await reopened.append(frameValue(17))
  t.is(extra.sequence, 17n, 'the truncated live segment accepts new frames')
  await reopened.close()
})

test('migration: a pre-segmentation wal.v2 imports as the live segment and seals across the cutover', async t => {
  const root = await temporaryRoot(t, 'hiverelay-wal-migration-')
  const control = path.join(root, 'control')
  await fs.mkdir(control, { mode: 0o700 })
  await fs.writeFile(path.join(control, 'wal.v2'), b4a.from(GOLDEN_WAL_HEX, 'hex'), { mode: 0o600 })

  const store = new BlindTransactionStore(storeOptions(root))
  const replayed = []
  await store.open(frame => replayed.push(frame))
  t.is(replayed.length, 5, 'the imported single-file store replays completely')
  t.alike(replayed.map(frame => b4a.toString(frame.walHash, 'hex')), GOLDEN_FRAME_HASHES)
  t.is(store.walSequence, 5n)
  t.is(store.liveSegmentFirstSequence, 1n)
  t.alike(store.sealedWalSegments, [], 'import is zero-copy: the legacy file is the live segment')

  const extra = await appendFrames(store, 6, 13)
  t.ok(b4a.equals(extra[0].previousWalHash, replayed[4].walHash), 'the chain continues across the cutover')
  t.alike(await sealedSegmentNames(root), [segmentName(1, 12)],
    'the first rollover seals the imported frames with the new ones')
  await store.close()

  const sealedBytes = await fs.readFile(path.join(control, segmentName(1, 12)))
  t.is(b4a.toString(sealedBytes.subarray(0, GOLDEN_WAL_BYTES), 'hex'), GOLDEN_WAL_HEX,
    'the imported frames are byte-for-byte preserved inside the sealed segment')

  const reopened = new BlindTransactionStore(storeOptions(root))
  const replayedAfter = []
  await reopened.open(frame => replayedAfter.push(frame))
  t.is(replayedAfter.length, 13)
  t.alike(replayedAfter.slice(0, 5).map(frame => b4a.toString(frame.walHash, 'hex')), GOLDEN_FRAME_HASHES,
    'golden hashes validate continuously out of the sealed segment')
  t.is(reopened.walSequence, 13n)
  await reopened.close()
})

test('checkpoint-anchored scan replays only post-anchor frames across segments', async t => {
  const root = await temporaryRoot(t, 'hiverelay-wal-scan-segments-')
  const control = path.join(root, 'control')
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 16)
  await store.close()
  await fs.writeFile(path.join(control, 'manifest-a.v1'), b4a.alloc(64, 0x74), { mode: 0o600 })

  const session = new BlindStoreSession({ root })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), root)
  t.teardown(async () => {
    lease.release()
    await session.close()
  })

  const scanOptions = checkpoint => ({
    root,
    lease,
    checkpoint,
    mapGeneration: 1n,
    writerFenceTokenHash: OWNER_FENCE,
    durabilityContinuityHash: CONTINUITY,
    maximumWalBytes: 1024 * 1024,
    maximumWalFrames: 1024,
    maximumWalPayloadBytes: 1024 * 1024,
    applyShadowFrame: async frame => { replayed.push(Number(frame.sequence)) }
  })

  const replayed = []
  const result = await scanBlindWalV2ForAnchoredRecovery(
    scanOptions({ sequence: frames[9].sequence, hash: frames[9].walHash }))
  t.alike(replayed, [11, 12, 13, 14, 15, 16], 'shadow replay starts after the anchor')
  t.is(result.sealedSegmentCount, 2)
  t.is(result.completeFrameCount, 16)
  t.is(result.headSequence, 16n)
  t.ok(b4a.equals(result.headHash, frames[15].walHash))
  t.is(await verifyBlindWalRecoveryScanResult(result, root, lease), true)

  const sealedPath = path.join(control, segmentName(8, 14))
  const sealedBytes = await fs.readFile(sealedPath)
  const tampered = b4a.from(sealedBytes)
  tampered[100] ^= 0xff
  await fs.writeFile(sealedPath, tampered, { mode: 0o600 })
  await t.exception(verifyBlindWalRecoveryScanResult(result, root, lease),
    /sealed WAL segment changed/)
  await fs.writeFile(sealedPath, sealedBytes, { mode: 0o600 })

  replayed.length = 0
  const rescanned = await scanBlindWalV2ForAnchoredRecovery(
    scanOptions({ sequence: frames[9].sequence, hash: frames[9].walHash }))
  t.alike(replayed, [11, 12, 13, 14, 15, 16], 'restored bytes scan clean again')
  t.is(await verifyBlindWalRecoveryScanResult(rescanned, root, lease), true)

  await fs.unlink(path.join(control, segmentName(8, 14)))
  await rejectsIntegrity(t, scanBlindWalV2ForAnchoredRecovery(
    scanOptions({ sequence: frames[9].sequence, hash: frames[9].walHash })))
})

test('checkpoint-anchored scan anchors on the segment boundary after pruning', async t => {
  const root = await temporaryRoot(t, 'hiverelay-wal-scan-boundary-')
  const control = path.join(root, 'control')
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  const frames = await appendFrames(store, 1, 16)
  const anchor = { sequence: frames[6].sequence, hash: frames[6].walHash }
  const result = await store.pruneWalSegments({ checkpointAnchor: anchor, retainFromSequence: 8n })
  t.alike(result.prunedSegments.map(segment => segment.name), [segmentName(1, 7)])
  await store.close()
  await fs.writeFile(path.join(control, 'manifest-a.v1'), b4a.alloc(64, 0x74), { mode: 0o600 })

  const session = new BlindStoreSession({ root })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), root)
  t.teardown(async () => {
    lease.release()
    await session.close()
  })

  const replayed = []
  const scan = await scanBlindWalV2ForAnchoredRecovery({
    root,
    lease,
    checkpoint: anchor,
    mapGeneration: 1n,
    writerFenceTokenHash: OWNER_FENCE,
    durabilityContinuityHash: CONTINUITY,
    maximumWalBytes: 1024 * 1024,
    maximumWalFrames: 1024,
    maximumWalPayloadBytes: 1024 * 1024,
    applyShadowFrame: async frame => { replayed.push(Number(frame.sequence)) }
  })
  t.alike(replayed, [8, 9, 10, 11, 12, 13, 14, 15, 16],
    'the pruned prefix is pinned by the boundary link alone')
  t.is(scan.sealedSegmentCount, 1)
  t.is(scan.completeFrameCount, 9)
  t.is(scan.checkpointEndOffset, 0)
  t.is(await verifyBlindWalRecoveryScanResult(scan, root, lease), true)
})

test('a sealed segment whose name lies about its range fails closed', async t => {
  const root = await temporaryRoot(t)
  const store = new BlindTransactionStore(storeOptions(root))
  await store.open(() => {})
  await appendFrames(store, 1, 8)
  await store.close()
  // A forged seal: the name claims frames 8..9 but the file holds only
  // frame 8 — the seal is the name, so a range mismatch is an interior
  // break, not a torn tail.
  await fs.rename(
    path.join(root, 'control', 'wal.v2'),
    path.join(root, 'control', segmentName(8, 9))
  )
  await fs.writeFile(path.join(root, 'control', 'wal.v2'), b4a.alloc(0), { mode: 0o600 })
  const error = await new BlindTransactionStore(storeOptions(root)).open(() => {}).catch(error => error)
  t.ok(error instanceof BlindWalIntegrityError, 'a forged segment seal fails closed')
  t.ok(/does not contain its sealed sequence range/.test(error.message))
})
