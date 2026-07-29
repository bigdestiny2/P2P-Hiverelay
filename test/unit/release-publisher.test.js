import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { verifyAppRelease } from '../../packages/core/core/release-lifecycle.js'
import { buildPublisherSignedSeedOpts } from '../../packages/core/core/seed-request-builder.js'
import {
  ROTATION_POINTER_RESERVE_BYTES,
  createPublisherRelease,
  createSignedSeedRequest,
  parseStorageBytes,
  shouldRotateReleaseDrive
} from '../../scripts/lib/release-publisher.mjs'

function keyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, 9))
  return { publicKey, secretKey }
}

test('publisher release history keeps only drive keys represented by the rollback window', (t) => {
  const pair = keyPair()
  const first = createPublisherRelease({
    appState: {},
    appId: 'app',
    version: '1.0.0',
    driveKey: 'a'.repeat(64),
    storageBudgetBytes: 1024 * 1024,
    rollbackWindow: 3,
    treeHash: '1'.repeat(64),
    issuedAt: 1,
    keyPair: pair
  })
  const second = createPublisherRelease({
    appState: first.appState,
    appId: 'app',
    version: '2.0.0',
    driveKey: 'b'.repeat(64),
    previousDriveKey: 'a'.repeat(64),
    storageBudgetBytes: 1024 * 1024,
    rollbackWindow: 3,
    treeHash: '2'.repeat(64),
    issuedAt: 2,
    keyPair: pair
  })
  const third = createPublisherRelease({
    appState: second.appState,
    appId: 'app',
    version: '3.0.0',
    driveKey: 'c'.repeat(64),
    previousDriveKey: 'b'.repeat(64),
    storageBudgetBytes: 1024 * 1024,
    rollbackWindow: 3,
    treeHash: '3'.repeat(64),
    issuedAt: 3,
    keyPair: pair
  })
  const fourth = createPublisherRelease({
    appState: third.appState,
    appId: 'app',
    version: '4.0.0',
    driveKey: 'd'.repeat(64),
    previousDriveKey: 'c'.repeat(64),
    storageBudgetBytes: 1024 * 1024,
    rollbackWindow: 3,
    treeHash: '4'.repeat(64),
    issuedAt: 4,
    keyPair: pair
  })
  const fifth = createPublisherRelease({
    appState: fourth.appState,
    appId: 'app',
    version: '4.1.0',
    driveKey: 'd'.repeat(64),
    storageBudgetBytes: 1024 * 1024,
    rollbackWindow: 3,
    treeHash: '5'.repeat(64),
    issuedAt: 5,
    keyPair: pair
  })
  const sixth = createPublisherRelease({
    appState: fifth.appState,
    appId: 'app',
    version: '4.2.0',
    driveKey: 'd'.repeat(64),
    storageBudgetBytes: 1024 * 1024,
    rollbackWindow: 3,
    treeHash: '6'.repeat(64),
    issuedAt: 6,
    keyPair: pair
  })

  t.alike(third.release.rollbackDriveKeys, ['b'.repeat(64), 'a'.repeat(64)])
  t.alike(fourth.release.rollbackDriveKeys, ['c'.repeat(64), 'b'.repeat(64)], 'oldest drive falls outside the three-release window')
  t.is(fourth.appState.releases.length, 3)
  t.is(fourth.release.sequence, 4)
  t.is(fourth.release.generation, 4)
  t.ok(verifyAppRelease(fourth.release, { now: 4 }).ok)
  t.alike(fifth.release.rollbackDriveKeys, ['c'.repeat(64)])
  t.alike(sixth.release.rollbackDriveKeys, [], 'a predecessor expires once every release in the window lives on the current drive')
})

test('budget planner reserves room for a predecessor rotation pointer', (t) => {
  const under = shouldRotateReleaseDrive({
    driveBytes: 100,
    plan: { contentBytes: 100, writes: [{}], removed: [] },
    storageBudgetBytes: 100 + 100 + 4096 + ROTATION_POINTER_RESERVE_BYTES
  })
  const over = shouldRotateReleaseDrive({
    driveBytes: 100,
    plan: { contentBytes: 101, writes: [{}], removed: [] },
    storageBudgetBytes: 100 + 100 + 4096 + ROTATION_POINTER_RESERVE_BYTES
  })
  t.absent(under.rotate)
  t.ok(over.rotate)
  t.is(parseStorageBytes('1GiB'), 1024 ** 3)
  t.is(parseStorageBytes('bad'), null)
})

test('publisher emits a replay-hardened seed request under the release identity', (t) => {
  const pair = keyPair()
  const now = 123456
  const body = createSignedSeedRequest({
    appKey: 'a'.repeat(64),
    maxStorageBytes: 1024 * 1024,
    keyPair: pair,
    issuedAt: now,
    requestNonce: b4a.alloc(16, 3)
  })
  const built = buildPublisherSignedSeedOpts(body, { now })
  t.ok(built.ok)
  t.is(built.opts.publisherPubkey, b4a.toString(pair.publicKey, 'hex'))
  t.is(built.opts.seedSignatureProfile, 'replay-v1')
  t.is(built.opts.maxStorage, 1024 * 1024)
})
