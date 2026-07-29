import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  APP_RELEASE_SIGNATURE_DOMAIN,
  hashReleaseTree,
  serializeAppReleaseForSigning,
  signAppRelease,
  verifyAppRelease
} from '../../packages/core/core/release-lifecycle.js'

function keyPair (byte = 7) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, byte))
  return { publicKey, secretKey }
}

function releaseFields (overrides = {}) {
  return {
    protocolVersion: 1,
    appId: 'pear-chat',
    version: '2.0.0',
    sequence: 4,
    generation: 2,
    driveKey: 'b'.repeat(64),
    previousDriveKey: 'a'.repeat(64),
    rotationReason: 'storage-budget',
    storageBudgetBytes: 1024 * 1024,
    rollbackWindow: 3,
    rollbackDriveKeys: ['a'.repeat(64)],
    treeHash: 'c'.repeat(64),
    issuedAt: 1234,
    ...overrides
  }
}

test('app release signs a domain-separated, publisher-bound key rotation', (t) => {
  const signed = signAppRelease(releaseFields(), keyPair())
  const verified = verifyAppRelease(signed, { now: 1234 })

  t.ok(verified.ok)
  t.is(verified.release.previousDriveKey, 'a'.repeat(64))
  t.is(verified.release.driveKey, 'b'.repeat(64))
  t.ok(serializeAppReleaseForSigning(signed).includes(b4a.from(APP_RELEASE_SIGNATURE_DOMAIN)))

  t.absent(verifyAppRelease({ ...signed, driveKey: 'd'.repeat(64) }, { now: 1234 }).ok, 'drive-key tamper fails')
  t.absent(verifyAppRelease({ ...signed, rollbackWindow: 2 }, { now: 1234 }).ok, 'retention tamper fails')
  t.absent(verifyAppRelease({ ...signed, publisherPubkey: b4a.toString(keyPair(8).publicKey, 'hex') }, { now: 1234 }).ok, 'publisher substitution fails')
})

test('app release rejects unsigned or malformed rotation policy', (t) => {
  const pair = keyPair()
  t.exception(
    () => signAppRelease(releaseFields({ rotationReason: null }), pair),
    /must declare storage-budget/
  )
  t.exception(
    () => signAppRelease(releaseFields({ rollbackWindow: 1, rollbackDriveKeys: ['a'.repeat(64)] }), pair),
    /exceeds rollbackWindow/
  )
  t.absent(verifyAppRelease({ ...releaseFields(), publisherPubkey: b4a.toString(pair.publicKey, 'hex') }).ok)
})

test('release tree hash is path-stable and content-sensitive', (t) => {
  const a = hashReleaseTree([
    { path: '/z.txt', content: b4a.from('z') },
    { path: '/a.txt', content: b4a.from('a') }
  ])
  const reordered = hashReleaseTree([
    { path: '/a.txt', content: b4a.from('a') },
    { path: '/z.txt', content: b4a.from('z') }
  ])
  const changed = hashReleaseTree([
    { path: '/a.txt', content: b4a.from('A') },
    { path: '/z.txt', content: b4a.from('z') }
  ])

  t.is(a, reordered)
  t.not(a, changed)
})
