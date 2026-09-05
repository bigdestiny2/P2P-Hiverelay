import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  APP_CATALOG_LIMITS,
  AppCatalogDigestBuilder,
  appCatalogPageSignable,
  appCatalogSnapshotId,
  compareCatalogAppWinners,
  compareCatalogSemanticVersions,
  createAppCatalogAbort,
  createAppCatalogAck,
  createAppCatalogExternalCursor,
  createAppCatalogPage,
  createAppCatalogSnapshotIdentity,
  createCanonicalCatalogRow,
  createLegacyCatalogEnvelope,
  decodeAppCatalogFrame,
  encodeAppCatalogFrame,
  projectAppCatalogSource,
  validateAppCatalogMessage,
  verifyAppCatalogAbort,
  verifyAppCatalogAck,
  verifyAppCatalogExternalCursor,
  verifyAppCatalogPage
} from '../../packages/core/core/relay-node/app-catalog-paged.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function record (overrides = {}) {
  return {
    appKey: 'a'.repeat(64),
    appId: 'example',
    type: 'app',
    parentKey: null,
    mountPath: '/',
    version: '1.0.0',
    discoveryKey: 'b'.repeat(64),
    blind: false,
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    privacyTier: 'public',
    seededAt: 123,
    redacted: false,
    metadataVisibility: 'public',
    blindContentId: null,
    anchored: true,
    maxStorageBytes: 1024,
    publisherPubkey: 'c'.repeat(64),
    durability: 2,
    revocable: false,
    retainUntil: null,
    ...overrides
  }
}

function framedRawJson (json) {
  const payload = b4a.from(json, 'utf8')
  const frame = b4a.alloc(4 + payload.byteLength)
  frame.writeUInt32BE(payload.byteLength, 0)
  payload.copy(frame, 4)
  return frame
}

test('paged catalog codec rejects bounds, duplicate keys, malformed UTF-8, and wrong types', (t) => {
  const message = { type: 0, nonce: '1'.repeat(64) }
  t.alike(decodeAppCatalogFrame(encodeAppCatalogFrame(message)), message)

  const overbound = b4a.alloc(4)
  overbound.writeUInt32BE(APP_CATALOG_LIMITS.maxPayloadBytes + 1, 0)
  t.exception(() => decodeAppCatalogFrame(overbound), /declared catalog payload/)

  t.exception(
    () => decodeAppCatalogFrame(framedRawJson('{"type":0,"nonce":"' + '1'.repeat(64) + '","\\u006eonce":"' + '2'.repeat(64) + '"}')),
    /duplicate JSON key nonce/
  )

  const malformed = b4a.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d])
  const malformedFrame = b4a.alloc(4 + malformed.byteLength)
  malformedFrame.writeUInt32BE(malformed.byteLength, 0)
  malformed.copy(malformedFrame, 4)
  t.exception(() => decodeAppCatalogFrame(malformedFrame), /malformed UTF-8/)

  t.exception(() => validateAppCatalogMessage({ type: 0, nonce: '1'.repeat(64), extra: true }), /unknown/)
  t.exception(() => validateAppCatalogMessage({ type: 5 }), /unknown catalog message type/)
  t.exception(() => validateAppCatalogMessage([]), /must be an object/)
})

test('canonical catalog rows require explicit public eligibility and deterministic SemVer winners', (t) => {
  const hidden = projectAppCatalogSource({ catalogPublic: false, record: null })
  t.alike(hidden, { eligible: false, reason: 'NON_PUBLIC_SOURCE', row: null })

  const v1 = createCanonicalCatalogRow(record())
  const v2 = createCanonicalCatalogRow(record({ appKey: 'd'.repeat(64), version: '2.0.0' }))
  const invalid = createCanonicalCatalogRow(record({ appKey: '0'.repeat(64), version: 'latest' }))
  t.ok(compareCatalogSemanticVersions('2.0.0', '1.99.99') > 0)
  t.ok(compareCatalogSemanticVersions('1.0.0', '1.0.0-rc.1') > 0)
  t.ok(compareCatalogSemanticVersions('1.0.0-alpha.10', '1.0.0-alpha.2') > 0)
  t.ok(compareCatalogSemanticVersions('1.0.0+left', '1.0.0+right') === 0, 'build metadata does not affect precedence')
  t.ok(compareCatalogSemanticVersions('1.0.0', 'latest') > 0, 'valid SemVer outranks invalid')
  t.ok(compareCatalogSemanticVersions(null, 'latest') === 0, 'null and invalid share the deterministic fallback class')
  t.ok(compareCatalogAppWinners(v2, v1) > 0, 'highest SemVer wins')
  t.ok(compareCatalogAppWinners(v1, invalid) > 0, 'valid version wins despite lexicographically larger key')

  const tieSmall = createCanonicalCatalogRow(record({ appKey: '0'.repeat(64), version: '1.0.0+small' }))
  const tieLarge = createCanonicalCatalogRow(record({ appKey: 'f'.repeat(64), version: '1.0.0+large' }))
  t.ok(compareCatalogAppWinners(tieSmall, tieLarge) > 0, 'equal precedence uses smallest lowercase appKey')

  t.exception(() => createCanonicalCatalogRow(record({ appId: 'e\u0301' })), /must be NFC/)
  t.exception(() => createCanonicalCatalogRow(record({ appKey: 'A'.repeat(64) })), /lowercase 64-hex/)
  t.exception(() => createCanonicalCatalogRow(record({ seededAt: Number.MAX_SAFE_INTEGER + 1 })), /safe integer/)

  const missingBlindId = record({
    appKey: null,
    appId: null,
    parentKey: null,
    mountPath: null,
    version: null,
    discoveryKey: null,
    publisherPubkey: null,
    retainUntil: null,
    redacted: true,
    metadataVisibility: 'redacted',
    blindContentId: null,
    durability: 0,
    revocable: true
  })
  t.alike(projectAppCatalogSource({ catalogPublic: true, record: missingBlindId }), {
    eligible: false,
    reason: 'REDACTED_IDENTIFIER_MISSING',
    row: null
  })
})

test('snapshot digest and id match an independent byte construction', (t) => {
  const senderPubkey = 'a'.repeat(64)
  const highWater = 42
  const row = createCanonicalCatalogRow(record())
  const identity = createAppCatalogSnapshotIdentity({ senderPubkey, highWater, rows: [row] })

  const prefix = b4a.from('hiverelay.app-catalog.snapshot.v1', 'utf8')
  const zero = b4a.from([0])
  const high = b4a.alloc(8)
  high.writeUInt32BE(0, 0)
  high.writeUInt32BE(highWater, 4)
  const count = b4a.alloc(4)
  count.writeUInt32BE(1, 0)
  const rowBytes = b4a.from(JSON.stringify(row), 'utf8')
  const rowLength = b4a.alloc(4)
  rowLength.writeUInt32BE(rowBytes.byteLength, 0)
  const digest = b4a.alloc(32)
  sodium.crypto_generichash(digest, b4a.concat([prefix, zero, high, count, rowLength, rowBytes]))
  const digestHex = b4a.toString(digest, 'hex')

  t.is(identity.rootDigest, digestHex)
  t.is(identity.snapshotId, appCatalogSnapshotId({ senderPubkey, highWater, rootDigest: digestHex, entryCount: 1 }))

  const incremental = new AppCatalogDigestBuilder(highWater, 1)
  incremental.update(row)
  t.is(incremental.final(), digestHex)
  t.exception(() => incremental.final(), /already finalized/)
})

test('PAGE signable bytes have the exact accepted array and peer-bound signature', (t) => {
  const sender = keyPair()
  const receiver = keyPair()
  const senderPubkey = b4a.toString(sender.publicKey, 'hex')
  const receiverPubkey = b4a.toString(receiver.publicKey, 'hex')
  const row = createCanonicalCatalogRow(record())
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey, highWater: 7, rows: [row] })
  const page = createAppCatalogPage({
    receiverPubkey,
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: [row]
  }, sender)

  const exact = b4a.from(JSON.stringify([
    'hiverelay.app-catalog.page.v1',
    1,
    senderPubkey,
    receiverPubkey,
    snapshot.snapshotId,
    7,
    snapshot.rootDigest,
    1,
    0,
    null,
    null,
    true,
    [row]
  ]), 'utf8')
  t.ok(b4a.equals(appCatalogPageSignable(page), exact), 'no extra or missing signable element')
  t.is(JSON.parse(b4a.toString(appCatalogPageSignable(page))).length, 13)
  t.alike(verifyAppCatalogPage(page, { localPubkey: receiverPubkey, remotePubkey: senderPubkey }), page)
  t.exception(() => verifyAppCatalogPage(page, { localPubkey: 'f'.repeat(64), remotePubkey: senderPubkey }), /peer binding mismatch/)

  const ack = createAppCatalogAck(page, receiver)
  t.alike(verifyAppCatalogAck(ack, { localPubkey: senderPubkey, remotePubkey: receiverPubkey }), ack)
  const abort = createAppCatalogAbort({ receiverPubkey, snapshotId: snapshot.snapshotId, code: 'HISTORY_EXPIRED' }, sender)
  t.alike(verifyAppCatalogAbort(abort, { localPubkey: receiverPubkey, remotePubkey: senderPubkey }), abort)
})

test('external cursors are stateless, exact, signed, and signer-bound', (t) => {
  const relay = keyPair()
  const relayPubkey = b4a.toString(relay.publicKey, 'hex')
  const cursor = createAppCatalogExternalCursor({
    highWater: 9,
    rootDigest: 'e'.repeat(64),
    lastRowKey: null
  }, relay)
  t.alike(verifyAppCatalogExternalCursor(cursor, relayPubkey), cursor)
  t.exception(() => verifyAppCatalogExternalCursor(cursor, 'f'.repeat(64)), /signer mismatch/)
  t.exception(() => verifyAppCatalogExternalCursor({ ...cursor, unknown: true }, relayPubkey), /unknown or missing field/)
})

test('legacy fallback measures the final signed frame, including signature bytes', (t) => {
  const relay = keyPair()
  const relayPubkey = b4a.toString(relay.publicKey, 'hex')
  const catalogTimestamp = 1
  let apps = null
  for (let size = APP_CATALOG_LIMITS.maxPayloadBytes; size > APP_CATALOG_LIMITS.maxPayloadBytes - 512; size--) {
    const candidate = [{ value: 'x'.repeat(size - 256) }]
    const unsignedBytes = b4a.byteLength(JSON.stringify({ type: 7, apps: candidate, relayPubkey, catalogTimestamp }))
    const finalBytes = b4a.byteLength(JSON.stringify({
      type: 7,
      apps: candidate,
      relayPubkey,
      catalogTimestamp,
      signature: 'f'.repeat(128)
    }))
    if (unsignedBytes <= APP_CATALOG_LIMITS.maxPayloadBytes && finalBytes > APP_CATALOG_LIMITS.maxPayloadBytes) {
      apps = candidate
      break
    }
  }
  t.ok(apps, 'constructed unsigned-fit/final-overbound boundary vector')
  const result = createLegacyCatalogEnvelope({ apps, keyPair: relay, catalogTimestamp })
  t.is(result.reason, 'CATALOG_LEGACY_OVERBOUND')
  t.alike(result.envelope.apps, [])
  t.is(result.envelope.type, 7)
  t.ok(b4a.byteLength(JSON.stringify(result.envelope)) <= APP_CATALOG_LIMITS.maxPayloadBytes)
})
