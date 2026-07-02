import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  OUTBOXLOG_BLIND_SEAL_NONCE_BYTES,
  canonicalOutboxRecord,
  createOutboxBlindRecipientDirectoryEntry,
  createOutboxBlindRecipientKeyPair,
  createOutboxBlindSealAAD,
  createOutboxBlindSealKey,
  createOutboxLog,
  encodeOutboxBlindSealKey,
  isOutboxBlindRecord,
  openOutboxBlindPayload,
  openOutboxBlindSealKeyEnvelope,
  verifyOutboxBlindRecipientDirectoryEntry,
  verifyOutboxBlindRecipientDirectoryRecord,
  verifyOutboxBlindRecipientDirectoryRotation,
  wrapOutboxBlindSealKey,
  sealOutboxBlindPayload
} from '../../packages/services/builtin/outboxlog/index.js'

test('outboxlog blind seal: encrypts JSON payloads and opens with matching aad', (t) => {
  const key = createOutboxBlindSealKey()
  const nonce = b4a.alloc(OUTBOXLOG_BLIND_SEAL_NONCE_BYTES, 7)
  const aad = 'privchat:message:m1'
  const body = sealOutboxBlindPayload({
    text: 'relay must never see this',
    nested: { n: 1 }
  }, { key, nonce, aad, keyId: 'room-key-1' })

  t.is(body.sealed.version, 1)
  t.is(body.sealed.alg, 'xchacha20poly1305')
  t.is(body.sealed.keyId, 'room-key-1')
  t.absent(JSON.stringify(body).includes('relay must never see this'))
  t.alike(openOutboxBlindPayload(body, { key, aad }), {
    text: 'relay must never see this',
    nested: { n: 1 }
  })
})

test('outboxlog blind seal: rejects wrong aad, wrong key, and malformed inputs', (t) => {
  const key = createOutboxBlindSealKey()
  const body = sealOutboxBlindPayload({ secret: true }, { key, aad: 'expected' })
  const wrongKey = createOutboxBlindSealKey()

  t.exception(() => openOutboxBlindPayload(body, { key, aad: 'wrong' }), /decrypt failed/)
  t.exception(() => openOutboxBlindPayload(body, { key: wrongKey, aad: 'expected' }), /decrypt failed/)
  t.exception(() => sealOutboxBlindPayload({ secret: true }, { key: b4a.alloc(31) }), /key must be 32 bytes/)
  t.exception(() => sealOutboxBlindPayload({ secret: true }, { key, nonce: b4a.alloc(12) }), /nonce must be 24 bytes/)
  t.exception(() => openOutboxBlindPayload({ sealed: { version: 1, alg: 'xchacha20poly1305', nonce: 'bad', ciphertext: 'bad' } }, { key }), /bad nonce/)
})

test('outboxlog blind seal: helper output appends into a blind namespace without plaintext storage', (t) => {
  const writer = keyPair(21)
  const key = createOutboxBlindSealKey()
  const keyHex = encodeOutboxBlindSealKey(key)
  const log = createOutboxLog({
    namespaces: {
      privchat: { blind: true, caps: { maxOutboxes: 1, maxEntriesPerOutbox: 2 } }
    }
  })
  const body = sealOutboxBlindPayload({ message: 'client secret' }, {
    key: keyHex,
    aad: 'privchat:' + writer.publicKeyHex + ':message:m1',
    keyId: 'room-key-2'
  })
  const record = signRecord(writer, { id: 'm1', _ns: 'privchat', body }, 'message')

  t.ok(isOutboxBlindRecord(record))
  log.sync.create(writer.publicKeyHex, { namespace: 'privchat' })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'message', data: record }), { ok: true, key: 'message!m1' })

  const stored = log.sync.get(writer.publicKeyHex, 'message!m1')
  t.absent(JSON.stringify(stored).includes('client secret'))
  t.alike(openOutboxBlindPayload(stored.body, {
    key,
    aad: 'privchat:' + writer.publicKeyHex + ':message:m1'
  }), { message: 'client secret' })
})

test('outboxlog blind seal: recipient key envelope unwraps only for intended recipients', (t) => {
  const key = createOutboxBlindSealKey()
  const keyHex = encodeOutboxBlindSealKey(key)
  const alice = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 1) })
  const bob = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 2) })
  const mallory = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 3) })
  const envelope = wrapOutboxBlindSealKey(keyHex, [
    { id: 'alice', publicKey: alice.publicKeyHex },
    { id: 'bob', publicKey: bob.publicKey }
  ])

  t.is(envelope.version, 1)
  t.is(envelope.alg, 'crypto_box_seal')
  t.is(envelope.recipients.length, 2)
  t.absent(JSON.stringify(envelope).includes(keyHex))
  t.ok(b4a.equals(openOutboxBlindSealKeyEnvelope(envelope, {
    recipientId: 'alice',
    publicKey: alice.publicKey,
    secretKey: alice.secretKey
  }), key))
  t.ok(b4a.equals(openOutboxBlindSealKeyEnvelope(envelope, {
    publicKey: bob.publicKeyHex,
    secretKey: bob.secretKeyHex
  }), key))
  t.exception(() => openOutboxBlindSealKeyEnvelope(envelope, {
    publicKey: mallory.publicKey,
    secretKey: mallory.secretKey
  }), /recipient not found/)
  t.exception(() => openOutboxBlindSealKeyEnvelope(envelope, {
    recipientId: 'alice',
    publicKey: bob.publicKey,
    secretKey: bob.secretKey
  }), /recipient public key mismatch/)
})

test('outboxlog blind seal: stored key envelope opens appended private payload for recipient', (t) => {
  const writer = keyPair(22)
  const recipient = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 8) })
  const stranger = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 9) })
  const key = createOutboxBlindSealKey()
  const keyHex = encodeOutboxBlindSealKey(key)
  const aad = 'privchat:' + writer.publicKeyHex + ':message:m2'
  const log = createOutboxLog({
    namespaces: {
      privchat: { blind: true, caps: { maxOutboxes: 1, maxEntriesPerOutbox: 2 } }
    }
  })
  const body = sealOutboxBlindPayload({ message: 'recipient secret' }, { key, aad })
  const keyEnvelope = wrapOutboxBlindSealKey(key, [{ id: 'recipient', publicKey: recipient.publicKey }])
  const record = signRecord(writer, { id: 'm2', _ns: 'privchat', body, keyEnvelope }, 'message')

  log.sync.create(writer.publicKeyHex, { namespace: 'privchat' })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'message', data: record }), { ok: true, key: 'message!m2' })

  const stored = log.sync.get(writer.publicKeyHex, 'message!m2')
  t.absent(JSON.stringify(stored).includes('recipient secret'))
  t.absent(JSON.stringify(stored).includes(keyHex))
  t.exception(() => openOutboxBlindSealKeyEnvelope(stored.keyEnvelope, {
    publicKey: stranger.publicKey,
    secretKey: stranger.secretKey
  }), /recipient not found/)

  const openedKey = openOutboxBlindSealKeyEnvelope(stored.keyEnvelope, {
    recipientId: 'recipient',
    publicKey: recipient.publicKey,
    secretKey: recipient.secretKey
  })
  t.alike(openOutboxBlindPayload(stored.body, { key: openedKey, aad }), { message: 'recipient secret' })
})

test('outboxlog blind seal: canonical aad binds private payloads to app namespace records', (t) => {
  const writer = keyPair(23)
  const recipient = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 10) })
  const key = createOutboxBlindSealKey()
  const keyId = 'poked-room:alpha@1'
  const id = 'poke:1'
  const aad = createOutboxBlindSealAAD({
    namespace: 'poked',
    appId: writer.publicKeyHex,
    type: 'poke',
    id,
    keyId
  })
  const log = createOutboxLog({
    namespaces: {
      poked: { blind: true, caps: { maxOutboxes: 1, maxEntriesPerOutbox: 2 } }
    }
  })
  const body = sealOutboxBlindPayload({ poke: 'secret wave' }, { key, aad, keyId })
  const keyEnvelope = wrapOutboxBlindSealKey(key, [{ id: 'recipient', publicKey: recipient.publicKey }])
  const record = signRecord(writer, { id, _ns: 'poked', body, keyEnvelope }, 'poke')

  t.is(aad, createOutboxBlindSealAAD({
    namespace: 'poked',
    appId: writer.publicKeyHex,
    type: 'poke',
    id,
    keyId
  }))
  t.exception(() => createOutboxBlindSealAAD({
    namespace: '',
    appId: writer.publicKeyHex,
    type: 'poke',
    id,
    keyId
  }), /bad aad namespace/)

  log.sync.create(writer.publicKeyHex, { namespace: 'poked' })
  t.alike(log.sync.append(writer.publicKeyHex, { type: 'poke', data: record }), { ok: true, key: 'poke!' + id })

  const stored = log.sync.get(writer.publicKeyHex, 'poke!' + id)
  const openedKey = openOutboxBlindSealKeyEnvelope(stored.keyEnvelope, {
    recipientId: 'recipient',
    publicKey: recipient.publicKey,
    secretKey: recipient.secretKey
  })
  t.alike(openOutboxBlindPayload(stored.body, { key: openedKey, aad }), { poke: 'secret wave' })
  t.exception(() => openOutboxBlindPayload(stored.body, {
    key: openedKey,
    aad: createOutboxBlindSealAAD({
      namespace: 'peerit',
      appId: writer.publicKeyHex,
      type: 'poke',
      id,
      keyId
    })
  }), /decrypt failed/)
  t.exception(() => openOutboxBlindPayload(stored.body, {
    key: openedKey,
    aad: createOutboxBlindSealAAD({
      namespace: 'poked',
      appId: writer.publicKeyHex,
      type: 'poke',
      id,
      keyId: 'poked-room:alpha@2'
    })
  }), /decrypt failed/)
})

test('outboxlog blind seal: recipient directory entry stays app-owned before private payload wrap', (t) => {
  const directoryWriter = keyPair(24)
  const privateWriter = keyPair(25)
  const recipient = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 11) })
  const key = createOutboxBlindSealKey()
  const keyId = 'poked-room:beta@1'
  const log = createOutboxLog({
    namespaces: {
      poked: { caps: { maxOutboxes: 1, maxEntriesPerOutbox: 4 } },
      'poked-private': { blind: true, caps: { maxOutboxes: 1, maxEntriesPerOutbox: 4 } }
    }
  })
  const directoryEntry = createOutboxBlindRecipientDirectoryEntry({
    namespace: 'poked-private',
    appId: privateWriter.publicKeyHex,
    id: 'alice',
    keyId,
    publicKey: recipient.publicKeyHex
  })
  const directoryRecord = signRecord(directoryWriter, {
    id: 'recipient:alice',
    _ns: 'poked',
    recipient: directoryEntry
  }, 'recipient')

  t.is(directoryEntry.fingerprint.length, 64)
  t.alike(verifyOutboxBlindRecipientDirectoryEntry(directoryEntry, {
    namespace: 'poked-private',
    appId: privateWriter.publicKeyHex,
    id: 'alice',
    keyId,
    publicKey: recipient.publicKey
  }), directoryEntry)

  log.sync.create(directoryWriter.publicKeyHex, { namespace: 'poked' })
  log.sync.create(privateWriter.publicKeyHex, { namespace: 'poked-private' })
  t.alike(log.sync.append(directoryWriter.publicKeyHex, { type: 'recipient', data: directoryRecord }), {
    ok: true,
    key: 'recipient!recipient:alice'
  })

  const storedDirectory = log.sync.get(directoryWriter.publicKeyHex, 'recipient!recipient:alice')
  const verifiedRecipient = verifyOutboxBlindRecipientDirectoryEntry(storedDirectory.recipient, {
    namespace: 'poked-private',
    appId: privateWriter.publicKeyHex
  })
  const privateId = 'poke:2'
  const aad = createOutboxBlindSealAAD({
    namespace: verifiedRecipient.namespace,
    appId: privateWriter.publicKeyHex,
    type: 'poke',
    id: privateId,
    keyId: verifiedRecipient.keyId
  })
  const body = sealOutboxBlindPayload({ poke: 'directory-backed secret' }, { key, aad, keyId: verifiedRecipient.keyId })
  const keyEnvelope = wrapOutboxBlindSealKey(key, [{
    id: verifiedRecipient.id,
    publicKey: verifiedRecipient.publicKey
  }])
  const privateRecord = signRecord(privateWriter, {
    id: privateId,
    _ns: verifiedRecipient.namespace,
    body,
    keyEnvelope
  }, 'poke')

  t.alike(log.sync.append(privateWriter.publicKeyHex, { type: 'poke', data: privateRecord }), {
    ok: true,
    key: 'poke!' + privateId
  })
  const storedPrivate = log.sync.get(privateWriter.publicKeyHex, 'poke!' + privateId)
  const openedKey = openOutboxBlindSealKeyEnvelope(storedPrivate.keyEnvelope, {
    recipientId: verifiedRecipient.id,
    publicKey: recipient.publicKey,
    secretKey: recipient.secretKey
  })
  t.alike(openOutboxBlindPayload(storedPrivate.body, { key: openedKey, aad }), { poke: 'directory-backed secret' })
  t.exception(() => verifyOutboxBlindRecipientDirectoryEntry({
    ...directoryEntry,
    keyId: 'poked-room:beta@2'
  }), /fingerprint mismatch/)
  t.exception(() => verifyOutboxBlindRecipientDirectoryEntry(directoryEntry, {
    namespace: 'peerit'
  }), /namespace mismatch/)
})

test('outboxlog blind seal: recipient directory rotation accepts only linked key replacements', (t) => {
  const writer = keyPair(26)
  const oldRecipient = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 12) })
  const newRecipient = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 13) })
  const key = createOutboxBlindSealKey()
  const previous = createOutboxBlindRecipientDirectoryEntry({
    namespace: 'poked-private',
    appId: writer.publicKeyHex,
    id: 'alice',
    keyId: 'poked-room:gamma@1',
    publicKey: oldRecipient.publicKey
  })
  const next = createOutboxBlindRecipientDirectoryEntry({
    namespace: 'poked-private',
    appId: writer.publicKeyHex,
    id: 'alice',
    keyId: 'poked-room:gamma@2',
    replacesKeyId: previous.keyId,
    publicKey: newRecipient.publicKey
  })

  t.alike(verifyOutboxBlindRecipientDirectoryRotation(next, previous, {
    namespace: 'poked-private',
    appId: writer.publicKeyHex,
    id: 'alice'
  }), next)

  const aad = createOutboxBlindSealAAD({
    namespace: next.namespace,
    appId: writer.publicKeyHex,
    type: 'poke',
    id: 'poke:3',
    keyId: next.keyId
  })
  const body = sealOutboxBlindPayload({ poke: 'rotated key secret' }, { key, aad, keyId: next.keyId })
  const keyEnvelope = wrapOutboxBlindSealKey(key, [{ id: next.id, publicKey: next.publicKey }])

  t.exception(() => openOutboxBlindSealKeyEnvelope(keyEnvelope, {
    recipientId: previous.id,
    publicKey: oldRecipient.publicKey,
    secretKey: oldRecipient.secretKey
  }), /recipient public key mismatch/)

  const openedKey = openOutboxBlindSealKeyEnvelope(keyEnvelope, {
    recipientId: next.id,
    publicKey: newRecipient.publicKey,
    secretKey: newRecipient.secretKey
  })
  t.alike(openOutboxBlindPayload(body, { key: openedKey, aad }), { poke: 'rotated key secret' })

  t.exception(() => verifyOutboxBlindRecipientDirectoryRotation(createOutboxBlindRecipientDirectoryEntry({
    namespace: 'poked-private',
    appId: writer.publicKeyHex,
    id: 'alice',
    keyId: 'poked-room:gamma@2',
    replacesKeyId: 'poked-room:gamma@0',
    publicKey: newRecipient.publicKey
  }), previous), /replacesKeyId mismatch/)
  t.exception(() => verifyOutboxBlindRecipientDirectoryRotation(createOutboxBlindRecipientDirectoryEntry({
    namespace: 'poked-private',
    appId: writer.publicKeyHex,
    id: 'alice',
    keyId: previous.keyId,
    replacesKeyId: previous.keyId,
    publicKey: newRecipient.publicKey
  }), previous), /keyId unchanged/)
  t.exception(() => verifyOutboxBlindRecipientDirectoryRotation(createOutboxBlindRecipientDirectoryEntry({
    namespace: 'poked-private',
    appId: writer.publicKeyHex,
    id: 'alice',
    keyId: 'poked-room:gamma@2',
    replacesKeyId: previous.keyId,
    publicKey: oldRecipient.publicKey
  }), previous), /public key unchanged/)
})

test('outboxlog blind seal: recipient directory records require app supplied trust roots', (t) => {
  const directoryWriter = keyPair(27)
  const untrustedWriter = keyPair(28)
  const privateWriter = keyPair(29)
  const recipient = createOutboxBlindRecipientKeyPair({ seed: b4a.alloc(32, 14) })
  const key = createOutboxBlindSealKey()
  const keyId = 'poked-room:delta@1'
  const log = createOutboxLog({
    namespaces: {
      poked: { caps: { maxOutboxes: 1, maxEntriesPerOutbox: 4 } },
      'poked-private': { blind: true, caps: { maxOutboxes: 1, maxEntriesPerOutbox: 4 } }
    }
  })
  const directoryEntry = createOutboxBlindRecipientDirectoryEntry({
    namespace: 'poked-private',
    appId: privateWriter.publicKeyHex,
    id: 'alice',
    keyId,
    publicKey: recipient.publicKey
  })
  const directoryRecord = signRecord(directoryWriter, {
    id: 'recipient:alice',
    _ns: 'poked',
    recipient: directoryEntry
  }, 'recipient')

  log.sync.create(directoryWriter.publicKeyHex, { namespace: 'poked' })
  log.sync.create(privateWriter.publicKeyHex, { namespace: 'poked-private' })
  t.alike(log.sync.append(directoryWriter.publicKeyHex, { type: 'recipient', data: directoryRecord }), {
    ok: true,
    key: 'recipient!recipient:alice'
  })

  const storedDirectory = log.sync.get(directoryWriter.publicKeyHex, 'recipient!recipient:alice')
  const trusted = verifyOutboxBlindRecipientDirectoryRecord(storedDirectory, {
    namespace: 'poked',
    trustedPublishers: [directoryWriter.publicKeyHex],
    entryOpts: {
      namespace: 'poked-private',
      appId: privateWriter.publicKeyHex,
      id: 'alice',
      keyId,
      publicKey: recipient.publicKey
    }
  })
  t.is(trusted.publisherId, directoryWriter.publicKeyHex)
  t.alike(trusted.recipient, directoryEntry)

  const privateId = 'poke:4'
  const aad = createOutboxBlindSealAAD({
    namespace: trusted.recipient.namespace,
    appId: privateWriter.publicKeyHex,
    type: 'poke',
    id: privateId,
    keyId: trusted.recipient.keyId
  })
  const body = sealOutboxBlindPayload({ poke: 'trusted publisher secret' }, { key, aad, keyId: trusted.recipient.keyId })
  const keyEnvelope = wrapOutboxBlindSealKey(key, [{
    id: trusted.recipient.id,
    publicKey: trusted.recipient.publicKey
  }])
  const privateRecord = signRecord(privateWriter, {
    id: privateId,
    _ns: trusted.recipient.namespace,
    body,
    keyEnvelope
  }, 'poke')

  t.alike(log.sync.append(privateWriter.publicKeyHex, { type: 'poke', data: privateRecord }), {
    ok: true,
    key: 'poke!' + privateId
  })
  const storedPrivate = log.sync.get(privateWriter.publicKeyHex, 'poke!' + privateId)
  const openedKey = openOutboxBlindSealKeyEnvelope(storedPrivate.keyEnvelope, {
    recipientId: trusted.recipient.id,
    publicKey: recipient.publicKey,
    secretKey: recipient.secretKey
  })
  t.alike(openOutboxBlindPayload(storedPrivate.body, { key: openedKey, aad }), { poke: 'trusted publisher secret' })

  t.exception(() => verifyOutboxBlindRecipientDirectoryRecord(storedDirectory, {
    namespace: 'poked'
  }), /trusted publishers required/)
  t.exception(() => verifyOutboxBlindRecipientDirectoryRecord(storedDirectory, {
    namespace: 'poked',
    trustedPublishers: [untrustedWriter.publicKeyHex]
  }), /untrusted recipient directory publisher/)
  t.exception(() => verifyOutboxBlindRecipientDirectoryRecord(storedDirectory, {
    namespace: 'peerit',
    trustedPublishers: [directoryWriter.publicKeyHex]
  }), /record namespace mismatch/)
  t.exception(() => verifyOutboxBlindRecipientDirectoryRecord({
    ...storedDirectory,
    recipient: {
      ...storedDirectory.recipient,
      keyId: 'poked-room:delta@2'
    }
  }, {
    namespace: 'poked',
    trustedPublishers: [directoryWriter.publicKeyHex]
  }), /signature mismatch/)
})

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

function signRecord (writer, fields = {}, type = 'post') {
  const namespace = fields._ns || 'peerit'
  const data = {
    id: fields.id || 'p1',
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
