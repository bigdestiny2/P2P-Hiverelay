import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { PokerApp, SignedLog } from '../../packages/services/builtin/poker/index.js'
import {
  SIGNED_LOG_CONTROL_DOMAIN,
  SIGNED_LOG_CONTROL_VERSION,
  canonicalSignedLogControl,
  hashControlOptions,
  verifySignedLogControl
} from '../../packages/services/builtin/poker/control-capability.js'

function keyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}

function signControl (authority, fields) {
  const now = Date.now()
  const control = {
    domain: SIGNED_LOG_CONTROL_DOMAIN,
    version: SIGNED_LOG_CONTROL_VERSION,
    tableKey: authority.hex,
    authority: authority.hex,
    issuedAt: now - 1000,
    expiresAt: now + 60_000,
    ...fields
  }
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, canonicalSignedLogControl(control), authority.secretKey)
  return { ...control, signature: b4a.toString(signature, 'hex') }
}

function signEntry (writer, tableKey, seq, payload = { kind: 'opaque' }) {
  const entry = { tableKey, writer: writer.hex, seq, ts: Date.now(), payload }
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, SignedLog.canonicalBytes(entry), writer.secretKey)
  return { ...entry, signature: b4a.toString(signature, 'hex') }
}

test('signed-log control: authenticated create binds writers and opaque options', t => {
  const authority = keyPair()
  const host = keyPair()
  const options = { app: 'any-turn-game', nested: { seats: 3 } }
  const create = signControl(authority, {
    action: 'create',
    revision: 0,
    writers: [host.hex],
    optionsHash: hashControlOptions(options)
  })
  const app = new PokerApp()

  const created = app.createAuthorized({ tableKey: authority.hex, writers: [host.hex], options, control: create })
  t.ok(created.ok, 'authority can create its signed log')
  t.is(created.table.authority, authority.hex)
  t.is(created.table.controlRevision, 0)
  t.is(app.createAuthorized({ tableKey: authority.hex, writers: [host.hex], options: { ...options, changed: true }, control: create }).reason, 'control-options-mismatch', 'opaque options cannot be changed after signing')

  const tampered = { ...create, writers: [keyPair().hex] }
  t.is(verifySignedLogControl(tampered).reason, 'bad-control-signature', 'tampered control fails cryptographic verification')
})

test('signed-log control: authority defeats legacy key squatting and closure blocks legacy reopen', t => {
  const authority = keyPair()
  const attacker = keyPair()
  const host = keyPair()
  const options = { game: 'opaque' }
  const app = new PokerApp()
  app.createTable({ tableKey: authority.hex, writers: [attacker.hex], options: { squatted: true } })
  const create = signControl(authority, {
    action: 'create', revision: 0, writers: [host.hex], optionsHash: hashControlOptions(options)
  })
  const claimed = app.createAuthorized({ tableKey: authority.hex, writers: [host.hex], options, control: create })
  t.ok(claimed.ok, 'proof of table-key authority replaces an unsigned legacy squat')
  t.alike(claimed.table.writers, [host.hex])

  const close = signControl(authority, { action: 'close', revision: 1 })
  t.ok(app.closeAuthorized({ tableKey: authority.hex, control: close }).ok)
  t.exception(
    () => app.createTable({ tableKey: authority.hex, writers: [attacker.hex] }),
    /table closed/,
    'legacy create cannot erase an authenticated close tombstone'
  )
})

test('signed-log control: grant, revoke, replay protection, regrant cursor, and close tombstone', t => {
  const authority = keyPair()
  const host = keyPair()
  const guest = keyPair()
  const events = []
  const app = new PokerApp()
  app.node = { router: { pubsub: { publish: (topic, event) => events.push({ topic, event }) } } }
  const options = { opaque: true }
  const create = signControl(authority, {
    action: 'create', revision: 0, writers: [host.hex], optionsHash: hashControlOptions(options)
  })
  t.ok(app.createAuthorized({ tableKey: authority.hex, writers: [host.hex], options, control: create }).ok)

  const request = signControl(guest, { action: 'request', tableKey: authority.hex, revision: 0, writer: guest.hex })
  t.ok(app.requestWriter({ tableKey: authority.hex, control: request }).ok, 'writer proves possession and requests admission')
  const requestEvent = events.find(event => event.topic === 'poker/control-request/' + authority.hex)
  t.is(requestEvent && requestEvent.event.control.writer, guest.hex, 'request is published only on the exact table topic')

  const attacker = keyPair()
  const forgedSignature = b4a.alloc(64)
  sodium.crypto_sign_detached(forgedSignature, canonicalSignedLogControl(request), attacker.secretKey)
  const forgedRequest = { ...request, signature: b4a.toString(forgedSignature, 'hex') }
  t.is(app.requestWriter({ tableKey: authority.hex, control: forgedRequest }).reason, 'bad-control-signature', 'request signer must be the requested writer')

  const forgedGrant = signControl(guest, { action: 'grant', tableKey: authority.hex, revision: 1, writer: guest.hex })
  t.is(app.grantWriter({ tableKey: authority.hex, control: forgedGrant }).reason, 'wrong-control-authority', 'non-authority cannot grant itself')

  const grant = signControl(authority, { action: 'grant', revision: 1, writer: guest.hex })
  t.ok(app.grantWriter({ tableKey: authority.hex, control: grant }).ok, 'authority grants a writer')
  t.ok(app.submitEntry(authority.hex, signEntry(guest, authority.hex, 0)).ok, 'granted writer can append')
  t.is(app.grantWriter({ tableKey: authority.hex, control: grant }).reason, 'bad-control-revision', 'grant replay is rejected')

  const revoke = signControl(authority, { action: 'revoke', revision: 2, writer: guest.hex })
  t.ok(app.revokeWriter({ tableKey: authority.hex, control: revoke }).ok, 'authority revokes writer')
  t.is(app.submitEntry(authority.hex, signEntry(guest, authority.hex, 1)).reason, 'unknown-writer', 'revoked writer cannot append')

  const regrant = signControl(authority, { action: 'grant', revision: 3, writer: guest.hex })
  t.ok(app.grantWriter({ tableKey: authority.hex, control: regrant }).ok, 'writer can be regranted')
  t.ok(app.submitEntry(authority.hex, signEntry(guest, authority.hex, 1)).ok, 'regrant preserves the writer cursor')

  const close = signControl(authority, { action: 'close', revision: 4 })
  t.ok(app.closeAuthorized({ tableKey: authority.hex, control: close }).ok, 'authority closes the log')
  const state = app.getState(authority.hex)
  t.ok(state.closed, 'readers see an authenticated close tombstone')
  t.is(state.closure.control.signature, close.signature)
  t.is(app.submitEntry(authority.hex, signEntry(host, authority.hex, 0)).reason, 'table-closed', 'closed log rejects appends distinctly')
  t.is(app.createAuthorized({ tableKey: authority.hex, writers: [host.hex], options, control: create }).reason, 'table-closed', 'old create cannot reopen a closed log')
  const controlEvents = events.filter(event => event.topic.startsWith('poker/control/'))
  t.alike(controlEvents.map(event => event.event.type), ['grant', 'revoke', 'grant', 'closed'], 'control changes publish on the exact control topic')
  t.ok(controlEvents.every(event => event.topic === 'poker/control/' + authority.hex))
})

test('signed-log control: expired and overlong capabilities fail closed', t => {
  const authority = keyPair()
  const expired = signControl(authority, { action: 'close', revision: 1, issuedAt: 1, expiresAt: 2 })
  t.is(verifySignedLogControl(expired, { now: Date.now() }).reason, 'control-expired')
  const tooLong = signControl(authority, { action: 'close', revision: 1, issuedAt: Date.now(), expiresAt: Date.now() + 8 * 24 * 60 * 60 * 1000 })
  t.is(verifySignedLogControl(tooLong).reason, 'control-validity-too-long')
})

test('signed-log presence: writer membership, freshness, exact topic, and expiry', t => {
  const authority = keyPair()
  const host = keyPair()
  const outsider = keyPair()
  const events = []
  const app = new PokerApp()
  app.node = { router: { pubsub: { publish: (topic, event) => events.push({ topic, event }) } } }
  const options = { opaque: true }
  const create = signControl(authority, {
    action: 'create', revision: 0, writers: [host.hex], optionsHash: hashControlOptions(options)
  })
  t.ok(app.createAuthorized({ tableKey: authority.hex, writers: [host.hex], options, control: create }).ok)

  const first = signControl(host, {
    action: 'presence',
    tableKey: authority.hex,
    revision: 1,
    instance: 'ab'.repeat(16),
    cursor: 12,
    expiresAt: Date.now() + 20_000
  })
  t.ok(app.announcePresence({ tableKey: authority.hex, control: first }).ok, 'table writer announces presence')
  t.is(app.getPresence({ tableKey: authority.hex }).presence[0].cursor, 12, 'snapshot exposes generic cursor')
  t.is(events[0].topic, 'poker/presence/' + authority.hex, 'presence uses exact table topic')
  t.is(app.announcePresence({ tableKey: authority.hex, control: first }).reason, 'stale-presence', 'same heartbeat cannot replay')

  const notWriter = signControl(outsider, {
    action: 'presence',
    tableKey: authority.hex,
    revision: 1,
    instance: 'cd'.repeat(16),
    cursor: 0,
    expiresAt: Date.now() + 20_000
  })
  t.is(app.announcePresence({ tableKey: authority.hex, control: notWriter }).reason, 'unknown-writer')

  const overlong = signControl(host, {
    action: 'presence',
    tableKey: authority.hex,
    revision: 2,
    instance: 'ab'.repeat(16),
    cursor: 13,
    expiresAt: Date.now() + 60_000
  })
  t.is(app.announcePresence({ tableKey: authority.hex, control: overlong }).reason, 'presence-validity-too-long')
})
