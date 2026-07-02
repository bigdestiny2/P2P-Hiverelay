import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  REPAIRTICKET_RECORD_TYPE_CLAIM,
  REPAIRTICKET_RECORD_TYPE_CLOSE,
  REPAIRTICKET_RECORD_TYPE_RECEIPT,
  REPAIRTICKET_RECORD_TYPE_TICKET,
  RepairTicketApp,
  canonicalRepairRecord,
  createRepairRecord,
  redactRepairRecord,
  repairRecordMarker,
  repairRecordTicketId,
  signRepairRecord,
  targetMatchesRepairRecord,
  verifyRepairOutboxRecord,
  verifyRepairRecord
} from '../../packages/services/builtin/repairticket/index.js'

const CREATED_AT = '2026-07-02T12:00:00.000Z'
const EXPIRES_AT = '2026-07-02T18:00:00.000Z'
const NOW = Date.parse('2026-07-02T12:05:00.000Z')
const TARGET = 'a'.repeat(64)
const TARGET_HASH = 'b'.repeat(64)
const WITNESS_ID = 'c'.repeat(64)

test('repairticket record: signs, verifies, canonicalizes, and redacts target keys', (t) => {
  const signer = keyPair(1)
  const base = ticketInput(signer)
  const created = createRepairRecord(base)
  const signed = signRepairRecord(base, signer.secretKey)

  t.is(created.id, signed.id)
  t.is(canonicalRepairRecord(base), canonicalRepairRecord(signed))
  t.ok(verifyRepairRecord(signed, { now: NOW }))
  t.absent(verifyRepairRecord({ ...signed, repair: { ...signed.repair, priority: 99 } }, { now: NOW }))
  t.is(repairRecordTicketId(signed), signed.id)

  const redacted = redactRepairRecord(signed)
  t.absent(redacted.target.key)
  t.is(redacted.target.keyHash, TARGET_HASH)
  t.ok(targetMatchesRepairRecord(signed, TARGET))
  t.ok(targetMatchesRepairRecord(signed, TARGET_HASH))

  t.alike(repairRecordMarker(signed), {
    id: signed.id,
    type: REPAIRTICKET_RECORD_TYPE_TICKET,
    ticketId: signed.id,
    createdAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    signer: signer.publicKeyHex,
    target: TARGET_HASH,
    targetKind: 'hypercore',
    reason: 'witness-failure',
    action: null,
    outcome: null,
    ok: null
  })
})

test('repairticket record: validates claim, receipt, and close records against signer keys', (t) => {
  const opener = keyPair(2)
  const relay = keyPair(3)
  const closer = keyPair(4)
  const ticket = signRepairRecord(ticketInput(opener), opener.secretKey)
  const claim = signRepairRecord(claimInput(relay, ticket.id), relay.secretKey)
  const receipt = signRepairRecord(receiptInput(relay, ticket.id), relay.secretKey)
  const close = signRepairRecord(closeInput(closer, ticket.id), closer.secretKey)

  t.ok(verifyRepairRecord(claim, { now: NOW }))
  t.ok(verifyRepairRecord(receipt, { now: NOW }))
  t.ok(verifyRepairRecord(close, { now: NOW }))
  t.is(repairRecordTicketId(claim), ticket.id)
  t.absent(verifyRepairOutboxRecord({ appId: opener.publicKeyHex, data: { ...claim, _ns: 'repair' } }, { now: NOW }))
  t.ok(verifyRepairOutboxRecord({ appId: relay.publicKeyHex, data: { ...claim, _ns: 'repair' } }, { now: NOW }))
})

test('repairticket record: timestamp policy rejects future, stale, and expired records', (t) => {
  const signer = keyPair(5)
  const future = signRepairRecord(ticketInput(signer, {
    createdAt: '2026-07-02T13:00:00.000Z',
    expiresAt: '2026-07-02T18:00:00.000Z'
  }), signer.secretKey)
  const stale = signRepairRecord(ticketInput(signer, {
    createdAt: '2026-06-20T12:00:00.000Z',
    expiresAt: '2026-06-20T18:00:00.000Z'
  }), signer.secretKey)
  const expired = signRepairRecord(ticketInput(signer, {
    createdAt: '2026-07-02T09:00:00.000Z',
    expiresAt: '2026-07-02T09:30:00.000Z'
  }), signer.secretKey)

  t.absent(verifyRepairRecord(future, { now: NOW }))
  t.absent(verifyRepairRecord(stale, { now: NOW }))
  t.absent(verifyRepairRecord(expired, { now: NOW }))
})

test('repairticket app: appends ticket lifecycle, ranges by target, and summarizes repair state', (t) => {
  const opener = keyPair(6)
  const relay = keyPair(7)
  const closer = keyPair(8)
  const app = new RepairTicketApp({ verify: { now: NOW } })
  const ticket = signRepairRecord(ticketInput(opener), opener.secretKey)
  const claim = signRepairRecord(claimInput(relay, ticket.id), relay.secretKey)
  const receipt = signRepairRecord(receiptInput(relay, ticket.id), relay.secretKey)
  const close = signRepairRecord(closeInput(closer, ticket.id), closer.secretKey)
  const live = []
  const unsubscribe = app.subscribe({ target: TARGET_HASH }, marker => live.push(marker))

  t.alike(app.append(ticket), { ok: true, key: 'ticket!' + ticket.id, id: ticket.id, ticketId: ticket.id })
  t.alike(app.append(claim), { ok: true, key: 'claim!' + claim.id, id: claim.id, ticketId: ticket.id })
  t.alike(app.append(receipt), { ok: true, key: 'receipt!' + receipt.id, id: receipt.id, ticketId: ticket.id })
  t.alike(app.append(close), { ok: true, key: 'close!' + close.id, id: close.id, ticketId: ticket.id })
  unsubscribe()

  const records = app.list({ ticketId: ticket.id })
  t.is(records.count, 4)
  t.is(records.records[0].id, ticket.id)
  t.absent(records.records[0].target.key)

  const tickets = app.tickets({ target: TARGET_HASH })
  t.is(tickets.count, 1)
  t.is(tickets.tickets[0].id, ticket.id)
  t.is(tickets.tickets[0].status, 'repaired')
  t.alike(tickets.tickets[0].counts, { claims: 1, receipts: 1, closes: 1 })
  t.is(live.length, 4)
  t.is(live[3].topic, 'repair/' + ticket.id)
})

test('repairticket app: rejects foreign outbox writers before storage', (t) => {
  const opener = keyPair(9)
  const foreign = keyPair(10)
  const ticket = signRepairRecord(ticketInput(opener), opener.secretKey)
  const app = new RepairTicketApp({ verify: { now: NOW } })
  const data = { ...ticket, _ns: 'repair' }

  t.absent(verifyRepairOutboxRecord({ appId: foreign.publicKeyHex, data }, { now: NOW }))
  const err = throws(() => app.sync.append(foreign.publicKeyHex, { type: 'ticket', data }))
  t.is(err.status, 400)
  t.is(app.list().count, 0)
})

test('repairticket app: default file persistence restores signed repair tickets', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'repairticket-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const signer = keyPair(11)
  const ticket = signRepairRecord(ticketInput(signer), signer.secretKey)
  const first = new RepairTicketApp({ verify: { now: NOW } })
  await first.start({ config: { storage: dir }, node: { id: 'relay-a' } })
  t.alike(first.append(ticket), { ok: true, key: 'ticket!' + ticket.id, id: ticket.id, ticketId: ticket.id })
  await first.stop()

  const second = new RepairTicketApp({ verify: { now: NOW } })
  await second.start({ config: { storage: dir }, node: { id: 'relay-b' } })
  const page = second.tickets({ target: TARGET_HASH })
  t.is(page.count, 1)
  t.is(page.tickets[0].id, ticket.id)
  t.is(page.tickets[0].status, 'open')
  await second.stop()
})

function ticketInput (signer, fields = {}) {
  return {
    type: REPAIRTICKET_RECORD_TYPE_TICKET,
    createdAt: fields.createdAt || CREATED_AT,
    expiresAt: fields.expiresAt || EXPIRES_AT,
    signer: {
      publicKey: signer.publicKeyHex,
      role: 'witness',
      appId: 'repair-agent'
    },
    target: {
      kind: 'hypercore',
      key: TARGET,
      keyHash: TARGET_HASH
    },
    repair: {
      reason: 'witness-failure',
      priority: 80,
      desiredReplicas: 5,
      observedReplicas: 1,
      evidence: [WITNESS_ID],
      note: 'witness quorum reports degraded availability'
    }
  }
}

function claimInput (signer, ticketId) {
  return {
    type: REPAIRTICKET_RECORD_TYPE_CLAIM,
    ticketId,
    createdAt: '2026-07-02T12:01:00.000Z',
    expiresAt: EXPIRES_AT,
    signer: {
      publicKey: signer.publicKeyHex,
      role: 'relay'
    },
    relay: {
      url: 'https://relay.example',
      operatorKey: signer.publicKeyHex
    },
    action: 'seed'
  }
}

function receiptInput (signer, ticketId) {
  return {
    type: REPAIRTICKET_RECORD_TYPE_RECEIPT,
    ticketId,
    createdAt: '2026-07-02T12:02:00.000Z',
    expiresAt: EXPIRES_AT,
    signer: {
      publicKey: signer.publicKeyHex,
      role: 'relay'
    },
    relay: {
      url: 'https://relay.example',
      operatorKey: signer.publicKeyHex
    },
    proof: {
      kind: 'witnesslog',
      witnessId: WITNESS_ID,
      observedAt: '2026-07-02T12:02:30.000Z',
      headSeq: 8,
      digest: 'sha256:' + 'd'.repeat(64)
    },
    result: {
      ok: true,
      latencyMs: 35,
      bytes: 4096
    }
  }
}

function closeInput (signer, ticketId) {
  return {
    type: REPAIRTICKET_RECORD_TYPE_CLOSE,
    ticketId,
    createdAt: '2026-07-02T12:03:00.000Z',
    expiresAt: EXPIRES_AT,
    signer: {
      publicKey: signer.publicKeyHex,
      role: 'witness'
    },
    outcome: 'repaired',
    evidence: [WITNESS_ID]
  }
}

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

function throws (fn) {
  try {
    fn()
  } catch (err) {
    return err
  }
  throw new Error('expected function to throw')
}
