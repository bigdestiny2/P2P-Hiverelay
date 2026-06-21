/**
 * UsageReceipt — counterparty-signed, content-free service-usage attestations,
 * and the relay-side UsageLedger (verify + replay-guard + aggregate + digest).
 */
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  createUsageReceipt, verifyUsageReceipt, UsageLedger, MAX_UNITS, USAGE_RECEIPT_VERSION
} from 'p2p-hiverelay/core/protocol/usage-receipt.js'

function keypair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}
const RELAY = b4a.toString(b4a.alloc(32, 7), 'hex')
const base = { relayPubkey: RELAY, service: 'poker', capability: 'append', unitKind: 'appends', units: 3, epoch: 100 }

test('create/verify round-trips a valid receipt', (t) => {
  const kp = keypair()
  const r = createUsageReceipt(kp, base)
  t.is(r.v, USAGE_RECEIPT_VERSION)
  t.is(r.peerPubkey, b4a.toString(kp.publicKey, 'hex'), 'signed by the consumer')
  t.is(r.relayPubkey, RELAY)
  t.is(r.units, 3)
  t.ok(verifyUsageReceipt(r), 'verifies')
})

test('PRIVACY: a receipt carries only content-free fields (no payload/ip/content/card)', (t) => {
  const r = createUsageReceipt(keypair(), base)
  const allowed = new Set(['v', 'relayPubkey', 'peerPubkey', 'service', 'capability', 'unitKind', 'units', 'epoch', 'timestamp', 'nonce', 'sig'])
  for (const k of Object.keys(r)) t.ok(allowed.has(k), 'field allowed: ' + k)
  const blob = JSON.stringify(r).toLowerCase()
  for (const bad of ['payload', 'card', 'hole', 'ip', 'content', 'addr']) {
    t.absent(blob.includes(bad), 'no "' + bad + '" anywhere in the receipt')
  }
})

test('verify rejects tampering + forgery', (t) => {
  const kp = keypair()
  const r = createUsageReceipt(kp, base)
  t.absent(verifyUsageReceipt({ ...r, units: 9999 }), 'tampered units')
  t.absent(verifyUsageReceipt({ ...r, service: 'vrf' }), 'tampered service')
  t.absent(verifyUsageReceipt({ ...r, capability: 'x' }), 'tampered capability')
  t.absent(verifyUsageReceipt({ ...r, relayPubkey: b4a.toString(b4a.alloc(32, 9), 'hex') }), 'tampered relay')
  t.absent(verifyUsageReceipt({ ...r, sig: 'ab'.repeat(64) }), 'wrong signature')
  t.absent(verifyUsageReceipt({ ...r, v: 99 }), 'wrong version')
  t.absent(verifyUsageReceipt(null), 'null')
})

test('create rejects invalid / non-content-free fields', (t) => {
  const kp = keypair()
  t.exception(() => createUsageReceipt(kp, { ...base, relayPubkey: 'nothex' }))
  t.exception(() => createUsageReceipt(kp, { ...base, units: -1 }))
  t.exception(() => createUsageReceipt(kp, { ...base, units: MAX_UNITS + 1 }))
  t.exception(() => createUsageReceipt(kp, { ...base, unitKind: 'has space' }))
  t.exception(() => createUsageReceipt(kp, { ...base, service: '' }))
  t.exception(() => createUsageReceipt({}, base), 'keyPair required')
})

test('UsageLedger: verified-only, replay-guarded, aggregated', (t) => {
  const led = new UsageLedger()
  const a = keypair(); const b = keypair()
  const r1 = createUsageReceipt(a, { ...base, units: 3 })
  const r2 = createUsageReceipt(b, { ...base, units: 5 })
  t.ok(led.record(r1).ok)
  t.ok(led.record(r2).ok)
  t.is(led.record(r1).reason, 'replay', 'same peer+nonce rejected')
  t.is(led.record({ ...r1, units: 100 }).reason, 'bad-signature', 'forged units rejected')
  const totals = led.totals()
  t.is(totals['poker.append.appends'], 8, 'aggregates verified units only')
  const d = led.digest()
  t.is(d.count, 2)
  t.is(d.totals['poker.append.appends'], 8)
  t.is(typeof d.receiptRoot, 'string')
  t.is(d.receiptRoot.length, 64, 'content-free 32-byte root')
})

test('UsageLedger: digest is stable regardless of insertion order', (t) => {
  const a = keypair(); const b = keypair()
  const r1 = createUsageReceipt(a, base); const r2 = createUsageReceipt(b, base)
  const l1 = new UsageLedger(); l1.record(r1); l1.record(r2)
  const l2 = new UsageLedger(); l2.record(r2); l2.record(r1)
  t.is(l1.digest().receiptRoot, l2.digest().receiptRoot, 'order-independent root')
})
