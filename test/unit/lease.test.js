/**
 * LeaseManager (paid pin-lease) tests.
 *
 * The demand-side counterpart to the subsidy: a publisher pays a relay they
 * don't own to keep their Hyperdrive pinned for a window. Zero-custody —
 * the relay mints an invoice on the operator's own node and verifies it
 * settled; the only durable artifact is the lease deadline. These tests pin
 * the byte-days quote math, the relay-signed stateless quote, settlement
 * verification, the replay-guard (incl. across restart), and the failure
 * modes (underpaid / expired / appKey-mismatch / forged quote).
 */

import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { mkdtemp } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { LeaseManager } from 'p2p-hiverelay/incentive/lease/index.js'
import { isLeaseExempt, evaluateSeedLease } from 'p2p-hiverelay/incentive/lease/gate.js'
import { assertPurgable } from 'p2p-hiverelay/core/relay-node/eviction.js'
import { MockProvider } from 'p2p-hiverelay/incentive/payment/mock-provider.js'

function makeKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const GIB = 1024 * 1024 * 1024
const DAY_MS = 86_400_000
const T0 = Date.UTC(2026, 5, 15, 0, 0, 0)
const APPKEY = 'a'.repeat(64)

async function makeManager (opts = {}) {
  const provider = opts.provider || new MockProvider()
  const lm = new LeaseManager({
    keyPair: opts.keyPair || makeKeyPair(),
    provider,
    storagePath: opts.storagePath || null,
    satsPerGiBDay: opts.satsPerGiBDay != null ? opts.satsPerGiBDay : 10,
    quoteTtlMs: opts.quoteTtlMs != null ? opts.quoteTtlMs : 60 * 60 * 1000,
    minDays: opts.minDays,
    maxDays: opts.maxDays
  })
  await lm.start()
  return { lm, provider }
}

test('byte-days quote math: ceil(bytes/GiB) * days * rate', async (t) => {
  const { lm } = await makeManager({ satsPerGiBDay: 10 })
  // 500 MB rounds up to 1 GiB → 1 * 7 * 10 = 70
  t.is(lm.quoteSats(500 * 1024 * 1024, 7).amountSats, 70)
  // exactly 2 GiB, 3 days, rate 10 → 60
  t.is(lm.quoteSats(2 * GIB, 3).amountSats, 60)
  // 2.5 GiB rounds up to 3 GiB → 3 * 1 * 10 = 30
  t.is(lm.quoteSats(2.5 * GIB, 1).amountSats, 30)
  await lm.destroy()
})

test('createQuote → pay → verify happy path sets paidUntil', async (t) => {
  const { lm, provider } = await makeManager({ satsPerGiBDay: 10 })
  const quote = await lm.createQuote({ appKey: APPKEY, maxStorageBytes: 2 * GIB, leaseDays: 5 }, T0)
  t.is(quote.amountSats, 100, '2 GiB * 5 days * 10')
  t.ok(quote.bolt11 && quote.quoteId, 'quote carries bolt11 + signed quoteId')
  t.is(quote.expiresAt, T0 + 60 * 60 * 1000)

  // Unpaid yet → rejected.
  const unpaid = await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 1000)
  t.is(unpaid.ok, false)
  t.is(unpaid.error.split(':')[0], 'LEASE_UNPAID')

  // Pay the invoice on the operator's (mock) node, then verify.
  const inv = provider.invoices[provider.invoices.length - 1]
  provider.settleInvoice(inv.rHash)
  const ok = await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 2000)
  t.is(ok.ok, true)
  t.is(ok.paidUntil, T0 + 2000 + 5 * DAY_MS, 'paidUntil = now + leaseDays')
  t.is(lm.getSummary().totalLeasedSats, 100)
  t.is(lm.getSummary().leaseCount, 1)
  await lm.destroy()
})

test('replay-guard: a settled payment cannot be redeemed twice', async (t) => {
  const { lm, provider } = await makeManager()
  const quote = await lm.createQuote({ appKey: APPKEY, maxStorageBytes: GIB, leaseDays: 2 }, T0)
  provider.settleInvoice(provider.invoices[0].rHash)
  const first = await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 1000)
  t.is(first.ok, true)
  const second = await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 2000)
  t.is(second.ok, false)
  t.is(second.error.split(':')[0], 'LEASE_REPLAY')
  await lm.destroy()
})

test('appKey mismatch: a quote for X cannot pay for Y', async (t) => {
  const { lm, provider } = await makeManager()
  const quote = await lm.createQuote({ appKey: APPKEY, maxStorageBytes: GIB, leaseDays: 1 }, T0)
  provider.settleInvoice(provider.invoices[0].rHash)
  const wrong = await lm.verifyLease({ appKey: 'b'.repeat(64), quoteId: quote.quoteId }, T0 + 1000)
  t.is(wrong.ok, false)
  t.is(wrong.error.split(':')[0], 'LEASE_QUOTE_APPKEY_MISMATCH')
  await lm.destroy()
})

test('expired quote is rejected even if paid', async (t) => {
  const { lm, provider } = await makeManager({ quoteTtlMs: 1000 })
  const quote = await lm.createQuote({ appKey: APPKEY, maxStorageBytes: GIB, leaseDays: 1 }, T0)
  provider.settleInvoice(provider.invoices[0].rHash)
  const late = await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 5000)
  t.is(late.ok, false)
  t.is(late.error.split(':')[0], 'LEASE_QUOTE_EXPIRED')
  await lm.destroy()
})

test('underpaid settlement is rejected', async (t) => {
  // Provider whose lookupInvoice reports a lower settled amount than quoted.
  const provider = new MockProvider()
  await provider.connect()
  provider.lookupInvoice = async () => ({ settled: true, amount: 1 })
  const { lm } = await makeManager({ provider })
  const quote = await lm.createQuote({ appKey: APPKEY, maxStorageBytes: 2 * GIB, leaseDays: 5 }, T0)
  t.is(quote.amountSats, 100)
  const res = await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 1000)
  t.is(res.ok, false)
  t.is(res.error.split(':')[0], 'LEASE_UNDERPAID')
  await lm.destroy()
})

test('forged quote (wrong relay key) fails signature check', async (t) => {
  const { lm: a, provider } = await makeManager()
  const quote = await a.createQuote({ appKey: APPKEY, maxStorageBytes: GIB, leaseDays: 1 }, T0)
  provider.settleInvoice(provider.invoices[0].rHash)
  // A different relay (different keyPair) must not accept A's quote.
  const { lm: b } = await makeManager()
  const res = await b.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 1000)
  t.is(res.ok, false)
  t.is(res.error.split(':')[0], 'LEASE_BAD_QUOTE')
  await a.destroy(); await b.destroy()
})

test('replay-guard survives restart (persisted consumed set)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'lease-'))
  const storagePath = join(dir, 'lease.json')
  const keyPair = makeKeyPair()
  const provider = new MockProvider()

  const { lm } = await makeManager({ keyPair, provider, storagePath })
  const quote = await lm.createQuote({ appKey: APPKEY, maxStorageBytes: GIB, leaseDays: 3 }, T0)
  provider.settleInvoice(provider.invoices[0].rHash)
  const ok = await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 1000)
  t.is(ok.ok, true)
  await lm.destroy()

  // New manager, same storage + key + (re-shared) provider state. The
  // consumed paymentHash must have persisted → replay still blocked.
  const lm2 = new LeaseManager({ keyPair, provider, storagePath, satsPerGiBDay: 10 })
  // Reload at a time within the quote window (T0 + 1500); the consumed entry
  // must survive so the replay is still blocked.
  await lm2.start({ now: T0 + 1500 })
  t.is(lm2.getSummary().totalLeasedSats, 30, 'lease totals persisted across restart (1 GiB * 3d * 10)')
  t.is(lm2.getSummary().leaseCount, 1)
  const replay = await lm2.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 2000)
  t.is(replay.ok, false)
  t.is(replay.error.split(':')[0], 'LEASE_REPLAY')
  await lm2.destroy()
})

test('replay-guard drops consumed entries once their quote has expired (finding #6)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'lease-'))
  const storagePath = join(dir, 'lease.json')
  const keyPair = makeKeyPair()
  const provider = new MockProvider()
  const { lm } = await makeManager({ keyPair, provider, storagePath, quoteTtlMs: 1000 })
  const quote = await lm.createQuote({ appKey: APPKEY, maxStorageBytes: GIB, leaseDays: 1 }, T0)
  provider.settleInvoice(provider.invoices[0].rHash)
  await lm.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 100) // consumed; quote expiresAt = T0 + 1000
  await lm.destroy()

  const lm2 = new LeaseManager({ keyPair, provider, storagePath, satsPerGiBDay: 10 })
  await lm2.start({ now: T0 + 5000 }) // load PAST the quote window → entry pruned
  t.is(lm2._consumed.size, 0, 'expired consumed hash pruned on load (bounded memory, no replay risk)')
  await lm2.destroy()
})

// ── Shared gate: exemption can't be forged (review finding #3) ──
test('isLeaseExempt: only a VERIFIED custody intent exempts', (t) => {
  const reg = { getCustodyIntent: (id) => id === 'good' ? { publisherPubkey: 'PUB' } : null }
  // No custodyIntentId → charged.
  t.is(isLeaseExempt({ publisherPubkey: 'PUB' }, { seedingRegistry: reg }), false)
  // Forged storageClass alone → NOT exempt (the fix: declared class is untrusted).
  t.is(isLeaseExempt({ storageClass: 'temporary', publisherPubkey: 'PUB' }, { seedingRegistry: reg }), false)
  t.is(isLeaseExempt({ availabilityClass: 'atomic-handoff', publisherPubkey: 'PUB' }, { seedingRegistry: reg }), false)
  // custodyIntentId that doesn't resolve → NOT exempt.
  t.is(isLeaseExempt({ custodyIntentId: 'bogus', publisherPubkey: 'PUB' }, { seedingRegistry: reg }), false)
  // Resolves but publisher mismatch → NOT exempt.
  t.is(isLeaseExempt({ custodyIntentId: 'good', publisherPubkey: 'OTHER' }, { seedingRegistry: reg }), false)
  // Resolves + publisher matches → exempt.
  t.is(isLeaseExempt({ custodyIntentId: 'good', publisherPubkey: 'PUB' }, { seedingRegistry: reg }), true)
  // No registry → can't verify → NOT exempt.
  t.is(isLeaseExempt({ custodyIntentId: 'good', publisherPubkey: 'PUB' }, {}), false)
})

test('evaluateSeedLease: outcomes the transports map on', async (t) => {
  // No leaseManager → exempt (lease off / self-host).
  t.is((await evaluateSeedLease({ leaseManager: null, appKey: APPKEY, opts: {}, body: {} })).outcome, 'exempt')

  const { lm, provider } = await makeManager({ satsPerGiBDay: 10 })
  // Non-exempt, no proof, no leaseDays → quote (payment required), no quote body.
  const q0 = await evaluateSeedLease({ leaseManager: lm, appKey: APPKEY, opts: { maxStorage: GIB }, body: {} })
  t.is(q0.outcome, 'quote'); t.is(q0.status, 402); t.absent(q0.quote)
  // With leaseDays → a real quote.
  const q1 = await evaluateSeedLease({ leaseManager: lm, appKey: APPKEY, opts: { maxStorage: 2 * GIB }, body: { leaseDays: 5 } })
  t.is(q1.outcome, 'quote'); t.is(q1.quote.amountSats, 100); t.ok(q1.quote.quoteId)
  // Pay it, then resubmit the quoteId as proof → paid.
  provider.settleInvoice(provider.invoices[provider.invoices.length - 1].rHash)
  const paid = await evaluateSeedLease({ leaseManager: lm, appKey: APPKEY, opts: { maxStorage: 2 * GIB }, body: { paymentProof: { quoteId: q1.quote.quoteId } } })
  t.is(paid.outcome, 'paid'); t.ok(paid.retainUntil > Date.now())
  // Bad proof → error.
  const bad = await evaluateSeedLease({ leaseManager: lm, appKey: APPKEY, opts: { maxStorage: GIB }, body: { paymentProof: { quoteId: 'garbage' } } })
  t.is(bad.outcome, 'error'); t.is(bad.status, 402)
  await lm.destroy()
})

// ── Eviction must not shed a paid pin before its lease expires (finding #5) ──
test('assertPurgable: a live paid lease is LEASE_BOUND; expired is purgable', (t) => {
  const now = 1_000_000
  t.exception(() => assertPurgable({ durability: 0, leaseManaged: true, retainUntil: now + 10_000 }, now), /not evictable until/, 'live lease refused')
  t.execution(() => assertPurgable({ durability: 0, leaseManaged: true, retainUntil: now - 1 }, now), 'expired lease purgable')
  t.execution(() => assertPurgable({ durability: 0, leaseManaged: false, retainUntil: now + 10_000 }, now), 'non-lease entry unaffected')
})
