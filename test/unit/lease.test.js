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
  await lm2.start()
  t.is(lm2.getSummary().totalLeasedSats, 30, 'lease totals persisted across restart (1 GiB * 3d * 10)')
  t.is(lm2.getSummary().leaseCount, 1)
  const replay = await lm2.verifyLease({ appKey: APPKEY, quoteId: quote.quoteId }, T0 + 2000)
  t.is(replay.ok, false)
  t.is(replay.error.split(':')[0], 'LEASE_REPLAY')
  await lm2.destroy()
})
