import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { readFile } from 'fs/promises'
import {
  ACCOUNTING_RECEIPT_DOMAIN,
  ACCOUNTING_RECEIPT_KIND,
  ACCOUNTING_RECEIPT_SOURCE,
  accountingFieldsFromStorageSummary,
  accountingReceiptEvidence,
  accountingReceiptSignable,
  createAccountingReceipt,
  verifyAccountingReceipt
} from 'p2p-hiverelay/core/protocol/accounting-receipt.js'

const VECTOR_URL = new URL('../fixtures/relaykernel-profile/accounting-receipt-v1.json', import.meta.url)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function keypairFromSeed (seedHex) {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.from(seedHex, 'hex'))
  return { publicKey, secretKey }
}

test('accounting receipt vector verifies and pins canonical signable bytes', async (t) => {
  const vector = await loadVector()
  const verdict = verifyAccountingReceipt(vector.receipt)

  t.ok(verdict.valid, 'fixture receipt verifies')
  t.ok(verdict.legacy, 'v1 remains typed legacy display data')
  t.absent(verdict.evidenceEligible, 'v1 cannot satisfy RC9 evidence')
  t.is(vector.receipt.relayPubkey, vector.relayPubkey, 'fixture names relay identity')
  t.is(b4a.toString(accountingReceiptSignable(vector.receipt), 'hex'), vector.signableHex, 'canonical bytes are stable')

  const decoded = JSON.parse(b4a.toString(accountingReceiptSignable(vector.receipt), 'utf8'))
  t.is(decoded[0], 'hiverelay.accounting.receipt.v1', 'legacy signature keeps its original domain')
})

test('accounting receipt v2 uses immutable StorageAccounting sample times', async (t) => {
  const vector = await loadVector()
  const keyPair = keypairFromSeed(vector.seedHex)
  const verifierNow = Date.now()
  const completedAt = verifierNow - 1_000
  const observedAt = completedAt - 1_000
  const fields = accountingFieldsFromStorageSummary({
    totalBytes: vector.receipt.storageBytes,
    diskBytes: vector.receipt.diskBytes,
    perEntryBytes: vector.receipt.perEntryBytes,
    measuredEntries: vector.receipt.seededCount,
    diskMeasurementComplete: true,
    diskObservedAt: observedAt,
    diskCompletedAt: completedAt
  }, {
    periodStart: observedAt,
    periodEnd: completedAt,
    bytesServed: vector.receipt.bytesServed,
    bytesReceived: vector.receipt.bytesReceived,
    leaseCount: vector.receipt.leaseCount
  })

  const receipt = createAccountingReceipt(keyPair, { ...fields, nonce: vector.receipt.nonce })
  const verdict = verifyAccountingReceipt(receipt, { verifierNow })
  t.is(receipt.kind, ACCOUNTING_RECEIPT_KIND)
  t.is(receipt.source, ACCOUNTING_RECEIPT_SOURCE)
  t.is(receipt.observedAt, observedAt)
  t.is(receipt.completedAt, completedAt)
  t.ok(verdict.valid)
  t.ok(verdict.evidenceEligible)
  const decoded = JSON.parse(b4a.toString(accountingReceiptSignable(receipt), 'utf8'))
  t.is(decoded[0], ACCOUNTING_RECEIPT_DOMAIN)
})

test('accounting receipt rejects tampering, unknown fields, and shape drift', async (t) => {
  const { receipt } = await loadVector()

  t.absent(verifyAccountingReceipt({ ...receipt, storageBytes: receipt.storageBytes + 1 }).valid, 'tampered storageBytes')
  t.absent(verifyAccountingReceipt({ ...receipt, bytesServed: receipt.bytesServed + 1 }).valid, 'tampered bytesServed')
  t.absent(verifyAccountingReceipt({ ...receipt, source: 'hypercore-counter-v1' }).valid, 'wrong source')
  t.absent(verifyAccountingReceipt({ ...receipt, caption: 'looks harmless' }).valid, 'unknown caption field')
  t.absent(verifyAccountingReceipt({ ...receipt, path: '/private/store' }).valid, 'unknown path field')
  t.absent(verifyAccountingReceipt({ ...receipt, storageBytes: receipt.diskBytes - 1 }).valid, 'storage cannot understate disk bytes')
})

test('accounting receipt requires an OS-grounded disk measurement', (t) => {
  t.exception(() => accountingFieldsFromStorageSummary({
    totalBytes: 64,
    diskBytes: null,
    perEntryBytes: 64,
    measuredEntries: 1,
    diskMeasurementComplete: true,
    diskObservedAt: 1,
    diskCompletedAt: 2
  }), /bad diskBytes/)

  t.exception(() => accountingFieldsFromStorageSummary({
    totalBytes: 64,
    diskBytes: 64,
    perEntryBytes: 64,
    diskObservedAt: 1,
    diskCompletedAt: 2,
    diskMeasurementComplete: false
  }), /complete storage sample required/)
})

test('v2 rejects hybrids and applies both immutable freshness windows', async (t) => {
  const { receipt: legacy } = await loadVector()
  t.absent(verifyAccountingReceipt({
    ...legacy,
    kind: ACCOUNTING_RECEIPT_KIND
  }).valid, 'kind/version hybrid rejected before signature dispatch')

  const observedAt = 1_800_000_000_000
  const completedAt = observedAt + 1_000
  t.ok(accountingReceiptEvidence({
    kind: ACCOUNTING_RECEIPT_KIND,
    version: 2,
    observedAt,
    completedAt
  }, completedAt + 1_000).eligible)
  t.is(accountingReceiptEvidence({
    kind: ACCOUNTING_RECEIPT_KIND,
    version: 2,
    observedAt,
    completedAt
  }, completedAt + 1_800_001).reason, 'completion-stale')
  t.is(accountingReceiptEvidence({
    kind: ACCOUNTING_RECEIPT_KIND,
    version: 2,
    observedAt,
    completedAt: observedAt + 28_800_001
  }, observedAt + 28_800_001).reason, 'epoch-duration-exceeded')
})
