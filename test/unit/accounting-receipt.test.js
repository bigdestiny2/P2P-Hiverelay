import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { readFile } from 'fs/promises'
import {
  ACCOUNTING_RECEIPT_DOMAIN,
  accountingFieldsFromStorageSummary,
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
  t.is(vector.receipt.relayPubkey, vector.relayPubkey, 'fixture names relay identity')
  t.is(b4a.toString(accountingReceiptSignable(vector.receipt), 'hex'), vector.signableHex, 'canonical bytes are stable')

  const decoded = JSON.parse(b4a.toString(accountingReceiptSignable(vector.receipt), 'utf8'))
  t.is(decoded[0], ACCOUNTING_RECEIPT_DOMAIN, 'signature is domain separated')
})

test('accounting receipt can be built from StorageAccounting summary fields', async (t) => {
  const vector = await loadVector()
  const keyPair = keypairFromSeed(vector.seedHex)
  const fields = accountingFieldsFromStorageSummary({
    totalBytes: vector.receipt.storageBytes,
    diskBytes: vector.receipt.diskBytes,
    perEntryBytes: vector.receipt.perEntryBytes,
    measuredEntries: vector.receipt.seededCount
  }, {
    periodStart: vector.receipt.periodStart,
    periodEnd: vector.receipt.periodEnd,
    measuredAt: vector.receipt.measuredAt,
    bytesServed: vector.receipt.bytesServed,
    bytesReceived: vector.receipt.bytesReceived,
    leaseCount: vector.receipt.leaseCount
  })

  const receipt = createAccountingReceipt(keyPair, { ...fields, nonce: vector.receipt.nonce })
  t.alike(receipt, vector.receipt, 'deterministic receipt matches vector')
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
    measuredEntries: 1
  }), /diskBytes required/)

  t.exception(() => createAccountingReceipt(keypairFromSeed('02'.repeat(32)), {
    storageBytes: 10,
    diskBytes: 20,
    perEntryBytes: 10,
    nonce: '22'.repeat(16)
  }), /storageBytes below diskBytes/)
})
