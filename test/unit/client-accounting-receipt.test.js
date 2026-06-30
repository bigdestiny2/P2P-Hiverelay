import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { createAccountingReceipt } from 'p2p-hiverelay/core/protocol/accounting-receipt.js'

function keypairFromSeed (byte) {
  const seed = b4a.alloc(sodium.crypto_sign_SEEDBYTES, byte)
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey }
}

function makeReceipt (keyPair = keypairFromSeed(8)) {
  return createAccountingReceipt(keyPair, {
    periodStart: 100,
    periodEnd: 200,
    measuredAt: 201,
    storageBytes: 4096,
    diskBytes: 3072,
    perEntryBytes: 2048,
    bytesServed: 900,
    bytesReceived: 12,
    leaseCount: 7,
    seededCount: 2,
    nonce: '66'.repeat(16)
  })
}

function client () {
  return Object.create(HiveRelayClient.prototype)
}

function withFetch (t, handler) {
  const before = globalThis.fetch
  globalThis.fetch = handler
  let active = true
  const restore = () => {
    if (!active) return
    globalThis.fetch = before
    active = false
  }
  t.teardown(restore)
  return restore
}

test('fetchAccountingReceipt verifies signed receipt and sends management auth', async (t) => {
  const keyPair = keypairFromSeed(8)
  const receipt = makeReceipt(keyPair)
  let seen = null

  withFetch(t, async (url, opts = {}) => {
    seen = { url, opts }
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ receipt })
    }
  })

  const result = await client().fetchAccountingReceipt('https://relay.example/', {
    apiKey: 'secret',
    refresh: false,
    expectedPubkey: b4a.toString(keyPair.publicKey, 'hex')
  })

  t.is(seen.url, 'https://relay.example/api/accounting/receipt?refresh=0')
  t.is(seen.opts.method, 'GET')
  t.is(seen.opts.headers.Authorization, 'Bearer secret')
  t.is(result.ok, true)
  t.is(result.verified, true)
  t.is(result.receipt.diskBytes, 3072)
  t.is(result.receipt.relayPubkey, b4a.toString(keyPair.publicKey, 'hex'))
})

test('fetchAccountingReceipt rejects tampered or wrong-relay receipts', async (t) => {
  const receipt = makeReceipt()

  const restoreTampered = withFetch(t, async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ receipt: { ...receipt, diskBytes: receipt.diskBytes + 1 } })
  }))
  await t.exception(
    client().fetchAccountingReceipt('https://relay.example', {}),
    /receipt verification failed/
  )
  restoreTampered()

  const other = b4a.toString(keypairFromSeed(9).publicKey, 'hex')
  withFetch(t, async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ receipt })
  }))
  await t.exception(
    client().fetchAccountingReceipt('https://relay.example', { expectedPubkey: other }),
    /pubkey mismatch/
  )
})

test('fetchAccountingReceipt surfaces HTTP and malformed response failures', async (t) => {
  const restoreHttp = withFetch(t, async () => ({
    ok: false,
    status: 401,
    text: async () => JSON.stringify({ error: 'auth-required' })
  }))
  await t.exception(
    client().fetchAccountingReceipt('https://relay.example', {}),
    /auth-required/
  )
  restoreHttp()

  withFetch(t, async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ ok: true })
  }))
  await t.exception(
    client().fetchAccountingReceipt('https://relay.example', {}),
    /malformed response/
  )
})
