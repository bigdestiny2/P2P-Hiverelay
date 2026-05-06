/**
 * Client SDK custody methods — verify each method posts to the right
 * endpoint with the right body and headers, and surfaces relay errors.
 *
 * Mocks globalThis.fetch so we can assert on the wire format without a
 * real relay. Higher-level integration tests (observe-testnet) cover
 * the round-trip.
 */

import test from 'brittle'
import { HiveRelayClient } from 'p2p-hiverelay-client'

function withMockFetch (handler, fn) {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url, opts })
    return handler({ url, opts })
  }
  return fn(calls).finally(() => { globalThis.fetch = originalFetch })
}

function jsonResponse (body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body)
  }
}

test('client.publishCustodyIntent: POSTs intent to /api/custody/intent with API key', async (t) => {
  await withMockFetch(
    () => jsonResponse({ intentId: 'i-1', signature: 'sig' }),
    async (calls) => {
      const client = new HiveRelayClient()
      const result = await client.publishCustodyIntent(
        'http://relay.example:9100',
        { blindContentId: 'b-1', ciphertextRoot: 'c-1', requiredReplicas: 3 },
        { apiKey: 'test-key' }
      )
      t.is(result.intentId, 'i-1')
      t.is(calls.length, 1)
      t.is(calls[0].url, 'http://relay.example:9100/api/custody/intent')
      t.is(calls[0].opts.method, 'POST')
      // Server reads only Authorization: Bearer (api.js _checkAuth, line 248).
      // X-API-Key was the previous (broken) header — silently ignored.
      t.is(calls[0].opts.headers.Authorization, 'Bearer test-key')
      t.absent(calls[0].opts.headers['X-API-Key'], 'X-API-Key must NOT be set')
      const body = JSON.parse(calls[0].opts.body)
      t.is(body.blindContentId, 'b-1')
    }
  )
})

test('client.publishCustodyCommit: POSTs to /api/custody/<intentId>/commit', async (t) => {
  await withMockFetch(
    () => jsonResponse({ ok: true, signature: 'sig' }),
    async (calls) => {
      const client = new HiveRelayClient()
      await client.publishCustodyCommit('http://relay.example:9100', 'intent-id-123', {}, { apiKey: 'k' })
      t.is(calls[0].url, 'http://relay.example:9100/api/custody/intent-id-123/commit')
    }
  )
})

test('client.publishSourceRetired: POSTs to /api/custody/<intentId>/source-retired', async (t) => {
  await withMockFetch(
    () => jsonResponse({ ok: true }),
    async (calls) => {
      const client = new HiveRelayClient()
      await client.publishSourceRetired('http://relay.example:9100', 'intent-id-123', {}, { apiKey: 'k' })
      t.is(calls[0].url, 'http://relay.example:9100/api/custody/intent-id-123/source-retired')
    }
  )
})

test('client.recordCustodyProof: POSTs to /api/custody/proof', async (t) => {
  await withMockFetch(
    () => jsonResponse({ ok: true }),
    async (calls) => {
      const client = new HiveRelayClient()
      await client.recordCustodyProof('http://relay.example:9100', { relayPubkey: 'p', passed: true }, { apiKey: 'k' })
      t.is(calls[0].url, 'http://relay.example:9100/api/custody/proof')
    }
  )
})

test('client.recordCustodyNonServingProof: POSTs to /api/custody/<intentId>/non-serving-proof', async (t) => {
  await withMockFetch(
    () => jsonResponse({ ok: true }),
    async (calls) => {
      const client = new HiveRelayClient()
      await client.recordCustodyNonServingProof('http://relay.example:9100', 'i-1', {}, { apiKey: 'k' })
      t.is(calls[0].url, 'http://relay.example:9100/api/custody/i-1/non-serving-proof')
    }
  )
})

test('client.recordCustodyExpiryWitness: POSTs to /api/custody/<intentId>/witness', async (t) => {
  await withMockFetch(
    () => jsonResponse({ ok: true, signature: 'sig' }),
    async (calls) => {
      const client = new HiveRelayClient()
      await client.recordCustodyExpiryWitness(
        'http://relay.example:9100', 'i-1',
        { relayPubkey: 'r', nonServingProofHash: 'h' },
        { apiKey: 'k' }
      )
      t.is(calls[0].url, 'http://relay.example:9100/api/custody/i-1/witness')
      const body = JSON.parse(calls[0].opts.body)
      t.is(body.relayPubkey, 'r')
    }
  )
})

test('client.getCustodyStatus: GETs /api/custody/<intentId>/status', async (t) => {
  await withMockFetch(
    () => jsonResponse({ intentId: 'i-1', quorumReached: true, committed: true, receiptCount: 3 }),
    async (calls) => {
      const client = new HiveRelayClient()
      const status = await client.getCustodyStatus('http://relay.example:9100', 'i-1')
      t.is(status.committed, true)
      t.is(status.receiptCount, 3)
      t.is(calls[0].url, 'http://relay.example:9100/api/custody/i-1/status')
      t.is(calls[0].opts.method, 'GET')
    }
  )
})

test('client.getCustodyStatus: returns null on 404', async (t) => {
  await withMockFetch(
    () => jsonResponse({ error: 'not found' }, 404),
    async () => {
      const client = new HiveRelayClient()
      const status = await client.getCustodyStatus('http://relay.example:9100', 'unknown')
      t.is(status, null)
    }
  )
})

test('client.publishCustodyIntent: surfaces relay error body and status', async (t) => {
  await withMockFetch(
    () => jsonResponse({ error: 'invalid blindContentId' }, 400),
    async () => {
      const client = new HiveRelayClient()
      try {
        await client.publishCustodyIntent('http://relay.example:9100', { blindContentId: 'bad' }, { apiKey: 'k' })
        t.fail('should have thrown')
      } catch (err) {
        t.is(err.status, 400)
        t.ok(err.message.includes('invalid blindContentId'))
      }
    }
  )
})

test('client.publishCustodyIntent: throws on missing relayUrl', async (t) => {
  const client = new HiveRelayClient()
  try {
    await client.publishCustodyIntent('', {}, {})
    t.fail('should have thrown')
  } catch (err) {
    t.ok(err.message.includes('relayUrl required'))
  }
})
