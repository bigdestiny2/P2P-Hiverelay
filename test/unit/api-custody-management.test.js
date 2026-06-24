import test from 'brittle'
import {
  runOperatorCustodyAction,
  runPublisherCustodyAction
} from '../../packages/core/core/relay-node/api-custody-management.js'

const INTENT_ID = 'a'.repeat(64)

function makeNode () {
  const calls = []
  const keyPair = { publicKey: Buffer.alloc(32, 1) }
  const node = {
    swarm: { keyPair },
    calls,
    seedingRegistry: {
      async publishCustodyIntent (body, signer) {
        calls.push(['intent', body, signer])
        return { type: 'custody-intent', intentId: body.intentId || INTENT_ID }
      },
      async publishCustodyCommit (body, signer) {
        calls.push(['commit', body, signer])
        return { type: 'custody-commit', intentId: body.intentId }
      },
      async publishSourceRetired (body, signer) {
        calls.push(['source-retired', body, signer])
        return { type: 'source-retired', intentId: body.intentId }
      },
      async recordCustodyProof (body, signer) {
        calls.push(['proof', body, signer])
        return { type: 'custody-proof', proof: body.proof }
      },
      async recordCustodyExpiryWitness (body, signer) {
        calls.push(['witness', body, signer])
        return { type: 'custody-expiry-witness', intentId: body.intentId }
      }
    },
    async createCustodyNonServingProof (intentId, body) {
      calls.push(['non-serving-proof', { ...body, intentId }])
      return { type: 'custody-non-serving-proof', intentId }
    }
  }
  return node
}

test('api custody management: operator routes preserve readiness and validation order', async (t) => {
  let out = await runOperatorCustodyAction({
    action: 'intent',
    body: {},
    node: { seedingRegistry: null }
  })
  t.is(out.status, 503)
  t.alike(out.payload, { error: 'Registry not running' })

  out = await runOperatorCustodyAction({
    action: 'intent',
    body: {},
    node: { seedingRegistry: {}, swarm: null }
  })
  t.is(out.status, 503)
  t.alike(out.payload, { error: 'Relay keypair unavailable' })

  out = await runOperatorCustodyAction({
    action: 'commit',
    body: {},
    intentId: 'bad-id',
    node: { seedingRegistry: null }
  })
  t.is(out.status, 503, 'commit checks registry readiness before route id shape')
  t.alike(out.payload, { error: 'Registry not running' })

  out = await runOperatorCustodyAction({
    action: 'witness',
    body: {},
    intentId: 'bad-id',
    node: { seedingRegistry: null }
  })
  t.is(out.status, 400, 'witness rejects malformed route ids before registry access')
  t.alike(out.payload, { error: 'intentId must be 64 hex characters' })

  out = await runOperatorCustodyAction({
    action: 'witness',
    body: {},
    intentId: INTENT_ID,
    node: { seedingRegistry: null }
  })
  t.is(out.status, 503)
  t.alike(out.payload, { error: 'registry not running' })
})

test('api custody management: operator actions call registry with relay keypair', async (t) => {
  const node = makeNode()

  let out = await runOperatorCustodyAction({
    action: 'intent',
    body: { intentId: INTENT_ID },
    node
  })
  t.alike(out.payload, { ok: true, type: 'custody-intent', intentId: INTENT_ID })

  out = await runOperatorCustodyAction({
    action: 'commit',
    body: { receiptRoot: 'b'.repeat(64) },
    intentId: INTENT_ID,
    node
  })
  t.alike(out.payload, { ok: true, type: 'custody-commit', intentId: INTENT_ID })

  out = await runOperatorCustodyAction({
    action: 'source-retired',
    body: { retiredAtVersion: 7 },
    intentId: INTENT_ID,
    node
  })
  t.alike(out.payload, { ok: true, type: 'source-retired', intentId: INTENT_ID })

  out = await runOperatorCustodyAction({
    action: 'proof',
    body: { proof: 'ok' },
    node
  })
  t.alike(out.payload, { ok: true, type: 'custody-proof', proof: 'ok' })

  out = await runOperatorCustodyAction({
    action: 'witness',
    body: { observedCatalog: false },
    intentId: INTENT_ID,
    node
  })
  t.alike(out.payload, { type: 'custody-expiry-witness', intentId: INTENT_ID })

  out = await runOperatorCustodyAction({
    action: 'non-serving-proof',
    body: { reason: 'expired' },
    intentId: INTENT_ID,
    node
  })
  t.alike(out.payload, { ok: true, type: 'custody-non-serving-proof', intentId: INTENT_ID })

  t.is(node.calls.length, 6)
  for (const call of node.calls.slice(0, 5)) {
    t.is(call[2], node.swarm.keyPair, call[0] + ' uses relay keypair')
  }
  t.is(node.calls[1][1].receiptRoot, 'b'.repeat(64))
  t.is(node.calls[2][1].retiredAtVersion, 7)
  t.is(node.calls[4][1].observedCatalog, false)
})

test('api custody management: non-serving proof keeps conflict status mapping', async (t) => {
  const node = {
    async createCustodyNonServingProof () {
      throw new Error('STILL_SERVING: catalog entry is still present')
    }
  }

  const out = await runOperatorCustodyAction({
    action: 'non-serving-proof',
    body: {},
    intentId: INTENT_ID,
    node
  })

  t.is(out.status, 409)
  t.alike(out.payload, { error: 'STILL_SERVING: catalog entry is still present' })
})

test('api custody management: publisher routes require signatures and pass null signer', async (t) => {
  const node = makeNode()

  let out = await runPublisherCustodyAction({
    action: 'intent',
    body: {},
    node
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'signature required (entry must be publisher-signed; see custody-signing.createCustodyIntent)' })

  out = await runPublisherCustodyAction({
    action: 'commit',
    body: { signature: 'sig' },
    intentId: 'bad-id',
    node
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'intentId must be 64 hex characters' })

  out = await runPublisherCustodyAction({
    action: 'commit',
    body: {},
    intentId: INTENT_ID,
    node
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'signature required (entry must be publisher-signed)' })

  out = await runPublisherCustodyAction({
    action: 'intent',
    body: { intentId: INTENT_ID, signature: 'sig' },
    node
  })
  t.alike(out.payload, { ok: true, type: 'custody-intent', intentId: INTENT_ID })

  out = await runPublisherCustodyAction({
    action: 'source-retired',
    body: { signature: 'sig' },
    intentId: INTENT_ID,
    node
  })
  t.alike(out.payload, { ok: true, type: 'source-retired', intentId: INTENT_ID })

  t.is(node.calls[0][2], null, 'publisher intent refuses relay-side signing fallback')
  t.is(node.calls[1][2], null, 'publisher source-retired refuses relay-side signing fallback')
})

test('api custody management: publisher registry errors stay delegated to custody error response', async (t) => {
  const persistError = new Error('The corestore is closed')
  const node = {
    seedingRegistry: {
      async publishCustodyIntent () {
        throw persistError
      }
    }
  }

  const out = await runPublisherCustodyAction({
    action: 'intent',
    body: { signature: 'sig' },
    node
  })

  t.is(out.ok, false)
  t.is(out.kind, 'custody-error')
  t.is(out.error, persistError)
})
