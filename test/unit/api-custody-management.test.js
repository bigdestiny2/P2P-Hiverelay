import test from 'brittle'
import {
  resolveOperatorCustodyRoute,
  resolvePublisherCustodyRoute,
  runOperatorCustodyAction,
  runOperatorCustodyRouteAction,
  runPublisherCustodyAction,
  runPublisherCustodyRouteAction
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

test('api custody management: operator route resolver preserves auth messages and path ids', (t) => {
  t.alike(resolveOperatorCustodyRoute('POST', '/api/custody/intent'), {
    action: 'intent',
    intentId: null,
    authMessage: 'Unauthorized — API key required for /api/custody/intent'
  })

  t.alike(resolveOperatorCustodyRoute('POST', `/api/custody/${INTENT_ID}/commit`), {
    action: 'commit',
    intentId: INTENT_ID,
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/commit'
  })

  t.alike(resolveOperatorCustodyRoute('POST', `/api/custody/${INTENT_ID}/source-retired`), {
    action: 'source-retired',
    intentId: INTENT_ID,
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/source-retired'
  })

  t.alike(resolveOperatorCustodyRoute('POST', '/api/custody/proof'), {
    action: 'proof',
    intentId: null,
    authMessage: 'Unauthorized — API key required for /api/custody/proof'
  })

  t.alike(resolveOperatorCustodyRoute('POST', `/api/custody/${INTENT_ID}/witness`), {
    action: 'witness',
    intentId: INTENT_ID,
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/witness'
  })

  t.alike(resolveOperatorCustodyRoute('POST', '/api/custody/not-hex/non-serving-proof'), {
    action: 'non-serving-proof',
    intentId: 'not-hex',
    authMessage: 'Unauthorized — API key required for /api/custody/:intentId/non-serving-proof'
  })

  t.is(resolveOperatorCustodyRoute('GET', '/api/custody/intent'), null)
  t.is(resolveOperatorCustodyRoute('POST', '/api/custody'), null)
  t.is(resolveOperatorCustodyRoute('POST', '/api/v1/custody/intent'), null)
})

test('api custody management: publisher route resolver keeps signed custody route scope narrow', (t) => {
  t.alike(resolvePublisherCustodyRoute('POST', '/api/v1/custody/intent'), {
    action: 'intent',
    intentId: null
  })

  t.alike(resolvePublisherCustodyRoute('POST', `/api/v1/custody/${INTENT_ID}/commit`), {
    action: 'commit',
    intentId: INTENT_ID,
    authMessage: null
  })

  t.alike(resolvePublisherCustodyRoute('POST', '/api/v1/custody/not-hex/source-retired'), {
    action: 'source-retired',
    intentId: 'not-hex',
    authMessage: null
  })

  t.is(resolvePublisherCustodyRoute('GET', '/api/v1/custody/intent'), null)
  t.is(resolvePublisherCustodyRoute('POST', '/api/custody/intent'), null)
  t.is(resolvePublisherCustodyRoute('POST', '/api/v1/custody/proof'), null)
})

test('api custody management: route action helpers keep operator and publisher signer boundaries separate', async (t) => {
  const node = makeNode()

  const operator = await runOperatorCustodyRouteAction({
    route: { action: 'commit', intentId: INTENT_ID },
    body: { receiptRoot: 'b'.repeat(64) },
    node
  })
  const publisher = await runPublisherCustodyRouteAction({
    route: { action: 'source-retired', intentId: INTENT_ID },
    body: { signature: 'sig' },
    node
  })
  const unknownOperator = await runOperatorCustodyRouteAction({ route: null, node })
  const unknownPublisher = await runPublisherCustodyRouteAction({ route: null, node })

  t.alike(operator.payload, { ok: true, type: 'custody-commit', intentId: INTENT_ID })
  t.alike(publisher.payload, { ok: true, type: 'source-retired', intentId: INTENT_ID })
  t.is(node.calls[0][0], 'commit')
  t.is(node.calls[0][2], node.swarm.keyPair, 'operator route action signs with relay keypair')
  t.is(node.calls[1][0], 'source-retired')
  t.is(node.calls[1][2], null, 'publisher route action refuses relay-side signing fallback')
  t.is(unknownOperator.status, 404)
  t.alike(unknownOperator.payload, { error: 'unknown operator custody route' })
  t.is(unknownPublisher.status, 404)
  t.alike(unknownPublisher.payload, { error: 'unknown publisher custody route' })
})

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

test('api custody management: disabled profile rejects operator and publisher actions before runtime access', async (t) => {
  const node = {
    swarm: {
      get keyPair () {
        t.fail('disabled custody action must not read relay signer')
      }
    },
    seedingRegistry: {
      async publishCustodyIntent () {
        t.fail('disabled custody action must not mutate registry')
      },
      async publishCustodyCommit () {
        t.fail('disabled custody action must not publish custody commit')
      }
    },
    async createCustodyNonServingProof () {
      t.fail('disabled custody action must not create non-serving proof')
    }
  }

  const operator = await runOperatorCustodyAction({
    action: 'intent',
    body: {},
    node,
    disabled: true
  })
  t.is(operator.ok, false)
  t.is(operator.kind, 'disabled-profile')
  t.is(operator.status, 409)
  t.ok(operator.payload.error.startsWith('not-enabled: '), 'operator action returns formatted disabled-profile error')

  const publisher = await runPublisherCustodyAction({
    action: 'commit',
    body: {},
    intentId: 'not-hex',
    node,
    disabled: true
  })
  t.is(publisher.ok, false)
  t.is(publisher.kind, 'disabled-profile')
  t.is(publisher.status, 409)
  t.ok(publisher.payload.error.startsWith('not-enabled: '), 'publisher action returns formatted disabled-profile error')
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
