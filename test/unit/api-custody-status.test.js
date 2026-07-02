import test from 'brittle'
import {
  buildCustodyStatusPayload,
  buildCustodyStatusRoutePayload,
  custodyStatusIntentId,
  detailedCustodyStatus,
  isCustodyStatusRoute,
  isDetailedCustodyStatusQuery,
  redactCustodyReceipt,
  redactCustodyStatus,
  resolveCustodyStatusRoute
} from '../../packages/core/core/relay-node/api-custody-status.js'

const INTENT_ID = 'a'.repeat(64)

function makeUrl (path) {
  return new URL(path, 'http://localhost')
}

function makeRegistry (status = {}) {
  const calls = []
  return {
    calls,
    getCustodyStatus (intentId) {
      calls.push(intentId)
      return { intentId, ...status }
    }
  }
}

test('api custody status: route helper validates registry and intent id before lookup', (t) => {
  t.alike(buildCustodyStatusRoutePayload({
    path: `/api/custody/${INTENT_ID}/status`,
    url: makeUrl(`/api/custody/${INTENT_ID}/status`),
    registry: null
  }), {
    status: 503,
    payload: { error: 'Registry not running' }
  })

  const registry = makeRegistry()
  t.alike(buildCustodyStatusRoutePayload({
    path: '/api/custody/not-hex/status',
    url: makeUrl('/api/custody/not-hex/status'),
    registry
  }), {
    status: 400,
    payload: { error: 'intentId must be 64 hex characters' }
  })
  t.alike(registry.calls, [])
})

test('api custody status: disabled profile rejects before registry lookup', (t) => {
  const result = buildCustodyStatusRoutePayload({
    path: `/api/custody/${INTENT_ID}/status`,
    url: makeUrl(`/api/custody/${INTENT_ID}/status`),
    disabled: true,
    registry: {
      getCustodyStatus () {
        t.fail('disabled custody status must not reach registry')
      }
    }
  })

  t.is(result.ok, false)
  t.is(result.kind, 'disabled-profile')
  t.is(result.status, 409)
  t.ok(result.payload.error.startsWith('not-enabled: '), 'status read returns formatted disabled-profile error')
})

test('api custody status: route helper builds public and detailed payloads', (t) => {
  const registry = makeRegistry({
    receipts: [{ relayPubkey: 'b'.repeat(64), shareIndex: 1, relayRegion: 'secret-region' }],
    pvss: { shareScheme: 'pvss-secp256k1-v1' }
  })

  const publicResult = buildCustodyStatusRoutePayload({
    path: `/api/custody/${INTENT_ID}/status`,
    url: makeUrl(`/api/custody/${INTENT_ID}/status`),
    registry
  })
  t.absent(publicResult.requiresAuth)
  t.is(publicResult.intentId, INTENT_ID)
  t.is(publicResult.status || 200, 200)
  t.absent(Object.prototype.hasOwnProperty.call(publicResult.payload, 'pvss'))
  t.absent(Object.prototype.hasOwnProperty.call(publicResult.payload.receipts[0], 'relayRegion'))

  const detailedResult = buildCustodyStatusRoutePayload({
    path: `/api/custody/${INTENT_ID}/status`,
    url: makeUrl(`/api/custody/${INTENT_ID}/status?detailed=true`),
    registry
  })
  t.is(detailedResult.requiresAuth, true)
  t.is(detailedResult.authMessage, 'Unauthorized — API key required for detailed custody status')
  t.is(detailedResult.payload.pvss.shareScheme, 'pvss-secp256k1-v1')
  t.alike(registry.calls, [INTENT_ID, INTENT_ID])
})

test('api custody status: route query helpers stay narrow', (t) => {
  t.alike(resolveCustodyStatusRoute('GET', `/api/custody/${INTENT_ID}/status`), {
    kind: 'custody-status'
  })
  t.is(resolveCustodyStatusRoute('POST', `/api/custody/${INTENT_ID}/status`), null)
  t.is(resolveCustodyStatusRoute('GET', '/api/custody/not-hex/commit'), null)
  t.is(isCustodyStatusRoute(`/api/custody/${INTENT_ID}/status`), true)
  t.is(isCustodyStatusRoute('/api/custody/not-hex/status'), true)
  t.is(isCustodyStatusRoute('/api/custody/not-hex/commit'), false)
  t.is(isCustodyStatusRoute('/api/v1/custody/not-hex/status'), false)
  t.is(custodyStatusIntentId(`/api/custody/${INTENT_ID}/status`), INTENT_ID)
  t.is(custodyStatusIntentId('/api/custody/not-hex/commit'), '')
  t.is(isDetailedCustodyStatusQuery(makeUrl('/api/custody/x/status?detailed=1')), true)
  t.is(isDetailedCustodyStatusQuery(makeUrl('/api/custody/x/status?detailed=true')), true)
  t.is(isDetailedCustodyStatusQuery(makeUrl('/api/custody/x/status?detailed=yes')), false)
})

test('api custody status: redacted receipts expose only public attestation fields', (t) => {
  const receipt = redactCustodyReceipt({
    relayPubkey: 'b'.repeat(64),
    shareIndex: 2,
    shareVerified: true,
    anchored: true,
    addressKey: '9'.repeat(64),
    blindContentId: 'c'.repeat(64),
    ciphertextRoot: '8'.repeat(64),
    relayRegion: 'us-test',
    signature: '7'.repeat(128)
  })

  t.alike(receipt, {
    relayPubkey: 'b'.repeat(64),
    shareIndex: 2,
    shareVerified: true,
    anchored: true
  })
  t.alike(Object.keys(receipt).sort(), ['anchored', 'relayPubkey', 'shareIndex', 'shareVerified'])
  t.absent(JSON.stringify(receipt).includes('9'.repeat(64)))
  t.absent(JSON.stringify(receipt).includes('8'.repeat(64)))
  t.absent(JSON.stringify(receipt).includes('7'.repeat(128)))
  t.absent(JSON.stringify(receipt).includes('us-test'))
})

test('api custody status: redacted status omits detailed intent proof and witness bodies', (t) => {
  const status = redactCustodyStatus({
    intentId: 'a'.repeat(64),
    blindContentId: 'c'.repeat(64),
    custodyMode: 'blind',
    requiredReplicas: 3,
    receiptCount: 1,
    quorumReached: true,
    receiptRoot: 'd'.repeat(64),
    relayQuorum: ['b'.repeat(64)],
    receipts: [{
      relayPubkey: 'b'.repeat(64),
      shareIndex: 1,
      shareVerified: true,
      anchored: true,
      addressKey: '9'.repeat(64),
      ciphertextRoot: '8'.repeat(64),
      signature: '7'.repeat(128)
    }],
    committed: true,
    sourceRetired: true,
    proofCount: 2,
    passingProofs: 1,
    nonServingProofCount: 1,
    nonServingRelays: ['b'.repeat(64)],
    expiryWitnessCount: 1,
    validExpiryWitnessCount: 1,
    expiryWitnessRelays: ['b'.repeat(64)],
    intent: { shareBundleKey: 'f'.repeat(64) },
    commit: { publisherSignature: 'e'.repeat(128) },
    proofs: [{ nonce: 'proof-secret' }],
    nonServingProofs: [{ signature: 'non-serving-secret' }],
    expiryWitnesses: [{ signature: 'witness-secret' }]
  })

  t.is(status.intentId, 'a'.repeat(64))
  t.is(status.receipts.length, 1)
  t.alike(Object.keys(status.receipts[0]).sort(), ['anchored', 'relayPubkey', 'shareIndex', 'shareVerified'])
  t.absent(Object.prototype.hasOwnProperty.call(status, 'intent'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'commit'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'proofs'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'nonServingProofs'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'expiryWitnesses'))
  t.absent(JSON.stringify(status).includes('shareBundleKey'))
  t.absent(JSON.stringify(status).includes('publisherSignature'))
  t.absent(JSON.stringify(status).includes('proof-secret'))
  t.absent(JSON.stringify(status).includes('non-serving-secret'))
  t.absent(JSON.stringify(status).includes('witness-secret'))
  t.absent(JSON.stringify(status).includes('7'.repeat(128)))
})

test('api custody status: detailed status preserves diagnostics without raw proof bodies', (t) => {
  const status = detailedCustodyStatus({
    intentId: 'a'.repeat(64),
    blindContentId: 'c'.repeat(64),
    custodyMode: 'blind',
    requiredReplicas: 3,
    receiptCount: 1,
    quorumReached: true,
    receiptRoot: 'd'.repeat(64),
    relayQuorum: ['b'.repeat(64)],
    receipts: [{
      relayPubkey: 'b'.repeat(64),
      shareIndex: 1,
      shareVerified: true,
      anchored: true,
      relayRegion: 'eu-west',
      receivedAt: 10,
      attestedAt: 20,
      addressKey: '9'.repeat(64),
      ciphertextRoot: '8'.repeat(64),
      signature: '7'.repeat(128)
    }],
    pvss: {
      shareScheme: 'pvss-secp256k1-v1',
      shareThreshold: 2,
      commitmentRoot: 'E'.repeat(64),
      shareIndices: [2, 1, 'bad']
    },
    committed: true,
    sourceRetired: false,
    commitPendingReason: 'waiting for receipts',
    sourceRetirementPendingReason: 'bad\nreason',
    intent: { shareBundleKey: 'f'.repeat(64) },
    commit: { publisherSignature: 'e'.repeat(128) },
    proofs: [{ nonce: 'proof-secret' }],
    nonServingProofs: [{ signature: 'non-serving-secret' }],
    expiryWitnesses: [{ signature: 'witness-secret' }]
  })

  t.is(status.committed, true)
  t.is(status.sourceRetired, false)
  t.is(status.commitPendingReason, 'waiting for receipts')
  t.is(status.sourceRetirementPendingReason, null)
  t.alike(status.pvss, {
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: 2,
    commitmentRoot: 'e'.repeat(64),
    shareIndices: [2, 1]
  })
  t.alike(status.receipts[0], {
    relayPubkey: 'b'.repeat(64),
    shareIndex: 1,
    shareVerified: true,
    anchored: true,
    relayRegion: 'eu-west',
    receivedAt: 10,
    attestedAt: 20
  })
  t.absent(Object.prototype.hasOwnProperty.call(status, 'intent'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'commit'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'proofs'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'nonServingProofs'))
  t.absent(Object.prototype.hasOwnProperty.call(status, 'expiryWitnesses'))
  const json = JSON.stringify(status)
  for (const hidden of ['shareBundleKey', 'publisherSignature', 'proof-secret', 'non-serving-secret', 'witness-secret', '7'.repeat(128), '9'.repeat(64), '8'.repeat(64)]) {
    t.absent(json.includes(hidden), hidden + ' omitted from detailed custody status')
  }
})

test('api custody status: missing or malformed fields normalize to stable defaults', (t) => {
  t.alike(buildCustodyStatusPayload({ receipts: [] }), redactCustodyStatus({ receipts: [] }))
  t.alike(buildCustodyStatusPayload({ receipts: [] }, { detailed: true }), detailedCustodyStatus({ receipts: [] }))

  t.alike(redactCustodyReceipt({ shareIndex: '2' }), {
    relayPubkey: null,
    shareIndex: null,
    shareVerified: false,
    anchored: false
  })

  t.alike(redactCustodyStatus({ receipts: 'not-array', relayQuorum: 'not-array' }), {
    intentId: null,
    blindContentId: null,
    custodyMode: 'blind',
    requiredReplicas: 0,
    receiptCount: 0,
    quorumReached: false,
    receiptRoot: null,
    relayQuorum: [],
    receipts: [],
    committed: false,
    sourceRetired: false,
    proofCount: 0,
    passingProofs: 0,
    nonServingProofCount: 0,
    nonServingRelays: [],
    expiryWitnessCount: 0,
    validExpiryWitnessCount: 0,
    expiryWitnessRelays: []
  })
})
