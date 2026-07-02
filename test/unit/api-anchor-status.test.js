import test from 'brittle'
import {
  anchorProofAppKeyFromPath,
  anchorStatusEntries,
  anchorStatusEntry,
  buildAnchorProofPayload,
  buildAnchorProofRoutePayload,
  buildAnchorStatusPayload,
  buildAnchorStatusRoutePayload,
  buildAnchorStatusRouteContext,
  isAnchorProofRoute,
  isDetailedAnchorStatusQuery,
  resolveAnchorProofRoute,
  resolveAnchorStatusRoute
} from '../../packages/core/core/relay-node/api-anchor-status.js'

test('api anchor status: detailed query parser is explicit', (t) => {
  t.ok(isDetailedAnchorStatusQuery('1'))
  t.ok(isDetailedAnchorStatusQuery('true'))
  t.absent(isDetailedAnchorStatusQuery('TRUE'))
  t.absent(isDetailedAnchorStatusQuery('0'))
  t.absent(isDetailedAnchorStatusQuery(null))
})

test('api anchor status: route helper maps exact aggregate read', (t) => {
  t.alike(resolveAnchorStatusRoute('GET', '/api/anchors'), {
    kind: 'anchor-status'
  })

  t.is(resolveAnchorStatusRoute('POST', '/api/anchors'), null)
  t.is(resolveAnchorStatusRoute('GET', '/api/anchors/extra'), null)
  t.is(resolveAnchorStatusRoute('GET', '/api/anchors/aaaaaaaa/proof'), null)
})

test('api anchor proof: route helpers isolate proof path parsing', async (t) => {
  const appKey = 'a'.repeat(64)
  const path = `/api/anchors/${appKey}/proof`
  const proof = { appKey, anchored: true }
  let calledWith = null

  t.ok(isAnchorProofRoute(path))
  t.ok(isAnchorProofRoute('/api/anchors/not-hex/proof'))
  t.absent(isAnchorProofRoute(`/api/anchors/${appKey}`))
  t.alike(resolveAnchorProofRoute('GET', path), { kind: 'anchor-proof' })
  t.is(resolveAnchorProofRoute('POST', path), null)
  t.is(resolveAnchorProofRoute('GET', `/api/anchors/${appKey}`), null)
  t.is(anchorProofAppKeyFromPath(path), appKey)
  t.is(anchorProofAppKeyFromPath('/api/anchors/not-hex/proof'), 'not-hex')
  t.is(anchorProofAppKeyFromPath('/api/anchors'), '')

  const result = await buildAnchorProofRoutePayload({
    path,
    node: {
      async createAnchorProof (key) {
        calledWith = key
        return proof
      }
    }
  })

  t.is(calledWith, appKey)
  t.alike(result, {
    ok: true,
    status: 200,
    payload: proof
  })

  t.alike(await buildAnchorProofRoutePayload({
    path: '/api/anchors/not-hex/proof',
    node: {
      async createAnchorProof () {
        t.fail('malformed route appKey must be rejected before proof generation')
      }
    }
  }), {
    ok: false,
    status: 400,
    payload: { error: 'invalid appKey' }
  })
})

test('api anchor status: route context owns detailed auth decision', (t) => {
  const detailed = buildAnchorStatusRouteContext(new URL('http://127.0.0.1/api/anchors?detailed=1'))
  t.alike(detailed, {
    detailed: true,
    requiresAuth: true
  })

  t.alike(buildAnchorStatusRouteContext(new URL('http://127.0.0.1/api/anchors?detailed=true')), {
    detailed: true,
    requiresAuth: true
  })

  t.alike(buildAnchorStatusRouteContext(new URL('http://127.0.0.1/api/anchors?detailed=TRUE')), {
    detailed: false,
    requiresAuth: false
  })

  t.alike(buildAnchorStatusRouteContext(null), {
    detailed: false,
    requiresAuth: false
  })
})

test('api anchor status: route payload helper dispatches aggregate status', (t) => {
  const appRegistry = {
    anchorStats () {
      return { total: 1, anchored: 1, unanchored: 0, neverChecked: 0 }
    },
    catalog () {
      return [{
        appKey: 'a'.repeat(64),
        type: 'drive',
        anchored: true,
        anchoredAt: 99,
        anchoredLength: 123
      }]
    }
  }

  const pub = buildAnchorStatusRoutePayload({
    route: { kind: 'anchor-status' },
    url: new URL('http://127.0.0.1/api/anchors'),
    appRegistry,
    lastCheckedAt: 42
  })
  const detailed = buildAnchorStatusRoutePayload({
    route: { kind: 'anchor-status' },
    url: new URL('http://127.0.0.1/api/anchors?detailed=true'),
    appRegistry,
    lastCheckedAt: 42
  })
  const contextOverride = buildAnchorStatusRoutePayload({
    route: { kind: 'anchor-status' },
    context: { detailed: false },
    url: new URL('http://127.0.0.1/api/anchors?detailed=true'),
    appRegistry,
    lastCheckedAt: 42
  })
  const unknown = buildAnchorStatusRoutePayload({
    route: { kind: 'unknown' },
    appRegistry
  })

  t.is(pub.ok, true)
  t.is(pub.payload.entries, null)
  t.is(pub.payload.lastCheckedAt, 42)
  t.is(detailed.ok, true)
  t.is(detailed.payload.entries.length, 1)
  t.is(detailed.payload.entries[0].appKey, 'a'.repeat(64))
  t.is(contextOverride.payload.entries, null)
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown anchor status route')
})

test('api anchor proof: valid appKey delegates to proof signer', async (t) => {
  const appKey = 'a'.repeat(64)
  const proof = {
    appKey,
    anchored: true,
    version: 7,
    attestedAt: 123,
    relayPubkey: 'b'.repeat(64),
    signature: 'c'.repeat(128)
  }

  let calledWith = null
  const result = await buildAnchorProofPayload({
    appKey,
    node: {
      async createAnchorProof (key) {
        calledWith = key
        return proof
      }
    }
  })

  t.is(calledWith, appKey)
  t.alike(result, {
    ok: true,
    status: 200,
    payload: proof
  })
})

test('api anchor proof: malformed appKey is rejected before proof generation', async (t) => {
  let called = false
  const result = await buildAnchorProofPayload({
    appKey: 'not-hex',
    node: {
      async createAnchorProof () {
        called = true
        return {}
      }
    }
  })

  t.absent(called)
  t.alike(result, {
    ok: false,
    status: 400,
    payload: { error: 'invalid appKey' }
  })
})

test('api anchor proof: unavailable or throwing signer returns stable payloads', async (t) => {
  const appKey = 'd'.repeat(64)

  t.alike(await buildAnchorProofPayload({ appKey }), {
    ok: false,
    status: 503,
    payload: { error: 'proof generation failed' }
  })

  t.alike(await buildAnchorProofPayload({
    appKey,
    node: {
      async createAnchorProof () {
        throw new Error('storage unavailable')
      }
    }
  }), {
    ok: false,
    status: 503,
    payload: { error: 'storage unavailable' }
  })

  t.alike(await buildAnchorProofPayload({
    appKey,
    node: {
      async createAnchorProof () {
        throw new Error('invalid appKey')
      }
    }
  }), {
    ok: false,
    status: 400,
    payload: { error: 'invalid appKey' }
  })
})

test('api anchor status: unavailable registry returns stable 503 payload', (t) => {
  t.alike(buildAnchorStatusPayload(), {
    ok: false,
    status: 503,
    payload: { error: 'anchor stats unavailable' }
  })
  t.alike(buildAnchorStatusPayload({ appRegistry: {} }), {
    ok: false,
    status: 503,
    payload: { error: 'anchor stats unavailable' }
  })
})

test('api anchor status: public payload keeps aggregate stats without entry details', (t) => {
  const appRegistry = {
    anchorStats () {
      return {
        total: 2,
        anchored: 1,
        unanchored: 1,
        neverChecked: 0,
        rawSchedulerState: 'should-not-leak'
      }
    },
    catalog () {
      t.fail('public anchor status must not enumerate catalog entries')
      return []
    }
  }

  t.alike(buildAnchorStatusPayload({
    appRegistry,
    lastCheckedAt: 12345
  }), {
    ok: true,
    status: 200,
    payload: {
      total: 2,
      anchored: 1,
      unanchored: 1,
      neverChecked: 0,
      lastCheckedAt: 12345,
      entries: null
    }
  })
  t.absent(JSON.stringify(buildAnchorStatusPayload({ appRegistry }).payload).includes('should-not-leak'))
})

test('api anchor status: malformed aggregate stats become bounded public counters', (t) => {
  const appRegistry = {
    anchorStats () {
      return {
        total: -1,
        anchored: 1.9,
        unanchored: Number.POSITIVE_INFINITY,
        neverChecked: '3'
      }
    }
  }

  t.alike(buildAnchorStatusPayload({
    appRegistry,
    lastCheckedAt: Number.POSITIVE_INFINITY
  }).payload, {
    total: 0,
    anchored: 1,
    unanchored: 0,
    neverChecked: 3,
    lastCheckedAt: null,
    entries: null
  })
})

test('api anchor status: detailed entries expose only custody diagnostics', (t) => {
  const entry = anchorStatusEntry({
    appKey: 'a'.repeat(64),
    type: 'drive',
    anchored: false,
    anchoredAt: null,
    anchoredLength: 0,
    custodyIntentId: 'b'.repeat(64),
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    publisherPubkey: 'secret-publisher',
    retainUntil: 999,
    ciphertextRoot: 'secret-ciphertext',
    shareBundleKey: 'secret-share-bundle'
  })

  t.alike(entry, {
    appKey: 'a'.repeat(64),
    type: 'drive',
    anchored: false,
    anchoredAt: null,
    anchoredLength: 0,
    custodyIntentId: 'b'.repeat(64),
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff'
  })
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'publisherPubkey'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'retainUntil'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'ciphertextRoot'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'shareBundleKey'))
})

test('api anchor status: detailed payload maps catalog through public helper', (t) => {
  const appRegistry = {
    anchorStats () {
      return { total: 1, anchored: 0, unanchored: 1, neverChecked: 0 }
    },
    catalog () {
      return [{
        appKey: 'c'.repeat(64),
        type: 'app',
        anchored: undefined,
        custodyIntentId: '',
        blind: false
      }]
    }
  }

  t.alike(anchorStatusEntries(appRegistry), [{
    appKey: 'c'.repeat(64),
    type: 'app',
    anchored: undefined,
    anchoredAt: undefined,
    anchoredLength: undefined,
    custodyIntentId: null,
    blind: false,
    storageClass: null,
    availabilityClass: null
  }])
  t.is(buildAnchorStatusPayload({ appRegistry, detailed: true }).payload.entries.length, 1)
})
