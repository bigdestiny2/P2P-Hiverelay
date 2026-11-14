import test from 'brittle'
import sodium from 'sodium-universal'
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
import {
  createAppCatalogExternalCursor,
  createCanonicalCatalogRow
} from '../../packages/core/core/relay-node/app-catalog-paged.js'

const TEST_KEY_PAIR = {
  publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
  secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
}
sodium.crypto_sign_seed_keypair(TEST_KEY_PAIR.publicKey, TEST_KEY_PAIR.secretKey, Buffer.alloc(32, 1))

const SNAPSHOT = Object.freeze({
  snapshotId: '1'.repeat(64),
  highWater: 9,
  rootDigest: '2'.repeat(64),
  entryCount: 0,
  senderPubkey: TEST_KEY_PAIR.publicKey.toString('hex')
})

function canonicalAnchorRow (entry) {
  return createCanonicalCatalogRow({
    appKey: entry.appKey,
    appId: entry.appId || null,
    type: entry.type,
    parentKey: entry.parentKey || null,
    mountPath: entry.mountPath || null,
    version: entry.version || null,
    discoveryKey: entry.discoveryKey || null,
    blind: entry.blind === true,
    storageClass: entry.storageClass || (entry.blind ? 'temporary' : 'persistent'),
    availabilityClass: entry.availabilityClass || (entry.blind ? 'atomic-handoff' : 'always-on'),
    privacyTier: entry.privacyTier || 'public',
    seededAt: null,
    redacted: false,
    metadataVisibility: 'public',
    blindContentId: null,
    anchored: entry.anchored === true,
    maxStorageBytes: null,
    publisherPubkey: null,
    durability: 0,
    revocable: true,
    retainUntil: null
  })
}

function nodeWithAnchorCatalog (entries) {
  const rows = entries.map(canonicalAnchorRow)
  const node = {
    swarm: { keyPair: TEST_KEY_PAIR },
    appCatalogStore: {
      readExternalPage (opts) {
        node.lastReadOpts = opts
        const page = rows.slice(0, opts.limit)
        return {
          snapshot: { ...SNAPSHOT, entryCount: rows.length },
          entries: page,
          complete: page.length === rows.length,
          cursor: page.length === rows.length
            ? null
            : createAppCatalogExternalCursor({
              highWater: SNAPSHOT.highWater,
              rootDigest: SNAPSHOT.rootDigest,
              lastRowKey: page[page.length - 1][0]
            }, TEST_KEY_PAIR)
        }
      }
    }
  }
  return node
}

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
    }
  }
  const node = nodeWithAnchorCatalog([{
    appKey: 'a'.repeat(64),
    type: 'drive',
    anchored: true
  }])

  const pub = buildAnchorStatusRoutePayload({
    route: { kind: 'anchor-status' },
    url: new URL('http://127.0.0.1/api/anchors'),
    appRegistry,
    lastCheckedAt: 42
  })
  const detailed = buildAnchorStatusRoutePayload({
    route: { kind: 'anchor-status' },
    url: new URL('http://127.0.0.1/api/anchors?detailed=true'),
    node,
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
  t.is(detailed.payload.pagination.limit, 200)
  t.is(detailed.payload.entryCount, 1)
  t.alike(detailed.payload.entrySchema, {
    version: 2,
    fields: ['appKey', 'type', 'anchored', 'blind', 'storageClass', 'availabilityClass'],
    omittedLegacyFields: ['anchoredAt', 'anchoredLength', 'custodyIntentId']
  })
  t.is(node.lastReadOpts.status, true)
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
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff'
  })
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'anchoredAt'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'anchoredLength'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'custodyIntentId'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'publisherPubkey'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'retainUntil'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'ciphertextRoot'))
  t.absent(Object.prototype.hasOwnProperty.call(entry, 'shareBundleKey'))
})

test('api anchor status: detailed payload maps only a bounded canonical snapshot page', (t) => {
  const appRegistry = {
    anchorStats () {
      return { total: 1, anchored: 0, unanchored: 1, neverChecked: 0 }
    }
  }
  const canonical = [{
    appKey: 'c'.repeat(64),
    type: 'app',
    anchored: false,
    blind: false
  }]
  const node = nodeWithAnchorCatalog(canonical)

  t.alike(anchorStatusEntries(canonical), [{
    appKey: 'c'.repeat(64),
    type: 'app',
    anchored: false,
    blind: false,
    storageClass: null,
    availabilityClass: null
  }])
  const result = buildAnchorStatusPayload({
    node,
    url: new URL('http://127.0.0.1/api/anchors?detailed=true&limit=1'),
    appRegistry,
    detailed: true
  })
  t.is(result.payload.entries.length, 1)
  t.is(result.payload.pagination.limit, 1)
  t.alike(result.payload.snapshot, { ...SNAPSHOT, entryCount: 1 })
  t.is(result.payload.entryCount, 1)
})

test('api anchor status: detailed cursor expiry is 409 and the 200-row cap is pre-store', (t) => {
  const appRegistry = {
    anchorStats () {
      return { total: 0, anchored: 0, unanchored: 0, neverChecked: 0 }
    }
  }
  const node = nodeWithAnchorCatalog([])
  let calls = 0
  node.appCatalogStore.readExternalPage = () => {
    calls++
    return { snapshot: SNAPSHOT, entries: [], complete: true, cursor: null }
  }
  const oversized = buildAnchorStatusPayload({
    node,
    url: new URL('http://127.0.0.1/api/anchors?detailed=true&limit=201'),
    appRegistry,
    detailed: true
  })
  t.is(oversized.status, 400)
  t.is(calls, 0)

  const cursor = createAppCatalogExternalCursor({
    highWater: 1,
    rootDigest: '5'.repeat(64),
    lastRowKey: '6'.repeat(64)
  }, TEST_KEY_PAIR)
  node.appCatalogStore.readExternalPage = () => {
    const err = new Error('expired')
    err.code = 'CURSOR_EXPIRED'
    throw err
  }
  const expired = buildAnchorStatusPayload({
    node,
    url: new URL(`http://127.0.0.1/api/anchors?detailed=true&cursor=${encodeURIComponent(JSON.stringify(cursor))}`),
    appRegistry,
    detailed: true
  })
  t.alike(expired, {
    ok: false,
    status: 409,
    payload: { error: 'CURSOR_EXPIRED' }
  })
})
