import test from 'brittle'
import sodium from 'sodium-universal'
import {
  CATALOG_CURSOR_EXPIRED,
  CATALOG_FILTER_UNAVAILABLE,
  CATALOG_LIMIT_AMBIGUOUS,
  CATALOG_TYPE_ERROR,
  RELAY_CATALOG_PAGE_SIZE_MAX,
  buildCatalogReadRoutePayload,
  buildGatewayCatalogPayload,
  buildRelayCatalogPayload,
  catalogEntriesByType,
  resolveCatalogReadRoute
} from 'p2p-hiverelay/core/relay-node/api-catalog-read.js'
import {
  createAppCatalogExternalCursor,
  createCanonicalCatalogRow
} from 'p2p-hiverelay/core/relay-node/app-catalog-paged.js'

const TEST_KEY_PAIR = {
  publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
  secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
}
sodium.crypto_sign_seed_keypair(TEST_KEY_PAIR.publicKey, TEST_KEY_PAIR.secretKey, Buffer.alloc(32, 7))

const SNAPSHOT = Object.freeze({
  snapshotId: 'a'.repeat(64),
  highWater: 7,
  rootDigest: 'b'.repeat(64),
  entryCount: 0,
  senderPubkey: TEST_KEY_PAIR.publicKey.toString('hex')
})

function cursorAfter (lastRowKey) {
  return createAppCatalogExternalCursor({
    highWater: SNAPSHOT.highWater,
    rootDigest: SNAPSHOT.rootDigest,
    lastRowKey
  }, TEST_KEY_PAIR)
}

function canonicalRow (entry) {
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
    seededAt: entry.seededAt || null,
    redacted: false,
    metadataVisibility: 'public',
    blindContentId: null,
    anchored: entry.anchored === true,
    maxStorageBytes: entry.maxStorageBytes || null,
    publisherPubkey: entry.publisherPubkey || null,
    durability: entry.durability || 0,
    revocable: entry.revocable !== false,
    retainUntil: entry.retainUntil || null
  })
}

function nodeWithCatalog (entries, config = {}) {
  const rows = entries.map(canonicalRow)
  return {
    config,
    swarm: { keyPair: TEST_KEY_PAIR },
    appCatalogStore: {
      readExternalPage (opts) {
        nodeWithCatalog.lastReadOpts = opts
        const lastRowKey = opts.cursor?.lastRowKey || null
        const prior = lastRowKey === null ? -1 : rows.findIndex(row => row[0] === lastRowKey)
        const start = prior + 1
        const page = rows.slice(start, start + opts.limit)
        const complete = start + page.length >= rows.length
        return {
          snapshot: { ...SNAPSHOT, entryCount: rows.length },
          entries: page,
          complete,
          cursor: complete ? null : cursorAfter(page[page.length - 1][0])
        }
      }
    },
    federation: {
      snapshot () {
        return { followed: [{ url: 'https://relay.example' }], mirrored: [] }
      }
    },
    _resolveAcceptMode () {
      return 'review'
    }
  }
}

test('api catalog read: route helper maps exact public catalog reads', (t) => {
  t.alike(resolveCatalogReadRoute('GET', '/catalog.json'), {
    kind: 'catalog'
  })
  t.alike(resolveCatalogReadRoute('GET', '/api/apps'), {
    kind: 'legacy-type',
    type: 'app'
  })
  t.alike(resolveCatalogReadRoute('GET', '/api/drives'), {
    kind: 'legacy-type',
    type: 'drive'
  })

  t.is(resolveCatalogReadRoute('POST', '/catalog.json'), null)
  t.is(resolveCatalogReadRoute('GET', '/catalog.json/extra'), null)
  t.is(resolveCatalogReadRoute('GET', '/api/apps/extra'), null)
  t.is(resolveCatalogReadRoute('GET', '/api/resources'), null)
})

test('api catalog read: route payload helper dispatches catalog and legacy typed routes', (t) => {
  const entries = [
    { appKey: '1'.repeat(64), type: 'app', name: 'App One' },
    { appKey: '2'.repeat(64), type: 'drive', name: 'Drive One' },
    { appKey: '3'.repeat(64), type: 'drive', name: 'Drive Two' }
  ]
  const node = nodeWithCatalog(entries)

  const catalog = buildCatalogReadRoutePayload({
    route: { kind: 'catalog' },
    node,
    url: new URL('http://relay.local/catalog.json?type=drive&limit=2')
  })
  const legacy = buildCatalogReadRoutePayload({
    route: { kind: 'legacy-type', type: 'drive' },
    node,
    url: new URL('http://relay.local/api/drives?limit=3')
  })
  const unknown = buildCatalogReadRoutePayload({
    route: { kind: 'unknown' },
    node,
    url: new URL('http://relay.local/catalog.json')
  })

  t.is(catalog.ok, true)
  t.is(catalog.payload.filters.type, 'drive')
  t.is(catalog.payload.pagination.limit, 2)
  t.is(catalog.payload.drives[0].appKey, '2'.repeat(64))
  t.is(legacy.status, 200)
  t.alike(legacy.payload.entries.map(entry => entry.appKey), [
    '2'.repeat(64),
    '3'.repeat(64)
  ])
  t.is(legacy.payload.entryCount, 3)
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown catalog read route')
})

test('api catalog read: relay filters only the bounded source page and advances its cursor', (t) => {
  const parentKey = 'f'.repeat(64)
  const entries = [
    { appKey: '1'.repeat(64), type: 'app', name: 'Chat', categories: ['social'] },
    { appKey: '2'.repeat(64), type: 'drive', name: 'Root Drive', categories: ['files'] },
    { appKey: '3'.repeat(64), type: 'drive', name: 'Mounted Drive', parentKey, categories: ['files', 'ghost-drive'] },
    { appKey: '4'.repeat(64), type: 'dataset', name: 'Data', categories: ['research'] },
    { appKey: '5'.repeat(64), type: 'media', name: 'Clip', categories: ['video'] }
  ]
  const node = nodeWithCatalog(entries, {
    regions: ['EU'],
    operator: 'operator-a',
    custody: { redactedCatalog: true }
  })

  const result = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?type=drive&page=1&limit=2')
  })

  t.is(result.ok, true)
  t.is(result.payload.version, 3)
  t.is(result.payload.region, 'EU')
  t.is(result.payload.operator, 'operator-a')
  t.is(result.payload.filters.type, 'drive')
  t.is(result.payload.filters.category, null)
  t.is(result.payload.pagination.limit, 2)
  t.is(result.payload.pagination.complete, false)
  t.ok(result.payload.pagination.nextCursor)
  t.is(result.payload.entryCount, 5, 'entryCount is the unfiltered frozen snapshot total')
  t.alike(result.payload.pageCount, {
    total: 1,
    apps: 0,
    drives: 1,
    resources: 0,
    datasets: 0,
    media: 0
  })
  t.absent(Object.prototype.hasOwnProperty.call(result.payload, 'count'))
  t.is(result.payload.drives.length, 1, 'bounded source page contains root drive bucket')
  t.is(result.payload.resources.length, 0, 'resource bucket is not leaked from off-page entries')
  t.is(result.payload.federation.followed[0].url, 'https://relay.example')
  t.is(result.payload.federation.followed[0].pubkey, null)
  t.is(result.payload.federation.followed[0].addedAt, null)
  t.is(result.payload.acceptMode, 'review')
  t.is(nodeWithCatalog.lastReadOpts.limit, 2)
  t.is(nodeWithCatalog.lastReadOpts.status, false)

  const cursor = encodeURIComponent(JSON.stringify(result.payload.pagination.nextCursor))
  const nextPage = buildRelayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?type=drive&limit=1&cursor=${cursor}`)
  })
  t.is(nextPage.payload.resources.length, 1, 'the cursor resumes at the next source row')
  t.is(nextPage.payload.resources[0].appKey, '3'.repeat(64))

  const parentFilter = buildRelayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?parent=${parentKey}&limit=3`)
  })
  t.is(parentFilter.payload.entryCount, 5)
  t.is(parentFilter.payload.pageCount.total, 1)
  t.is(parentFilter.payload.resources[0].appKey, '3'.repeat(64))
})

test('api catalog read: category, offsets, and oversized limits fail before store access', (t) => {
  let calls = 0
  const node = nodeWithCatalog([])
  node.appCatalogStore.readExternalPage = () => {
    calls++
    throw new Error('must not read')
  }

  const category = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?category=files')
  })
  const offset = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?page=2')
  })
  const oversized = buildRelayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?limit=${RELAY_CATALOG_PAGE_SIZE_MAX + 1}`)
  })
  const ambiguous = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?limit=1&pageSize=1')
  })
  const malformedCursor = buildRelayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?cursor=${encodeURIComponent('{}')}`)
  })

  t.alike(category, {
    ok: false,
    status: 400,
    payload: { error: CATALOG_FILTER_UNAVAILABLE, filter: 'category' }
  })
  t.is(offset.status, 400)
  t.is(offset.payload.error, 'CATALOG_CURSOR_REQUIRED')
  t.is(oversized.status, 400)
  t.ok(/limit/.test(oversized.payload.error))
  t.alike(ambiguous, {
    ok: false,
    status: 400,
    payload: { error: CATALOG_LIMIT_AMBIGUOUS }
  })
  t.is(malformedCursor.status, 400)
  t.is(malformedCursor.payload.error, 'INVALID_CATALOG_CURSOR')
  t.is(calls, 0, 'invalid requests are rejected before MVCC store access')
})

test('api catalog read: an empty filtered page still returns the underlying next cursor', (t) => {
  const node = nodeWithCatalog([
    { appKey: '1'.repeat(64), type: 'app' },
    { appKey: '2'.repeat(64), type: 'drive' }
  ])
  const result = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?type=drive&limit=1')
  })

  t.is(result.ok, true)
  t.is(result.payload.entries.length, 0)
  t.is(result.payload.pagination.complete, false)
  t.ok(result.payload.pagination.nextCursor)
  t.is(result.payload.entryCount, 2)
})

test('api catalog read: relay catalog sanitizes top-level public metadata', (t) => {
  const node = nodeWithCatalog([], {
    regions: ['EU\u0000bad'],
    operator: 'operator\nsecret'
  })
  node._resolveAcceptMode = () => 'not-a-mode'

  const malformed = buildRelayCatalogPayload({
    node,
    relayKey: 'not-a-key',
    url: new URL('http://relay.local/catalog.json')
  })

  t.is(malformed.payload.relayKey, null)
  t.is(malformed.payload.region, null)
  t.is(malformed.payload.operator, null)
  t.is(malformed.payload.acceptMode, null)

  node.config = {
    regions: ['  NA  '],
    operator: '  operator-one  '
  }
  node._resolveAcceptMode = () => 'allowlist'
  const valid = buildRelayCatalogPayload({
    node,
    relayKey: 'A'.repeat(64),
    url: new URL('http://relay.local/catalog.json')
  })

  t.is(valid.payload.relayKey, 'a'.repeat(64))
  t.is(valid.payload.region, 'NA')
  t.is(valid.payload.operator, 'operator-one')
  t.is(valid.payload.acceptMode, 'allowlist')

  node.config.operator = 'x'.repeat(256)
  const truncated = buildRelayCatalogPayload({
    node,
    relayKey: 'b'.repeat(64),
    url: new URL('http://relay.local/catalog.json')
  })
  t.is(Buffer.byteLength(truncated.payload.operator, 'utf8'), 128)
})

test('api catalog read: invalid types are rejected instead of widening public catalog reads', (t) => {
  const node = nodeWithCatalog([{ appKey: '1'.repeat(64), type: 'app' }])
  const relay = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?type=unknown')
  })
  const gateway = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?type=unknown')
  })

  t.is(relay.ok, false)
  t.is(relay.status, 400)
  t.is(relay.payload.error, CATALOG_TYPE_ERROR)
  t.is(gateway.ok, false)
  t.is(gateway.status, 400)
  t.is(gateway.payload.error, CATALOG_TYPE_ERROR)
})

test('api catalog read: relay catalog sanitizes federation snapshot before public response', (t) => {
  const node = nodeWithCatalog([])
  node.federation = {
    snapshot () {
      return {
        followed: [
          { url: 'https://user:pass@secret.example', pubkey: 'a'.repeat(64), addedAt: 1, apiKey: 'leak' },
          { url: 'https://relay.example', pubkey: 'B'.repeat(64), addedAt: 2, apiKey: 'leak' }
        ],
        mirrored: [
          { url: 'https://mirror.example', pubkey: 'not-a-key', addedAt: -1, hidden: 'leak' }
        ],
        republished: [
          {
            appKey: 'c'.repeat(64),
            sourceUrl: 'https://source.example',
            sourcePubkey: 'D'.repeat(64),
            channel: 'stable',
            note: 'operator curated',
            privateKey: 'leak'
          }
        ],
        peerCatalogs: [
          {
            url: 'https://peer.example',
            pubkey: 'e'.repeat(64),
            region: 'EU\u0000bad',
            operator: 'operator-one',
            fetchedAt: 3,
            apps: [
              {
                appKey: 'f'.repeat(64),
                publisherPubkey: 'a'.repeat(64),
                type: 'drive',
                privacyTier: 'public',
                hidden: 'leak'
              }
            ],
            rawCatalog: 'leak'
          }
        ],
        secret: 'leak',
        running: true,
        followIntervalMs: 300000
      }
    }
  }

  const result = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json')
  })

  t.is(result.ok, true)
  t.alike(result.payload.federation.followed, [{
    url: 'https://relay.example',
    pubkey: 'b'.repeat(64),
    addedAt: 2
  }])
  t.alike(result.payload.federation.mirrored, [{
    url: 'https://mirror.example',
    pubkey: null,
    addedAt: null
  }])
  t.alike(result.payload.federation.republished, [{
    appKey: 'c'.repeat(64),
    sourceUrl: 'https://source.example',
    sourcePubkey: 'd'.repeat(64),
    channel: 'stable',
    note: 'operator curated',
    addedAt: null
  }])
  t.is(result.payload.federation.peerCatalogs[0].region, null)
  t.is(result.payload.federation.peerCatalogs[0].operator, 'operator-one')
  t.alike(result.payload.federation.peerCatalogs[0].apps[0], {
    appKey: 'f'.repeat(64),
    publisherPubkey: 'a'.repeat(64),
    type: 'drive',
    privacyTier: 'public',
    storageClass: null,
    availabilityClass: null,
    blind: false
  })
  const text = JSON.stringify(result.payload.federation)
  t.absent(text.includes('user:pass'))
  t.absent(text.includes('apiKey'))
  t.absent(text.includes('privateKey'))
  t.absent(text.includes('rawCatalog'))
  t.absent(text.includes('hidden'))
  t.absent(text.includes('secret'))
})

test('api catalog read: relaykernel profile omits federation snapshot', (t) => {
  const node = nodeWithCatalog([], {
    productProfile: 'relaykernel',
    federation: { enabled: false }
  })

  const result = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json')
  })

  t.is(result.ok, true)
  t.is(result.payload.federation, null)

  node.config = {}
  node.mode = 'relaykernel'
  const modeResult = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json')
  })
  t.is(modeResult.payload.federation, null)
})

test('api catalog read: gateway catalog exposes bounded MVCC metadata and catalogBeeKey', (t) => {
  const entries = [
    { appKey: '1'.repeat(64), type: 'app', name: 'App One' },
    { appKey: '2'.repeat(64), type: 'drive', name: 'Drive Two' },
    { appKey: '3'.repeat(64), type: 'dataset', name: 'Dataset Three' }
  ]
  const key = 'a'.repeat(64)
  const node = nodeWithCatalog(entries, { catalogBeeKey: key })

  const result = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?page=1&limit=3&type=drive')
  })

  t.is(result.ok, true)
  t.is(result.payload.items.length, 1)
  t.is(result.payload.items[0].appKey, '2'.repeat(64))
  t.is(result.payload.items[0].type, 'drive')
  t.absent(Object.prototype.hasOwnProperty.call(result.payload.items[0], 'name'))
  t.is(result.payload.limit, 3)
  t.is(result.payload.entryCount, 3)
  t.is(result.payload.complete, true)
  t.is(result.payload.cursor, null)
  t.alike(result.payload.snapshot, { ...SNAPSHOT, entryCount: 3 })
  t.is(result.payload.catalogBeeKey, key)
  t.is(nodeWithCatalog.lastReadOpts.status, true)

  node.config.catalogBeeKey = 'not-a-key'
  const invalidKey = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json')
  })
  t.absent(invalidKey.payload.catalogBeeKey, 'invalid catalogBeeKey is omitted')
})

test('api catalog read: redacted canonical rows never synthesize appKey from blindContentId', (t) => {
  const blindContentId = 'e'.repeat(64)
  const row = createCanonicalCatalogRow({
    appKey: null,
    appId: null,
    type: 'drive',
    parentKey: null,
    mountPath: null,
    version: null,
    discoveryKey: null,
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    privacyTier: 'p2p-only',
    seededAt: null,
    redacted: true,
    metadataVisibility: 'redacted',
    blindContentId,
    anchored: false,
    maxStorageBytes: null,
    publisherPubkey: null,
    durability: 0,
    revocable: true,
    retainUntil: null
  })
  const node = nodeWithCatalog([])
  node.appCatalogStore.readExternalPage = () => ({
    snapshot: { ...SNAPSHOT, entryCount: 1 },
    entries: [row],
    complete: true,
    cursor: null
  })

  const result = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json')
  })
  t.is(result.ok, true)
  t.is(result.payload.items[0].appKey, null)
  t.is(result.payload.items[0].blindContentId, blindContentId)
  t.is(result.payload.items[0].redacted, true)
})

test('api catalog read: legacy typed routes fail closed without an MVCC store', (t) => {
  t.alike(catalogEntriesByType({ node: {}, type: 'drive' }), {
    ok: false,
    status: 503,
    payload: { error: 'CATALOG_UNAVAILABLE' }
  })
  let catalogCalls = 0
  t.alike(catalogEntriesByType({
    node: {
      appRegistry: {
        catalog () {
          catalogCalls++
          return [{ appKey: 'f'.repeat(64), type: 'drive' }]
        }
      }
    },
    type: 'drive'
  }), {
    ok: false,
    status: 503,
    payload: { error: 'CATALOG_UNAVAILABLE' }
  })
  t.is(catalogCalls, 0, 'legacy full-catalog fallback is never invoked')

  const valid = catalogEntriesByType({
    node: nodeWithCatalog([
      { appKey: 'a'.repeat(64), type: 'app' },
      { appKey: 'b'.repeat(64), type: 'drive' }
    ]),
    type: 'drive'
  })
  t.is(valid.ok, true)
  t.alike(valid.payload.entries.map(entry => entry.appKey), ['b'.repeat(64)])
  t.is(valid.payload.entryCount, 2)
})

test('api catalog read: legacy typed routes use signed cursor envelopes', (t) => {
  const entries = []
  for (let i = 0; i < RELAY_CATALOG_PAGE_SIZE_MAX + 5; i++) {
    entries.push({ appKey: String(i).padStart(64, '0'), type: 'drive', name: 'Drive ' + i })
  }
  entries.push({ appKey: 'f'.repeat(64), type: 'app', name: 'Filtered App' })
  const node = nodeWithCatalog(entries)

  const first = catalogEntriesByType({ node, type: 'drive' })
  t.is(first.payload.entries.length, RELAY_CATALOG_PAGE_SIZE_MAX, 'default legacy response is capped')
  t.is(first.payload.entries[0].appKey, String(0).padStart(64, '0'))
  t.is(first.payload.entries[first.payload.entries.length - 1].appKey, String(RELAY_CATALOG_PAGE_SIZE_MAX - 1).padStart(64, '0'))
  t.ok(first.payload.cursor)

  const second = catalogEntriesByType({
    node,
    type: 'drive',
    url: new URL(`http://relay.local/api/drives?limit=3&cursor=${encodeURIComponent(JSON.stringify(first.payload.cursor))}`)
  })
  t.alike(second.payload.entries.map(entry => entry.appKey), [500, 501, 502].map(i => String(i).padStart(64, '0')))

  const offset = catalogEntriesByType({
    node,
    type: 'drive',
    url: new URL('http://relay.local/api/drives?page=2&limit=3')
  })
  t.is(offset.status, 400)
  t.is(offset.payload.error, 'CATALOG_CURSOR_REQUIRED')

  const oversized = catalogEntriesByType({
    node,
    type: 'drive',
    url: new URL('http://relay.local/api/drives?limit=501')
  })
  t.is(oversized.status, 400)

  t.is(catalogEntriesByType({ node, type: 'unknown' }).status, 400)
})

test('api catalog read: exact cursor objects reach the store and expiry is terminal 409', (t) => {
  const node = nodeWithCatalog([
    { appKey: '1'.repeat(64), type: 'app' },
    { appKey: '2'.repeat(64), type: 'drive' }
  ])
  const first = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?limit=1')
  })
  const cursor = first.payload.cursor
  const originalRead = node.appCatalogStore.readExternalPage
  let storeCalls = 0
  node.appCatalogStore.readExternalPage = (opts) => {
    storeCalls++
    return originalRead(opts)
  }
  const forged = { ...cursor, signature: '0'.repeat(128) }
  const rejected = buildGatewayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?cursor=${encodeURIComponent(JSON.stringify(forged))}`)
  })
  t.alike(rejected, {
    ok: false,
    status: 400,
    payload: { error: 'INVALID_CATALOG_CURSOR' }
  })
  t.is(storeCalls, 0, 'forged exact-shape cursor is rejected before store access')

  const second = buildGatewayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?limit=1&cursor=${encodeURIComponent(JSON.stringify(cursor))}`)
  })

  t.is(second.ok, true)
  t.is(storeCalls, 1)
  t.alike(nodeWithCatalog.lastReadOpts.cursor, cursor)
  t.is(second.payload.items[0].appKey, '2'.repeat(64))

  node.appCatalogStore.readExternalPage = () => {
    const err = new Error('history evicted')
    err.code = 'CURSOR_EXPIRED'
    throw err
  }
  const expired = buildGatewayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?cursor=${encodeURIComponent(JSON.stringify(cursor))}`)
  })
  t.alike(expired, {
    ok: false,
    status: 409,
    payload: { error: CATALOG_CURSOR_EXPIRED }
  })

  node.appCatalogStore.readExternalPage = () => {
    throw new Error('disk failed')
  }
  const failed = buildGatewayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?cursor=${encodeURIComponent(JSON.stringify(cursor))}`)
  })
  t.alike(failed, {
    ok: false,
    status: 503,
    payload: { error: 'CATALOG_UNAVAILABLE' }
  })

  node.appCatalogStore.readExternalPage = () => {
    const err = new Error('not published')
    err.code = 'CURSOR_EXPIRED'
    throw err
  }
  const unpublished = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json')
  })
  t.alike(unpublished, {
    ok: false,
    status: 503,
    payload: { error: 'CATALOG_UNAVAILABLE' }
  })
})

test('api catalog read: gateway enforces the 200-row status cap before store access', (t) => {
  let calls = 0
  let seen = null
  const node = nodeWithCatalog([])
  node.appCatalogStore.readExternalPage = (opts) => {
    calls++
    seen = opts
    return { snapshot: SNAPSHOT, entries: [], complete: true, cursor: null }
  }
  const rejected = buildGatewayCatalogPayload({
    node,
    maxPageSize: 999,
    url: new URL('http://relay.local/catalog.json?limit=201')
  })
  t.is(rejected.status, 400)
  t.is(calls, 0)

  const accepted = buildGatewayCatalogPayload({
    node,
    maxPageSize: 999,
    url: new URL('http://relay.local/catalog.json?limit=200')
  })
  t.is(accepted.ok, true)
  t.is(seen.status, true)
  t.is(seen.limit, 200)
})
