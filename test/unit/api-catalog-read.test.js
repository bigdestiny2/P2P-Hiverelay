import test from 'brittle'
import {
  CATALOG_TYPE_ERROR,
  RELAY_CATALOG_PAGE_SIZE_MAX,
  buildGatewayCatalogPayload,
  buildRelayCatalogPayload,
  catalogEntriesByType
} from 'p2p-hiverelay/core/relay-node/api-catalog-read.js'

function nodeWithCatalog (entries, config = {}) {
  return {
    config,
    swarm: { keyPair: { publicKey: Buffer.alloc(32, 7) } },
    appRegistry: {
      catalog (opts) {
        nodeWithCatalog.lastCatalogOpts = opts
        return entries
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

test('api catalog read: relay catalog filters, counts, and paginates in one bounded helper', (t) => {
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
    url: new URL('http://relay.local/catalog.json?category=FILES&page=1&pageSize=1')
  })

  t.is(result.ok, true)
  t.is(result.payload.region, 'EU')
  t.is(result.payload.operator, 'operator-a')
  t.is(result.payload.filters.category, 'FILES')
  t.is(result.payload.pagination.pageSize, 1)
  t.is(result.payload.pagination.total, 2)
  t.is(result.payload.pagination.hasNext, true)
  t.alike(result.payload.count, {
    total: 2,
    apps: 0,
    drives: 1,
    resources: 1,
    datasets: 0,
    media: 0
  })
  t.is(result.payload.drives.length, 1, 'first page contains root drive bucket')
  t.is(result.payload.resources.length, 0, 'resource bucket is not leaked from off-page entries')
  t.is(result.payload.federation.followed[0].url, 'https://relay.example')
  t.is(result.payload.federation.followed[0].pubkey, null)
  t.is(result.payload.federation.followed[0].addedAt, null)
  t.is(result.payload.acceptMode, 'review')
  t.alike(nodeWithCatalog.lastCatalogOpts, { redactPrivate: true })

  const secondPage = buildRelayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?category=FILES&page=2&pageSize=1')
  })
  t.is(secondPage.payload.resources.length, 1, 'second page contains mounted drive bucket')

  const parentFilter = buildRelayCatalogPayload({
    node,
    url: new URL(`http://relay.local/catalog.json?parent=${parentKey}`)
  })
  t.is(parentFilter.payload.pagination.total, 1)
  t.is(parentFilter.payload.resources[0].appKey, '3'.repeat(64))
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
  const node = nodeWithCatalog([{ type: 'app' }])
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

test('api catalog read: gateway catalog keeps its legacy shape and valid catalogBeeKey advertisement', (t) => {
  const entries = [
    { appKey: '1'.repeat(64), type: 'app', name: 'App One' },
    { appKey: '2'.repeat(64), type: 'drive', name: 'Drive Two' },
    { appKey: '3'.repeat(64), type: 'dataset', name: 'Dataset Three' }
  ]
  const key = 'a'.repeat(64)
  const node = nodeWithCatalog(entries, { catalogBeeKey: key })

  const result = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json?page=2abc&pageSize=1e2&type=drive')
  })

  t.is(result.ok, true)
  t.alike(result.payload.items, [{ appKey: '2'.repeat(64), type: 'drive', name: 'Drive Two' }])
  t.is(result.payload.page, 1, 'malformed page falls back to default')
  t.is(result.payload.pageSize, 50, 'malformed pageSize falls back to default')
  t.is(result.payload.total, 1)
  t.is(result.payload.hasMore, false)
  t.is(result.payload.catalogBeeKey, key)

  node.config.catalogBeeKey = 'not-a-key'
  const invalidKey = buildGatewayCatalogPayload({
    node,
    url: new URL('http://relay.local/catalog.json')
  })
  t.absent(invalidKey.payload.catalogBeeKey, 'invalid catalogBeeKey is omitted')
})

test('api catalog read: legacy type arrays tolerate missing or malformed registries', (t) => {
  t.alike(catalogEntriesByType({ node: {}, type: 'drive' }), [])
  t.alike(catalogEntriesByType({
    node: {
      appRegistry: {
        catalog () {
          return { not: 'an array' }
        }
      }
    },
    type: 'drive'
  }), [])

  t.alike(catalogEntriesByType({
    node: nodeWithCatalog([
      { appKey: 'a'.repeat(64), type: 'app' },
      { appKey: 'b'.repeat(64), type: 'drive' }
    ]),
    type: 'drive'
  }), [{ appKey: 'b'.repeat(64), type: 'drive' }])
})

test('api catalog read: legacy type arrays are bounded and paginated', (t) => {
  const entries = []
  for (let i = 0; i < RELAY_CATALOG_PAGE_SIZE_MAX + 5; i++) {
    entries.push({ appKey: String(i).padStart(64, '0'), type: 'drive', name: 'Drive ' + i })
  }
  entries.push({ appKey: 'f'.repeat(64), type: 'app', name: 'Filtered App' })
  const node = nodeWithCatalog(entries)

  const first = catalogEntriesByType({ node, type: 'drive' })
  t.is(first.length, RELAY_CATALOG_PAGE_SIZE_MAX, 'default legacy response is capped')
  t.is(first[0].name, 'Drive 0')
  t.is(first[first.length - 1].name, 'Drive ' + (RELAY_CATALOG_PAGE_SIZE_MAX - 1))

  const second = catalogEntriesByType({
    node,
    type: 'drive',
    url: new URL('http://relay.local/api/drives?page=2&pageSize=3')
  })
  t.alike(second.map(entry => entry.name), ['Drive 3', 'Drive 4', 'Drive 5'])

  const malformed = catalogEntriesByType({
    node,
    type: 'drive',
    url: new URL('http://relay.local/api/drives?page=bad&pageSize=999999')
  })
  t.is(malformed.length, RELAY_CATALOG_PAGE_SIZE_MAX, 'malformed/oversized legacy query falls back to bounded defaults')

  t.alike(catalogEntriesByType({ node, type: 'unknown' }), [])
})
