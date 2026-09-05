import test from 'brittle'
import {
  MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST,
  MAX_REGISTRY_STATUS_REQUESTS,
  buildRegistryStatusPayload,
  buildRegistryStatusRoutePayload,
  resolveRegistryStatusRoute
} from 'p2p-hiverelay/core/relay-node/api-registry-status.js'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'

function requestEntry (appKey, overrides = {}) {
  return {
    type: 'seed-request',
    timestamp: 123,
    appKey,
    discoveryKeys: ['b'.repeat(64)],
    contentType: 'drive',
    parentKey: 'c'.repeat(64),
    mountPath: '/docs',
    replicationFactor: 3,
    geoPreference: ['EU'],
    maxStorageBytes: 1024,
    bountyRate: 7,
    ttlSeconds: 3600,
    privacyTier: 'public',
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    publisherPubkey: 'd'.repeat(64),
    publisherSignature: 'do-not-leak',
    delegationCert: { secret: 'do-not-leak' },
    ...overrides
  }
}

test('api registry status: route helper maps exact operator status route', (t) => {
  t.alike(resolveRegistryStatusRoute('GET', '/api/registry'), {
    kind: 'registry-status',
    authMessage: 'Unauthorized — API key required for /api/registry'
  })

  t.is(resolveRegistryStatusRoute('POST', '/api/registry'), null)
  t.is(resolveRegistryStatusRoute('GET', '/api/registry/extra'), null)
  t.is(resolveRegistryStatusRoute('GET', '/api/registries'), null)
})

test('api registry status: missing registry reports unavailable', async (t) => {
  const out = await buildRegistryStatusPayload()
  t.is(out.status, 503)
  t.alike(out.payload, { error: 'Registry not running' })
})

test('api registry status: route payload helper dispatches operator status reads', async (t) => {
  const requests = [
    requestEntry('A'.repeat(64)),
    requestEntry('B'.repeat(64))
  ]
  let activeRequests = 0
  let relayLookups = 0

  const result = await buildRegistryStatusRoutePayload({
    route: resolveRegistryStatusRoute('GET', '/api/registry'),
    registry: {
      key: Buffer.alloc(32, 2),
      advanceRequestStatusSnapshot () {
        activeRequests++
        return { complete: true }
      },
      requestStatusSnapshot () {
        return { activeRequests: requests.length, requests, completedHighWater: 2, completedAt: 456 }
      },
      async getRelaysForApp () {
        relayLookups++
        return [{ relayPubkey: 'C'.repeat(64), region: 'EU' }]
      }
    },
    maxRequests: 1,
    maxRelaysPerRequest: 1
  })

  t.is(activeRequests, 1)
  t.is(relayLookups, 1, 'only capped requests are relay-enriched')
  t.is(result.ok, true)
  t.is(result.payload.key, '02'.repeat(32))
  t.is(result.payload.count, 1)
  t.is(result.payload.total, 2)
  t.is(result.payload.truncated, true)
  t.is(result.payload.requests[0].relays.length, 1)

  const unknown = await buildRegistryStatusRoutePayload({
    route: null,
    registry: {
      advanceRequestStatusSnapshot () {
        throw new Error('should not query registry')
      },
      requestStatusSnapshot () {
        throw new Error('should not query registry')
      }
    }
  })
  t.alike(unknown, {
    ok: false,
    status: 404,
    payload: { error: 'unknown registry status route' }
  })
})

test('api registry status: sanitizes request fields and relay metadata', async (t) => {
  const calls = []
  const appKey = 'A'.repeat(64)
  const out = await buildRegistryStatusPayload({
    registry: {
      key: Buffer.alloc(32, 1),
      advanceRequestStatusSnapshot () {
        return { complete: true }
      },
      requestStatusSnapshot () {
        const requests = [requestEntry(appKey, {
          geoPreference: [' EU ', 99, 'x'.repeat(65)],
          discoveryKeys: ['B'.repeat(64), '../secret'],
          relaysSecret: 'do-not-leak'
        })]
        return { activeRequests: requests.length, requests, completedHighWater: 1, completedAt: 456 }
      },
      async getRelaysForApp (key) {
        calls.push(key)
        return [
          { relayPubkey: 'E'.repeat(64), region: ' NA ', secret: 'hidden' },
          { relayPubkey: 'not-hex', region: 'x'.repeat(65) }
        ]
      }
    }
  })

  t.is(out.ok, true)
  t.is(out.payload.key, '01'.repeat(32))
  t.is(out.payload.activeRequests, 1)
  t.is(out.payload.count, 1)
  t.is(out.payload.truncated, false)
  t.alike(calls, ['a'.repeat(64)])
  t.alike(out.payload.requests[0], {
    type: 'seed-request',
    timestamp: 123,
    appKey: 'a'.repeat(64),
    discoveryKeys: ['B'.repeat(64)],
    contentType: 'drive',
    parentKey: 'c'.repeat(64),
    mountPath: '/docs',
    replicationFactor: 3,
    geoPreference: ['EU'],
    maxStorageBytes: 1024,
    bountyRate: 7,
    ttlSeconds: 3600,
    privacyTier: 'public',
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    publisherPubkey: 'd'.repeat(64),
    acceptedRelays: 2,
    relays: [
      { pubkey: 'e'.repeat(64), region: 'NA' },
      { pubkey: null, region: null }
    ],
    relaysTruncated: false
  })
  t.absent(JSON.stringify(out.payload).includes('publisherSignature'))
  t.absent(JSON.stringify(out.payload).includes('delegationCert'))
  t.absent(JSON.stringify(out.payload).includes('do-not-leak'))
})

test('api registry status: caps request enrichment and per-request relays', async (t) => {
  t.is(MAX_REGISTRY_STATUS_REQUESTS, 64)
  t.is(MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST, 100)
  const requests = []
  for (let i = 0; i < 69; i++) {
    requests.push(requestEntry(String(i % 10).repeat(64)))
  }
  const relayList = []
  for (let i = 0; i < 105; i++) {
    relayList.push({ relayPubkey: String(i % 10).repeat(64), region: 'R' + i })
  }
  let relayLookups = 0
  const out = await buildRegistryStatusPayload({
    registry: {
      key: null,
      advanceRequestStatusSnapshot () {
        return { complete: true }
      },
      requestStatusSnapshot () {
        return { activeRequests: requests.length, requests, completedHighWater: 69, completedAt: 456 }
      },
      async getRelaysForApp () {
        relayLookups++
        return relayList
      }
    }
  })

  t.is(out.payload.activeRequests, 69)
  t.is(out.payload.count, 64)
  t.is(out.payload.total, 69)
  t.is(out.payload.truncated, true)
  t.is(out.payload.requests.length, 64)
  t.is(relayLookups, 64, 'capped-out requests are not relay-enriched')
  t.is(out.payload.requests[0].acceptedRelays, 105)
  t.is(out.payload.requests[0].relays.length, 100)
  t.is(out.payload.requests[0].relaysTruncated, true)
})

test('api registry status: publishes only a completed bounded request cycle', async (t) => {
  const registry = new SeedingRegistry(null, null)
  const now = Date.now()
  for (let i = 0; i < 70; i++) {
    const appKey = i.toString(16).padStart(64, '0')
    const entry = requestEntry(appKey, { timestamp: now, ttlSeconds: 3600 })
    registry._requestPopulation.insert(appKey)
    registry._requests.set(appKey, entry)
  }

  const first = registry.advanceRequestStatusSnapshot(32)
  t.is(first.complete, false)
  t.is(first.examined, 32, 'first pass inspects only its finite budget')
  t.is(registry.requestStatusSnapshot().activeRequests, 0, 'partial pass retains the prior complete aggregate')
  registry.advanceRequestStatusSnapshot(32)
  const terminal = registry.advanceRequestStatusSnapshot(32)
  t.is(terminal.complete, true)

  const snapshot = registry.requestStatusSnapshot()
  t.is(snapshot.activeRequests, 70)
  t.is(snapshot.requests.length, 64, 'complete aggregate retains a fixed detail cap')
  registry.getActiveRequests = () => { throw new Error('full registry snapshot is forbidden') }
  const out = await buildRegistryStatusPayload({ registry })
  t.is(out.ok, true)
  t.is(out.payload.total, 70)
  t.is(out.payload.count, 64)
  t.is(out.payload.refreshing, true, 'next high-water cycle advances without erasing the completed aggregate')
})
