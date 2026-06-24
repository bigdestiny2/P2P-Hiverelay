import test from 'brittle'
import {
  MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST,
  MAX_REGISTRY_STATUS_REQUESTS,
  buildRegistryStatusPayload
} from 'p2p-hiverelay/core/relay-node/api-registry-status.js'

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

test('api registry status: missing registry reports unavailable', async (t) => {
  const out = await buildRegistryStatusPayload()
  t.is(out.status, 503)
  t.alike(out.payload, { error: 'Registry not running' })
})

test('api registry status: sanitizes request fields and relay metadata', async (t) => {
  const calls = []
  const appKey = 'A'.repeat(64)
  const out = await buildRegistryStatusPayload({
    registry: {
      key: Buffer.alloc(32, 1),
      async getActiveRequests () {
        return [requestEntry(appKey, {
          geoPreference: [' EU ', 99, 'x'.repeat(65)],
          discoveryKeys: ['B'.repeat(64), '../secret'],
          relaysSecret: 'do-not-leak'
        })]
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
  t.is(MAX_REGISTRY_STATUS_REQUESTS, 500)
  t.is(MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST, 100)
  const requests = []
  for (let i = 0; i < 505; i++) {
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
      async getActiveRequests () {
        return requests
      },
      async getRelaysForApp () {
        relayLookups++
        return relayList
      }
    }
  })

  t.is(out.payload.activeRequests, 505)
  t.is(out.payload.count, 500)
  t.is(out.payload.total, 505)
  t.is(out.payload.truncated, true)
  t.is(out.payload.requests.length, 500)
  t.is(relayLookups, 500, 'capped-out requests are not relay-enriched')
  t.is(out.payload.requests[0].acceptedRelays, 105)
  t.is(out.payload.requests[0].relays.length, 100)
  t.is(out.payload.requests[0].relaysTruncated, true)
})
