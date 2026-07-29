import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  MAX_DISCOVERY_KEYS,
  OPERATOR_SEED_AUTH_MESSAGE,
  REGISTRY_PUBLISH_AUTH_MESSAGE,
  resolveSeedPublishRoute,
  runOperatorSeedAction,
  runPublisherSeedAction,
  runRegistryPublishAction,
  runSeedPublishRouteAction
} from '../../packages/core/core/relay-node/api-seed-publish.js'
import {
  serializeSeedRequestForReplaySigning,
  serializeSeedRequestForSigning
} from '../../packages/core/core/protocol/seed-request.js'

const STORAGE_BOUND = 500 * 1024 * 1024

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function signedSeedBody (publisherKp, overrides = {}) {
  const body = {
    appKey: 'a'.repeat(64),
    discoveryKeys: [],
    replicationFactor: 3,
    maxStorageBytes: 500 * 1024 * 1024,
    ttlSeconds: 30 * 24 * 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0,
    ...overrides,
    publisherPubkey: b4a.toString(publisherKp.publicKey, 'hex'),
    publisherSignature: '0'.repeat(128)
  }
  const msg = {
    appKey: b4a.from(body.appKey, 'hex'),
    discoveryKeys: body.discoveryKeys.map(key => b4a.from(key, 'hex')),
    replicationFactor: body.replicationFactor,
    maxStorageBytes: body.maxStorageBytes,
    ttlSeconds: body.ttlSeconds,
    bountyRate: body.bountyRate,
    revocable: body.revocable !== false,
    unseedFreezeMs: body.unseedFreezeMs,
    durability: body.durability,
    issuedAt: body.issuedAt,
    requestNonce: body.requestNonce ? b4a.from(body.requestNonce, 'hex') : undefined,
    publisherPubkey: publisherKp.publicKey,
    publisherSignature: b4a.alloc(64)
  }
  const payload = body.issuedAt !== undefined || body.requestNonce !== undefined
    ? serializeSeedRequestForReplaySigning(msg)
    : serializeSeedRequestForSigning(msg)
  sodium.crypto_sign_detached(msg.publisherSignature, payload, publisherKp.secretKey)
  body.publisherSignature = b4a.toString(msg.publisherSignature, 'hex')
  return body
}

test('api seed publish: route resolver maps exact seed and registry publish routes', (t) => {
  t.alike(resolveSeedPublishRoute('POST', '/seed'), {
    kind: 'operator-seed',
    authMessage: OPERATOR_SEED_AUTH_MESSAGE
  })
  t.alike(resolveSeedPublishRoute('POST', '/registry/publish'), {
    kind: 'registry-publish',
    authMessage: REGISTRY_PUBLISH_AUTH_MESSAGE
  })
  t.alike(resolveSeedPublishRoute('POST', '/api/v1/seed'), {
    kind: 'publisher-seed'
  })
  t.is(resolveSeedPublishRoute('GET', '/seed'), null, 'wrong method falls through')
  t.is(resolveSeedPublishRoute('POST', '/seed-core'), null, 'adjacent seed-core route falls through')
  t.is(resolveSeedPublishRoute('POST', '/registry/publish/extra'), null, 'registry subpath falls through')
  t.is(resolveSeedPublishRoute('POST', '/api/v1/seed/extra'), null, 'publisher subpath falls through')
  t.is(resolveSeedPublishRoute('POST', '/api/v1/unseed'), null, 'adjacent publisher route falls through')
})

test('api seed publish: route action helper dispatches seed and registry primitives', async (t) => {
  const publisher = keyPair()
  const calls = []
  const node = {
    swarm: { keyPair: { publicKey: Buffer.alloc(32, 9) } },
    seedingRegistry: {
      async publishRequest (request) {
        calls.push({ type: 'registry', request })
        return { entryId: 'registry-entry' }
      },
      getCustodyIntent () { return null }
    },
    async seedApp (appKey, opts) {
      calls.push({ type: 'seed', appKey, opts })
      return { discoveryKey: 'seeded-' + appKey[0] }
    }
  }

  const operator = await runSeedPublishRouteAction({
    route: { kind: 'operator-seed' },
    body: { appKey: 'a'.repeat(64), maxStorageBytes: STORAGE_BOUND },
    node
  })
  const registry = await runSeedPublishRouteAction({
    route: { kind: 'registry-publish' },
    body: { appKey: 'b'.repeat(64), discoveryKeys: [], maxStorageBytes: STORAGE_BOUND },
    node
  })
  const publisherOut = await runSeedPublishRouteAction({
    route: { kind: 'publisher-seed' },
    body: signedSeedBody(publisher, { appKey: 'c'.repeat(64) }),
    node
  })
  const unknown = await runSeedPublishRouteAction({
    route: { kind: 'unknown' },
    body: {},
    node
  })

  t.alike(operator.payload, { ok: true, discoveryKey: 'seeded-a' })
  t.alike(registry.payload, { ok: true, entryId: 'registry-entry' })
  t.alike(publisherOut.payload, { ok: true, discoveryKey: 'seeded-c' })
  t.alike(calls.map(call => call.type), ['seed', 'registry', 'seed'])
  t.is(calls[0].appKey, 'a'.repeat(64))
  t.is(calls[1].request.appKey.toString('hex'), 'b'.repeat(64))
  t.is(calls[2].appKey, 'c'.repeat(64))
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown seed publish route')
})

test('api seed publish: operator seed normalizes metadata without mutating opts', async (t) => {
  const calls = []
  const node = {
    async seedApp (appKey, opts) {
      calls.push({ appKey, opts })
      return { discoveryKey: 'seeded' }
    }
  }
  const opts = {
    storageClass: 'persistent',
    availabilityClass: 'best-effort',
    blind: false
  }
  const body = {
    appKey: 'A'.repeat(64),
    maxStorageBytes: STORAGE_BOUND,
    opts,
    type: 'drive',
    parentKey: 'b'.repeat(64),
    mountPath: ' /vault ',
    durability: '1',
    appId: 'ghost-drive-demo',
    version: '1.2.3',
    name: '  Ghost Drive  ',
    description: 'Pinned archive',
    author: '  relay ops  ',
    categories: [' docs ', '', 'docs', 'x'.repeat(70)],
    privacyTier: 'P2P-ONLY',
    blind: true,
    custodyIntentId: 'C'.repeat(64),
    blindContentId: 'D'.repeat(64),
    ciphertextRoot: 'E'.repeat(64),
    contentVersion: 2.9,
    retainUntil: 9.1,
    shardIds: [0, 2]
  }

  const out = await runOperatorSeedAction({ body, node })

  t.alike(out.payload, { ok: true, discoveryKey: 'seeded' })
  t.is(calls.length, 1)
  t.is(calls[0].appKey, 'a'.repeat(64), 'appKey is canonicalized before runtime ingress')
  t.alike(opts, {
    storageClass: 'persistent',
    availabilityClass: 'best-effort',
    blind: false
  }, 'request opts object is not mutated')
  t.is(calls[0].opts.type, 'drive')
  t.is(calls[0].opts.parentKey, 'b'.repeat(64))
  t.is(calls[0].opts.mountPath, '/vault')
  t.is(calls[0].opts.durability, 1)
  t.is(calls[0].opts.appId, 'ghost-drive-demo')
  t.is(calls[0].opts.version, '1.2.3')
  t.is(calls[0].opts.name, 'Ghost Drive')
  t.is(calls[0].opts.description, 'Pinned archive')
  t.is(calls[0].opts.author, 'relay ops')
  t.alike(calls[0].opts.categories, ['docs', 'x'.repeat(64)])
  t.is(calls[0].opts.privacyTier, 'p2p-only')
  t.is(calls[0].opts.blind, true)
  t.is(calls[0].opts.storageClass, 'persistent')
  t.is(calls[0].opts.availabilityClass, 'best-effort')
  t.is(calls[0].opts.custodyIntentId, 'c'.repeat(64))
  t.is(calls[0].opts.blindContentId, 'd'.repeat(64))
  t.is(calls[0].opts.ciphertextRoot, 'e'.repeat(64))
  t.is(calls[0].opts.contentVersion, 2)
  t.is(calls[0].opts.retainUntil, 9)
  t.alike(calls[0].opts.shardIds, [0, 2])
})

test('api seed publish: operator seed rejects malformed input before seeding', async (t) => {
  const node = {
    async seedApp () {
      t.fail('invalid seed request must not reach seedApp')
    }
  }

  let out = await runOperatorSeedAction({ body: {}, node })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'appKey required' })

  out = await runOperatorSeedAction({
    body: { appKey: 'a'.repeat(64), opts: [] },
    node
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'opts must be an object' })

  out = await runOperatorSeedAction({
    body: { appKey: 'a'.repeat(64), type: 'torrent', maxStorageBytes: STORAGE_BOUND },
    node
  })
  t.is(out.status, 400)
  t.ok(out.payload.error.includes('type must be one of'))

  out = await runOperatorSeedAction({
    body: { appKey: 'a'.repeat(64), type: 'app', parentKey: 'b'.repeat(64), maxStorageBytes: STORAGE_BOUND },
    node
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'parentKey and mountPath are only supported when type is "drive"' })

  out = await runOperatorSeedAction({
    body: { appKey: 'a'.repeat(64), shardIds: [1, -1], maxStorageBytes: STORAGE_BOUND },
    node
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'shardIds must contain non-negative integers' })
})

test('api seed publish: disabled custody seed fields reject before seed runtime access', async (t) => {
  const intentId = 'c'.repeat(64)
  const operator = await runOperatorSeedAction({
    body: { custodyIntentId: intentId },
    node: {
      async seedApp () {
        t.fail('disabled operator custody seed must not reach seedApp')
      }
    },
    disabled: true
  })
  t.is(operator.ok, false)
  t.is(operator.kind, 'disabled-profile')
  t.is(operator.status, 409)
  t.ok(operator.payload.error.startsWith('not-enabled: '), 'operator custody seed returns formatted disabled-profile error')

  const publisher = await runPublisherSeedAction({
    body: { custodyIntentId: intentId },
    node: {
      get seedApp () {
        t.fail('disabled publisher custody seed must not inspect seedApp readiness')
      }
    },
    disabled: true
  })
  t.is(publisher.ok, false)
  t.is(publisher.kind, 'disabled-profile')
  t.is(publisher.status, 409)
  t.ok(publisher.payload.error.startsWith('not-enabled: '), 'publisher custody seed returns formatted disabled-profile error')
})

test('api seed publish: disabled profile still allows plain operator seed', async (t) => {
  const calls = []
  const out = await runOperatorSeedAction({
    body: { appKey: 'a'.repeat(64), maxStorageBytes: STORAGE_BOUND },
    node: {
      async seedApp (appKey, opts) {
        calls.push({ appKey, opts })
        return { discoveryKey: 'plain-seed-ok' }
      }
    },
    disabled: true
  })

  t.alike(out.payload, { ok: true, discoveryKey: 'plain-seed-ok' })
  t.is(calls.length, 1)
  t.is(calls[0].appKey, 'a'.repeat(64))
  t.alike(calls[0].opts, { maxStorage: STORAGE_BOUND })
})

test('api seed publish: registry publish builds the signed catalog request', async (t) => {
  const calls = []
  const publisherPubkey = Buffer.alloc(32, 7)
  const node = {
    swarm: { keyPair: { publicKey: publisherPubkey } },
    seedingRegistry: {
      async publishRequest (request) {
        calls.push(request)
        return { entryId: 'registry-entry' }
      }
    }
  }

  const out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      discoveryKeys: ['b'.repeat(64)],
      contentType: 'drive',
      parentKey: 'c'.repeat(64),
      mountPath: ' /docs ',
      blind: true,
      privacyTier: 'local-first',
      replicas: 5,
      geo: 'EU',
      maxStorageBytes: 1024,
      bountyRate: 3,
      ttlDays: 2
    }
  })

  t.alike(out.payload, { ok: true, entryId: 'registry-entry' })
  t.is(calls.length, 1)
  t.is(calls[0].appKey.toString('hex'), 'a'.repeat(64))
  t.alike(calls[0].discoveryKeys.map(key => key.toString('hex')), ['b'.repeat(64)])
  t.is(calls[0].contentType, 'drive')
  t.is(calls[0].parentKey, 'c'.repeat(64))
  t.is(calls[0].mountPath, '/docs')
  t.is(calls[0].blind, true)
  t.is(calls[0].storageClass, 'temporary')
  t.is(calls[0].availabilityClass, 'atomic-handoff')
  t.is(calls[0].privacyTier, 'local-first')
  t.is(calls[0].replicationFactor, 5)
  t.alike(calls[0].geoPreference, ['EU'])
  t.is(calls[0].maxStorageBytes, 1024)
  t.is(calls[0].bountyRate, 3)
  t.is(calls[0].ttlSeconds, 172800)
  t.is(calls[0].publisherPubkey, publisherPubkey)
})

test('api seed publish: registry publish preserves readiness and validation errors', async (t) => {
  let out = await runRegistryPublishAction({
    node: { seedingRegistry: null },
    body: {}
  })
  t.is(out.status, 503, 'registry readiness is checked before appKey shape')
  t.alike(out.payload, { error: 'Registry not running' })

  const node = {
    seedingRegistry: {
      async publishRequest () {
        t.fail('invalid registry publish request must not reach registry')
      }
    }
  }

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      discoveryKeys: Array(MAX_DISCOVERY_KEYS + 1).fill('b'.repeat(64)),
      maxStorageBytes: STORAGE_BOUND
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: `discoveryKeys must be an array of at most ${MAX_DISCOVERY_KEYS} items` })

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      type: 'app',
      mountPath: '/docs',
      maxStorageBytes: STORAGE_BOUND
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'parentKey and mountPath are only supported when type is "drive"' })

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      blind: 'yes',
      maxStorageBytes: STORAGE_BOUND
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'blind must be a boolean' })

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      replicas: 0,
      maxStorageBytes: STORAGE_BOUND
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'replicas must be between 1 and 255' })

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      geo: { region: 'EU' },
      maxStorageBytes: STORAGE_BOUND
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'geo must be a string or array of strings' })

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      ttlDays: '1e3',
      maxStorageBytes: STORAGE_BOUND
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'ttlDays must be a valid integer' })

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      bountyRate: 4294967296,
      maxStorageBytes: STORAGE_BOUND
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'bountyRate must be between 0 and 4294967295' })

  out = await runRegistryPublishAction({
    node,
    body: {
      appKey: 'a'.repeat(64),
      discoveryKeys: []
    }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'maxStorageBytes must be a positive safe integer' })
})

test('api seed publish: publisher seed checks seedApp readiness before request validation', async (t) => {
  const out = await runPublisherSeedAction({
    node: { seedingRegistry: { getCustodyIntent () { return null } } },
    body: {}
  })

  t.is(out.status, 503)
  t.alike(out.payload, { error: 'seedApp not available' })
})

test('api seed publish: publisher seed forwards signed opts and validation errors', async (t) => {
  const publisher = keyPair()
  const calls = []
  const node = {
    seedingRegistry: { getCustodyIntent () { return null } },
    async seedApp (appKey, opts) {
      calls.push({ appKey, opts })
      return { accepted: true }
    }
  }

  let out = await runPublisherSeedAction({
    node,
    body: { appKey: 'a'.repeat(64), publisherSignature: '0'.repeat(128) }
  })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'publisherPubkey required' })
  t.is(calls.length, 0, 'invalid publisher seed does not reach seedApp')

  const body = signedSeedBody(publisher, {
    appKey: 'b'.repeat(64),
    replicationFactor: 5,
    ttlSeconds: 7 * 24 * 3600
  })
  out = await runPublisherSeedAction({ node, body })

  t.alike(out.payload, { ok: true, accepted: true })
  t.is(calls.length, 1)
  t.is(calls[0].appKey, 'b'.repeat(64))
  t.is(calls[0].opts.replicas, 5)
  t.is(calls[0].opts.ttlDays, 7)
  t.is(calls[0].opts.publisherPubkey, b4a.toString(publisher.publicKey, 'hex'))
  t.is(calls[0].opts.publisherSignature, body.publisherSignature)
})

test('api seed publish: publisher seed rejects replayed replay-v1 nonce', async (t) => {
  const publisher = keyPair()
  const calls = []
  const now = Date.now()
  const node = {
    seedingRegistry: { getCustodyIntent () { return null } },
    _publisherSeedReplayCache: new Map(),
    async seedApp (appKey, opts) {
      calls.push({ appKey, opts })
      return { accepted: true }
    }
  }
  const body = signedSeedBody(publisher, {
    appKey: 'f'.repeat(64),
    issuedAt: now,
    requestNonce: '05'.repeat(16)
  })

  const first = await runPublisherSeedAction({ node, body })
  t.alike(first.payload, { ok: true, accepted: true })
  t.is(calls.length, 1)
  t.is(calls[0].opts.seedSignatureProfile, 'replay-v1')

  const second = await runPublisherSeedAction({ node, body })
  t.is(second.status, 409)
  t.ok(second.payload.error.includes('SEED_REQUEST_REPLAY'))
  t.is(calls.length, 1, 'replayed seed did not reach seedApp')
})

test('api seed publish: publisher seed rejects unknown signed-ingress fields before seeding', async (t) => {
  const publisher = keyPair()
  const calls = []
  const node = {
    seedingRegistry: { getCustodyIntent () { return null } },
    async seedApp (appKey, opts) {
      calls.push({ appKey, opts })
      return { accepted: true }
    }
  }
  const body = signedSeedBody(publisher, {
    appKey: 'c'.repeat(64)
  })
  body.caption = 'private docs'

  const out = await runPublisherSeedAction({ node, body })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'unknown publisher seed field: caption' })
  t.is(calls.length, 0, 'unknown publisher seed field does not reach seedApp')
})

test('api seed publish: publisher seed preserves custody publisher mismatch and seed error delegation', async (t) => {
  const publisher = keyPair()
  const otherPublisher = keyPair()
  const intentId = 'c'.repeat(64)
  const node = {
    seedingRegistry: {
      getCustodyIntent () {
        return { publisherPubkey: b4a.toString(otherPublisher.publicKey, 'hex') }
      }
    },
    async seedApp () {
      t.fail('mismatched custody publisher must not reach seedApp')
    }
  }

  let out = await runPublisherSeedAction({
    node,
    body: signedSeedBody(publisher, {
      appKey: 'd'.repeat(64),
      custodyIntentId: intentId
    })
  })
  t.is(out.status, 403)
  t.ok(out.payload.error.includes('CUSTODY_PUBLISHER_MISMATCH'))

  const seedError = new Error('The corestore is closed')
  out = await runPublisherSeedAction({
    node: {
      seedingRegistry: { getCustodyIntent () { return null } },
      async seedApp () { throw seedError }
    },
    body: signedSeedBody(publisher, { appKey: 'e'.repeat(64) })
  })
  t.is(out.ok, false)
  t.is(out.kind, 'seed-error')
  t.is(out.error, seedError)
})
