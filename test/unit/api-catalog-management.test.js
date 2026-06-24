import test from 'brittle'
import {
  buildPendingCatalogPayload,
  runCatalogAllowlistAction,
  runCatalogAppAction,
  runCatalogModeAction,
  runLegacyAutoAcceptAction,
  runRegistryCancelAction
} from '../../packages/core/core/relay-node/api-catalog-management.js'

test('api catalog management: pending payload uses a stable public schema', (t) => {
  const appKey = 'a'.repeat(64)
  const forgedAppKey = 'b'.repeat(64)
  const publisherBytes = Buffer.alloc(32, 7)
  const payload = buildPendingCatalogPayload({
    pendingRequests: new Map([
      [appKey, {
        appKey: forgedAppKey,
        publisherPubkey: publisherBytes,
        publisherSignature: Buffer.alloc(64, 8),
        source: 'federation',
        sourceRelay: 'https://relay.example',
        contentType: 'drive',
        privacyTier: 'public',
        categories: ['ghost-drive', 99, 'files'],
        blind: true,
        currentRelays: 2,
        discoveredAt: 12345,
        secretToken: 'do-not-leak'
      }],
      ['odd-key', 'not-an-object']
    ]),
    resolveAcceptMode: () => 'review'
  })

  t.is(payload.count, 2)
  t.is(payload.mode, 'review')
  t.is(payload.requests[0].appKey, appKey, 'map key remains canonical')
  t.is(payload.requests[0].publisherPubkey, publisherBytes.toString('hex'), 'byte pubkey is encoded')
  t.alike(payload.requests[0].categories, ['ghost-drive', 'files'], 'categories stay string-only')
  t.is(payload.requests[0].blind, true)
  t.is(payload.requests[0].currentRelays, 2)
  t.is(payload.requests[0].discoveredAt, 12345)
  t.absent(payload.requests[0].publisherSignature, 'signatures are not exposed')
  t.absent(payload.requests[0].secretToken, 'unknown internal fields are not exposed')
  t.alike(payload.requests[1], { appKey: 'odd-key' }, 'non-object entries cannot leak fields')
})

test('api catalog management: validates mode and allowlist before mutation', async (t) => {
  const config = {
    acceptMode: 'review',
    acceptAllowlist: ['c'.repeat(64)]
  }

  let out = await runCatalogModeAction({
    body: { mode: 'invalid' },
    config,
    persistConfig: async () => t.fail('invalid mode should not persist')
  })
  t.is(out.ok, false)
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'mode must be one of: open, review, allowlist, closed' })
  t.is(config.acceptMode, 'review')

  out = await runCatalogAllowlistAction({
    body: { allowlist: ['not-a-pubkey'] },
    config,
    persistConfig: async () => t.fail('invalid allowlist should not persist')
  })
  t.is(out.ok, false)
  t.is(out.status, 400)
  t.alike(config.acceptAllowlist, ['c'.repeat(64)])
})

test('api catalog management: mode persists accept mode and rolls back failures', async (t) => {
  {
    const config = {
      acceptMode: 'review',
      registryAutoAccept: true
    }
    const persisted = []

    const out = await runCatalogModeAction({
      body: { mode: 'allowlist' },
      config,
      persistConfig: async () => persisted.push({ ...config })
    })

    t.is(out.ok, true)
    t.alike(out.payload, { ok: true, mode: 'allowlist' })
    t.is(config.acceptMode, 'allowlist')
    t.absent(config.registryAutoAccept)
    t.alike(persisted, [{ acceptMode: 'allowlist' }])
  }

  {
    const config = {
      acceptMode: 'review',
      registryAutoAccept: false
    }

    const out = await runCatalogModeAction({
      body: { mode: 'open' },
      config,
      persistConfig: async () => { throw new Error('readonly config') }
    })

    t.is(out.ok, false)
    t.is(out.kind, 'config-persist')
    t.is(out.error.message, 'readonly config')
    t.is(config.acceptMode, 'review')
    t.is(config.registryAutoAccept, false)
  }
})

test('api catalog management: legacy auto-accept persists alias and rolls back failures', async (t) => {
  {
    const config = { acceptMode: 'review' }
    const persisted = []

    const out = await runLegacyAutoAcceptAction({
      body: { enabled: true },
      config,
      persistConfig: async () => persisted.push({ ...config })
    })

    t.is(out.ok, true)
    t.alike(out.payload, { ok: true, autoAccept: true })
    t.absent(config.acceptMode)
    t.is(config.registryAutoAccept, true)
    t.alike(persisted, [{ registryAutoAccept: true }])
  }

  {
    const config = {
      acceptMode: 'review',
      registryAutoAccept: false
    }
    let persisted = false

    const out = await runLegacyAutoAcceptAction({
      body: { enabled: 'false' },
      config,
      persistConfig: async () => { persisted = true }
    })

    t.is(out.ok, false)
    t.is(out.status, 400)
    t.alike(out.payload, { error: 'enabled must be a boolean' })
    t.is(config.acceptMode, 'review')
    t.is(config.registryAutoAccept, false)
    t.is(persisted, false)
  }

  {
    const config = {
      acceptMode: 'review',
      registryAutoAccept: false
    }

    const out = await runLegacyAutoAcceptAction({
      body: { enabled: true },
      config,
      persistConfig: async () => { throw new Error('readonly config') }
    })

    t.is(out.ok, false)
    t.is(out.kind, 'config-persist')
    t.is(config.acceptMode, 'review')
    t.is(config.registryAutoAccept, false)
  }
})

test('api catalog management: allowlist normalizes, de-duplicates, and rolls back failures', async (t) => {
  {
    const config = {}
    const upper = 'A'.repeat(64)
    const lower = 'b'.repeat(64)
    const persisted = []

    const out = await runCatalogAllowlistAction({
      body: { allowlist: [upper, lower, upper.toLowerCase()] },
      config,
      persistConfig: async () => persisted.push({ acceptAllowlist: config.acceptAllowlist.slice() })
    })

    t.is(out.ok, true)
    t.alike(out.payload.allowlist, [upper.toLowerCase(), lower])
    t.alike(config.acceptAllowlist, [upper.toLowerCase(), lower])
    t.alike(persisted, [{ acceptAllowlist: [upper.toLowerCase(), lower] }])
  }

  {
    const previous = ['d'.repeat(64)]
    const config = { acceptAllowlist: previous.slice() }

    const out = await runCatalogAllowlistAction({
      body: { allowlist: ['e'.repeat(64)] },
      config,
      persistConfig: async () => { throw new Error('readonly config') }
    })

    t.is(out.ok, false)
    t.is(out.kind, 'config-persist')
    t.alike(config.acceptAllowlist, previous)
  }
})

test('api catalog management: app actions validate keys and call node operations', async (t) => {
  const calls = []
  const node = {
    async approveRequest (appKey) { calls.push(['approve', appKey]) },
    rejectRequest (appKey) { calls.push(['reject', appKey]) },
    async unseedApp (appKey) { calls.push(['remove', appKey]) }
  }
  const upperKey = 'A'.repeat(64)
  const lowerKey = 'b'.repeat(64)

  let out = await runCatalogAppAction({
    action: 'approve',
    body: { appKey: upperKey },
    node
  })
  t.alike(out, { ok: true, payload: { ok: true } })

  out = await runCatalogAppAction({
    action: 'reject',
    body: { appKey: lowerKey },
    node
  })
  t.alike(out, { ok: true, payload: { ok: true } })

  out = await runCatalogAppAction({
    action: 'remove',
    body: { appKey: lowerKey },
    node
  })
  t.alike(out, { ok: true, payload: { ok: true } })

  out = await runCatalogAppAction({
    action: 'approve',
    body: { appKey: 'not-a-key' },
    node
  })
  t.is(out.ok, false)
  t.is(out.status, 400)
  t.alike(calls, [
    ['approve', upperKey],
    ['reject', lowerKey],
    ['remove', lowerKey]
  ])
})

test('api catalog management: registry cancel keeps readiness and pubkey behavior', async (t) => {
  const missing = await runRegistryCancelAction({
    body: { appKey: 'not-a-key' },
    node: { seedingRegistry: null }
  })
  t.is(missing.status, 503)
  t.alike(missing.payload, { error: 'Registry not running' })

  const calls = []
  const pubkeyBytes = Buffer.alloc(32, 7)
  const node = {
    swarm: { keyPair: { publicKey: pubkeyBytes } },
    seedingRegistry: {
      async cancelRequest (appKey, pubkey) {
        calls.push({ appKey, pubkey })
      }
    }
  }

  const appKey = 'f'.repeat(64)
  const out = await runRegistryCancelAction({
    body: { appKey },
    node
  })

  t.alike(out, { ok: true, payload: { ok: true } })
  t.alike(calls, [{
    appKey,
    pubkey: pubkeyBytes.toString('hex')
  }])
})
