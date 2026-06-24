import test from 'brittle'
import { Federation } from '../../packages/core/core/federation.js'
import {
  MAX_FEDERATION_SNAPSHOT_PEER_APPS,
  MAX_FEDERATION_SNAPSHOT_RELAYS,
  buildFederationSnapshotPayload,
  MAX_FEDERATION_NOTE_LENGTH,
  runFederationManagementAction
} from '../../packages/core/core/relay-node/api-federation-management.js'

test('api federation management: validates action bodies before federation access', async (t) => {
  const missingUrl = await runFederationManagementAction({
    action: 'follow',
    body: {},
    federation: null
  })
  t.is(missingUrl.status, 400)
  t.alike(missingUrl.payload, { error: 'url required' })

  const missingKey = await runFederationManagementAction({
    action: 'republish',
    body: {},
    federation: null
  })
  t.is(missingKey.status, 400)
  t.alike(missingKey.payload, { error: 'appKey required' })

  const malformedKey = await runFederationManagementAction({
    action: 'unrepublish',
    body: { appKey: 'xyz' },
    federation: null
  })
  t.is(malformedKey.status, 400)
  t.alike(malformedKey.payload, { error: 'appKey must be 64 hex characters' })

  const malformedMirrorPubkey = await runFederationManagementAction({
    action: 'mirror',
    body: { url: 'https://relay.example', pubkey: 'xyz' },
    federation: null
  })
  t.is(malformedMirrorPubkey.status, 400)
  t.alike(malformedMirrorPubkey.payload, { error: 'pubkey must be 64 hex characters' })

  const malformedSourcePubkey = await runFederationManagementAction({
    action: 'republish',
    body: { appKey: 'a'.repeat(64), sourcePubkey: 'xyz' },
    federation: null
  })
  t.is(malformedSourcePubkey.status, 400)
  t.alike(malformedSourcePubkey.payload, { error: 'sourcePubkey must be 64 hex characters' })

  const malformedChannel = await runFederationManagementAction({
    action: 'republish',
    body: { appKey: 'a'.repeat(64), channel: { name: 'stable' } },
    federation: null
  })
  t.is(malformedChannel.status, 400)
  t.alike(malformedChannel.payload, { error: 'channel must be a string' })

  const oversizedNote = await runFederationManagementAction({
    action: 'republish',
    body: { appKey: 'a'.repeat(64), note: 'x'.repeat(MAX_FEDERATION_NOTE_LENGTH + 1) },
    federation: null
  })
  t.is(oversizedNote.status, 400)
  t.alike(oversizedNote.payload, { error: `note exceeds max length (${MAX_FEDERATION_NOTE_LENGTH})` })

  const unavailable = await runFederationManagementAction({
    action: 'follow',
    body: { url: 'https://relay.example' },
    federation: null
  })
  t.is(unavailable.status, 503)
  t.alike(unavailable.payload, { error: 'Federation not initialized' })
})

test('api federation management: persists every mutation before success', async (t) => {
  const federation = new Federation({})
  const saved = []
  federation.save = async (opts = {}) => {
    t.is(opts.throwOnError, true)
    saved.push(federation.snapshot())
  }

  const followed = await runFederationManagementAction({
    action: 'follow',
    body: { url: 'http://relay-a.example' },
    federation
  })
  t.is(followed.ok, true)
  t.is(followed.payload.mode, 'follow')

  const mirrored = await runFederationManagementAction({
    action: 'mirror',
    body: { url: 'https://relay-b.example', pubkey: 'b'.repeat(64) },
    federation
  })
  t.is(mirrored.ok, true)
  t.is(mirrored.payload.mode, 'mirror')

  const republished = await runFederationManagementAction({
    action: 'republish',
    body: {
      appKey: 'a'.repeat(64),
      sourceUrl: 'https://source.example',
      sourcePubkey: 'c'.repeat(64),
      channel: 'stable',
      note: 'operator curated'
    },
    federation
  })
  t.is(republished.ok, true)
  t.is(republished.payload.appKey, 'a'.repeat(64))

  const unfollowed = await runFederationManagementAction({
    action: 'unfollow',
    body: { url: 'http://relay-a.example' },
    federation
  })
  t.is(unfollowed.ok, true)
  t.is(unfollowed.payload.removed, true)

  const unrepublished = await runFederationManagementAction({
    action: 'unrepublish',
    body: { appKey: 'a'.repeat(64) },
    federation
  })
  t.is(unrepublished.ok, true)
  t.is(unrepublished.payload.removed, true)

  const snap = federation.snapshot()
  t.alike(snap.followed, [])
  t.is(snap.mirrored.length, 1)
  t.is(snap.mirrored[0].url, 'https://relay-b.example')
  t.alike(snap.republished, [])
  t.is(saved.length, 5)
})

test('api federation management: canonicalizes optional trusted metadata before persistence', async (t) => {
  const federation = new Federation({})
  federation.save = async () => {}

  const mirrored = await runFederationManagementAction({
    action: 'mirror',
    body: { url: ' https://relay.example ', pubkey: 'B'.repeat(64) },
    federation
  })
  t.is(mirrored.ok, true)

  const republished = await runFederationManagementAction({
    action: 'republish',
    body: {
      appKey: 'A'.repeat(64),
      sourceUrl: ' https://source.example ',
      sourcePubkey: 'C'.repeat(64),
      channel: ' stable ',
      note: ' curated '
    },
    federation
  })
  t.is(republished.ok, true)

  const snap = federation.snapshot()
  t.is(snap.mirrored[0].url, 'https://relay.example')
  t.is(snap.mirrored[0].pubkey, 'b'.repeat(64))
  t.is(snap.republished[0].appKey, 'a'.repeat(64))
  t.is(snap.republished[0].sourceUrl, 'https://source.example')
  t.is(snap.republished[0].sourcePubkey, 'c'.repeat(64))
  t.is(snap.republished[0].channel, 'stable')
  t.is(snap.republished[0].note, 'curated')
})

test('api federation management: persistence failure restores snapshot', async (t) => {
  const federation = new Federation({})
  federation.follow('http://existing.example', { persist: false })
  federation.save = async () => {
    throw new Error('readonly federation volume')
  }

  const result = await runFederationManagementAction({
    action: 'follow',
    body: { url: 'http://new.example' },
    federation
  })

  t.is(result.ok, false)
  t.is(result.kind, 'federation-persist')
  t.is(result.error.message, 'readonly federation volume')
  const snap = federation.snapshot()
  t.is(snap.followed.length, 1)
  t.is(snap.followed[0].url, 'http://existing.example')
})

test('api federation management: federation validation failures roll back without save', async (t) => {
  const federation = new Federation({})
  let saveCalls = 0
  federation.save = async () => { saveCalls++ }

  const result = await runFederationManagementAction({
    action: 'republish',
    body: {
      appKey: 'd'.repeat(64),
      sourceUrl: 'javascript:alert(1)'
    },
    federation
  })

  t.is(result.ok, false)
  t.is(result.status, 400)
  t.ok(result.payload.error.startsWith('Federation:'))
  t.alike(federation.snapshot().republished, [])
  t.is(saveCalls, 0)
})

test('api federation management: rollback errors are emitted without hiding persistence failure', async (t) => {
  const restoreError = new Error('restore failed')
  const persistError = new Error('readonly federation volume')
  const events = []
  const federation = {
    snapshot: () => ({ followed: [] }),
    follow () {},
    async save () { throw persistError },
    restoreSnapshot () { throw restoreError }
  }

  const result = await runFederationManagementAction({
    action: 'follow',
    body: { url: 'https://relay.example' },
    federation,
    emit: (event, payload) => events.push({ event, payload })
  })

  t.is(result.ok, false)
  t.is(result.kind, 'federation-persist')
  t.is(result.error, persistError)
  t.is(events.length, 1)
  t.is(events[0].event, 'federation-rollback-error')
  t.is(events[0].payload.error, restoreError)
})

test('api federation management: snapshot payload sanitizes remote federation state', (t) => {
  const followed = [
    { url: 'https://relay-a.example', pubkey: 'A'.repeat(64), addedAt: 1, token: 'do-not-leak' },
    { url: 'https://user:pass@relay-secret.example', pubkey: 'b'.repeat(64), addedAt: 2 },
    { url: 'javascript:alert(1)', pubkey: 'c'.repeat(64), addedAt: 3 }
  ]
  for (let i = 0; i < MAX_FEDERATION_SNAPSHOT_RELAYS + 4; i++) {
    followed.push({
      url: `https://relay-${i}.example`,
      pubkey: (i % 16).toString(16).repeat(64),
      addedAt: i + 10
    })
  }

  const peerApps = [
    {
      appKey: 'D'.repeat(64),
      publisherPubkey: 'E'.repeat(64),
      type: 'app',
      privacyTier: 'public',
      storageClass: 'archive',
      availabilityClass: 'standard',
      blind: true,
      secretToken: 'do-not-leak-app'
    },
    { appKey: 'not-a-key', name: 'ignored', secret: 'hidden' }
  ]
  for (let i = 0; i < MAX_FEDERATION_SNAPSHOT_PEER_APPS + 4; i++) {
    peerApps.push({
      appKey: (i % 16).toString(16).repeat(64),
      publisherPubkey: 'f'.repeat(64),
      type: 'drive'
    })
  }

  const federation = {
    snapshot () {
      return {
        followed,
        mirrored: [
          { url: 'http://mirror.example', pubkey: 'B'.repeat(64), addedAt: 5, privateKey: 'hidden' },
          { url: 'file:///etc/passwd', pubkey: 'c'.repeat(64), addedAt: 6 }
        ],
        republished: [
          {
            appKey: 'C'.repeat(64),
            sourceUrl: 'https://source.example',
            sourcePubkey: 'D'.repeat(64),
            channel: 'stable',
            note: 'operator curated',
            addedAt: 7,
            secret: 'do-not-leak-note'
          },
          {
            appKey: 'E'.repeat(64),
            sourceUrl: 'https://user:pass@source-secret.example',
            sourcePubkey: 'not-a-key',
            channel: 'bad\nchannel',
            note: 'bad\nnote',
            addedAt: -1
          },
          { appKey: 'not-a-key', sourceUrl: 'https://ignored.example' }
        ],
        followIntervalMs: 30_000,
        running: true,
        peerCatalogs: [
          {
            url: 'https://peer.example',
            pubkey: 'F'.repeat(64),
            region: 'EU',
            operator: 'operator-a',
            fetchedAt: 8,
            apps: peerApps,
            secret: 'do-not-leak-peer'
          },
          { url: 'https://user:pass@peer-secret.example', apps: [] }
        ]
      }
    }
  }

  const result = buildFederationSnapshotPayload({ federation })
  t.is(result.ok, true)
  const payload = result.payload

  t.is(payload.followed.length, MAX_FEDERATION_SNAPSHOT_RELAYS)
  t.is(payload.followedTotal, MAX_FEDERATION_SNAPSHOT_RELAYS + 7)
  t.ok(payload.followedTruncated)
  t.alike(payload.followed[0], {
    url: 'https://relay-a.example',
    pubkey: 'a'.repeat(64),
    addedAt: 1
  })
  t.absent(payload.followed.some(entry => entry.url.includes('@')), 'credential URLs are omitted')

  t.alike(payload.mirrored, [{
    url: 'http://mirror.example',
    pubkey: 'b'.repeat(64),
    addedAt: 5
  }])
  t.is(payload.mirroredTotal, 2)
  t.ok(payload.mirroredTruncated)

  t.alike(payload.republished[0], {
    appKey: 'c'.repeat(64),
    sourceUrl: 'https://source.example',
    sourcePubkey: 'd'.repeat(64),
    channel: 'stable',
    note: 'operator curated',
    addedAt: 7
  })
  t.alike(payload.republished[1], {
    appKey: 'e'.repeat(64),
    sourceUrl: null,
    sourcePubkey: null,
    channel: null,
    note: null,
    addedAt: null
  })
  t.is(payload.republishedTotal, 3)
  t.ok(payload.republishedTruncated)

  t.is(payload.peerCatalogs.length, 1)
  t.is(payload.peerCatalogsTotal, 2)
  t.ok(payload.peerCatalogsTruncated)
  t.is(payload.peerCatalogs[0].apps.length, MAX_FEDERATION_SNAPSHOT_PEER_APPS)
  t.is(payload.peerCatalogs[0].appsTotal, MAX_FEDERATION_SNAPSHOT_PEER_APPS + 6)
  t.ok(payload.peerCatalogs[0].appsTruncated)
  t.alike(payload.peerCatalogs[0].apps[0], {
    appKey: 'd'.repeat(64),
    publisherPubkey: 'e'.repeat(64),
    type: 'app',
    privacyTier: 'public',
    storageClass: 'archive',
    availabilityClass: 'standard',
    blind: true
  })

  const json = JSON.stringify(payload)
  for (const hidden of ['do-not-leak', 'do-not-leak-app', 'do-not-leak-note', 'do-not-leak-peer', 'privateKey', 'secretToken', 'user:pass']) {
    t.absent(json.includes(hidden), hidden + ' omitted from federation snapshot')
  }
})
