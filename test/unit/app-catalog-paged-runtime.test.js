import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { mkdtemp, realpath, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  APP_CATALOG_LIMITS,
  createAppCatalogAbort,
  createAppCatalogAck,
  createAppCatalogPage,
  createAppCatalogSnapshotIdentity,
  createCanonicalCatalogRow,
  decodeAppCatalogFrame,
  encodeAppCatalogFrame
} from '../../packages/core/core/relay-node/app-catalog-paged.js'
import {
  AppCatalogCapabilitySession,
  AppCatalogInboundManager,
  AppCatalogMvccStore,
  AppCatalogOutboundManager,
  APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES,
  attachAppCatalogPagedChannel,
  guardAppCatalogMessageIds
} from '../../packages/core/core/relay-node/app-catalog-paged-runtime.js'
import { AppCatalogDiskStageFactory } from '../../packages/core/core/relay-node/app-catalog-paged-stage.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function pubkey (pair) {
  return b4a.toString(pair.publicKey, 'hex')
}

function record (name, overrides = {}) {
  const nibble = (name.charCodeAt(0) % 16).toString(16)
  return {
    appKey: nibble.repeat(64),
    appId: name,
    type: 'app',
    parentKey: null,
    mountPath: '/',
    version: '1.0.0',
    discoveryKey: ((parseInt(nibble, 16) + 1) % 16).toString(16).repeat(64),
    blind: false,
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    privacyTier: 'public',
    seededAt: 1,
    redacted: false,
    metadataVisibility: 'public',
    blindContentId: null,
    anchored: true,
    maxStorageBytes: 1024,
    publisherPubkey: ((parseInt(nibble, 16) + 2) % 16).toString(16).repeat(64),
    durability: 1,
    revocable: false,
    retainUntil: null,
    ...overrides
  }
}

function source (name, overrides = {}) {
  return { catalogPublic: true, record: record(name, overrides) }
}

function indexedHex (index, offset = 0) {
  return (BigInt(index) + BigInt(offset)).toString(16).padStart(64, '0')
}

function indexedSource (index, overrides = {}) {
  return source('i', {
    appKey: indexedHex(index, 1),
    discoveryKey: indexedHex(index, 1_000_001),
    publisherPubkey: indexedHex(index, 2_000_001),
    ...overrides
  })
}

function finishSnapshot (store, pair, budget = 128) {
  const build = store.beginDigest({ senderPubkey: pubkey(pair), budget })
  let result
  do result = build.step()
  while (!result.done)
  return result.snapshot
}

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
  return { promise, resolve, reject }
}

function memoryStageFactory (events = []) {
  return {
    async open (metadata) {
      const rows = []
      let discarded = false
      events.push(['open', metadata.snapshotId])
      return {
        async append (row) {
          rows.push(row)
          events.push(['append', row[0]])
        },
        async commit (snapshot) {
          events.push(['commit', snapshot.snapshotId])
          return Object.freeze({
            ...snapshot,
            async readPage ({ cursor = null, limit = 128 } = {}) {
              const eligible = rows.filter(row => cursor === null || row[0] > cursor)
              const entries = eligible.slice(0, limit)
              const complete = entries.length === eligible.length
              return Object.freeze({
                entries: Object.freeze(entries),
                complete,
                cursor: complete ? null : entries[entries.length - 1][0]
              })
            }
          })
        },
        async discard () {
          discarded = true
          events.push(['discard'])
        },
        get discarded () { return discarded }
      }
    }
  }
}

function retainedMemoryStageFactory (state) {
  return {
    async open () {
      const rows = []
      return {
        async append (row) { rows.push(row) },
        async commit (snapshot) {
          const createHandle = () => {
            let released = false
            state.references++
            return {
              ...snapshot,
              get released () { return released },
              acquire () {
                if (released) throw new Error('released catalog')
                return createHandle()
              },
              async release () {
                if (released) return false
                released = true
                state.references--
                state.releases++
                return true
              },
              async readPage () {
                if (released) throw new Error('released catalog')
                return { entries: rows, complete: true, cursor: null }
              }
            }
          }
          return createHandle()
        },
        async discard () {}
      }
    }
  }
}

function gatedMemoryStageFactory (boundary, entered, gate, events) {
  const wait = async name => {
    if (boundary !== name) return
    entered.resolve()
    await gate.promise
  }
  return {
    async open () {
      events.push('open-start')
      await wait('open')
      events.push('open-end')
      let released = false
      return {
        async append () {
          events.push('append-start')
          await wait('append')
          events.push('append-end')
        },
        async commit (snapshot) {
          events.push('commit-start')
          await wait('commit')
          events.push('commit-end')
          return {
            ...snapshot,
            async readPage () { return { entries: [], complete: true, cursor: null } },
            async release () {
              if (released) return false
              released = true
              events.push('release')
              return true
            }
          }
        },
        async discard () { events.push('discard') }
      }
    }
  }
}

function retryingDiscardStageFactory (state) {
  return {
    async open () {
      const stage = {
        rows: [],
        discarded: false,
        _discard: null,
        async append (row) { this.rows.push(row) },
        async commit () { throw new Error('partial test stage must not commit') },
        discard () {
          if (this._discard !== null) return this._discard
          const attempt = (async () => {
            state.discardCalls++
            if (state.discardCalls <= state.failures) throw new Error('forced retained discard failure')
            this.discarded = true
          })()
          this._discard = attempt
          attempt.catch(() => {
            if (this._discard === attempt) this._discard = null
          })
          return attempt
        }
      }
      state.stage = stage
      return stage
    }
  }
}

test('capability proof is mutual, channel-fresh, single-use, and time-bound', (t) => {
  const alice = keyPair()
  const bob = keyPair()
  let now = 10_000
  const a = new AppCatalogCapabilitySession({
    keyPair: alice,
    remotePubkey: bob.publicKey,
    now: () => now,
    randomBytes: size => b4a.alloc(size, 0x11)
  })
  const b = new AppCatalogCapabilitySession({
    keyPair: bob,
    remotePubkey: alice.publicKey,
    now: () => now,
    randomBytes: size => b4a.alloc(size, 0x22)
  })
  const aProof = a.createProof(b.challenge())
  const bProof = b.createProof(a.challenge())
  a.markProofSent(aProof)
  b.markProofSent(bProof)
  t.is(a.verifyPeerProof(bProof), true)
  t.is(b.verifyPeerProof(aProof), true)
  t.is(a.ready, true)
  t.is(b.ready, true)
  t.exception(() => a.verifyPeerProof(bProof), /already accepted/)

  const expired = new AppCatalogCapabilitySession({
    keyPair: alice,
    remotePubkey: bob.publicKey,
    now: () => now,
    randomBytes: size => b4a.alloc(size, 0x33)
  })
  now += APP_CATALOG_LIMITS.negotiationTimeoutMs + 1
  t.exception(() => expired.challenge(), /negotiation expired/)
})

test('MVCC snapshot survives concurrent mutation and expires before required history eviction', (t) => {
  const relay = keyPair()
  const store = new AppCatalogMvccStore({ maxHistoryRecords: 4, maxHistoryBytes: 1_000_000 })
  store.put('a', source('a'))
  store.put('b', source('b'))
  const beforeRows = [
    createCanonicalCatalogRow(record('a')),
    createCanonicalCatalogRow(record('b'))
  ]
  const expected = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(relay), highWater: 2, rows: beforeRows })
  const build = store.beginDigest({ senderPubkey: pubkey(relay), budget: 1 })
  t.is(build.step().done, false)
  store.put('a', source('a', { version: '2.0.0' }))
  const completed = build.step()
  t.is(completed.done, true)
  t.is(completed.snapshot.highWater, 2)
  t.is(completed.snapshot.rootDigest, expected.rootDigest, 'digest resolves rows at frozen H')

  const tight = new AppCatalogMvccStore({ maxHistoryRecords: 1, maxHistoryBytes: 1_000_000 })
  tight.put('a', source('a'))
  const doomed = tight.beginDigest({ senderPubkey: pubkey(relay), budget: 1 })
  tight.put('b', source('b'))
  tight.put('c', source('c'))
  t.exception(() => doomed.step(), /history expired/)
})

test('MVCC rejects source cap and terminal row-key collisions before mutation', (t) => {
  const capped = new AppCatalogMvccStore({ maxSources: 1 })
  t.is(capped.put('one', source('a')).changed, true)
  const unchanged = capped.put('one', source('a'))
  t.is(unchanged.changed, false, 'an unchanged projection is idempotent')
  t.is(unchanged.revision, 1)
  t.exception(() => capped.put('two', source('b')), /source cap/)
  t.is(capped.lastCatalogRevision, 1, 'rejected source does not consume a revision')

  const collision = new AppCatalogMvccStore()
  const drive = source('d', { type: 'drive', appId: null, version: '1.0.0' })
  collision.put('one', drive)
  t.exception(() => collision.put('two', {
    catalogPublic: true,
    record: { ...drive.record, version: '2.0.0' }
  }), /row-key collision/)
  t.is(collision.lastCatalogRevision, 1, 'collision fails before mutation')

  const excluded = new AppCatalogMvccStore({ maxSources: 1 })
  excluded.put('private', { catalogPublic: false, record: null })
  t.is(excluded.size, 0)
  t.is(excluded.excludedRows, 1)
  t.exception(() => excluded.put('second', source('b')), /source cap/)
})

test('MVCC duplicate winner index remains logarithmic and reveals successors', (t) => {
  const count = 8_192
  const store = new AppCatalogMvccStore({ maxSources: count })
  const before = store.indexMetrics.groupComparisons
  for (let i = 0; i < count; i++) {
    store.put(`duplicate-${i}`, indexedSource(i, { appId: 'one-shared-app', version: `1.0.${i}` }))
  }
  const insertedComparisons = store.indexMetrics.groupComparisons - before
  t.ok(insertedComparisons < count * 64, 'duplicate insertion performs bounded logarithmic comparisons')
  let page = store.readSnapshotPage({ highWater: store.lastCatalogRevision, limit: 1 })
  t.is(page.rows.length, 1)
  t.is(page.rows[0][6], `1.0.${count - 1}`)

  store.put('duplicate-0', indexedSource(0, { appId: 'one-shared-app', version: '2.0.0' }))
  page = store.readSnapshotPage({ highWater: store.lastCatalogRevision, limit: 1 })
  t.is(page.rows[0][6], '2.0.0', 'an updated source replaces the winner')
  store.delete('duplicate-0')
  page = store.readSnapshotPage({ highWater: store.lastCatalogRevision, limit: 1 })
  t.is(page.rows[0][6], `1.0.${count - 1}`, 'deleting the winner reveals the next index entry')
  store.delete(`duplicate-${count - 1}`)
  page = store.readSnapshotPage({ highWater: store.lastCatalogRevision, limit: 1 })
  t.is(page.rows[0][6], `1.0.${count - 2}`)
  t.ok(store.indexMetrics.groupComparisons - before < (count + 3) * 64, 'winner replacement and deletes stay inside the logarithmic work bound')
})

test('MVCC randomized row-key insert, identity update, and delete stay logarithmic', (t) => {
  const count = 8_192
  const store = new AppCatalogMvccStore({ maxSources: count })
  const before = store.indexMetrics.rowComparisons
  for (let i = 0; i < count; i++) {
    store.put(`unique-${i}`, indexedSource(i, { appId: null, type: 'drive' }))
  }
  const afterInsert = store.indexMetrics.rowComparisons
  t.is(store.size, count)
  t.ok(afterInsert - before < count * 64, 'randomized canonical row keys do not shift a flat population array')

  let cursor = null
  let visited = 0
  let ordered = true
  let prior = null
  let scans = 0
  while (true) {
    const page = store.readSnapshotPage({ highWater: store.lastCatalogRevision, cursor, limit: 500 })
    scans++
    for (const row of page.rows) {
      if (prior !== null && row[0] <= prior) ordered = false
      prior = row[0]
      visited++
    }
    if (page.complete) break
    cursor = page.lastRowKey
  }
  const afterScan = store.indexMetrics.rowComparisons
  t.is(visited, count)
  t.is(ordered, true, 'bounded cursor pages traverse the index in canonical order')
  t.ok(afterScan - afterInsert < scans * 64, 'each page performs one logarithmic cursor seek and linear local traversal')

  for (let i = 0; i < count; i += 8) {
    store.put(`unique-${i}`, indexedSource(i + count, { appId: null, type: 'drive' }))
  }
  const afterUpdate = store.indexMetrics.rowComparisons
  t.ok(afterUpdate - afterScan < (count / 8) * 128, 'identity-changing updates use bounded remove and insert operations')

  for (let i = 0; i < count; i++) {
    const sourceIndex = (i * 4_051) % count
    store.delete(`unique-${sourceIndex}`)
  }
  const afterDelete = store.indexMetrics.rowComparisons
  t.is(store.size, 0)
  t.ok(afterDelete - afterUpdate < count * 64, 'random-order deletes remain logarithmic')
})

test('history churn clears a published snapshot before the next digest completes', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore({ maxHistoryRecords: 2, maxHistoryBytes: 1_000_000 })
  store.put('a', source('a'))
  const snapshot = finishSnapshot(store, relay)
  const manager = new AppCatalogOutboundManager({ store, keyPair: relay, autoDeadlineSweep: false })
  const active = manager.open(peer.publicKey, snapshot)

  store.put('b', source('b'))
  store.put('c', source('c'))
  store.put('d', source('d'))
  t.is(store.publishedSnapshot, null, 'status cannot expose an expired completed tuple')
  t.is(active.issuePage().abort.code, 'HISTORY_EXPIRED', 'the retained outbound reader terminates exactly')
  t.exception(() => store.readExternalPage({ cursor: null, keyPair: relay }), /no completed catalog snapshot/)
  t.exception(() => manager.open(keyPair().publicKey), /no completed catalog snapshot/)
  await manager.stop()
})

test('256 outbound sessions retain one bounded digest-reader slot', async (t) => {
  const relay = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  const snapshot = finishSnapshot(store, relay)
  const manager = new AppCatalogOutboundManager({ store, keyPair: relay, autoDeadlineSweep: false })
  for (let i = 0; i < APP_CATALOG_LIMITS.maxOutboundPeers; i++) {
    manager.open(i.toString(16).padStart(64, '0'), snapshot)
  }
  t.is(manager.sessions.size, APP_CATALOG_LIMITS.maxOutboundPeers)
  const build = store.beginDigest({ senderPubkey: pubkey(relay), budget: 1 })
  t.exception(() => store.beginDigest({ senderPubkey: pubkey(relay), budget: 1 }), /digest reader slot/)
  t.is(build.step().done, true, 'digest progresses at the exact outbound cap')
  await manager.stop()
})

test('stateless external cursor keeps its retained high-water after a newer snapshot', (t) => {
  const relay = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  store.put('b', source('b'))
  const first = finishSnapshot(store, relay, 1)
  const page1 = store.readExternalPage({ cursor: null, limit: 1, keyPair: relay })
  t.is(page1.snapshot.snapshotId, first.snapshotId)
  t.ok(page1.cursor)

  store.put('c', source('c'))
  const second = finishSnapshot(store, relay, 1)
  t.unlike(second.snapshotId, first.snapshotId)
  const page2 = store.readExternalPage({ cursor: page1.cursor, limit: 1, keyPair: relay })
  t.is(page2.snapshot.snapshotId, first.snapshotId, 'old cursor never restarts on the newer H')
  t.is(page2.entries.length, 1)
})

test('outbound dirty rollover retains exact terminal ACK receipt', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  const first = finishSnapshot(store, relay)
  const manager = new AppCatalogOutboundManager({ store, keyPair: relay, autoDeadlineSweep: false })
  const original = manager.open(peer.publicKey, first)
  const issued = original.issuePage()

  store.put('b', source('b'))
  const second = finishSnapshot(store, relay)
  t.is(manager.open(peer.publicKey, second), original, 'additional trigger coalesces on active session')
  const ack = createAppCatalogAck(issued.page, peer)
  t.is(manager.acceptAck(peer.publicKey, ack).status, 'complete')
  const replacement = manager.sessions.get(pubkey(peer))
  t.not(replacement, original)
  t.is(replacement.snapshot.snapshotId, second.snapshotId, 'one newest completed snapshot starts after dirty completion')
  t.is(manager.acceptAck(peer.publicKey, ack).status, 'duplicate', 'terminal ACK receipt remains routable')

  const wrong = { ...ack, signature: '0'.repeat(128) }
  const rejected = manager.acceptAck(peer.publicKey, wrong)
  t.is(rejected.status, 'aborted')
  t.is(rejected.abort.code, 'PROTOCOL_ERROR')
  await manager.stop()
})

test('runTurn treats Protomux boolean sends as delivery state, never ACKs', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  const manager = new AppCatalogOutboundManager({ store, keyPair: relay, autoDeadlineSweep: false })
  const session = manager.open(peer.publicKey, finishSnapshot(store, relay))
  const sent = await manager.runTurn(peer.publicKey, () => true)
  t.is(sent.status, 'sent')
  t.is(session.abort, null)
  const outstanding = session.outstanding
  const backpressure = await manager.runTurn(peer.publicKey, () => false)
  t.is(backpressure.status, 'backpressure')
  t.is(session.abort, null)
  t.is(session.outstanding, outstanding, 'both sends leave the PAGE awaiting an asynchronous ACK')
  await manager.stop()
})

test('verified remote ABORT retires only its outbound session without a reciprocal ABORT', async (t) => {
  const relay = keyPair()
  const firstPeer = keyPair()
  const secondPeer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  const snapshot = finishSnapshot(store, relay)
  let sentAborts = 0
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    autoDeadlineSweep: false,
    sendAbort: () => { sentAborts++ }
  })
  manager.open(firstPeer.publicKey, snapshot).issuePage()
  const firstAbort = createAppCatalogAbort({
    receiverPubkey: pubkey(relay),
    snapshotId: snapshot.snapshotId,
    code: 'RESOURCE_LIMIT'
  }, firstPeer)
  t.is(manager.acceptAbort(firstPeer.publicKey, firstAbort).status, 'closed')
  t.is(manager.acceptAbort(firstPeer.publicKey, firstAbort).status, 'duplicate')
  t.is(sentAborts, 0)

  manager.open(secondPeer.publicKey, snapshot).issuePage()
  const wrong = createAppCatalogAbort({
    receiverPubkey: pubkey(relay),
    snapshotId: 'f'.repeat(64),
    code: 'SNAPSHOT_MISMATCH'
  }, secondPeer)
  t.is(manager.acceptAbort(secondPeer.publicKey, wrong).status, 'mismatch')
  t.is(manager.acceptAbort(secondPeer.publicKey, { ...wrong, signature: '0'.repeat(128) }).status, 'mismatch')
  t.ok(manager.sessions.has(pubkey(secondPeer)), 'mismatch cannot retire a different snapshot')
  const matching = createAppCatalogAbort({
    receiverPubkey: pubkey(relay),
    snapshotId: snapshot.snapshotId,
    code: 'SNAPSHOT_MISMATCH'
  }, secondPeer)
  t.is(manager.acceptAbort(secondPeer.publicKey, matching).status, 'closed')
  t.is(sentAborts, 0, 'remote ABORT never produces a reciprocal ABORT')
  await manager.stop()
  t.is(manager.acceptAck(secondPeer.publicKey, {}).status, 'stopped', 'ACK routing is fenced after stop')
  t.is(manager.acceptAbort(secondPeer.publicKey, matching).status, 'stopped', 'ABORT routing is fenced after stop')
})

test('history eviction hands off signed ABORT before outbound session closes', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore({ maxHistoryRecords: 1, maxHistoryBytes: 1_000_000 })
  store.put('a', source('a'))
  const snapshot = finishSnapshot(store, relay)
  const gate = deferred()
  const sent = []
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    autoDeadlineSweep: false,
    sendAbort: async (peerKey, abort) => {
      sent.push([peerKey, abort])
      await gate.promise
    }
  })
  const session = manager.open(peer.publicKey, snapshot)
  session.issuePage()
  store.put('b', source('b'))
  store.put('c', source('c'))
  t.is(sent.length, 1, 'signed abort handed to transport during eviction')
  t.is(sent[0][1].code, 'HISTORY_EXPIRED')
  t.is(session.closed, false, 'session stays alive until abort delivery settles')
  gate.resolve()
  await session.abortDelivery
  t.is(session.closed, true, 'session closes only after abort delivery')
})

test('dirty history expiry delivers ABORT before repumping the retained newer snapshot', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore({ maxHistoryRecords: 1, maxHistoryBytes: 1_000_000 })
  store.put('a', source('a'))
  const first = finishSnapshot(store, relay)
  const events = []
  let replacementPage = null
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    autoDeadlineSweep: false,
    sendAbort: async (peerKey, abort) => {
      events.push(['abort', peerKey, abort.code, abort.snapshotId])
    },
    onSessionReady: (peerKey, session, details) => {
      events.push(['ready', peerKey, details.reason, session.snapshot.snapshotId])
      replacementPage = session.issuePage().page
      events.push(['page', replacementPage.snapshotId])
    }
  })
  const old = manager.open(peer.publicKey, first)
  old.issuePage()

  store.put('b', source('b'))
  const newer = finishSnapshot(store, relay)
  manager.open(peer.publicKey, newer)
  t.is(old.dirty, true)
  store.put('c', source('c'))
  await old.abortDelivery

  const replacement = manager.sessions.get(pubkey(peer))
  t.is(old.closed, true)
  t.is(replacement.snapshot.snapshotId, newer.snapshotId)
  t.alike(events.map(event => event[0]), ['abort', 'ready', 'page'], 'signed ABORT delivery precedes replacement pump notification')
  t.is(events[0][2], 'HISTORY_EXPIRED')
  t.is(events[0][3], first.snapshotId)
  t.is(replacementPage.snapshotId, newer.snapshotId)
  await manager.stop()
})

test('ACK deadline sweep retransmits identical PAGE twice then sends one ABORT', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  const snapshot = finishSnapshot(store, relay)
  let now = 0
  const pages = []
  const aborts = []
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    now: () => now,
    deadlineSweepMs: 1,
    sendPage: async (peerKey, page) => pages.push([peerKey, JSON.stringify(page)]),
    sendAbort: async (peerKey, abort) => aborts.push([peerKey, abort])
  })
  const session = manager.open(peer.publicKey, snapshot)
  const original = session.issuePage()
  now = APP_CATALOG_LIMITS.ackTimeoutMs
  await new Promise(resolve => setTimeout(resolve, 8))
  now += APP_CATALOG_LIMITS.ackTimeoutMs
  await new Promise(resolve => setTimeout(resolve, 8))
  now += APP_CATALOG_LIMITS.ackTimeoutMs
  await new Promise(resolve => setTimeout(resolve, 8))
  t.is(pages.length, 2)
  t.ok(pages.every(([, bytes]) => bytes === JSON.stringify(original.page)), 'retries are byte-identical')
  t.is(aborts.length, 1, 'retry exhaustion sends one ABORT')
  t.is(aborts[0][1].code, 'RESOURCE_LIMIT')
  t.is(session.closed, true)
  await manager.stop()
})

test('automatic ACK sweep is one-flight and stop drains a stalled delivery', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  const snapshot = finishSnapshot(store, relay)
  const delivery = deferred()
  let calls = 0
  let now = 0
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    now: () => now,
    deadlineSweepMs: 1,
    sendPage: async () => {
      calls++
      await delivery.promise
    }
  })
  const session = manager.open(peer.publicKey, snapshot)
  session.issuePage()
  now = APP_CATALOG_LIMITS.ackTimeoutMs
  await new Promise(resolve => setTimeout(resolve, 8))
  t.is(calls, 1, 'no second sweep overlaps a stalled delivery')

  let stopped = false
  const stopping = manager.stop().then(() => { stopped = true })
  await Promise.resolve()
  t.is(stopped, false, 'stop waits for the active deadline flight')
  delivery.resolve()
  await stopping
  t.is(stopped, true)
})

test('outbound manager stop is bounded when an injected delivery never settles', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  let now = 0
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    now: () => now,
    deadlineSweepMs: 1,
    stopDrainTimeoutMs: 5,
    sendPage: async () => new Promise(() => {})
  })
  manager.open(peer.publicKey, finishSnapshot(store, relay)).issuePage()
  now = APP_CATALOG_LIMITS.ackTimeoutMs
  await new Promise(resolve => setTimeout(resolve, 8))
  await manager.stop()
  t.pass('stop returns after its bounded delivery-drain timeout')
})

test('a timed-out deadline flight cannot resume onto another peer after stop', async (t) => {
  const relay = keyPair()
  const firstPeer = keyPair()
  const secondPeer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  const delivery = deferred()
  const sends = []
  let now = 0
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    now: () => now,
    deadlineSweepMs: 1,
    stopDrainTimeoutMs: 5,
    sendPage: async peer => {
      sends.push(peer)
      await delivery.promise
    }
  })
  const snapshot = finishSnapshot(store, relay)
  const first = manager.open(firstPeer.publicKey, snapshot)
  const second = manager.open(secondPeer.publicKey, snapshot)
  first.issuePage()
  second.issuePage()
  now = APP_CATALOG_LIMITS.ackTimeoutMs
  await new Promise(resolve => setTimeout(resolve, 8))
  t.alike(sends, [pubkey(firstPeer)], 'the first retransmit owns the only in-flight transport write')
  const flight = manager._deadlineFlight

  await manager.stop()
  t.is(second.retryCount, 0, 'stop did not advance the next peer')
  t.is(manager.sessions.size, 0)
  delivery.resolve()
  await flight
  await new Promise(resolve => setTimeout(resolve, 8))
  t.alike(sends, [pubkey(firstPeer)], 'the stale flight never sends the next peer')
  t.is(second.retryCount, 0, 'the stale flight never mutates the next session')
  t.is(manager._deadlineTimer, null, 'the stale flight cannot re-arm the timer')
  t.is(manager._deadlineFlight, null)
})

test('outbound manager stop bounded-drains a never-settling ABORT delivery', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const store = new AppCatalogMvccStore()
  store.put('a', source('a'))
  let sends = 0
  const manager = new AppCatalogOutboundManager({
    store,
    keyPair: relay,
    autoDeadlineSweep: false,
    stopDrainTimeoutMs: 5,
    sendAbort: async () => {
      sends++
      return new Promise(() => {})
    }
  })
  manager.open(peer.publicKey, finishSnapshot(store, relay))
  await manager.stop()
  t.is(sends, 1)
  t.is(manager.sessions.size, 0)
})

test('inbound commit publishes once and closed receipt requires the exact verified PAGE', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const rows = [createCanonicalCatalogRow(record('a'))]
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: rows
  }, peer)
  const events = []
  const completed = []
  const manager = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: memoryStageFactory(events),
    onComplete: result => completed.push(result)
  })
  const ack = await manager.receivePage(peer.publicKey, page)
  t.is(completed.length, 1)
  t.ok(events.find(event => event[0] === 'commit'))
  const committedPage = await completed[0].catalog.readPage()
  t.alike(committedPage.entries, rows)

  const duplicate = await manager.receivePage(peer.publicKey, page)
  t.alike(duplicate, ack)
  t.is(completed.length, 1, 'exact retransmit does not repeat action pass')
  await t.exception(manager.receivePage(peer.publicKey, { ...page, signature: '0'.repeat(128) }), /signature is invalid/)
  t.is(manager.sessions.size, 1, 'unverified page cannot rotate terminal receipt')
  await manager.stop()
})

test('inbound completion permits synchronous action-handle acquisition before releasing its handle', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const rows = [createCanonicalCatalogRow(record('a'))]
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: rows
  }, peer)
  const state = { references: 0, releases: 0 }
  let original = null
  let action = null
  const manager = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: retainedMemoryStageFactory(state),
    onComplete: async ({ catalog }) => {
      original = catalog
      action = catalog.acquire()
      t.ok(action !== catalog, 'acquire synchronously returns a distinct action-owned handle')
      await Promise.resolve()
      t.is(state.references, 2, 'the inbound and action handles coexist through the callback')
    }
  })
  await manager.receivePage(peer.publicKey, page)
  t.is(original.released, true, 'inbound releases its original only after callback settlement')
  t.is(action.released, false)
  t.is(state.references, 1)
  t.alike((await action.readPage()).entries, rows)
  t.is(await action.release(), true)
  t.is(await action.release(), false, 'action release is asynchronous and idempotent')
  t.is(state.references, 0)
  t.is(state.releases, 2)
  await manager.stop()
})

test('closed inbound receipt rejects semantically equal PAGE bytes with alternate whitespace', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const rows = [createCanonicalCatalogRow(record('a'))]
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: rows
  }, peer)
  const canonical = decodeAppCatalogFrame(encodeAppCatalogFrame(page))
  const alternatePayload = b4a.from(JSON.stringify(page, null, 1), 'utf8')
  const alternateFrame = b4a.alloc(4 + alternatePayload.byteLength)
  alternateFrame.writeUInt32BE(alternatePayload.byteLength, 0)
  alternatePayload.copy(alternateFrame, 4)
  const alternate = decodeAppCatalogFrame(alternateFrame)
  const manager = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: memoryStageFactory()
  })
  await manager.receivePage(peer.publicKey, canonical)
  await t.exception(manager.receivePage(peer.publicKey, alternate), /byte-exact retransmit/)
  await manager.stop()
})

test('inbound staging caps include fixed metadata, row prefix, and index record', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const row = createCanonicalCatalogRow(record('a'))
  const recordBytes = b4a.byteLength(JSON.stringify(row))
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows: [row] })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: [row]
  }, peer)
  const requiredBytes = APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES + 4 + 72 + recordBytes
  const sessionEvents = []
  const sessionCapped = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: memoryStageFactory(sessionEvents),
    maxSessionBytes: requiredBytes - 1
  })
  await t.exception(sessionCapped.receivePage(peer.publicKey, page), /session cap reached/)
  t.is(sessionCapped.stagingBytes, 0)
  t.ok(sessionEvents.find(event => event[0] === 'discard'))

  const processEvents = []
  const processCapped = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: memoryStageFactory(processEvents),
    maxSessionBytes: requiredBytes,
    maxStagingBytes: requiredBytes - 1
  })
  await t.exception(processCapped.receivePage(peer.publicKey, page), /process-wide/)
  t.is(processCapped.stagingBytes, 0)
  t.ok(processEvents.find(event => event[0] === 'discard'))

  const exact = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: memoryStageFactory(),
    maxSessionBytes: requiredBytes,
    maxStagingBytes: requiredBytes
  })
  const ack = await exact.receivePage(peer.publicKey, page)
  t.is(ack.pageDigest, page.pageDigest, 'exact accounted-byte boundary is admitted')
  t.is(exact.stagingBytes, 0, 'committed staging reservation is released')
  await exact.stop()
})

test('closePeer drains inbound open and append boundaries before discard and suppresses commit or ACK', async (t) => {
  for (const boundary of ['open', 'append']) {
    const relay = keyPair()
    const peer = keyPair()
    const rows = [createCanonicalCatalogRow(record(boundary))]
    const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
    const page = createAppCatalogPage({
      receiverPubkey: pubkey(relay),
      ...snapshot,
      sequence: 0,
      cursor: null,
      nextCursor: null,
      complete: true,
      entries: rows
    }, peer)
    const entered = deferred()
    const gate = deferred()
    const events = []
    let completed = 0
    const manager = new AppCatalogInboundManager({
      keyPair: relay,
      stageFactory: gatedMemoryStageFactory(boundary, entered, gate, events),
      onComplete: () => { completed++ }
    })
    const receiveResult = manager.receivePage(peer.publicKey, page).catch(err => err)
    await entered.promise
    let closed = false
    const closing = manager.closePeer(peer.publicKey).then(() => { closed = true })
    await Promise.resolve()
    t.is(closed, false, `${boundary}: close waits for the receive-owned filesystem boundary`)
    gate.resolve()
    t.is((await receiveResult).code, 'RESOURCE_LIMIT', `${boundary}: stopped receive returns no ACK`)
    await closing
    t.is(completed, 0, `${boundary}: stopped receive invokes no completion callback`)
    t.absent(events.find(event => event === 'commit-start'), `${boundary}: commit is fenced before invocation`)
    t.ok(events.includes('discard'), `${boundary}: cleanup runs only after the receive drains`)
    t.is(manager.sessions.size, 0)
    t.is(manager.stagingBytes, 0)
    await manager.stop()
  }
})

test('idle sweep and remote ABORT serialize behind an inbound commit and preserve their signed abort', async (t) => {
  for (const mode of ['sweep', 'abort']) {
    const relay = keyPair()
    const peer = keyPair()
    const rows = [createCanonicalCatalogRow(record(mode))]
    const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
    const page = createAppCatalogPage({
      receiverPubkey: pubkey(relay),
      ...snapshot,
      sequence: 0,
      cursor: null,
      nextCursor: null,
      complete: true,
      entries: rows
    }, peer)
    const entered = deferred()
    const gate = deferred()
    const events = []
    let completed = 0
    const manager = new AppCatalogInboundManager({
      keyPair: relay,
      stageFactory: gatedMemoryStageFactory('commit', entered, gate, events),
      now: () => 0,
      onComplete: () => { completed++ }
    })
    const session = manager.open(peer.publicKey)
    const receiveResult = manager.receivePage(peer.publicKey, page).catch(err => err)
    await entered.promise
    let terminationSettled = false
    let expectedAbort = null
    let termination
    if (mode === 'sweep') {
      termination = manager.sweep(APP_CATALOG_LIMITS.inboundIdleTimeoutMs + 1)
    } else {
      expectedAbort = createAppCatalogAbort({
        receiverPubkey: pubkey(relay),
        snapshotId: snapshot.snapshotId,
        code: 'PROTOCOL_ERROR'
      }, peer)
      termination = manager.receiveAbort(peer.publicKey, expectedAbort)
    }
    const terminated = termination.then(result => {
      terminationSettled = true
      return result
    })
    await Promise.resolve()
    t.is(terminationSettled, false, `${mode}: termination waits for the receive-owned commit`)
    t.absent(events.find(event => event === 'discard'), `${mode}: discard never races pointer publication`)
    gate.resolve()
    t.is((await receiveResult).code, 'RESOURCE_LIMIT', `${mode}: terminal ACK is suppressed`)
    const terminationResult = await terminated
    if (mode === 'sweep') t.is(terminationResult, 1)
    else t.alike(terminationResult, expectedAbort)
    t.is(session.abort.code, mode === 'sweep' ? 'RESOURCE_LIMIT' : 'PROTOCOL_ERROR')
    t.alike(events.slice(-3), ['commit-end', 'release', 'discard'], `${mode}: commit settles before release and discard`)
    t.is(completed, 0)
    t.is(manager.sessions.size, 0)
    t.is(manager.stagingBytes, 0)
    await manager.stop()
  }
})

test('manager stop at the snapshot-to-pointer barrier drains one exact authority without a dangling pointer or ACK', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const rows = [createCanonicalCatalogRow(record('disk-stop'))]
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: rows
  }, peer)
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-inbound-stop-')))
  const pointerEntered = deferred()
  const pointerGate = deferred()
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    beforePointerRename: async () => {
      pointerEntered.resolve()
      await pointerGate.promise
    }
  })
  t.teardown(async () => {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  })
  let completed = 0
  const manager = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: factory,
    onComplete: () => { completed++ }
  })
  const receiveResult = manager.receivePage(peer.publicKey, page).catch(err => err)
  await pointerEntered.promise
  const stopping = manager.stop()
  t.is(manager.stop(), stopping, 'concurrent stop callers share the exact drain promise')
  let stopped = false
  stopping.then(() => { stopped = true })
  await Promise.resolve()
  t.is(stopped, false, 'stop cannot settle while commit owns the renamed snapshot')
  pointerGate.resolve()
  t.is((await receiveResult).code, 'RESOURCE_LIMIT', 'stop winner suppresses the terminal ACK')
  await stopping
  t.is(completed, 0, 'stop winner suppresses completion publication')
  t.is(manager.sessions.size, 0)
  t.is(manager.stagingBytes, 0)

  const committed = await factory.openCommittedPeer(pubkey(peer))
  t.ok(committed, 'pointer publication remains authoritative after the drained commit')
  t.alike((await committed.readPage({ limit: 1 })).entries, rows, 'published pointer never dangles')
  await committed.release()
})

test('stop, remote ABORT, and expiry retain failed discard sessions and exact byte ownership for retry', async (t) => {
  for (const mode of ['stop', 'abort', 'expiry']) {
    const relay = keyPair()
    const peer = keyPair()
    const rows = [
      createCanonicalCatalogRow(record(`${mode}-a`)),
      createCanonicalCatalogRow(record(`${mode}-b`))
    ].sort((left, right) => left[0].localeCompare(right[0]))
    const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
    const page = createAppCatalogPage({
      receiverPubkey: pubkey(relay),
      ...snapshot,
      sequence: 0,
      cursor: null,
      nextCursor: rows[0][0],
      complete: false,
      entries: [rows[0]]
    }, peer)
    const state = { failures: 1, discardCalls: 0, stage: null }
    const manager = new AppCatalogInboundManager({
      keyPair: relay,
      stageFactory: retryingDiscardStageFactory(state),
      now: () => 0
    })
    const ack = await manager.receivePage(peer.publicKey, page)
    t.is(ack.pageDigest, page.pageDigest, `${mode}: partial page remains staged and ACKed`)
    const session = manager.sessions.get(pubkey(peer))
    const ownedBytes = manager.stagingBytes
    t.ok(ownedBytes > APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES)

    let first
    if (mode === 'stop') {
      first = manager.stop()
      t.is(manager.stop(), first, 'stop: concurrent callers share the current exact attempt')
    } else if (mode === 'abort') {
      const abort = createAppCatalogAbort({
        receiverPubkey: pubkey(relay),
        snapshotId: snapshot.snapshotId,
        code: 'PROTOCOL_ERROR'
      }, peer)
      first = manager.receiveAbort(peer.publicKey, abort)
    } else {
      first = manager.sweep(APP_CATALOG_LIMITS.inboundIdleTimeoutMs + 1)
    }
    await t.exception(first, /retained discard failure/)
    t.is(manager.sessions.get(pubkey(peer)), session, `${mode}: exact session remains terminal owner`)
    t.is(manager.stagingBytes, ownedBytes, `${mode}: failed cleanup retains reserved bytes`)
    t.is(session.stagedBytes, ownedBytes, `${mode}: session accounting remains exact`)
    t.is(state.stage.discarded, false)

    if (mode === 'stop') {
      await manager.stop()
    } else if (mode === 'abort') {
      await manager.receiveAbort(peer.publicKey, session.abort)
    } else {
      t.is(await manager.sweep(APP_CATALOG_LIMITS.inboundIdleTimeoutMs + 1), 1)
    }
    t.is(state.discardCalls, 2, `${mode}: retry targets the same stage once`)
    t.is(state.stage.discarded, true)
    t.is(manager.sessions.size, 0)
    t.is(manager.stagingBytes, 0)
    await manager.stop()
  }
})

test('append-stop race retains the appended row reservation until failed discard retries', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const rows = [createCanonicalCatalogRow(record('append-stop-accounting'))]
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: rows
  }, peer)
  const appendEntered = deferred()
  const appendGate = deferred()
  let discardCalls = 0
  const stageFactory = {
    async open () {
      return {
        async append () {
          appendEntered.resolve()
          await appendGate.promise
        },
        async commit () { throw new Error('commit must remain fenced') },
        async discard () {
          discardCalls++
          if (discardCalls === 1) throw new Error('forced append-race discard failure')
        }
      }
    }
  }
  const manager = new AppCatalogInboundManager({ keyPair: relay, stageFactory })
  const receiving = manager.receivePage(peer.publicKey, page).catch(err => err)
  await appendEntered.promise
  const firstStop = manager.stop()
  appendGate.resolve()
  t.is((await receiving).code, 'RESOURCE_LIMIT')
  await t.exception(firstStop, /append-race discard failure/)
  const rowBytes = 4 + 72 + b4a.byteLength(JSON.stringify(rows[0]))
  t.is(manager.stagingBytes, APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES + rowBytes, 'successful append stays charged while disk cleanup is unresolved')
  t.is(manager.sessions.size, 1)
  await manager.stop()
  t.is(discardCalls, 2)
  t.is(manager.stagingBytes, 0)
  t.is(manager.sessions.size, 0)
})

test('inbound last-lease reclaim failure is handed to factory retry ownership before session close', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-inbound-reclaim-retry-')))
  let barrierFailures = 2
  const actionErrors = []
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'prior-snapshot-removed' && barrierFailures > 0) {
        barrierFailures--
        throw new Error('forced inbound last-lease reclaim failure')
      }
    }
  })
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const rows = [createCanonicalCatalogRow(record('inbound-reclaim'))]
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: rows
  }, peer)
  let inboundCatalog = null
  const manager = new AppCatalogInboundManager({
    keyPair: relay,
    stageFactory: factory,
    onActionError: err => actionErrors.push(err),
    onComplete: async ({ catalog }) => {
      inboundCatalog = catalog
      const replacement = createAppCatalogSnapshotIdentity({
        senderPubkey: pubkey(peer),
        highWater: snapshot.highWater + 1,
        rows
      })
      const stage = await factory.open({
        peerPubkey: pubkey(peer),
        snapshotId: replacement.snapshotId,
        highWater: replacement.highWater,
        rootDigest: replacement.rootDigest,
        entryCount: replacement.entryCount
      })
      for (const row of rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))
      const replacementCatalog = await stage.commit(replacement)
      await replacementCatalog.release()
    }
  })

  const ack = await manager.receivePage(peer.publicKey, page)
  t.is(ack.pageDigest, page.pageDigest)
  t.is(inboundCatalog.released, true, 'lease state transfers before the reclaim error is reported')
  t.is(factory._failedReclaims.size, 1, 'factory retains the exact failed reclaim phase')
  t.is(actionErrors.length, 1, 'release/reclaim error remains observable')
  t.is(manager.stagingBytes, 0, 'session closes only after the factory owns the retry')
  await manager.stop()

  await t.exception(factory.stop(), /inbound last-lease reclaim failure/)
  t.is(factory._failedReclaims.size, 1)
  await factory.stop()
  t.is(factory._failedReclaims.size, 0)
  t.is(barrierFailures, 0)
})

function mockMux (sendResult = false) {
  const connection = { destroyed: false }
  let options = null
  const handlers = []
  const sent = []
  const channel = {
    closed: false,
    opened: false,
    drained: sendResult,
    _recv () { return 'delegated' },
    addMessage (messageOptions) {
      const id = handlers.length
      handlers.push(messageOptions)
      return {
        send (message) {
          sent.push({ id, message })
          return sendResult
        }
      }
    },
    open () {
      this.opened = true
      return options.onopen()
    },
    close () {
      if (this.closed) return
      this.closed = true
      return options.onclose()
    }
  }
  const mux = {
    createChannel (opts) {
      options = opts
      return channel
    }
  }
  return { connection, mux, channel, handlers, sent }
}

test('Protomux attach serializes callbacks and treats false send as backpressure', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const mock = mockMux(false)
  const gate = deferred()
  const started = []
  const api = attachAppCatalogPagedChannel(mock.connection, {
    mux: mock.mux,
    keyPair: relay,
    remotePubkey: peer.publicKey,
    randomBytes: size => b4a.alloc(size, 0x44),
    onAbort: async () => {
      started.push(started.length)
      if (started.length === 1) await gate.promise
    }
  })
  t.is(mock.channel.closed, false, 'false send is backpressure, not failure')
  t.is(mock.sent[0].id, 0, 'challenge was written')

  const remote = new AppCatalogCapabilitySession({
    keyPair: peer,
    remotePubkey: relay.publicKey,
    randomBytes: size => b4a.alloc(size, 0x55)
  })
  const localChallenge = mock.sent[0].message
  const peerProof = remote.createProof(localChallenge)
  remote.markProofSent(peerProof)
  await mock.handlers[0].onmessage(remote.challenge())
  const localProof = mock.sent.find(item => item.id === 1).message
  remote.verifyPeerProof(localProof)
  await mock.handlers[1].onmessage(peerProof)
  t.is(api.ready, true)

  const abort = createAppCatalogAbort({
    receiverPubkey: pubkey(relay),
    snapshotId: 'a'.repeat(64),
    code: 'PROTOCOL_ERROR'
  }, peer)
  const first = mock.handlers[4].onmessage(abort)
  const second = mock.handlers[4].onmessage(abort)
  await Promise.resolve()
  t.is(started.length, 1, 'second callback waits behind first')
  gate.resolve()
  await Promise.all([first, second])
  t.is(started.length, 2)
  await api.close()
  await api.closed
})

test('Protomux onclose waits behind an in-flight PAGE callback', async (t) => {
  const relay = keyPair()
  const peer = keyPair()
  const mock = mockMux(true)
  const gate = deferred()
  const events = []
  const api = attachAppCatalogPagedChannel(mock.connection, {
    mux: mock.mux,
    keyPair: relay,
    remotePubkey: peer.publicKey,
    randomBytes: size => b4a.alloc(size, 0x66),
    onPage: async () => {
      events.push('page-start')
      await gate.promise
      events.push('page-end')
    },
    onClose: async () => {
      events.push('close')
    }
  })
  const remote = new AppCatalogCapabilitySession({
    keyPair: peer,
    remotePubkey: relay.publicKey,
    randomBytes: size => b4a.alloc(size, 0x77)
  })
  const localChallenge = mock.sent[0].message
  const peerProof = remote.createProof(localChallenge)
  remote.markProofSent(peerProof)
  await mock.handlers[0].onmessage(remote.challenge())
  remote.verifyPeerProof(mock.sent.find(item => item.id === 1).message)
  await mock.handlers[1].onmessage(peerProof)

  const rows = [createCanonicalCatalogRow(record('a'))]
  const snapshot = createAppCatalogSnapshotIdentity({ senderPubkey: pubkey(peer), highWater: 1, rows })
  const page = createAppCatalogPage({
    receiverPubkey: pubkey(relay),
    ...snapshot,
    sequence: 0,
    cursor: null,
    nextCursor: null,
    complete: true,
    entries: rows
  }, peer)
  const handling = mock.handlers[2].onmessage(page)
  await new Promise(resolve => setTimeout(resolve, 0))
  t.alike(events, ['page-start'])
  const closing = mock.channel.close()
  await Promise.resolve()
  t.alike(events, ['page-start'], 'cleanup remains queued behind PAGE handling')
  gate.resolve()
  await Promise.all([handling, closing, api.closed])
  t.alike(events, ['page-start', 'page-end', 'close'])
})

test('unknown outer Protomux ids close only the catalog channel', (t) => {
  for (const id of [5, Number.MAX_SAFE_INTEGER]) {
    let closed = 0
    let delegated = 0
    const channel = {
      close () { closed++ },
      _recv () { delegated++ }
    }
    guardAppCatalogMessageIds(channel)
    const state = { start: 0, end: 17 }
    channel._recv(id, state)
    t.is(closed, 1)
    t.is(delegated, 0)
    t.is(state.start, 17, 'unknown frame is consumed without touching another channel')
  }
})
